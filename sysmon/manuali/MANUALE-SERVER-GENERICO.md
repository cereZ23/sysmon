# Manuale Configurazione Sicurezza - Server Generico (SRV)

**Versione:** 1.0
**Data:** 23 Dicembre 2025
**Target:** Windows Server 2016/2019/2022 (File Server, Print Server, Application Server)

---

## 1. Panoramica

Questo manuale copre la configurazione per server Windows generici che non rientrano in categorie specifiche (DC, SQL, IIS, Exchange).

### Profilo di Rischio Server Generico

| Caratteristica | Valore |
|----------------|--------|
| Esposizione | MEDIA (dipende dal ruolo) |
| Attacchi comuni | Lateral movement, privilege escalation |
| Volume eventi | BASSO (nessuna attività utente) |
| Priorità | Rilevamento anomalie, accessi non autorizzati |

### Ruoli Coperti

- File Server
- Print Server
- Application Server
- Member Server
- Utility Server

---

## 2. Installazione Sysmon

### 2.1 Installazione

```powershell
# 1. Copiare i file
Copy-Item "Sysmon64.exe" -Destination "C:\Tools\"
Copy-Item "sysmon-srv.xml" -Destination "C:\Tools\"

# 2. Installare
C:\Tools\Sysmon64.exe -accepteula -i C:\Tools\sysmon-srv.xml

# 3. Verificare
Get-Service Sysmon64
```

### 2.2 Caratteristiche Configurazione SRV

La configurazione `sysmon-srv.xml` è ottimizzata per:
- Basso volume (server senza utenti interattivi)
- Focus su lateral movement
- Rilevamento shells da servizi
- Monitoraggio admin tools

---

## 3. Eventi Sysmon per Server

### 3.1 Eventi Abilitati

| Event ID | Focus Server | Volume |
|----------|--------------|--------|
| 1 | ProcessCreate - Solo da path sospetti | BASSO |
| 3 | NetworkConnect - Connessioni in uscita | BASSO |
| 5 | ProcessTerminate | BASSO |
| 10 | ProcessAccess - LSASS | BASSO |
| 11 | FileCreate - Eseguibili in temp | BASSO |
| 12-14 | Registry - Services, Run keys | BASSO |
| 17-18 | Pipe - Lateral movement | BASSO |

### 3.2 Regole Context-Aware

```xml
<!-- Shell da parent insoliti = SOSPETTO su server -->
<Rule groupRelation="and">
  <Image condition="image">powershell.exe</Image>
  <ParentImage condition="begin with">C:\Users\</ParentImage>
</Rule>
<Rule groupRelation="and">
  <Image condition="image">cmd.exe</Image>
  <ParentImage condition="begin with">C:\Windows\Temp\</ParentImage>
</Rule>
```

---

## 4. Windows Security Events

### 4.1 Eseguire Audit Policy

```powershell
.\deploy\windows-audit-policy.ps1 -SysmonInstalled
```

### 4.2 Eventi Critici per Server Generico

#### Accesso Remoto

| Event ID | Descrizione | Importanza |
|----------|-------------|------------|
| 4624 | Logon Success (Type 3, 10) | ALTO |
| 4625 | Logon Failed | CRITICO |
| 4648 | Explicit Credentials | ALTO |
| 4672 | Special Logon | MEDIO |

#### Servizi e Scheduled Tasks

| Event ID | Descrizione | Importanza |
|----------|-------------|------------|
| 4697 | Service Installed | CRITICO |
| 7045 | Service Installed (System log) | CRITICO |
| 4698 | Scheduled Task Created | CRITICO |
| 4699 | Scheduled Task Deleted | ALTO |

#### File Share (se File Server)

| Event ID | Descrizione | Importanza |
|----------|-------------|------------|
| 5140 | Network Share Accessed | MEDIO |
| 5145 | Network Share Object Access | ALTO |

---

## 5. Regole di Rilevamento

### 5.1 Lateral Movement Detection

**PsExec Detection:**
```spl
index=sysmon EventCode=1
| where match(ParentImage, "(?i)psexesvc\.exe")
| table _time, ComputerName, User, Image, CommandLine
```

**WMI Lateral Movement:**
```spl
index=sysmon EventCode=1
| where match(ParentImage, "(?i)wmiprvse\.exe")
| where match(Image, "(?i)(cmd|powershell)\.exe")
| table _time, ComputerName, User, Image, CommandLine
```

### 5.2 Service Abuse

**Malicious Service Installation:**
```spl
index=wineventlog (EventCode=4697 OR EventCode=7045)
| where NOT match(ServiceFileName, "(?i)^(C:\\Windows\\|C:\\Program Files)")
| table _time, ComputerName, ServiceName, ServiceFileName, ServiceAccount
```

### 5.3 Anomalous Process

**Process from Temp Folders:**
```spl
index=sysmon EventCode=1
| where match(Image, "(?i)(\\Temp\\|\\AppData\\Local\\Temp\\)")
| where match(Image, "(?i)\.exe$")
| table _time, ComputerName, User, Image, CommandLine, ParentImage
```

---

## 6. Checklist Deployment

### Pre-Deployment

- [ ] Identificare ruolo specifico del server
- [ ] Verificare applicazioni critiche installate
- [ ] Pianificare finestra di manutenzione

### Deployment

- [ ] Installare Sysmon con `sysmon-srv.xml`
- [ ] Eseguire `windows-audit-policy.ps1 -SysmonInstalled`
- [ ] Eseguire `enable-powershell-logging.ps1`
- [ ] Configurare Event Log

### Post-Deployment

- [ ] Verificare che applicazioni funzionino
- [ ] Monitorare per 24h
- [ ] Configurare forwarding SIEM

---

## 7. Configurazione Event Log

```powershell
# Server generico - configurazione standard
wevtutil sl "Microsoft-Windows-Sysmon/Operational" /ms:1073741824  # 1GB
wevtutil sl "Security" /ms:1073741824  # 1GB
wevtutil sl "System" /ms:268435456  # 256MB
wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:524288000  # 500MB
```

---

## 8. Baseline Comportamentale

### Cosa È NORMALE su Server Generico

- Processi schedulati da SYSTEM
- Servizi che si avviano automaticamente
- Accessi amministrativi pianificati
- Connessioni da management tools

### Cosa È ANOMALO su Server Generico

| Comportamento | Indicatore | Priorità |
|---------------|------------|----------|
| PowerShell interattivo | ParentImage = explorer.exe | ALTA |
| Download da internet | Connessione porta 80/443 in uscita | MEDIA |
| Nuovo servizio creato | Event 4697/7045 | ALTA |
| Accesso LSASS | Sysmon Event 10 | CRITICA |
| Eseguibile in Temp | Event 1 + path Temp | ALTA |

---

## 9. Hardening Raccomandato

### 9.1 Disabilitare Servizi Non Necessari

```powershell
# Esempio: disabilitare Print Spooler se non necessario
Stop-Service -Name "Spooler" -Force
Set-Service -Name "Spooler" -StartupType Disabled
```

### 9.2 Rimuovere SMBv1

```powershell
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
```

### 9.3 Abilitare Windows Firewall Logging

```powershell
Set-NetFirewallProfile -Profile Domain,Private,Public -LogBlocked True -LogAllowed True
```

---

## 10. Alert da Configurare

| Alert | Priorità | Descrizione |
|-------|----------|-------------|
| New Service Installed | P2 | Event 4697/7045 |
| PsExec Usage | P2 | ParentImage = psexesvc.exe |
| PowerShell from Service | P2 | ParentImage = services.exe + powershell |
| LSASS Access | P1 | Sysmon 10 target lsass.exe |
| Executable in Temp | P3 | Event 1 + path Temp |

---

## Appendice: MITRE ATT&CK Coverage

| Tecnica | ID | Coverage |
|---------|-----|----------|
| Remote Services | T1021 | Windows 4624, 5140 |
| Service Execution | T1569.002 | Windows 4697, 7045 |
| Scheduled Task | T1053.005 | Windows 4698 |
| WMI | T1047 | Sysmon 1 |
| PowerShell | T1059.001 | Sysmon 1, PS 4104 |
| Lateral Tool Transfer | T1570 | Windows 5145 |

---

**Documento Version:** 1.0
**Autore:** Security Engineering Team
**Prossima Revisione:** Marzo 2026
