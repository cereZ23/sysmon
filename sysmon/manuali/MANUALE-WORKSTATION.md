# Manuale Configurazione Sicurezza - Workstation (WS)

**Versione:** 1.0
**Data:** 23 Dicembre 2025
**Target:** Windows 10/11 Workstation

---

## 1. Panoramica

Questo manuale descrive la configurazione completa di sicurezza per workstation Windows, combinando:
- **Sysmon** per il monitoraggio endpoint avanzato
- **Windows Security Events** per autenticazione e account management
- **PowerShell Logging** per rilevamento script malevoli

### Profilo di Rischio Workstation

| Caratteristica | Valore |
|----------------|--------|
| Esposizione | ALTA (utenti, browser, email) |
| Attacchi comuni | Phishing, malware, credential theft |
| Volume eventi | ALTO (attività utente continua) |
| Priorità | Endpoint protection, user behavior |

---

## 2. Installazione Sysmon

### 2.1 Download e Installazione

```powershell
# 1. Scaricare Sysmon da Sysinternals
Invoke-WebRequest -Uri "https://live.sysinternals.com/Sysmon64.exe" -OutFile "C:\Tools\Sysmon64.exe"

# 2. Copiare la configurazione
Copy-Item "sysmon-ws.xml" -Destination "C:\Tools\sysmon-ws.xml"

# 3. Installare Sysmon con la configurazione
C:\Tools\Sysmon64.exe -accepteula -i C:\Tools\sysmon-ws.xml

# 4. Verificare l'installazione
Get-Service Sysmon64
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
```

### 2.2 Aggiornamento Configurazione

```powershell
# Aggiornare la configurazione senza reinstallare
C:\Tools\Sysmon64.exe -c C:\Tools\sysmon-ws.xml
```

### 2.3 Disinstallazione (se necessario)

```powershell
C:\Tools\Sysmon64.exe -u
```

---

## 3. Eventi Sysmon Configurati

### 3.1 Eventi Abilitati per Workstation

| Event ID | Nome | Scopo | Volume |
|----------|------|-------|--------|
| 1 | ProcessCreate | Rilevamento malware, LOLBins | ALTO |
| 3 | NetworkConnect | C2 communication, exfiltration | MEDIO |
| 5 | ProcessTerminate | Correlazione processi | BASSO |
| 7 | ImageLoad | DLL hijacking, injection | ALTO |
| 8 | CreateRemoteThread | Process injection | BASSO |
| 10 | ProcessAccess | Credential dumping (LSASS) | MEDIO |
| 11 | FileCreate | Malware drops, webshells | MEDIO |
| 12-14 | Registry | Persistence mechanisms | MEDIO |
| 15 | FileCreateStreamHash | ADS abuse | BASSO |
| 17-18 | Pipe | Lateral movement | BASSO |
| 22 | DNSQuery | C2 domains, tunneling | ALTO |
| 23 | FileDelete | Anti-forensics | BASSO |

### 3.2 Tecniche MITRE Rilevate da Sysmon

| Tecnica | ID | Rilevamento |
|---------|----|--------------|
| PowerShell Execution | T1059.001 | Event 1 (CommandLine) |
| Scheduled Task | T1053.005 | Event 1 (schtasks.exe) |
| Registry Run Keys | T1547.001 | Events 12-13 |
| LSASS Memory Dump | T1003.001 | Event 10 |
| DLL Side-Loading | T1574.002 | Event 7 |
| Process Injection | T1055 | Events 8, 10 |
| Credential Dumping | T1003 | Events 1, 10 |
| DNS Tunneling | T1071.004 | Event 22 |

---

## 4. Configurazione Windows Security Events

### 4.1 Eseguire lo Script di Audit Policy

```powershell
# Con Sysmon installato (evita duplicati Process Creation)
.\deploy\windows-audit-policy.ps1 -SysmonInstalled

# Senza Sysmon
.\deploy\windows-audit-policy.ps1
```

### 4.2 Eventi Windows Critici per Workstation

#### Autenticazione (NON coperti da Sysmon)

| Event ID | Descrizione | Criticità | Tecnica MITRE |
|----------|-------------|-----------|---------------|
| 4624 | Logon Success | INFO | T1078 |
| 4625 | Logon Failed | CRITICO | T1110 (Brute Force) |
| 4648 | Explicit Credentials | ALTO | T1078 |
| 4672 | Special Privileges | ALTO | T1078.002 |

#### Account Management (NON coperti da Sysmon)

| Event ID | Descrizione | Criticità | Tecnica MITRE |
|----------|-------------|-----------|---------------|
| 4720 | User Created | CRITICO | T1136.001 |
| 4722 | User Enabled | ALTO | T1098 |
| 4724 | Password Reset | ALTO | T1098 |
| 4732 | User Added to Local Admins | CRITICO | T1098 |

### 4.3 Verifica Configurazione Audit

```powershell
# Verificare le policy attive
auditpol /get /category:*

# Output atteso per workstation:
# Logon/Logoff -> Success and Failure
# Account Management -> Success and Failure
# Detailed Tracking -> Success (se no Sysmon)
```

---

## 5. Configurazione PowerShell Logging

### 5.1 Eseguire lo Script

```powershell
.\deploy\enable-powershell-logging.ps1
```

### 5.2 Eventi PowerShell Generati

| Event ID | Log | Descrizione | Uso |
|----------|-----|-------------|-----|
| 4103 | PowerShell/Operational | Module Logging | Comandi eseguiti |
| 4104 | PowerShell/Operational | Script Block | Codice deoffuscato |
| 4105 | PowerShell/Operational | Script Start | Inizio esecuzione |
| 4106 | PowerShell/Operational | Script Stop | Fine esecuzione |

### 5.3 Cosa Rileva

```
Event 4104 cattura (anche se offuscato):
- Invoke-Mimikatz
- Invoke-WebRequest (download cradles)
- -EncodedCommand (decodificato!)
- IEX (Invoke-Expression)
- Net.WebClient
```

---

## 6. Checklist Deployment Workstation

### Pre-Deployment

- [ ] Backup della configurazione esistente
- [ ] Verificare spazio disco per log (min 10GB liberi)
- [ ] Testare su workstation pilota

### Deployment

- [ ] Installare Sysmon con `sysmon-ws.xml`
- [ ] Eseguire `windows-audit-policy.ps1 -SysmonInstalled`
- [ ] Eseguire `enable-powershell-logging.ps1`
- [ ] Configurare dimensione Event Log (vedi sotto)

### Post-Deployment

- [ ] Verificare servizio Sysmon attivo
- [ ] Verificare eventi in Event Viewer
- [ ] Configurare forwarding al SIEM
- [ ] Documentare baseline comportamentale

---

## 7. Configurazione Event Log

```powershell
# Aumentare dimensione log per workstation
wevtutil sl "Microsoft-Windows-Sysmon/Operational" /ms:1073741824  # 1GB
wevtutil sl "Security" /ms:1073741824  # 1GB
wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:524288000  # 500MB

# Verificare
wevtutil gl "Microsoft-Windows-Sysmon/Operational" | Select-String "maxSize"
```

---

## 8. Regole di Rilevamento SIEM

### 8.1 Credential Dumping (Splunk)

```spl
index=sysmon EventCode=10 TargetImage="*lsass.exe"
| where NOT match(SourceImage, "(?i)(MsMpEng|csrss|services)\.exe$")
| stats count by ComputerName, SourceImage, SourceUser
| where count > 0
```

### 8.2 Encoded PowerShell (Splunk)

```spl
index=wineventlog source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
| where match(ScriptBlockText, "(?i)(FromBase64|Invoke-|IEX|WebClient)")
| table _time, ComputerName, ScriptBlockText
```

### 8.3 Suspicious Process from User Folder (Elastic)

```json
{
  "query": {
    "bool": {
      "must": [
        { "term": { "event.code": "1" }},
        { "wildcard": { "process.executable": "*\\Users\\*\\AppData\\*" }}
      ],
      "must_not": [
        { "wildcard": { "process.executable": "*\\Microsoft\\*" }}
      ]
    }
  }
}
```

---

## 9. Troubleshooting

### Problema: Sysmon non genera eventi

```powershell
# Verificare servizio
Get-Service Sysmon64

# Verificare configurazione caricata
C:\Tools\Sysmon64.exe -c

# Reinstallare se necessario
C:\Tools\Sysmon64.exe -u
C:\Tools\Sysmon64.exe -accepteula -i C:\Tools\sysmon-ws.xml
```

### Problema: Volume eventi troppo alto

```powershell
# Verificare quali eventi generano più volume
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10000 |
  Group-Object Id | Sort-Object Count -Descending | Select-Object -First 10
```

### Problema: Eventi mancanti in SIEM

```powershell
# Verificare Windows Event Forwarding
wecutil gs "Subscription Name"

# Verificare connettività SIEM
Test-NetConnection -ComputerName "siem.domain.local" -Port 514
```

---

## 10. Manutenzione

### Giornaliera
- Verificare che Sysmon sia attivo
- Controllare spazio disco per log

### Settimanale
- Analizzare eventi ad alto volume per tuning
- Verificare falsi positivi nelle regole SIEM

### Mensile
- Aggiornare Sysmon all'ultima versione
- Rivedere e aggiornare configurazione XML
- Verificare copertura MITRE ATT&CK

---

## Appendice A: File di Configurazione

| File | Posizione | Scopo |
|------|-----------|-------|
| sysmon-ws.xml | sysmon/ | Configurazione Sysmon |
| windows-audit-policy.ps1 | sysmon/deploy/ | Audit Policy |
| enable-powershell-logging.ps1 | sysmon/deploy/ | PowerShell Logging |

## Appendice B: Porte e Servizi

| Servizio | Porta | Protocollo | Note |
|----------|-------|------------|------|
| Sysmon | N/A | Driver kernel | Servizio locale |
| WEF | 5985/5986 | WinRM | Event forwarding |
| Syslog | 514 | UDP/TCP | Forwarding SIEM |

---

**Documento Version:** 1.0
**Autore:** Security Engineering Team
**Prossima Revisione:** Marzo 2026
