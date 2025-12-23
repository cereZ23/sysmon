# Manuale Configurazione Sicurezza - Domain Controller (DC)

**Versione:** 1.0
**Data:** 23 Dicembre 2025
**Target:** Windows Server 2016/2019/2022 Domain Controller

---

## 1. Panoramica

Il Domain Controller è l'asset più critico dell'infrastruttura Active Directory. Questo manuale descrive la configurazione di sicurezza completa.

### Profilo di Rischio Domain Controller

| Caratteristica | Valore |
|----------------|--------|
| Esposizione | CRITICA (contiene tutti i secret AD) |
| Attacchi comuni | DCSync, Golden Ticket, Kerberoasting |
| Volume eventi | MOLTO ALTO (autenticazione centralizzata) |
| Priorità | Protezione AD, rilevamento lateral movement |

### Minacce Specifiche DC

| Minaccia | Tecnica MITRE | Rilevamento |
|----------|---------------|-------------|
| DCSync | T1003.006 | Windows Event 4662 |
| Golden Ticket | T1558.001 | Windows Event 4768, 4769 |
| Kerberoasting | T1558.003 | Windows Event 4769 |
| AS-REP Roasting | T1558.004 | Windows Event 4768 |
| AdminSDHolder | T1098 | Windows Event 4780 |
| DCShadow | T1207 | Sysmon + Windows Events |

---

## 2. Installazione Sysmon

### 2.1 Installazione

```powershell
# ATTENZIONE: Eseguire in finestra di manutenzione
# Sysmon può causare breve latenza all'avvio

# 1. Copiare i file
Copy-Item "Sysmon64.exe" -Destination "C:\Tools\"
Copy-Item "sysmon-dc.xml" -Destination "C:\Tools\"

# 2. Installare
C:\Tools\Sysmon64.exe -accepteula -i C:\Tools\sysmon-dc.xml

# 3. Verificare
Get-Service Sysmon64
```

### 2.2 Configurazione Specifica DC

La configurazione `sysmon-dc.xml` include regole specifiche per:
- Monitoraggio ntdsutil.exe
- Rilevamento secretsdump/mimikatz
- Monitoraggio replication
- Active Directory tools abuse

---

## 3. Eventi Sysmon Configurati per DC

### 3.1 Eventi Critici

| Event ID | Focus DC | Volume |
|----------|----------|--------|
| 1 | ProcessCreate - AD tools, mimikatz | ALTO |
| 3 | NetworkConnect - Replication anomala | MEDIO |
| 10 | ProcessAccess - LSASS | CRITICO |
| 11 | FileCreate - ntds.dit copy | CRITICO |
| 12-14 | Registry - AD persistence | MEDIO |
| 17-18 | Pipe - SMB lateral movement | ALTO |

### 3.2 Processi Monitorati Specifici DC

```xml
<!-- Già configurati in sysmon-dc.xml -->
<Image condition="image">ntdsutil.exe</Image>
<Image condition="image">dsdbutil.exe</Image>
<Image condition="image">secretsdump.exe</Image>
<Image condition="image">mimikatz.exe</Image>
<Image condition="image">rubeus.exe</Image>
<CommandLine condition="contains">DCSync</CommandLine>
<CommandLine condition="contains">lsadump::dcsync</CommandLine>
```

---

## 4. Configurazione Windows Security Events

### 4.1 Eventi CRITICI per DC (NON coperti da Sysmon)

#### Kerberos Events (T1558)

| Event ID | Descrizione | Rilevamento |
|----------|-------------|-------------|
| **4768** | TGT Request | Golden Ticket, AS-REP Roast |
| **4769** | Service Ticket | Kerberoasting |
| **4770** | TGT Renewal | Ticket lifetime anomalo |
| **4771** | Pre-Auth Failed | Password Spray |
| **4773** | Service Ticket Failed | Kerberoasting failed |

#### Directory Service Events

| Event ID | Descrizione | Rilevamento |
|----------|-------------|-------------|
| **4662** | DS Object Access | DCSync (Properties: 1131f6ad) |
| **4742** | Computer Account Changed | Rogue DC |
| **5136** | DS Object Modified | AdminSDHolder abuse |
| **5137** | DS Object Created | Malicious object |
| **5141** | DS Object Deleted | Evidence destruction |

#### Replication Events

| Event ID | Descrizione | Rilevamento |
|----------|-------------|-------------|
| **4929** | AD Replication Source Removed | DCSync cleanup |
| **8222** | DS Replication | DCSync detection |

### 4.2 Eseguire Audit Policy

```powershell
# CRITICO: Su DC usare SEMPRE con -SysmonInstalled
.\deploy\windows-audit-policy.ps1 -SysmonInstalled

# Verificare Directory Service auditing
auditpol /get /subcategory:"Directory Service Access"
auditpol /get /subcategory:"Directory Service Changes"
```

### 4.3 Configurazione Aggiuntiva per DC

```powershell
# Abilitare DS Access auditing (se non già attivo)
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Replication" /success:enable /failure:enable
```

---

## 5. Regole di Rilevamento Specifiche DC

### 5.1 DCSync Detection (CRITICO)

**Windows Event 4662:**
```spl
index=wineventlog EventCode=4662
| where match(Properties, "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2")
    OR match(Properties, "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2")
| where NOT match(SubjectUserName, "\$$")  # Exclude computer accounts
| table _time, SubjectUserName, SubjectDomainName, ObjectName, Properties
```

**Spiegazione GUIDs:**
- `1131f6ad-...` = DS-Replication-Get-Changes-All
- `1131f6aa-...` = DS-Replication-Get-Changes

### 5.2 Kerberoasting Detection

**Windows Event 4769:**
```spl
index=wineventlog EventCode=4769
| where TicketEncryptionType="0x17"  # RC4-HMAC (weak)
| where ServiceName!="krbtgt" AND NOT match(ServiceName, "\$$")
| stats count by ClientAddress, ServiceName, TargetUserName
| where count > 5
```

### 5.3 Golden Ticket Detection

**Windows Event 4768 + 4769:**
```spl
index=wineventlog (EventCode=4768 OR EventCode=4769)
| where TicketOptions="0x40810010"  # Forwardable, Renewable, Canonicalize
| where AccountDomain!=ClientDomain  # Domain mismatch
| table _time, AccountName, AccountDomain, ClientDomain, ServiceName
```

### 5.4 AS-REP Roasting Detection

**Windows Event 4768:**
```spl
index=wineventlog EventCode=4768
| where PreAuthType="0"  # No pre-authentication
| where Status="0x0"  # Success
| stats count by TargetUserName, IpAddress
```

### 5.5 AdminSDHolder Abuse

**Windows Event 5136:**
```spl
index=wineventlog EventCode=5136
| where ObjectDN="*AdminSDHolder*"
| table _time, SubjectUserName, ObjectDN, AttributeLDAPDisplayName, AttributeValue
```

---

## 6. Checklist Deployment DC

### Pre-Deployment (CRITICO)

- [ ] Pianificare finestra di manutenzione
- [ ] Backup System State del DC
- [ ] Testare su DC non-FSMO prima
- [ ] Verificare replica AD funzionante
- [ ] Notificare team operativo

### Deployment

- [ ] Installare Sysmon con `sysmon-dc.xml`
- [ ] Eseguire `windows-audit-policy.ps1 -SysmonInstalled`
- [ ] Eseguire `enable-powershell-logging.ps1`
- [ ] Configurare dimensione Event Log
- [ ] Verificare replica AD dopo installazione

### Post-Deployment

- [ ] Monitorare performance DC per 24h
- [ ] Verificare eventi in Event Viewer
- [ ] Configurare forwarding SIEM
- [ ] Creare alert per DCSync, Kerberoasting

---

## 7. Configurazione Event Log per DC

```powershell
# DC richiede log più grandi per il volume elevato
wevtutil sl "Security" /ms:4294967296  # 4GB
wevtutil sl "Microsoft-Windows-Sysmon/Operational" /ms:2147483648  # 2GB
wevtutil sl "Directory Service" /ms:1073741824  # 1GB
wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:1073741824  # 1GB
```

---

## 8. Hardening Aggiuntivo DC

### 8.1 Protected Users Group

```powershell
# Aggiungere admin critici a Protected Users
Add-ADGroupMember -Identity "Protected Users" -Members "admin1", "admin2"
```

### 8.2 Credential Guard (se supportato)

```powershell
# Verificare compatibilità
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
```

### 8.3 LAPS (Local Admin Password Solution)

```powershell
# Verificare LAPS installato
Get-AdmPwdPassword -ComputerName "DC01"
```

---

## 9. Troubleshooting DC

### Problema: Latenza autenticazione dopo Sysmon

```powershell
# Verificare esclusioni Sysmon per processi AD
# In sysmon-dc.xml dovrebbero essere esclusi:
# - lsass.exe (per performance)
# - ntfrs.exe
# - dfsr.exe
```

### Problema: Volume eventi 4769 troppo alto

```powershell
# Contare eventi Kerberos
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4769} -MaxEvents 100000 |
  Measure-Object | Select-Object Count

# Se > 100k/giorno, considerare filtraggio SIEM
```

### Problema: DCSync false positive

```powershell
# Verificare account con permessi di replica legittimi
Get-ADUser -Filter * -Properties * |
  Where-Object {$_."msDS-ReplAttributeMetaData" -ne $null} |
  Select-Object Name, SamAccountName
```

---

## 10. Alert Critici da Configurare

| Alert | Priorità | Evento | Threshold |
|-------|----------|--------|-----------|
| DCSync Detected | P1 - CRITICO | 4662 | Qualsiasi |
| Kerberoasting | P2 - ALTO | 4769 (RC4) | >5/ora |
| Golden Ticket | P1 - CRITICO | 4768 + domain mismatch | Qualsiasi |
| Admin SDHolder Modified | P1 - CRITICO | 5136 | Qualsiasi |
| LSASS Access | P2 - ALTO | Sysmon 10 | >3/giorno |
| Mimikatz Detected | P1 - CRITICO | Sysmon 1 | Qualsiasi |

---

## Appendice: MITRE ATT&CK Coverage DC

| Tecnica | ID | Sysmon | Windows Events | Coverage |
|---------|-----|--------|----------------|----------|
| DCSync | T1003.006 | - | 4662 | 100% |
| Golden Ticket | T1558.001 | 1 | 4768, 4769 | 100% |
| Kerberoasting | T1558.003 | 1 | 4769 | 100% |
| AS-REP Roast | T1558.004 | 1 | 4768 | 100% |
| Pass the Hash | T1550.002 | 10 | 4624 (Type 9) | 100% |
| Pass the Ticket | T1550.003 | 1 | 4768 | 100% |
| DCShadow | T1207 | 1, 3 | 4742, 5137 | 100% |

---

**Documento Version:** 1.0
**Autore:** Security Engineering Team
**Classificazione:** CONFIDENZIALE
**Prossima Revisione:** Marzo 2026
