# Manuale Configurazione Sicurezza - Exchange Server (EXCH)

**Versione:** 1.0
**Data:** 23 Dicembre 2025
**Target:** Microsoft Exchange Server 2016/2019

---

## 1. Panoramica

Exchange Server è un target ad alta priorità per attaccanti. Le vulnerabilità ProxyLogon/ProxyShell hanno dimostrato l'importanza del monitoraggio.

### Profilo di Rischio Exchange

| Caratteristica | Valore |
|----------------|--------|
| Esposizione | CRITICA (email + Active Directory) |
| Attacchi comuni | ProxyLogon, ProxyShell, webshell, OWA abuse |
| Volume eventi | MOLTO ALTO (IIS + Exchange processes) |
| Priorità | Webshell, privilege escalation, data exfiltration |

### Minacce Specifiche Exchange

| Minaccia | CVE | Indicatore |
|----------|-----|------------|
| ProxyLogon | CVE-2021-26855 | File in aspnet_client |
| ProxyShell | CVE-2021-34473 | Autodiscover abuse |
| ProxyNotShell | CVE-2022-41040 | PowerShell remoting |
| OWA Credential Theft | - | Phishing, keylogger |
| Mailbox Export | T1114 | New-MailboxExportRequest |

---

## 2. Installazione Sysmon

### 2.1 Pre-Requisiti

```powershell
# Exchange è critico - SEMPRE pianificare manutenzione
# Verificare stato Exchange
Get-ExchangeServer | Format-Table Name, ServerRole, Edition

# Verificare coda messaggi
Get-Queue | Where-Object {$_.MessageCount -gt 100}
```

### 2.2 Installazione

```powershell
# 1. Copiare i file
Copy-Item "Sysmon64.exe" -Destination "C:\Tools\"
Copy-Item "sysmon-exch.xml" -Destination "C:\Tools\"

# 2. Installare (durante manutenzione)
C:\Tools\Sysmon64.exe -accepteula -i C:\Tools\sysmon-exch.xml

# 3. Verificare
Get-Service Sysmon64
```

### 2.3 Caratteristiche Configurazione Exchange

La configurazione `sysmon-exch.xml` include:
- Monitoraggio IIS (w3wp.exe) per webshell
- Monitoraggio Exchange processes
- FileCreate per path ProxyLogon/ProxyShell
- Esclusioni per processi Exchange legittimi

---

## 3. Eventi Sysmon per Exchange

### 3.1 Regole CRITICHE - ProxyLogon/ProxyShell

```xml
<!-- CRITICO: IIS che spawna processi = WEBSHELL -->
<ParentImage condition="is">C:\Windows\System32\inetsrv\w3wp.exe</ParentImage>

<!-- Exchange processes che spawnano shell -->
<ParentImage condition="contains">\Exchange Server\</ParentImage>
<ParentImage condition="end with">\UMWorkerProcess.exe</ParentImage>
<ParentImage condition="end with">\UMService.exe</ParentImage>
<ParentImage condition="end with">\MSExchangeTransport.exe</ParentImage>
```

### 3.2 FileCreate - Webshell Paths

```xml
<!-- ProxyLogon/ProxyShell paths - QUALSIASI file = ALERT -->
<TargetFilename condition="contains">\inetpub\wwwroot\aspnet_client\</TargetFilename>
<TargetFilename condition="contains">\FrontEnd\HttpProxy\</TargetFilename>
<TargetFilename condition="contains">\Autodiscover\</TargetFilename>
<TargetFilename condition="contains">\ecp\</TargetFilename>
<TargetFilename condition="contains">\OWA\</TargetFilename>
<TargetFilename condition="contains">\EWS\</TargetFilename>

<!-- Webshell extensions -->
<TargetFilename condition="end with">.aspx</TargetFilename>
<TargetFilename condition="end with">.ashx</TargetFilename>
<TargetFilename condition="end with">.asmx</TargetFilename>
```

---

## 4. Windows Security Events

### 4.1 Eseguire Audit Policy

```powershell
.\deploy\windows-audit-policy.ps1 -SysmonInstalled
```

### 4.2 Eventi Windows per Exchange

| Event ID | Descrizione | Importanza |
|----------|-------------|------------|
| 4624 | Logon | ALTO |
| 4625 | Logon Failed (OWA brute force) | CRITICO |
| 4648 | Explicit Credentials | ALTO |
| 4672 | Special Logon | MEDIO |
| 4697 | Service Installed | CRITICO |

---

## 5. Exchange Audit Logging

### 5.1 Abilitare Admin Audit Log

```powershell
# Abilitare audit per tutti i cmdlet
Set-AdminAuditLogConfig -AdminAuditLogEnabled $true
Set-AdminAuditLogConfig -AdminAuditLogCmdlets *
Set-AdminAuditLogConfig -AdminAuditLogParameters *

# Verificare
Get-AdminAuditLogConfig | Format-List AdminAuditLogEnabled, AdminAuditLogCmdlets
```

### 5.2 Abilitare Mailbox Audit

```powershell
# Abilitare per tutte le mailbox
Get-Mailbox -ResultSize Unlimited | Set-Mailbox -AuditEnabled $true

# Configurare azioni da audire
Get-Mailbox -ResultSize Unlimited | Set-Mailbox -AuditOwner Create,HardDelete,MailboxLogin,Move,MoveToDeletedItems,SoftDelete,Update
```

### 5.3 Monitorare Export Requests

```powershell
# Alert per nuove export requests (possibile data exfil)
Get-MailboxExportRequest | Where-Object {$_.WhenCreated -gt (Get-Date).AddDays(-1)}
```

---

## 6. Regole di Rilevamento

### 6.1 Webshell Detection (CRITICO - P1)

**Sysmon Event 1:**
```spl
index=sysmon EventCode=1
| where match(ParentImage, "(?i)w3wp\.exe$")
| where match(Image, "(?i)(cmd|powershell|pwsh)\.exe$")
| table _time, ComputerName, User, Image, CommandLine
```

**Action:** Alert P1 + Isolamento + IR Team

### 6.2 ProxyLogon/ProxyShell File Creation

**Sysmon Event 11:**
```spl
index=sysmon EventCode=11
| where match(TargetFilename, "(?i)(aspnet_client|FrontEnd\\HttpProxy|Autodiscover|ecp|OWA|EWS)")
| where match(TargetFilename, "(?i)\.(aspx|ashx|asmx|config)$")
| table _time, ComputerName, Image, TargetFilename, User
```

### 6.3 Mailbox Export (Data Exfiltration)

**Exchange Logs:**
```spl
index=exchange sourcetype=exchange:audit
| where match(CmdletName, "(?i)MailboxExportRequest")
| table _time, User, CmdletName, ObjectModified, CmdletParameters
```

### 6.4 OWA Brute Force

**Windows Security:**
```spl
index=wineventlog EventCode=4625
| where LogonType=8  # NetworkCleartext (OWA)
| stats count by TargetUserName, IpAddress
| where count > 10
```

### 6.5 Suspicious PowerShell from Exchange

```spl
index=sysmon EventCode=1
| where match(ParentImage, "(?i)(MSExchange|Exchange)")
| where match(Image, "(?i)powershell\.exe$")
| where match(CommandLine, "(?i)(-enc|-encoded|downloadstring|invoke-)")
| table _time, ComputerName, CommandLine
```

---

## 7. Checklist Deployment

### Pre-Deployment (CRITICO)

- [ ] Pianificare finestra di manutenzione
- [ ] Verificare backup Exchange
- [ ] Controllare code messaggi vuote
- [ ] Notificare team messaging
- [ ] Testare su server non-production prima

### Deployment

- [ ] Installare Sysmon con `sysmon-exch.xml`
- [ ] Eseguire `windows-audit-policy.ps1 -SysmonInstalled`
- [ ] Abilitare Exchange Admin Audit Log
- [ ] Abilitare Mailbox Audit
- [ ] Eseguire `enable-powershell-logging.ps1`

### Post-Deployment

- [ ] Verificare servizi Exchange attivi
- [ ] Testare invio/ricezione email
- [ ] Testare accesso OWA
- [ ] Monitorare performance per 48h
- [ ] Configurare forwarding SIEM

---

## 8. Configurazione Event Log

```powershell
# Exchange genera MOLTI eventi
wevtutil sl "Microsoft-Windows-Sysmon/Operational" /ms:4294967296  # 4GB
wevtutil sl "Security" /ms:4294967296  # 4GB
wevtutil sl "MSExchange Management" /ms:1073741824  # 1GB
wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:1073741824  # 1GB
```

---

## 9. Hardening Exchange

### 9.1 Disabilitare PowerShell Remoting per Utenti

```powershell
# Solo admin dovrebbero avere accesso
Get-User -ResultSize Unlimited | Where-Object {$_.RemotePowerShellEnabled -eq $true} |
    Where-Object {$_.Name -notlike "*admin*"} |
    Set-User -RemotePowerShellEnabled $false
```

### 9.2 Extended Protection

```powershell
# Abilitare Extended Protection (mitiga ProxyNotShell)
Set-ExchangeServer -Identity "EXCH01" -ExtendedProtectionSPNList @{Add="HTTP/mail.contoso.com"}
```

### 9.3 Disabilitare Servizi Non Necessari

```powershell
# Se UM non usato
Get-Service MSExchangeUM, MSExchangeUMCR | Stop-Service -PassThru | Set-Service -StartupType Disabled
```

### 9.4 Emergency Mitigation Service

```powershell
# Verificare EMS attivo (auto-mitiga vulnerabilità)
Get-ExchangeServer | Format-Table Name, MitigationsEnabled, MitigationsApplied
```

---

## 10. Alert da Configurare

| Alert | Priorità | Trigger |
|-------|----------|---------|
| w3wp.exe → Process | P1 - CRITICO | Qualsiasi match |
| File in aspnet_client | P1 - CRITICO | FileCreate |
| New Export Request | P2 - ALTO | MailboxExportRequest |
| OWA Brute Force | P2 - ALTO | >10 4625/5min |
| PowerShell from Exchange | P2 - ALTO | Encoded command |
| Admin Audit Log Disabled | P1 - CRITICO | Config change |

---

## 11. Indicatori di Compromissione (IOC)

### File Paths ProxyLogon

```
C:\inetpub\wwwroot\aspnet_client\*.aspx
C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\*.aspx
C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\ecp\auth\*.aspx
```

### Common Webshell Names

```
shell.aspx, cmd.aspx, error.aspx, errorEE.aspx
load.aspx, OutlookEN.aspx, discover.aspx
RedirSuiteServerProxy.aspx
```

### Suspicious Cmdlets

```powershell
# Da monitorare
New-MailboxExportRequest
Set-OabVirtualDirectory -ExternalUrl
New-ManagementRoleAssignment
Add-MailboxPermission -AccessRights FullAccess
```

---

## Appendice A: Exchange Services Reference

| Servizio | Funzione | Monitorare |
|----------|----------|------------|
| MSExchangeTransport | Mail transport | Sì |
| MSExchangeIS | Information Store | Sì |
| w3wp.exe | IIS Worker | CRITICO |
| UMWorkerProcess | Unified Messaging | Sì |
| EdgeTransport | Edge server | Sì |

## Appendice B: MITRE ATT&CK Coverage

| Tecnica | ID | Coverage |
|---------|-----|----------|
| Exploit Public-Facing | T1190 | Sysmon 1, 11 |
| Web Shell | T1505.003 | Sysmon 1, 11 |
| Email Collection | T1114 | Exchange Audit |
| Valid Accounts | T1078 | Windows 4624 |
| Remote Services | T1021 | Windows 4624 |
| Archive Collected Data | T1560 | Sysmon 1 |

---

## Appendice C: Patching Priority

| CVE | Nome | Criticità | Patch |
|-----|------|-----------|-------|
| CVE-2021-26855 | ProxyLogon | CRITICA | KB5000871 |
| CVE-2021-34473 | ProxyShell | CRITICA | KB5003435 |
| CVE-2022-41040 | ProxyNotShell | ALTA | KB5019758 |
| CVE-2023-21529 | RCE | CRITICA | Ultimo CU |

**IMPORTANTE:** Verificare SEMPRE che Exchange sia aggiornato all'ultimo Cumulative Update.

---

**Documento Version:** 1.0
**Autore:** Security Engineering Team
**Classificazione:** CONFIDENZIALE
**Prossima Revisione:** Marzo 2026
