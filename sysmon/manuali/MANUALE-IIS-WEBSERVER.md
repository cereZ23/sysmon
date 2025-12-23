# Manuale Configurazione Sicurezza - IIS Web Server (IIS)

**Versione:** 1.0
**Data:** 23 Dicembre 2025
**Target:** Windows Server con IIS 10.0+

---

## 1. Panoramica

IIS Web Server è un target primario per attacchi web. La configurazione si focalizza su webshell detection, RCE e command injection.

### Profilo di Rischio IIS

| Caratteristica | Valore |
|----------------|--------|
| Esposizione | MOLTO ALTA (esposto a Internet) |
| Attacchi comuni | Webshell, RCE, SQL injection, LFI/RFI |
| Volume eventi | ALTO (richieste web continue) |
| Priorità | Webshell detection, command execution |

### Minacce Specifiche IIS

| Minaccia | Tecnica | Indicatore |
|----------|---------|------------|
| Webshell Upload | T1505.003 | .aspx/.ashx in wwwroot |
| RCE via Application | T1190 | w3wp.exe → cmd/ps |
| Command Injection | T1059 | w3wp.exe spawning processes |
| Web Shell Execution | T1059.001 | PowerShell from w3wp.exe |
| File Upload Abuse | T1105 | File creation in inetpub |

---

## 2. Installazione Sysmon

### 2.1 Installazione

```powershell
# 1. Copiare i file
Copy-Item "Sysmon64.exe" -Destination "C:\Tools\"
Copy-Item "sysmon-iis.xml" -Destination "C:\Tools\"

# 2. Installare
C:\Tools\Sysmon64.exe -accepteula -i C:\Tools\sysmon-iis.xml

# 3. Verificare
Get-Service Sysmon64
```

### 2.2 Caratteristiche Configurazione IIS

La configurazione `sysmon-iis.xml` include:
- **Regole AND critiche:** w3wp.exe che spawna qualsiasi processo
- **FileCreate:** Monitoraggio .aspx/.ashx/.asmx in tutte le cartelle web
- **Esclusioni:** Processi IIS normali per ridurre noise

---

## 3. Eventi Sysmon per IIS

### 3.1 Regole CRITICHE - Webshell/RCE Detection

```xml
<!-- CRITICO: w3wp.exe che spawna QUALSIASI processo = WEBSHELL/RCE -->
<Rule groupRelation="and">
  <ParentImage condition="end with">\w3wp.exe</ParentImage>
  <Image condition="image">cmd.exe</Image>
</Rule>
<Rule groupRelation="and">
  <ParentImage condition="end with">\w3wp.exe</ParentImage>
  <Image condition="image">powershell.exe</Image>
</Rule>
<Rule groupRelation="and">
  <ParentImage condition="end with">\w3wp.exe</ParentImage>
  <Image condition="image">whoami.exe</Image>
</Rule>
<Rule groupRelation="and">
  <ParentImage condition="end with">\w3wp.exe</ParentImage>
  <Image condition="image">net.exe</Image>
</Rule>
```

**QUALSIASI match di queste regole richiede investigazione IMMEDIATA.**

### 3.2 FileCreate - Webshell Upload

```xml
<!-- Webshell file types - SEMPRE monitorare -->
<TargetFilename condition="end with">.aspx</TargetFilename>
<TargetFilename condition="end with">.ashx</TargetFilename>
<TargetFilename condition="end with">.asmx</TargetFilename>
<TargetFilename condition="end with">.asp</TargetFilename>
<TargetFilename condition="end with">.config</TargetFilename>

<!-- Path critici -->
<TargetFilename condition="contains">\inetpub\</TargetFilename>
<TargetFilename condition="contains">\wwwroot\</TargetFilename>
```

---

## 4. Windows Security Events

### 4.1 Eseguire Audit Policy

```powershell
.\deploy\windows-audit-policy.ps1 -SysmonInstalled
```

### 4.2 Eventi Windows per IIS

| Event ID | Descrizione | Importanza |
|----------|-------------|------------|
| 4624 | Logon (Type 3 = Network) | MEDIO |
| 4625 | Logon Failed | ALTO |
| 4688 | Process Creation* | ALTO |
| 4663 | Object Access (con SACL) | MEDIO |
| 4697 | Service Installed | CRITICO |

*Solo se Sysmon non installato

---

## 5. IIS Logging Configuration

### 5.1 Abilitare W3C Extended Logging

```powershell
# Configurare campi log IIS
Import-Module WebAdministration
Set-WebConfigurationProperty -Filter "system.applicationHost/sites/siteDefaults/logFile" `
    -Name "logFormat" -Value "W3C"

# Aggiungere campi critici
Set-WebConfigurationProperty -Filter "system.applicationHost/sites/siteDefaults/logFile" `
    -Name "logExtFileFlags" -Value "Date,Time,ClientIP,UserName,Method,UriStem,UriQuery,HttpStatus,BytesSent,BytesRecv,UserAgent,Referer,TimeTaken"
```

### 5.2 Failed Request Tracing

```powershell
# Abilitare per codici errore 400-599
Set-WebConfigurationProperty -Filter "system.webServer/tracing/traceFailedRequests" `
    -Name "enabled" -Value "True"
```

---

## 6. Regole di Rilevamento

### 6.1 Webshell Execution (CRITICO - P1)

**Sysmon Detection:**
```spl
index=sysmon EventCode=1
| where match(ParentImage, "(?i)w3wp\.exe$")
| table _time, ComputerName, User, Image, CommandLine, ParentCommandLine
| sort -_time
```

**Action:** Alert immediato + isolamento host

### 6.2 Webshell Upload Detection

**Sysmon Detection:**
```spl
index=sysmon EventCode=11
| where match(TargetFilename, "(?i)\.(aspx?|ashx|asmx|config)$")
| where match(TargetFilename, "(?i)(inetpub|wwwroot)")
| table _time, ComputerName, User, Image, TargetFilename
```

### 6.3 Suspicious IIS Log Patterns

**Log Analysis:**
```spl
index=iis
| where match(cs_uri_stem, "(?i)\.(aspx|ashx|asmx)$")
| where match(cs_uri_query, "(?i)(cmd|exec|shell|powershell|eval)")
| table _time, c_ip, cs_uri_stem, cs_uri_query, cs_User_Agent, sc_status
```

### 6.4 Command Injection Patterns

**IIS Log Analysis:**
```spl
index=iis
| where match(cs_uri_query, "(?i)(\||;|`|\$\(|%7c|%3b)")
| where match(cs_uri_query, "(?i)(whoami|net\+user|ping|nslookup|dir)")
| table _time, c_ip, cs_uri_stem, cs_uri_query
```

---

## 7. Checklist Deployment

### Pre-Deployment

- [ ] Inventariare tutte le web applications
- [ ] Identificare applicazioni legacy
- [ ] Pianificare finestra di manutenzione
- [ ] Backup configurazione IIS

### Deployment

- [ ] Installare Sysmon con `sysmon-iis.xml`
- [ ] Eseguire `windows-audit-policy.ps1 -SysmonInstalled`
- [ ] Configurare IIS Extended Logging
- [ ] Eseguire `enable-powershell-logging.ps1`

### Post-Deployment

- [ ] Verificare che siti web funzionino
- [ ] Testare upload file normale
- [ ] Monitorare performance per 24h
- [ ] Configurare forwarding SIEM

---

## 8. Configurazione Event Log

```powershell
# IIS genera molti eventi, servono log grandi
wevtutil sl "Microsoft-Windows-Sysmon/Operational" /ms:2147483648  # 2GB
wevtutil sl "Security" /ms:1073741824  # 1GB
wevtutil sl "Microsoft-Windows-IIS-Logging/Logs" /ms:1073741824  # 1GB
```

---

## 9. Hardening IIS

### 9.1 Rimuovere Handler Non Necessari

```powershell
# Rimuovere handler pericolosi se non usati
Remove-WebHandler -Name "ISAPI-dll"
Remove-WebHandler -Name "CGI-exe"
```

### 9.2 Disabilitare Directory Browsing

```powershell
Set-WebConfigurationProperty -Filter "system.webServer/directoryBrowse" `
    -Name "enabled" -Value "False"
```

### 9.3 Configurare Request Filtering

```powershell
# Bloccare estensioni pericolose
Add-WebConfigurationProperty -Filter "system.webServer/security/requestFiltering/fileExtensions" `
    -Name "." -Value @{fileExtension=".exe";allowed="False"}
Add-WebConfigurationProperty -Filter "system.webServer/security/requestFiltering/fileExtensions" `
    -Name "." -Value @{fileExtension=".dll";allowed="False"}
```

### 9.4 Abilitare Application Pool Isolation

```powershell
# Ogni sito con proprio Application Pool
New-WebAppPool -Name "SiteIsolatedPool"
Set-ItemProperty "IIS:\AppPools\SiteIsolatedPool" -Name "processModel.identityType" -Value "ApplicationPoolIdentity"
```

---

## 10. Alert da Configurare

| Alert | Priorità | Trigger |
|-------|----------|---------|
| w3wp.exe → Any Process | P1 - CRITICO | Qualsiasi match |
| New .aspx File Created | P2 - ALTO | FileCreate in wwwroot |
| Suspicious URI Query | P2 - ALTO | cmd/shell in query string |
| Multiple 500 Errors | P3 - MEDIO | >10 500 errors/5min |
| Directory Traversal Attempt | P2 - ALTO | ../ in URI |

---

## Appendice A: Common Webshell Indicators

### Filename Patterns
```
shell.aspx, cmd.aspx, r57.aspx, c99.aspx
test.ashx, upload.ashx, file.ashx
web.config (modified)
```

### Content Patterns
```csharp
// Suspicious .aspx content
<% @Page Language="C#" %>
Process.Start()
cmd.exe /c
powershell -enc
eval(
System.Diagnostics.Process
```

### User Agent Patterns
```
python-requests
curl
wget
sqlmap
nikto
```

## Appendice B: MITRE ATT&CK Coverage

| Tecnica | ID | Coverage |
|---------|-----|----------|
| Server Software Component: Web Shell | T1505.003 | Sysmon 1, 11 |
| Exploit Public-Facing Application | T1190 | Sysmon 1 |
| Command and Scripting Interpreter | T1059 | Sysmon 1 |
| Ingress Tool Transfer | T1105 | Sysmon 11 |
| File and Directory Discovery | T1083 | Sysmon 1 |

---

**Documento Version:** 1.0
**Autore:** Security Engineering Team
**Prossima Revisione:** Marzo 2026
