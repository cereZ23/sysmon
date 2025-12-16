# Sysmon Configuration: Exchange Server

**File:** `sysmon-exch.xml`
**Target:** Exchange Server 2016/2019
**Focus:** ProxyLogon/ProxyShell, webshells, OWA abuse, credential theft

## Overview

Critical Tier-0 asset configuration focusing on Exchange-specific attack vectors that have been heavily exploited in the wild (HAFNIUM, ProxyLogon, ProxyShell, ProxyNotShell). Any w3wp.exe child process is treated as a critical indicator.

## Key Threats Detected

| Threat | Detection Method |
|--------|-----------------|
| ProxyLogon/ProxyShell | w3wp.exe spawning processes |
| Webshell Deployment | .aspx/.ashx file creation in web paths |
| OWA Credential Theft | PowerShell in Exchange context |
| Lateral Movement | PsExec, credential dumping |
| Persistence | Registry, Services, WMI |

## Critical Rule: w3wp.exe Child Processes

**ANY process spawned by w3wp.exe on Exchange = ATTACK INDICATOR**

```
w3wp.exe → cmd.exe       = WEBSHELL
w3wp.exe → powershell.exe = WEBSHELL
w3wp.exe → whoami.exe    = POST-EXPLOITATION RECON
w3wp.exe → net.exe       = LATERAL MOVEMENT PREP
```

## Event ID Coverage

| Event ID | Name | Status | Notes |
|----------|------|--------|-------|
| 1 | ProcessCreate | Active | w3wp.exe focus |
| 2 | FileCreateTime | Active | Webshell timestomping |
| 3 | NetworkConnect | Active | Reverse shell detection |
| 5 | ProcessTerminate | Active | Exchange service + EDR |
| 7 | ImageLoad | Active | DLL injection detection |
| 8 | CreateRemoteThread | Active | Injection detection |
| 10 | ProcessAccess | Active | LSASS protection |
| 11 | FileCreate | Active | Webshell file types |
| 13 | RegistryEvent | Active | Persistence + Exchange keys |
| 15 | FileCreateStreamHash | Active | ADS detection |
| 17/18 | PipeEvent | Active | C2 frameworks |
| 19/20/21 | WmiEvent | Active | WMI persistence |
| 22 | DnsQuery | Active | Fixed exclusions |

## Exchange-Specific Detections

### Webshell File Creation (Event 11)
```xml
<!-- Critical web file types -->
<TargetFilename condition="end with">.aspx</TargetFilename>
<TargetFilename condition="end with">.ashx</TargetFilename>
<TargetFilename condition="end with">.asmx</TargetFilename>

<!-- ProxyLogon/ProxyShell paths -->
<TargetFilename condition="contains">\inetpub\wwwroot\aspnet_client\</TargetFilename>
<TargetFilename condition="contains">\FrontEnd\HttpProxy\</TargetFilename>
<TargetFilename condition="contains">\Autodiscover\</TargetFilename>
<TargetFilename condition="contains">\ecp\</TargetFilename>
<TargetFilename condition="contains">\OWA\</TargetFilename>
<TargetFilename condition="contains">\EWS\</TargetFilename>
```

### Exchange Process Monitoring
```xml
<!-- Exchange processes spawning cmd/powershell -->
<ParentImage condition="contains">\Exchange Server\</ParentImage>
<ParentImage condition="end with">\UMWorkerProcess.exe</ParentImage>
<ParentImage condition="end with">\MSExchangeTransport.exe</ParentImage>
```

### Timestomping Detection (Event 2)
```xml
<!-- Webshell timestomping in Exchange paths -->
<TargetFilename condition="end with">.aspx</TargetFilename>
<TargetFilename condition="end with">.ashx</TargetFilename>
<TargetFilename condition="contains">\FrontEnd\HttpProxy\</TargetFilename>
```

## Security Fixes Applied

1. **Added Event 2** - Timestomping detection for webshells
2. **Added Event 5** - Security tool termination monitoring
3. **Added Event 15** - Alternate Data Stream detection
4. **Expanded Registry** - COM hijacking, AppInit DLLs, IFEO
5. **Fixed DNS exclusions** - Removed broad *.microsoft.com

## MITRE ATT&CK Coverage

| Technique | ID | Coverage |
|-----------|-----|----------|
| Exploit Public-Facing Application | T1190 | Focus |
| Server Software Component: Web Shell | T1505.003 | Full |
| OS Credential Dumping | T1003 | Full |
| Boot or Logon Autostart | T1547 | Full |
| Event Triggered Execution | T1546 | Full |
| Indicator Removal: Timestomping | T1070.006 | Full |

## Installation

```powershell
# New installation
sysmon.exe -accepteula -i sysmon-exch.xml

# Update existing
sysmon.exe -c sysmon-exch.xml
```

## Splunk Queries

**Webshell Detection (w3wp.exe child):**
```spl
index=sysmon EventCode=1 ParentImage="*w3wp.exe"
| table _time, Computer, Image, CommandLine
| sort -_time
```

**Webshell File Creation:**
```spl
index=sysmon EventCode=11
| search TargetFilename IN ("*.aspx", "*.ashx", "*.asmx")
| search TargetFilename IN ("*aspnet_client*", "*FrontEnd*", "*OWA*", "*EWS*", "*ecp*")
| table _time, Computer, Image, TargetFilename
```

**ProxyShell Path Activity:**
```spl
index=sysmon EventCode=11
| search TargetFilename="*\\FrontEnd\\HttpProxy\\*" OR TargetFilename="*\\Autodiscover\\*"
| table _time, Computer, Image, TargetFilename
```

**Exchange Service Termination:**
```spl
index=sysmon EventCode=5
| search Image IN ("*Exchange*", "*w3wp.exe", "*MSExchangeTransport.exe")
| table _time, Computer, Image
```

**Timestomping on Webshells:**
```spl
index=sysmon EventCode=2
| search TargetFilename IN ("*.aspx", "*.ashx")
| table _time, Computer, Image, TargetFilename, CreationUtcTime, PreviousCreationUtcTime
```

## High-Priority Alerts

| Priority | Event | Description |
|----------|-------|-------------|
| CRITICAL | w3wp.exe → cmd.exe | Active webshell execution |
| CRITICAL | w3wp.exe → powershell.exe | Active webshell execution |
| HIGH | .aspx in aspnet_client | ProxyLogon webshell drop |
| HIGH | .aspx in FrontEnd\HttpProxy | ProxyShell webshell drop |
| HIGH | Timestomping on .aspx | Webshell hiding |
| MEDIUM | Exchange service terminated | Potential sabotage |

## Known Attack Patterns

### HAFNIUM (ProxyLogon)
1. CVE-2021-26855: SSRF to access ECP
2. CVE-2021-26857: Insecure deserialization
3. Webshell drop in `aspnet_client`
4. Credential dumping

### ProxyShell
1. CVE-2021-34473: ACL bypass
2. CVE-2021-34523: Elevation
3. CVE-2021-31207: Post-auth RCE
4. Webshell in `Autodiscover`

---
**Version:** 2.0
**Last Updated:** December 2025
**Threat Level:** CRITICAL - Tier-0 Asset
