# Sysmon Configuration: IIS Web Server

**File:** `sysmon-iis.xml`
**Target:** Windows Server with IIS
**Focus:** Webshell detection, RCE, command injection

## Overview

Strict security posture based on the principle that IIS worker processes (w3wp.exe) should **NEVER** spawn child processes under normal operations. Any child process from w3wp.exe is treated as a critical indicator of webshell execution or remote code execution attack.

## Key Principle

```
w3wp.exe spawning ANY process = ATTACK

Normal IIS operation:
  w3wp.exe → handles HTTP requests
  w3wp.exe → serves static files
  w3wp.exe → executes ASP.NET code (in-process)

Attack indicator:
  w3wp.exe → cmd.exe       ❌ WEBSHELL
  w3wp.exe → powershell.exe ❌ WEBSHELL
  w3wp.exe → whoami.exe    ❌ POST-EXPLOITATION
```

## Key Threats Detected

| Threat | Detection Method |
|--------|-----------------|
| Webshell Execution | w3wp.exe child processes |
| Webshell Upload | .aspx/.asp file creation in webroots |
| Remote Code Execution | Command injection via web app |
| Reverse Shell | Network connections from suspicious ports |
| Credential Theft | LSASS access, credential DLLs |

## Event ID Coverage

| Event ID | Name | Status | Notes |
|----------|------|--------|-------|
| 1 | ProcessCreate | Active | w3wp.exe parent focus |
| 2 | FileCreateTime | Active | Webshell timestomping |
| 3 | NetworkConnect | Active | Reverse shell ports |
| 5 | ProcessTerminate | Active | IIS crash + EDR |
| 7 | ImageLoad | Active | DLL injection into w3wp |
| 8 | CreateRemoteThread | Active | Injection detection |
| 10 | ProcessAccess | Active | LSASS protection |
| 11 | FileCreate | Active | Web file types in webroots |
| 13 | RegistryEvent | Active | Persistence + IIS keys |
| 15 | FileCreateStreamHash | Active | ADS detection |
| 17/18 | PipeEvent | Active | C2 frameworks |
| 19/20/21 | WmiEvent | Active | WMI persistence |
| 22 | DnsQuery | Active | Minimal exclusions |

## IIS-Specific Detections

### Critical: IIS Child Processes (Event 1)
```xml
<!-- CRITICAL: IIS worker spawning processes = WEBSHELL/RCE -->
<ParentImage condition="is">C:\Windows\System32\inetsrv\w3wp.exe</ParentImage>
<ParentImage condition="is">C:\Windows\SysWOW64\inetsrv\w3wp.exe</ParentImage>
<ParentImage condition="is">C:\Windows\System32\inetsrv\inetinfo.exe</ParentImage>
```

### Webshell File Creation (Event 11)
```xml
<!-- CRITICAL: Web file types -->
<TargetFilename condition="end with">.aspx</TargetFilename>
<TargetFilename condition="end with">.ashx</TargetFilename>
<TargetFilename condition="end with">.asmx</TargetFilename>
<TargetFilename condition="end with">.asp</TargetFilename>
<TargetFilename condition="end with">.php</TargetFilename>
<TargetFilename condition="end with">.jsp</TargetFilename>
<TargetFilename condition="end with">.config</TargetFilename>

<!-- Webroot paths (customize for your environment) -->
<TargetFilename condition="begin with">C:\inetpub\</TargetFilename>
<TargetFilename condition="begin with">D:\inetpub\</TargetFilename>
<TargetFilename condition="begin with">D:\wwwroot\</TargetFilename>
<TargetFilename condition="begin with">E:\wwwroot\</TargetFilename>
```

### Reverse Shell Detection (Event 3)
```xml
<!-- Reverse shell ports -->
<DestinationPort condition="is">4444</DestinationPort>
<DestinationPort condition="is">5555</DestinationPort>
<DestinationPort condition="is">6666</DestinationPort>
<DestinationPort condition="is">31337</DestinationPort>
<DestinationPort condition="is">9001</DestinationPort>

<!-- Processes from webroot making connections -->
<Image condition="begin with">C:\inetpub\</Image>
```

### DLL Injection into IIS (Event 7)
```xml
<!-- DLLs loaded by w3wp from suspicious locations -->
<Rule groupRelation="and">
  <Image condition="end with">\w3wp.exe</Image>
  <ImageLoaded condition="begin with">C:\Users\</ImageLoaded>
</Rule>
<Rule groupRelation="and">
  <Image condition="end with">\w3wp.exe</Image>
  <ImageLoaded condition="begin with">C:\Windows\Temp\</ImageLoaded>
</Rule>
```

### IIS-Specific Registry
```xml
<TargetObject condition="contains">Microsoft\InetStp\</TargetObject>
<TargetObject condition="contains">\W3SVC\</TargetObject>
```

## MITRE ATT&CK Coverage

| Technique | ID | Coverage |
|-----------|-----|----------|
| Exploit Public-Facing Application | T1190 | Focus |
| Server Software Component: Web Shell | T1505.003 | Full |
| Command and Scripting Interpreter | T1059 | Full |
| OS Credential Dumping | T1003 | Full |
| Boot or Logon Autostart | T1547 | Full |
| Event Triggered Execution | T1546 | Full |
| Indicator Removal: Timestomping | T1070.006 | Full |

## Installation

```powershell
# New installation
sysmon.exe -accepteula -i sysmon-iis.xml

# Update existing
sysmon.exe -c sysmon-iis.xml
```

## Customization Required

### Additional Webroot Paths
```xml
<!-- Add your webroot paths -->
<TargetFilename condition="begin with">F:\WebApps\</TargetFilename>
<TargetFilename condition="begin with">D:\Sites\</TargetFilename>
```

### Application-Specific Exclusions
If your web application legitimately spawns processes:
```xml
<!-- Example: PDF generation that spawns wkhtmltopdf -->
<Rule groupRelation="and">
  <ParentImage condition="is">C:\Windows\System32\inetsrv\w3wp.exe</ParentImage>
  <Image condition="is">C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe</Image>
</Rule>
```

## Splunk Queries

**Webshell Execution (w3wp child):**
```spl
index=sysmon EventCode=1 ParentImage="*w3wp.exe"
| table _time, Computer, Image, CommandLine
| sort -_time
```

**Webshell File Upload:**
```spl
index=sysmon EventCode=11
| search TargetFilename IN ("*.aspx", "*.ashx", "*.asp", "*.php", "*.jsp")
| search TargetFilename IN ("*inetpub*", "*wwwroot*")
| table _time, Computer, Image, TargetFilename
```

**Reverse Shell Connections:**
```spl
index=sysmon EventCode=3
| search DestinationPort IN (4444, 5555, 6666, 31337, 9001)
| table _time, Computer, Image, DestinationIp, DestinationPort
```

**DLL Injection into IIS:**
```spl
index=sysmon EventCode=7 Image="*w3wp.exe"
| search ImageLoaded IN ("C:\\Users\\*", "C:\\Windows\\Temp\\*", "C:\\Temp\\*")
| table _time, Computer, ImageLoaded
```

**IIS Crash (Potential DoS):**
```spl
index=sysmon EventCode=5 Image="*w3wp.exe"
| timechart count by Computer
```

**Webshell Timestomping:**
```spl
index=sysmon EventCode=2
| search TargetFilename IN ("*.aspx", "*.ashx", "*.asp")
| table _time, Computer, Image, TargetFilename, CreationUtcTime, PreviousCreationUtcTime
```

## High-Priority Alerts

| Priority | Event | Description |
|----------|-------|-------------|
| CRITICAL | w3wp.exe → cmd.exe | Active webshell |
| CRITICAL | w3wp.exe → powershell.exe | Active webshell |
| CRITICAL | w3wp.exe → ANY process | Webshell or RCE |
| HIGH | .aspx created in webroot | Webshell upload |
| HIGH | .config modified in webroot | web.config attack |
| HIGH | Connection to port 4444/31337 | Reverse shell |
| HIGH | DLL loaded into w3wp from temp | DLL injection |
| MEDIUM | IIS crash (w3wp terminated) | DoS or instability |

## Common Webshell Behaviors

### China Chopper
```
w3wp.exe → cmd.exe /c "whoami"
w3wp.exe → cmd.exe /c "net user"
w3wp.exe → cmd.exe /c "ipconfig /all"
```

### ASPXSpy
```
File: /aspx/aspxspy.aspx
w3wp.exe → cmd.exe (various commands)
```

### Web.config RCE
Malicious web.config can execute code without .aspx:
```xml
<TargetFilename condition="end with">.config</TargetFilename>
```

---
**Version:** 2.0
**Last Updated:** December 2025
**Threat Level:** HIGH - Internet-Facing Asset
