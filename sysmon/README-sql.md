# Sysmon Configuration: SQL Server

**File:** `sysmon-sql.xml`
**Target:** SQL Server 2016/2019/2022
**Focus:** xp_cmdshell abuse, SQL injection, credential theft, data exfiltration

## Overview

Specialized configuration for SQL Server environments focusing on database-specific attack vectors. SQL Server's high process activity requires careful exclusion management while maintaining visibility into critical attack paths.

## Key Threats Detected

| Threat | Detection Method |
|--------|-----------------|
| xp_cmdshell Abuse | sqlservr.exe spawning cmd/powershell |
| SQL Injection | Command execution from SQL process |
| Linked Server Attacks | SQL utilities network connections |
| Data Exfiltration | BCP, backup to unusual locations |
| Credential Access | LSASS access, SQL Server process injection |

## Critical Detection: SQL Process Child Spawning

**Any child process from sqlservr.exe is HIGH PRIORITY:**
```
sqlservr.exe → cmd.exe       = xp_cmdshell
sqlservr.exe → powershell.exe = xp_cmdshell + PowerShell
sqlservr.exe → bcp.exe       = Potential data exfil
```

## Event ID Coverage

| Event ID | Name | Status | Notes |
|----------|------|--------|-------|
| 1 | ProcessCreate | Active | SQL parent process focus |
| 2 | FileCreateTime | Active | Timestomping detection |
| 3 | NetworkConnect | Active | Linked server abuse |
| 5 | ProcessTerminate | Active | SQL service termination |
| 7 | ImageLoad | Active | DLL injection into SQL |
| 8 | CreateRemoteThread | Active | SQL process injection |
| 10 | ProcessAccess | Active | LSASS + SQL process |
| 11 | FileCreate | Active | Backup files in unusual paths |
| 13 | RegistryEvent | Active | SQL-specific + persistence |
| 15 | FileCreateStreamHash | Active | ADS detection |
| 17/18 | PipeEvent | Active | SQL named pipes |
| 19/20/21 | WmiEvent | Active | WMI persistence |
| 22 | DnsQuery | Active | **Fixed: Specific endpoints only** |

## SQL-Specific Detections

### Process Creation
```xml
<!-- SQL spawning processes = ATTACK -->
<ParentImage condition="end with">\sqlservr.exe</ParentImage>
<ParentImage condition="end with">\SQLAGENT.EXE</ParentImage>

<!-- SQL attack commands -->
<CommandLine condition="contains">xp_cmdshell</CommandLine>
<CommandLine condition="contains">sp_configure</CommandLine>
<CommandLine condition="contains">OPENROWSET</CommandLine>
<CommandLine condition="contains">OPENDATASOURCE</CommandLine>
<CommandLine condition="contains">xp_regread</CommandLine>
<CommandLine condition="contains">xp_dirtree</CommandLine>
```

### File Creation (Data Exfil)
```xml
<!-- Backup files outside normal paths -->
<TargetFilename condition="end with">.bak</TargetFilename>
<TargetFilename condition="end with">.mdf</TargetFilename>
<TargetFilename condition="end with">.ldf</TargetFilename>
```

### Network Connections
```xml
<!-- SQL utilities making connections -->
<Image condition="image">sqlcmd.exe</Image>
<Image condition="image">bcp.exe</Image>
```

## Security Fix Applied

**Removed dangerous DNS exclusion:**
```xml
<!-- REMOVED: *.microsoft.com - C2 hiding risk -->
<!-- REPLACED WITH: Specific endpoints only -->
<QueryName condition="is">settings-win.data.microsoft.com</QueryName>
<QueryName condition="is">vortex.data.microsoft.com</QueryName>
<QueryName condition="end with">.update.microsoft.com</QueryName>
```

## MITRE ATT&CK Coverage

| Technique | ID | Coverage |
|-----------|-----|----------|
| Command and Scripting Interpreter | T1059 | Full |
| OS Credential Dumping | T1003 | Full |
| Data from Local System | T1005 | Partial |
| Exfiltration Over C2 Channel | T1041 | Partial |
| Boot or Logon Autostart | T1547 | Full |
| Event Triggered Execution | T1546 | Full |

## Installation

```powershell
# New installation
sysmon.exe -accepteula -i sysmon-sql.xml

# Update existing
sysmon.exe -c sysmon-sql.xml
```

## Customization Required

### Backup Paths
```xml
<!-- Add your normal backup locations to exclude -->
<TargetFilename condition="begin with">D:\SQLBackups\</TargetFilename>
<TargetFilename condition="begin with">\\BackupServer\SQLBackups\</TargetFilename>
```

### SQL Server Version Paths
```xml
<!-- Adjust for your SQL version -->
<Image condition="begin with">C:\Program Files\Microsoft SQL Server\MSSQL15\</Image>
```

### SSMS Versions
```xml
<Image condition="is">C:\Program Files (x86)\Microsoft SQL Server Management Studio 19\Common7\IDE\Ssms.exe</Image>
```

## Splunk Queries

**xp_cmdshell Detection:**
```spl
index=sysmon EventCode=1
| search ParentImage="*sqlservr.exe"
| table _time, Computer, Image, CommandLine
| sort -_time
```

**Backup to Unusual Location:**
```spl
index=sysmon EventCode=11 TargetFilename="*.bak"
| search NOT TargetFilename IN ("D:\\SQLBackups\\*", "E:\\Backups\\*")
| table _time, Computer, Image, TargetFilename
```

**SQL Process Injection:**
```spl
index=sysmon EventCode=10 TargetImage="*sqlservr.exe"
| table _time, Computer, SourceImage, GrantedAccess
```

**Linked Server Abuse:**
```spl
index=sysmon EventCode=3 Image IN ("*sqlcmd.exe", "*bcp.exe", "*osql.exe")
| table _time, Computer, Image, DestinationIp, DestinationPort
```

## High-Value Alerts

1. **sqlservr.exe → cmd.exe/powershell.exe** = xp_cmdshell abuse
2. **Backup file outside normal paths** = Potential exfil staging
3. **DLL loaded into sqlservr.exe from temp/user paths** = SQL CLR attack
4. **SQL process accessing LSASS** = Credential theft

---
**Version:** 2.0
**Last Updated:** December 2025
