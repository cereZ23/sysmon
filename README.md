# Sysmon Configuration for Enterprise Security Monitoring

Production-ready Sysmon configurations optimized for Windows endpoint security monitoring with Splunk integration.

## Overview

This repository contains hardened Sysmon configurations designed for enterprise environments, balancing comprehensive threat detection with noise reduction for SOC operations.

## Configurations

| File | Target | Description |
|------|--------|-------------|
| `sysmon/sysmon-ws.xml` | Workstations | Windows 10/11 client endpoints |
| `sysmon/sysmon-srv.xml` | Generic Server | Windows Server 2016/2019/2022 |
| `sysmon/sysmon-sql.xml` | SQL Server | SQL Server 2016/2019/2022 |
| `sysmon/sysmon-exch.xml` | Exchange | Exchange Server 2016/2019 |
| `sysmon/sysmon-dc.xml` | Domain Controller | AD DS servers |
| `sysmon/sysmon-iis.xml` | Web Server | IIS web servers |

## Role-Specific Focus

| Config | Key Threats | Critical Detection |
|--------|-------------|-------------------|
| **Workstation** | Phishing, LOLBins | Office macro → cmd/ps |
| **Generic Server** | Lateral movement | Discovery commands |
| **SQL Server** | SQL injection, xp_cmdshell | sqlservr.exe → cmd |
| **Exchange** | ProxyLogon/Shell, webshell | w3wp.exe → cmd |
| **Domain Controller** | DCSync, Golden Ticket | ntdsutil, LSASS access |
| **IIS** | Webshell, RCE | w3wp.exe child process |

## Features

### Threat Detection Coverage

- **MITRE ATT&CK Mapping**: 13+ techniques covered
- **Credential Dumping**: procdump, comsvcs.dll, LSASS access monitoring
- **LOLBins**: certutil, mshta, regsvr32, rundll32, wmic, etc.
- **Persistence**: Registry Run keys, Scheduled Tasks, WMI subscriptions
- **Lateral Movement**: PsExec, named pipes (Cobalt Strike, Metasploit)
- **Defense Evasion**: Process injection, timestomping, ADS

### Event ID Coverage

| Event ID | Name | Status |
|----------|------|--------|
| 1 | ProcessCreate | Active |
| 2 | FileCreateTime | Active |
| 3 | NetworkConnect | Active |
| 5 | ProcessTerminate | Active |
| 7 | ImageLoad | Active |
| 8 | CreateRemoteThread | Active |
| 10 | ProcessAccess | Active |
| 11 | FileCreate | Active |
| 13 | RegistryEvent | Active |
| 15 | FileCreateStreamHash | Active |
| 17/18 | PipeEvent | Active |
| 19/20/21 | WmiEvent | Active |
| 22 | DnsQuery | Active |

### Workstation Optimizations

- Reduced noise from browsers (Chrome, Edge, Firefox)
- Filtered Teams, OneDrive, Office background activity
- Excluded Windows Update and Search Indexer
- Removed common discovery commands (ping, ipconfig, nslookup)
- Estimated 60-70% event reduction vs. default configs

## Installation

### New Installation
```powershell
# Download Sysmon from Microsoft Sysinternals
# https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

sysmon.exe -accepteula -i sysmon-ws.xml
```

## Windows Audit Policy & Logging

### Deploy Scripts

| Script | Description |
|--------|-------------|
| `sysmon/deploy/windows-audit-policy.ps1` | Configure Windows Advanced Audit Policy |
| `sysmon/deploy/enable-powershell-logging.ps1` | Enable PowerShell Script Block & Module Logging |

### Windows Audit Policy (v2.1.0)

Configures 55+ Windows audit subcategories for comprehensive security event logging.

```powershell
# Download and run (requires Administrator)
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/cereZ23/sysmon/main/sysmon/deploy/windows-audit-policy.ps1" -OutFile "windows-audit-policy.ps1"
powershell.exe -ExecutionPolicy Bypass -File .\windows-audit-policy.ps1
```

**Features:**
- ✅ **Multi-Language Support** - Works on ALL Windows languages (English, Italian, German, French, Spanish, etc.)
- ✅ Uses language-independent GUIDs instead of localized subcategory names
- ✅ MITRE ATT&CK aligned detection coverage
- ✅ Automatic backup before changes
- ✅ Event log size optimization

**Key Events Enabled:**

| Event ID | Description | MITRE ATT&CK |
|----------|-------------|--------------|
| 4625 | Failed Logon | T1110 Brute Force |
| 4720 | User Account Created | T1136 Create Account |
| 4732 | Member Added to Group | T1098 Account Manipulation |
| 4697 | Service Installed | T1543.003 Windows Service |
| 4698 | Scheduled Task Created | T1053.005 Scheduled Task |
| 4672 | Special Privileges | T1134 Token Manipulation |

### PowerShell Logging

Enables Script Block Logging (4104) and Module Logging (4103) for PowerShell attack detection.

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\sysmon\deploy\enable-powershell-logging.ps1
```

### Update Configuration
```powershell
sysmon.exe -c sysmon-ws.xml
```

### Verify Installation
```powershell
sysmon.exe -c
```

### Uninstall
```powershell
sysmon.exe -u
```

## Splunk Integration

### Index Configuration
```
[sysmon]
homePath = $SPLUNK_DB/sysmon/db
coldPath = $SPLUNK_DB/sysmon/colddb
thawedPath = $SPLUNK_DB/sysmon/thaweddb
```

### Sample Searches

**Encoded PowerShell Detection**
```spl
index=sysmon EventCode=1
| search CommandLine="*-enc*" OR CommandLine="*-encodedcommand*"
| table _time, Computer, User, ParentImage, Image, CommandLine
```

**LSASS Credential Access**
```spl
index=sysmon EventCode=10 TargetImage="*lsass.exe"
| where NOT match(SourceImage, "(?i)(MsMpEng|csrss|services|wininit)\.exe$")
| table _time, Computer, SourceImage, GrantedAccess
```

**Office Macro Execution**
```spl
index=sysmon EventCode=1
| search ParentImage IN ("*winword.exe", "*excel.exe", "*powerpnt.exe")
| search Image IN ("*cmd.exe", "*powershell.exe", "*wscript.exe", "*mshta.exe")
| table _time, Computer, ParentImage, Image, CommandLine
```

**Cobalt Strike Named Pipes**
```spl
index=sysmon EventCode=17 OR EventCode=18
| search PipeName IN ("*msagent_*", "*MSSE-*", "*postex_*", "*meterpreter*")
| table _time, Computer, Image, PipeName
```

**Discovery Command Burst**
```spl
index=sysmon EventCode=1
| search Image IN ("*whoami.exe", "*net.exe", "*nltest.exe", "*systeminfo.exe")
| bucket _time span=5m
| stats count by _time, Computer, User
| where count > 5
```

## Requirements

- **Sysmon**: v15.0 or later
- **Schema Version**: 4.50
- **Windows**: 10/11 (Workstations), Server 2016+ (Servers)
- **Permissions**: Administrator for installation

## Customization

### Adding Exclusions
Add application-specific exclusions in the appropriate `_Exclude` RuleGroup:

```xml
<RuleGroup name="ProcessCreate_Exclude" groupRelation="or">
  <ProcessCreate onmatch="exclude">
    <!-- Your custom exclusion -->
    <Image condition="is">C:\Program Files\YourApp\app.exe</Image>
  </ProcessCreate>
</RuleGroup>
```

### Adding Detections
Add new detection rules in the main include block:

```xml
<ProcessCreate onmatch="include">
  <!-- Your custom detection -->
  <Image condition="image">suspicious-tool.exe</Image>
</ProcessCreate>
```

## Security Considerations

- **Path Specificity**: Use `condition="is"` with full paths when possible
- **No Broad Exclusions**: Avoid `C:\Program Files\` wildcard exclusions
- **Test Before Deploy**: Validate on pilot systems first
- **Monitor Bypass Attempts**: Alert on Sysmon service stops

## Contributing

1. Fork the repository
2. Create a feature branch
3. Test configuration on isolated systems
4. Submit pull request with description of changes

## License

MIT License - See [LICENSE](LICENSE) for details.

## References

- [Microsoft Sysmon Documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
- [Splunk Security Essentials](https://splunkbase.splunk.com/app/3435/)

---

**Maintained by:** Security Operations Team
**Last Updated:** December 2025
