# Sysmon Configuration: Windows Workstation

**File:** `sysmon-ws.xml`
**Target:** Windows 10/11 Client Endpoints
**Focus:** User-initiated attacks, phishing, LOLBins, credential theft

## Overview

Optimized for high-activity workstations with significant noise reduction (~60-70%) while maintaining comprehensive threat detection. Balances security visibility with SOC operational efficiency.

## Key Threats Detected

| Threat | Detection Method |
|--------|-----------------|
| Phishing/Macro Attacks | Office apps spawning cmd/powershell |
| Credential Dumping | LSASS access, procdump, comsvcs.dll |
| LOLBins Abuse | certutil, mshta, regsvr32, rundll32, etc. |
| Persistence | Registry Run keys, Scheduled Tasks, WMI |
| Lateral Movement | PsExec, named pipes |
| Defense Evasion | Timestomping, ADS, process injection |

## Event ID Coverage

| Event ID | Name | Status | Notes |
|----------|------|--------|-------|
| 1 | ProcessCreate | Active | Full coverage with exclusions |
| 2 | FileCreateTime | Active | Timestomping detection |
| 3 | NetworkConnect | Active | Filtered for noise |
| 5 | ProcessTerminate | Active | Security tool monitoring |
| 7 | ImageLoad | Active | Credential DLL detection |
| 8 | CreateRemoteThread | Active | Injection detection |
| 10 | ProcessAccess | Active | LSASS protection |
| 11 | FileCreate | Active | Executable monitoring |
| 13 | RegistryEvent | Active | 50+ persistence mechanisms |
| 15 | FileCreateStreamHash | Active | ADS detection |
| 17/18 | PipeEvent | Active | C2 framework detection |
| 19/20/21 | WmiEvent | Active | WMI persistence |
| 22 | DnsQuery | Active | Extensive exclusions |

## Workstation-Specific Optimizations

### Noise Reduction
- Browser activity excluded (Chrome, Edge, Firefox)
- Teams, OneDrive, Office background processes filtered
- Windows Update and Search Indexer excluded
- Common discovery commands (ping, ipconfig) removed

### Security Hardening
- Exact path matching for browser updates (prevents masquerading)
- Office macro → child process detection
- Credential DLL monitoring (samlib.dll, vaultcli.dll)
- 15 different LSASS access flag combinations monitored

## MITRE ATT&CK Coverage

| Technique | ID | Coverage |
|-----------|-----|----------|
| Command and Scripting Interpreter | T1059 | Full |
| Boot or Logon Autostart Execution | T1547 | Full |
| Scheduled Task/Job | T1053 | Full |
| Process Injection | T1055 | Partial |
| OS Credential Dumping | T1003 | Full |
| System Binary Proxy Execution | T1218 | Full |
| Signed Binary Proxy Execution | T1216 | Partial |

## Installation

```powershell
# New installation
sysmon.exe -accepteula -i sysmon-ws.xml

# Update existing
sysmon.exe -c sysmon-ws.xml

# Verify
sysmon.exe -c
```

## Customization

### Adding Application Exclusions
```xml
<RuleGroup name="ProcessCreate_Exclude" groupRelation="or">
  <ProcessCreate onmatch="exclude">
    <Image condition="is">C:\Program Files\YourApp\app.exe</Image>
  </ProcessCreate>
</RuleGroup>
```

### Environment-Specific
- Update proxy server IPs in NetworkConnect exclusions
- Add SIEM server IPs to DNS exclusions
- Customize backup software paths

## Splunk Queries

**Encoded PowerShell:**
```spl
index=sysmon EventCode=1 Computer=*-WS*
| search CommandLine="*-enc*" OR CommandLine="*-encodedcommand*"
| table _time, Computer, User, ParentImage, CommandLine
```

**Office Macro Execution:**
```spl
index=sysmon EventCode=1
| search ParentImage IN ("*winword.exe", "*excel.exe", "*powerpnt.exe")
| search Image IN ("*cmd.exe", "*powershell.exe", "*wscript.exe")
| table _time, Computer, ParentImage, Image, CommandLine
```

## Maintenance

- Review exclusions quarterly
- Monitor event volume trends
- Update LOLBins list as new techniques emerge
- Test after Windows feature updates

---
**Version:** 2.0
**Last Updated:** December 2025
