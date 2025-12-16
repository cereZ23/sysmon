# Sysmon Configuration: Domain Controller

**File:** `sysmon-dc.xml`
**Target:** Windows Server DC (2016/2019/2022)
**Focus:** DCSync, Golden Ticket, Kerberoasting, AD reconnaissance

## Overview

Maximum security posture for Tier-0 infrastructure. Domain Controllers hold the keys to the kingdom - any compromise leads to full domain takeover. This configuration monitors ALL discovery commands and focuses heavily on credential-based attacks.

## Key Threats Detected

| Threat | Detection Method |
|--------|-----------------|
| DCSync | DRSUAPI pipe access, secretsdump patterns |
| Golden Ticket | Kerberos ticket manipulation |
| Credential Dumping | ntdsutil, mimikatz, LSASS access |
| AD Reconnaissance | ldifde, dsquery, adfind |
| Persistence | GPO tampering, Registry, Services |

## Critical Detections

### DCSync Attack Chain
```
Attacker → DC (port 135/DRSUAPI)
         → Replication request
         → NTDS.dit secrets extracted
```

### Golden Ticket Attack Chain
```
mimikatz → LSASS access
        → krbtgt hash extraction
        → Forged TGT creation
        → Unlimited domain access
```

## Event ID Coverage

| Event ID | Name | Status | Notes |
|----------|------|--------|-------|
| 1 | ProcessCreate | Active | ALL discovery commands |
| 2 | FileCreateTime | Active | SYSVOL/NTDS timestomping |
| 3 | NetworkConnect | Active | Suspicious outbound |
| 5 | ProcessTerminate | Active | AD services + EDR |
| 6 | DriverLoad | Active | Unsigned/suspicious drivers |
| 7 | ImageLoad | Active | Credential DLLs, LSASS loads |
| 8 | CreateRemoteThread | Active | Injection detection |
| 9 | RawAccessRead | Active | Raw disk access (NTDS offline) |
| 10 | ProcessAccess | Active | LSASS with 6 access flags |
| 11 | FileCreate | Active | NTDS.dit copies, scripts |
| 13 | RegistryEvent | Active | GPO, SAM, NTDS, Kerberos |
| 15 | FileCreateStreamHash | Active | ADS detection |
| 17/18 | PipeEvent | Active | DRSUAPI, C2 frameworks |
| 19/20/21 | WmiEvent | Active | WMI persistence |
| 22 | DnsQuery | Active | Optimized for DNS role |
| 25 | ProcessTampering | Active | Hollowing, herpaderping |
| 26 | FileDelete | Active | Evidence deletion |

## DC-Specific Detections

### AD Attack Tools (Event 1)
```xml
<!-- CRITICAL: AD attack tools -->
<Image condition="image">ntdsutil.exe</Image>
<Image condition="image">mimikatz.exe</Image>
<CommandLine condition="contains">sekurlsa</CommandLine>
<CommandLine condition="contains">lsadump</CommandLine>
<CommandLine condition="contains">dcsync</CommandLine>
<CommandLine condition="contains">kerberos::</CommandLine>
<CommandLine condition="contains">privilege::debug</CommandLine>

<!-- NTDS.dit extraction -->
<CommandLine condition="contains">ntds.dit</CommandLine>
<CommandLine condition="contains">SYSTEM.hiv</CommandLine>
```

### AD Reconnaissance
```xml
<Image condition="image">ldifde.exe</Image>
<Image condition="image">csvde.exe</Image>
<Image condition="image">dsquery.exe</Image>
<Image condition="image">dsget.exe</Image>
<Image condition="image">nltest.exe</Image>
<Image condition="image">setspn.exe</Image>
<Image condition="image">adfind.exe</Image>
```

### User/Group Enumeration
```xml
<CommandLine condition="contains">net user</CommandLine>
<CommandLine condition="contains">net group</CommandLine>
<CommandLine condition="contains">domain admins</CommandLine>
<CommandLine condition="contains">enterprise admins</CommandLine>
<CommandLine condition="contains">/domain</CommandLine>
```

### Registry Monitoring (DC-Specific)
```xml
<!-- Group Policy integrity -->
<TargetObject condition="contains">\Group Policy\</TargetObject>
<TargetObject condition="contains">\Policies\Microsoft\</TargetObject>

<!-- SAM/NTDS protection -->
<TargetObject condition="contains">\SAM\</TargetObject>
<TargetObject condition="contains">\NTDS\</TargetObject>

<!-- Kerberos settings -->
<TargetObject condition="contains">\kerberos\</TargetObject>
```

### Named Pipes (DCSync Detection)
```xml
<!-- DRSUAPI replication pipe -->
<PipeName condition="contains">\drsuapi</PipeName>
```

### LSASS Access (Event 10)
```xml
<!-- Multiple access flags for comprehensive detection -->
<GrantedAccess condition="contains any">
  0x40;0x1000;0x1010;0x1038;0x1410;0x1fffff
</GrantedAccess>
```

## MITRE ATT&CK Coverage

| Technique | ID | Coverage |
|-----------|-----|----------|
| OS Credential Dumping: DCSync | T1003.006 | Full |
| OS Credential Dumping: LSASS | T1003.001 | Full |
| Steal or Forge Kerberos Tickets | T1558 | Full |
| Account Discovery | T1087 | Full |
| Domain Trust Discovery | T1482 | Full |
| Group Policy Discovery | T1615 | Full |
| Boot or Logon Autostart | T1547 | Full |
| Event Triggered Execution | T1546 | Full |

## Installation

```powershell
# New installation
sysmon.exe -accepteula -i sysmon-dc.xml

# Update existing
sysmon.exe -c sysmon-dc.xml
```

## Splunk Queries

**DCSync Detection:**
```spl
index=sysmon EventCode=18 PipeName="*drsuapi*"
| table _time, Computer, Image, PipeName
```

**Mimikatz Patterns:**
```spl
index=sysmon EventCode=1
| search CommandLine IN ("*sekurlsa*", "*lsadump*", "*dcsync*", "*kerberos::*")
| table _time, Computer, User, CommandLine
```

**NTDS.dit Extraction:**
```spl
index=sysmon EventCode=1
| search CommandLine IN ("*ntds.dit*", "*SYSTEM.hiv*", "*ntdsutil*")
| table _time, Computer, User, CommandLine
```

**LSASS Access (Credential Theft):**
```spl
index=sysmon EventCode=10 TargetImage="*lsass.exe"
| where NOT match(SourceImage, "(?i)(MsMpEng|csrss|services|wininit|lsass)\.exe$")
| table _time, Computer, SourceImage, GrantedAccess
```

**AD Recon Tool Usage:**
```spl
index=sysmon EventCode=1
| search Image IN ("*ldifde.exe", "*csvde.exe", "*dsquery.exe", "*adfind.exe", "*setspn.exe")
| table _time, Computer, User, Image, CommandLine
```

**Shadow Copy for NTDS:**
```spl
index=sysmon EventCode=1
| search CommandLine="*vssadmin*create*shadow*"
| table _time, Computer, User, CommandLine
```

## High-Priority Alerts

| Priority | Event | Description |
|----------|-------|-------------|
| CRITICAL | DRSUAPI pipe access | Active DCSync attack |
| CRITICAL | mimikatz/sekurlsa in cmdline | Credential dumping |
| CRITICAL | ntds.dit in command line | Database extraction |
| CRITICAL | LSASS access (0x1fffff) | Full memory dump |
| HIGH | ntdsutil.exe execution | Potential DB extraction |
| HIGH | adfind.exe execution | AD reconnaissance |
| HIGH | AD service termination | Potential sabotage |
| MEDIUM | Group Policy registry changes | Persistence attempt |

## Critical Services Monitored (Event 5)

- `lsass.exe` - Local Security Authority
- `dns.exe` - AD DNS
- `ntfrs.exe` - File Replication Service
- `dfsr.exe` - DFS Replication
- Security tools (Defender, CrowdStrike, Carbon Black)

## Important Limitations

### DCSync Detection via Sysmon

**Sysmon on the DC has limited visibility for DCSync attacks:**

DCSync uses DRSUAPI replication protocol. When an attacker runs DCSync from another machine:
- The DC receives an **inbound** RPC connection on port 135
- Sysmon NetworkConnect only logs **outbound** connections from the DC
- The attack traffic is invisible to Sysmon on the DC

**Recommended Detection Strategy:**

1. **Windows Security Event 4662** - Monitor for DS-Replication-Get-Changes operations
2. **Sysmon on attacker host** - Detect secretsdump.py/mimikatz execution
3. **Network monitoring** - Detect RPC to DC from non-DC hosts
4. **Named Pipe monitoring** - DRSUAPI pipe access (limited reliability)

```spl
# Better DCSync detection via Security Events
index=wineventlog EventCode=4662
| search ObjectType="*DS-Replication-Get-Changes*"
| table _time, SubjectUserName, SubjectDomainName, ObjectName
```

### Raw Disk Access (Event 9)

Event ID 9 (RawAccessRead) detects offline NTDS.dit extraction attempts where attackers:
1. Create VSS shadow copy
2. Access raw disk to read NTDS.dit directly
3. Bypass file locks

---
**Version:** 2.1
**Last Updated:** December 2025
**Threat Level:** CRITICAL - Tier-0 Asset
