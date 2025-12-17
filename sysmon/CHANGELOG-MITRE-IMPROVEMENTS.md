# MITRE ATT&CK Coverage Improvements

**Date:** December 17, 2025
**Based on:** Detection Coverage Test Results (40 techniques)

---

## Summary

This PR improves MITRE ATT&CK detection coverage based on test results that identified gaps in:
- T1087.001 (Local Account Discovery) - 0% detection
- T1021.002 (SMB/Windows Admin Shares) - Low detection on servers
- T1570 (Lateral Tool Transfer) - Low detection on servers

### Expected Improvement

| Technique | Before | After | Change |
|-----------|--------|-------|--------|
| T1087.001 | 0% | ~90%+ | New CommandLine rules |
| T1021.002 | 17% | ~90%+ | SMB port monitoring |
| T1570 | 33% | ~60%+ | Improved lateral detection |

---

## Changes by Configuration

### sysmon-ws.xml (Workstation)

**ProcessCreate additions:**
```xml
<Image condition="image">query.exe</Image>
<!-- T1087.001 specific - Local Account Discovery -->
<CommandLine condition="contains">net user</CommandLine>
<CommandLine condition="contains">net1 user</CommandLine>
<CommandLine condition="contains">get-localuser</CommandLine>
<CommandLine condition="contains">wmic useraccount</CommandLine>
```

**NetworkConnect additions:**
```xml
<!-- T1021.002 - SMB/Windows Admin Shares (Lateral Movement) -->
<DestinationPort condition="is">445</DestinationPort>
<DestinationPort condition="is">139</DestinationPort>
```

**Rationale:** Workstations rarely need to enumerate local accounts via command line. SMB connections from workstations should be monitored for lateral movement.

---

### sysmon-srv.xml (Generic Server)

**ProcessCreate additions:**
```xml
<!-- T1087.001 specific - Local Account Discovery -->
<CommandLine condition="contains">net user</CommandLine>
<CommandLine condition="contains">net1 user</CommandLine>
<CommandLine condition="contains">get-localuser</CommandLine>
<CommandLine condition="contains">wmic useraccount</CommandLine>
```

**NetworkConnect additions:**
```xml
<!-- T1021.002 - SMB/Windows Admin Shares (Lateral Movement) -->
<DestinationPort condition="is">445</DestinationPort>
<DestinationPort condition="is">139</DestinationPort>
```

**Rationale:** Servers being used for lateral movement often initiate SMB connections. Account enumeration on servers is unusual.

---

### sysmon-dc.xml (Domain Controller)

**ProcessCreate additions:**
```xml
<!-- T1087.001 specific - Local Account Discovery -->
<Image condition="image">query.exe</Image>
<Image condition="image">quser.exe</Image>
<CommandLine condition="contains">net1 user</CommandLine>
<CommandLine condition="contains">get-localuser</CommandLine>
<CommandLine condition="contains">wmic useraccount</CommandLine>
```

**NetworkConnect additions:**
```xml
<!-- T1021.002 - SMB/Windows Admin Shares (Lateral Movement) -->
<DestinationPort condition="is">445</DestinationPort>
<DestinationPort condition="is">139</DestinationPort>
```

**Rationale:** DCs already monitor `net user` but lacked `net1.exe` (the real executable) and PowerShell/WMI methods. SMB from DC is suspicious (lateral movement).

---

### sysmon-sql.xml (SQL Server)

**ProcessCreate additions:**
```xml
<!-- Discovery commands (unusual on SQL server) -->
<Image condition="image">whoami.exe</Image>
<Image condition="image">hostname.exe</Image>
<Image condition="image">net.exe</Image>
<Image condition="image">net1.exe</Image>
<Image condition="image">systeminfo.exe</Image>
<Image condition="image">tasklist.exe</Image>
<Image condition="image">query.exe</Image>
<Image condition="image">ipconfig.exe</Image>
<Image condition="image">netstat.exe</Image>
<!-- T1087.001 specific - Local Account Discovery -->
<CommandLine condition="contains">net user</CommandLine>
<CommandLine condition="contains">net1 user</CommandLine>
<CommandLine condition="contains">get-localuser</CommandLine>
<CommandLine condition="contains">wmic useraccount</CommandLine>
```

**NetworkConnect additions:**
```xml
<!-- T1021.002 - SMB/Windows Admin Shares (Lateral Movement) -->
<DestinationPort condition="is">445</DestinationPort>
<DestinationPort condition="is">139</DestinationPort>
```

**Rationale:** SQL servers previously lacked discovery command monitoring. These are highly suspicious on a dedicated SQL server as they indicate post-exploitation activity.

---

### sysmon-exch.xml (Exchange Server)

**ProcessCreate additions:**
```xml
<Image condition="image">net1.exe</Image>
<Image condition="image">query.exe</Image>
<Image condition="image">quser.exe</Image>
<!-- T1087.001 specific - Local Account Discovery -->
<CommandLine condition="contains">net user</CommandLine>
<CommandLine condition="contains">net1 user</CommandLine>
<CommandLine condition="contains">get-localuser</CommandLine>
<CommandLine condition="contains">wmic useraccount</CommandLine>
```

**NetworkConnect additions:**
```xml
<!-- T1021.002 - SMB/Windows Admin Shares (Lateral Movement) -->
<DestinationPort condition="is">445</DestinationPort>
<DestinationPort condition="is">139</DestinationPort>
```

**Rationale:** Exchange servers are high-value targets. Adding net1.exe and local account discovery rules catches post-exploitation after webshell deployment.

---

### sysmon-iis.xml (IIS Web Server)

**ProcessCreate additions:**
```xml
<!-- Discovery commands (unusual on IIS server) -->
<Image condition="image">tasklist.exe</Image>
<Image condition="image">query.exe</Image>
<Image condition="image">netstat.exe</Image>
<Image condition="image">nltest.exe</Image>
<!-- T1087.001 specific - Local Account Discovery -->
<CommandLine condition="contains">net user</CommandLine>
<CommandLine condition="contains">net1 user</CommandLine>
<CommandLine condition="contains">get-localuser</CommandLine>
<CommandLine condition="contains">wmic useraccount</CommandLine>
```

**NetworkConnect additions:**
```xml
<!-- T1021.002 - SMB/Windows Admin Shares (Lateral Movement) -->
<DestinationPort condition="is">445</DestinationPort>
<DestinationPort condition="is">139</DestinationPort>
```

**Rationale:** IIS servers handling webshell attacks need detection for account enumeration and lateral movement attempts.

---

## MITRE ATT&CK Techniques Addressed

| ID | Name | Type | Detection Method |
|----|------|------|------------------|
| T1087.001 | Local Account Discovery | Discovery | CommandLine monitoring for `net user`, `get-localuser`, `wmic useraccount` |
| T1021.002 | SMB/Windows Admin Shares | Lateral Movement | NetworkConnect port 445/139 |
| T1570 | Lateral Tool Transfer | Lateral Movement | Improved via SMB monitoring |

---

## Testing

After deploying these changes, re-run the MITRE ATT&CK coverage test:

```bash
gh workflow run sysmon-test.yml --repo cereZ23/sysmon
```

Expected detection improvements:
- T1087.001: NOT_DETECTED → DETECTED
- T1021.002: Partial → DETECTED (all configs)
- Overall detection rate: 81% → 85%+

---

## Noise Considerations

### Low Risk (Recommended for all environments)
- `query.exe`, `quser.exe` - Rarely used legitimately
- `get-localuser` - PowerShell cmdlet, unusual in automation
- SMB ports 445/139 - Already filtered by Image in NetworkConnect

### Medium Risk (Monitor after deployment)
- `net user` CommandLine - May trigger on legitimate admin scripts
- `wmic useraccount` - Inventory scripts may use this

### Exclusions to Consider
If you have legitimate scripts that enumerate users, add exclusions:
```xml
<ProcessCreate onmatch="exclude">
  <ParentImage condition="is">C:\Scripts\LegitInventory.exe</ParentImage>
</ProcessCreate>
```

---

## Files Modified

- `sysmon/sysmon-ws.xml`
- `sysmon/sysmon-srv.xml`
- `sysmon/sysmon-dc.xml`
- `sysmon/sysmon-sql.xml`
- `sysmon/sysmon-exch.xml`
- `sysmon/sysmon-iis.xml`
