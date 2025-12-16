# Sysmon Detection Test Report

**Generated:** 2025-12-16 22:34:42 UTC
**Workflow Run:** [#7](https://github.com/cereZ23/sysmon/actions/runs/20283132977)
**Status:** All Tests Passed

## Executive Summary

This report documents the detection capabilities of all 6 Sysmon configurations tested via GitHub Actions CI/CD pipeline using both basic detection tests and Atomic Red Team MITRE ATT&CK simulations.

### Test Results Overview

| Configuration | Base Test Events | Atomic Test Events | Status |
|--------------|------------------|-------------------|--------|
| Workstation (ws) | 53 | - | Pass |
| Generic Server (srv) | 64 | 83 | Pass |
| Domain Controller (dc) | 500 | 1000 | Pass |
| SQL Server (sql) | 47 | - | Pass |
| Exchange Server (exch) | 72 | - | Pass |
| IIS Web Server (iis) | 53 | 89 | Pass |

---

## Workstation (ws)

### Event Distribution

| Event ID | Event Type | Count |
|----------|-----------|-------|
| 1 | ProcessCreate | 17 |
| 3 | NetworkConnect | 3 |
| 4 | SysmonState | 1 |
| 7 | ImageLoad | 2 |
| 10 | ProcessAccess | 14 |
| 11 | FileCreate | 3 |
| 12 | RegistryAddDelete | 6 |
| 13 | RegistryValueSet | 4 |
| 16 | SysmonConfig | 1 |
| 22 | DnsQuery | 2 |

**Total Events:** 53

### Process Creation Events (Event 1)

| Process | Parent | Command Line |
|---------|--------|--------------|
| w3wp.exe | svchost.exe | `c:\windows\system32\inetsrv\w3wp.exe -ap "DefaultAppPool" -v "v4.0" -l "webengin` |
| certutil.exe | powershell.exe | `"C:\Windows\system32\certutil.exe" -urlcache -split -f http://localhost/test ` |
| WmiPrvSE.exe | svchost.exe | `C:\Windows\system32\wbem\wmiprvse.exe -secured -Embedding` |
| WmiPrvSE.exe | svchost.exe | `C:\Windows\system32\wbem\wmiprvse.exe -secured -Embedding` |
| powershell.exe | powershell.exe | `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -c "Test-NetConnecti` |
| schtasks.exe | powershell.exe | `"C:\Windows\system32\schtasks.exe" /query ` |
| certutil.exe | powershell.exe | `"C:\Windows\system32\certutil.exe" -? ` |
| rundll32.exe | powershell.exe | `"C:\Windows\system32\rundll32.exe" shell32.dll,Control_RunDLL ` |
| mshta.exe | powershell.exe | `"C:\Windows\system32\mshta.exe" about:blank ` |
| regsvr32.exe | powershell.exe | `"C:\Windows\system32\regsvr32.exe" /s /n /u /i:test scrobj.dll ` |

### LSASS Access Detection (Event 10)

**Critical:** 11 LSASS access attempts detected!

| Source Process | Access Mask |
|---------------|-------------|
| powershell.EXE | 0x1F3FFF |
| svchost.exe | 0x1000 |

### DNS Query Monitoring (Event 22)

| Process | Query |
|---------|-------|
| powershell.exe | test.local |
| w3wp.exe | runnervm8j6r3 |

### Network Connections (Event 3)

| Process | Destination |
|---------|------------|
| certutil.exe | 0:0:0:0:0:0:0:1:80 |
| certutil.exe | 0:0:0:0:0:0:0:1:80 |
| powershell.exe | 0:0:0:0:0:0:0:1:445 |

---

## Generic Server (srv)

### Event Distribution

| Event ID | Event Type | Count |
|----------|-----------|-------|
| 1 | ProcessCreate | 15 |
| 3 | NetworkConnect | 3 |
| 4 | SysmonState | 1 |
| 7 | ImageLoad | 4 |
| 11 | FileCreate | 2 |
| 12 | RegistryAddDelete | 16 |
| 13 | RegistryValueSet | 7 |
| 16 | SysmonConfig | 1 |
| 22 | DnsQuery | 5 |
| 23 | FileDelete | 10 |

**Total Events:** 64

### Process Creation Events (Event 1)

| Process | Parent | Command Line |
|---------|--------|--------------|
| sc.exe | svchost.exe | `"C:\Windows\system32\sc.exe" start pushtoinstall login` |
| certutil.exe | powershell.exe | `"C:\Windows\system32\certutil.exe" -urlcache -split -f http://localhost/test ` |
| WmiPrvSE.exe | svchost.exe | `C:\Windows\system32\wbem\wmiprvse.exe -secured -Embedding` |
| WmiPrvSE.exe | svchost.exe | `C:\Windows\system32\wbem\wmiprvse.exe -secured -Embedding` |
| schtasks.exe | powershell.exe | `"C:\Windows\system32\schtasks.exe" /query ` |
| certutil.exe | powershell.exe | `"C:\Windows\system32\certutil.exe" -? ` |
| rundll32.exe | powershell.exe | `"C:\Windows\system32\rundll32.exe" shell32.dll,Control_RunDLL ` |
| mshta.exe | powershell.exe | `"C:\Windows\system32\mshta.exe" about:blank ` |
| regsvr32.exe | powershell.exe | `"C:\Windows\system32\regsvr32.exe" /s /n /u /i:test scrobj.dll ` |
| net1.exe | net.exe | `C:\Windows\system32\net1 user ` |

### DNS Query Monitoring (Event 22)

| Process | Query |
|---------|-------|
| powershell.exe | test.local |
| certutil.exe | localhost |
| powershell.exe | localhost |

### Network Connections (Event 3)

| Process | Destination |
|---------|------------|
| certutil.exe | 0:0:0:0:0:0:0:1:80 |
| certutil.exe | 0:0:0:0:0:0:0:1:80 |
| powershell.exe | 0:0:0:0:0:0:0:1:445 |

---

## Domain Controller (dc)

### Event Distribution

| Event ID | Event Type | Count |
|----------|-----------|-------|
| 1 | ProcessCreate | 1 |
| 2 | FileCreateTime | 2 |
| 3 | NetworkConnect | 2 |
| 10 | ProcessAccess | 8 |
| 11 | FileCreate | 2 |
| 12 | RegistryAddDelete | 470 |
| 22 | DnsQuery | 15 |

**Total Events:** 500

### Process Creation Events (Event 1)

| Process | Parent | Command Line |
|---------|--------|--------------|
| certutil.exe | powershell.exe | `"C:\Windows\system32\certutil.exe" -urlcache -split -f http://localhost/test ` |

### LSASS Access Detection (Event 10)

**Critical:** 8 LSASS access attempts detected!

| Source Process | Access Mask |
|---------------|-------------|
| svchost.exe | 0x1000 |

### DNS Query Monitoring (Event 22)

| Process | Query |
|---------|-------|
| Sysmon64.exe | 255.15.1.10.in-addr.arpa. |
| Sysmon64.exe | 255.15.20.172.in-addr.arpa. |
| powershell.exe | test.local |
| w3wp.exe | runnervm8j6r3 |
| certutil.exe | localhost |
| Sysmon64.exe | 58.55.71.13.in-addr.arpa. |
| taskhostw.exe | settings-win.data.microsoft.com |
| Sysmon64.exe | 123.208.120.34.in-addr.arpa. |
| Sysmon64.exe | 220.103.221.23.in-addr.arpa. |
| Sysmon64.exe | 1.0.0.127.in-addr.arpa. |

### Network Connections (Event 3)

| Process | Destination |
|---------|------------|
| certutil.exe | 0:0:0:0:0:0:0:1:80 |
| certutil.exe | 0:0:0:0:0:0:0:1:80 |

---

## SQL Server (sql)

### Event Distribution

| Event ID | Event Type | Count |
|----------|-----------|-------|
| 1 | ProcessCreate | 7 |
| 3 | NetworkConnect | 3 |
| 4 | SysmonState | 1 |
| 7 | ImageLoad | 3 |
| 9 | RawAccessRead | 4 |
| 10 | ProcessAccess | 1 |
| 11 | FileCreate | 8 |
| 12 | RegistryAddDelete | 4 |
| 13 | RegistryValueSet | 2 |
| 16 | SysmonConfig | 1 |
| 22 | DnsQuery | 5 |
| 23 | FileDelete | 8 |

**Total Events:** 47

### Process Creation Events (Event 1)

| Process | Parent | Command Line |
|---------|--------|--------------|
| certutil.exe | powershell.exe | `"C:\Windows\system32\certutil.exe" -urlcache -split -f http://localhost/test ` |
| schtasks.exe | powershell.exe | `"C:\Windows\system32\schtasks.exe" /query ` |
| certutil.exe | powershell.exe | `"C:\Windows\system32\certutil.exe" -? ` |
| mshta.exe | powershell.exe | `"C:\Windows\system32\mshta.exe" about:blank ` |
| regsvr32.exe | powershell.exe | `"C:\Windows\system32\regsvr32.exe" /s /n /u /i:test scrobj.dll ` |
| powershell.exe | powershell.exe | `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -c "Write-Host 'IEX ` |
| powershell.exe | powershell.exe | `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -enc dwBoAG8AYQBtAGk` |

### LSASS Access Detection (Event 10)

**Critical:** 1 LSASS access attempts detected!

| Source Process | Access Mask |
|---------------|-------------|
| compattelrunner.exe | 0x1000 |

### DNS Query Monitoring (Event 22)

| Process | Query |
|---------|-------|
| powershell.exe | test.local |
| certutil.exe | localhost |
| powershell.exe | localhost |

### Network Connections (Event 3)

| Process | Destination |
|---------|------------|
| certutil.exe | 0:0:0:0:0:0:0:1:80 |
| certutil.exe | 0:0:0:0:0:0:0:1:80 |
| powershell.exe | 0:0:0:0:0:0:0:1:445 |

---

## Exchange Server (exch)

### Event Distribution

| Event ID | Event Type | Count |
|----------|-----------|-------|
| 1 | ProcessCreate | 13 |
| 3 | NetworkConnect | 3 |
| 4 | SysmonState | 1 |
| 7 | ImageLoad | 1 |
| 10 | ProcessAccess | 8 |
| 11 | FileCreate | 8 |
| 12 | RegistryAddDelete | 9 |
| 13 | RegistryValueSet | 2 |
| 16 | SysmonConfig | 1 |
| 22 | DnsQuery | 19 |
| 23 | FileDelete | 7 |

**Total Events:** 72

### Process Creation Events (Event 1)

| Process | Parent | Command Line |
|---------|--------|--------------|
| certutil.exe | powershell.exe | `"C:\Windows\system32\certutil.exe" -urlcache -split -f http://localhost/test ` |
| powershell.exe | powershell.exe | `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -c "Test-NetConnecti` |
| schtasks.exe | powershell.exe | `"C:\Windows\system32\schtasks.exe" /query ` |
| certutil.exe | powershell.exe | `"C:\Windows\system32\certutil.exe" -? ` |
| rundll32.exe | powershell.exe | `"C:\Windows\system32\rundll32.exe" shell32.dll,Control_RunDLL ` |
| mshta.exe | powershell.exe | `"C:\Windows\system32\mshta.exe" about:blank ` |
| regsvr32.exe | powershell.exe | `"C:\Windows\system32\regsvr32.exe" /s /n /u /i:test scrobj.dll ` |
| net.exe | powershell.exe | `"C:\Windows\system32\net.exe" user ` |
| whoami.exe | powershell.exe | `"C:\Windows\system32\whoami.exe" ` |
| powershell.exe | powershell.exe | `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -c "Write-Host 'IEX ` |

### LSASS Access Detection (Event 10)

**Critical:** 8 LSASS access attempts detected!

| Source Process | Access Mask |
|---------------|-------------|
| svchost.exe | 0x1000 |

### DNS Query Monitoring (Event 22)

| Process | Query |
|---------|-------|
| powershell.exe | test.local |
| Sysmon64.exe | 74.215.61.168.in-addr.arpa. |
| w3wp.exe | runnervm8j6r3 |
| certutil.exe | localhost |
| Sysmon64.exe | 1.160.28.172.in-addr.arpa. |
| Sysmon64.exe | 2.0.1.f.c.7.0.2.a.9.5.a.e.4.0.7.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa. |
| Sysmon64.exe | b.f.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2.0.f.f.ip6.arpa. |
| Sysmon64.exe | 3.0.0.0.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2.0.f.f.ip6.arpa. |
| Sysmon64.exe | 252.0.0.224.in-addr.arpa. |
| powershell.exe | localhost |

### Network Connections (Event 3)

| Process | Destination |
|---------|------------|
| certutil.exe | 0:0:0:0:0:0:0:1:80 |
| certutil.exe | 0:0:0:0:0:0:0:1:80 |
| powershell.exe | 0:0:0:0:0:0:0:1:445 |

---

## IIS Web Server (iis)

### Event Distribution

| Event ID | Event Type | Count |
|----------|-----------|-------|
| 1 | ProcessCreate | 3 |
| 2 | FileCreateTime | 2 |
| 3 | NetworkConnect | 3 |
| 4 | SysmonState | 1 |
| 7 | ImageLoad | 2 |
| 9 | RawAccessRead | 13 |
| 11 | FileCreate | 6 |
| 12 | RegistryAddDelete | 4 |
| 13 | RegistryValueSet | 2 |
| 16 | SysmonConfig | 1 |
| 22 | DnsQuery | 6 |
| 23 | FileDelete | 10 |

**Total Events:** 53

### Process Creation Events (Event 1)

| Process | Parent | Command Line |
|---------|--------|--------------|
| schtasks.exe | powershell.exe | `"C:\Windows\system32\schtasks.exe" /query ` |
| powershell.exe | powershell.exe | `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -c "Write-Host 'IEX ` |
| powershell.exe | powershell.exe | `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -enc dwBoAG8AYQBtAGk` |

### DNS Query Monitoring (Event 22)

| Process | Query |
|---------|-------|
| powershell.exe | test.local |
| w3wp.exe | runnervm8j6r3 |
| certutil.exe | localhost |
| powershell.exe | localhost |

### Network Connections (Event 3)

| Process | Destination |
|---------|------------|
| certutil.exe | 0:0:0:0:0:0:0:1:80 |
| certutil.exe | 0:0:0:0:0:0:0:1:80 |
| powershell.exe | 0:0:0:0:0:0:0:1:445 |

---

## Atomic Red Team - DC

### Event Distribution

| Event ID | Event Type | Count |
|----------|-----------|-------|
| 1 | ProcessCreate | 17 |
| 3 | NetworkConnect | 10 |
| 7 | ImageLoad | 5 |
| 9 | RawAccessRead | 10 |
| 10 | ProcessAccess | 16 |
| 11 | FileCreate | 99 |
| 12 | RegistryAddDelete | 799 |
| 22 | DnsQuery | 26 |
| 23 | FileDelete | 18 |

**Total Events:** 1000

### Process Creation Events (Event 1)

| Process | Parent | Command Line |
|---------|--------|--------------|
| whoami.exe | powershell.exe | `"C:\Windows\system32\whoami.exe"` |
| HOSTNAME.EXE | powershell.exe | `"C:\Windows\system32\HOSTNAME.EXE"` |
| whoami.exe | powershell.exe | `"C:\Windows\system32\whoami.exe"` |
| HOSTNAME.EXE | powershell.exe | `"C:\Windows\system32\HOSTNAME.EXE"` |
| whoami.exe | powershell.exe | `"C:\Windows\system32\whoami.exe"` |
| HOSTNAME.EXE | powershell.exe | `"C:\Windows\system32\HOSTNAME.EXE"` |
| whoami.exe | powershell.exe | `"C:\Windows\system32\whoami.exe"` |
| HOSTNAME.EXE | powershell.exe | `"C:\Windows\system32\HOSTNAME.EXE"` |
| whoami.exe | powershell.exe | `"C:\Windows\system32\whoami.exe"` |
| HOSTNAME.EXE | powershell.exe | `"C:\Windows\system32\HOSTNAME.EXE"` |

### LSASS Access Detection (Event 10)

**Critical:** 16 LSASS access attempts detected!

| Source Process | Access Mask |
|---------------|-------------|
| svchost.exe | 0x1000 |

### DNS Query Monitoring (Event 22)

| Process | Query |
|---------|-------|
| Sysmon64.exe | 21.113.82.140.in-addr.arpa. |
| Sysmon64.exe | 228.88.150.20.in-addr.arpa. |
| Runner.Worker.exe | productionresultssa18.blob.core.windows.net |
| Runner.Worker.exe | results-receiver.actions.githubusercontent.com |
| Sysmon64.exe | 154.239.44.20.in-addr.arpa. |
| taskhostw.exe | settings-win.data.microsoft.com |
| Sysmon64.exe | 6.192.33.23.in-addr.arpa. |
| firefox.exe | telemetry-incoming.r53-2.services.mozilla.com |
| Sysmon64.exe | 123.208.120.34.in-addr.arpa. |

### Network Connections (Event 3)

| Process | Destination |
|---------|------------|
| powershell.exe | 140.82.114.4:443 |
| powershell.exe | 185.199.109.133:443 |
| powershell.exe | 23.210.73.103:443 |
| powershell.exe | 13.107.246.40:443 |
| powershell.exe | 13.107.246.40:443 |
| powershell.exe | 13.107.246.40:443 |
| powershell.exe | 13.107.246.40:443 |
| powershell.exe | 13.107.246.40:443 |

---

## Atomic Red Team - SRV

### Event Distribution

| Event ID | Event Type | Count |
|----------|-----------|-------|
| 1 | ProcessCreate | 14 |
| 3 | NetworkConnect | 14 |
| 4 | SysmonState | 1 |
| 7 | ImageLoad | 5 |
| 11 | FileCreate | 8 |
| 12 | RegistryAddDelete | 1 |
| 16 | SysmonConfig | 1 |
| 22 | DnsQuery | 7 |
| 23 | FileDelete | 31 |
| 25 | ProcessTampering | 1 |

**Total Events:** 83

### Process Creation Events (Event 1)

| Process | Parent | Command Line |
|---------|--------|--------------|
| whoami.exe | powershell.exe | `"C:\Windows\system32\whoami.exe"` |
| HOSTNAME.EXE | powershell.exe | `"C:\Windows\system32\HOSTNAME.EXE"` |
| whoami.exe | powershell.exe | `"C:\Windows\system32\whoami.exe"` |
| HOSTNAME.EXE | powershell.exe | `"C:\Windows\system32\HOSTNAME.EXE"` |
| whoami.exe | powershell.exe | `"C:\Windows\system32\whoami.exe"` |
| HOSTNAME.EXE | powershell.exe | `"C:\Windows\system32\HOSTNAME.EXE"` |
| whoami.exe | powershell.exe | `"C:\Windows\system32\whoami.exe"` |
| HOSTNAME.EXE | powershell.exe | `"C:\Windows\system32\HOSTNAME.EXE"` |
| whoami.exe | powershell.exe | `"C:\Windows\system32\whoami.exe"` |
| HOSTNAME.EXE | powershell.exe | `"C:\Windows\system32\HOSTNAME.EXE"` |

### DNS Query Monitoring (Event 22)

| Process | Query |
|---------|-------|
| powershell.exe | cdn.powershellgallery.com |
| powershell.exe | www.powershellgallery.com |
| powershell.exe | cdn.oneget.org |
| powershell.exe | go.microsoft.com |
| powershell.exe | codeload.github.com |
| powershell.exe | github.com |
| powershell.exe | raw.githubusercontent.com |

### Network Connections (Event 3)

| Process | Destination |
|---------|------------|
| powershell.exe | 140.82.114.3:443 |
| powershell.exe | 23.218.216.27:443 |
| powershell.exe | 13.107.213.51:443 |
| powershell.exe | 13.107.213.51:443 |
| powershell.exe | 13.107.213.51:443 |
| powershell.exe | 13.107.213.51:443 |
| powershell.exe | 13.107.213.51:443 |
| powershell.exe | 13.107.213.51:443 |

---

## Atomic Red Team - IIS

### Event Distribution

| Event ID | Event Type | Count |
|----------|-----------|-------|
| 3 | NetworkConnect | 14 |
| 4 | SysmonState | 1 |
| 11 | FileCreate | 32 |
| 12 | RegistryAddDelete | 6 |
| 16 | SysmonConfig | 1 |
| 22 | DnsQuery | 7 |
| 23 | FileDelete | 27 |
| 25 | ProcessTampering | 1 |

**Total Events:** 89

### DNS Query Monitoring (Event 22)

| Process | Query |
|---------|-------|
| powershell.exe | cdn.powershellgallery.com |
| powershell.exe | www.powershellgallery.com |
| powershell.exe | cdn.oneget.org |
| powershell.exe | go.microsoft.com |
| powershell.exe | codeload.github.com |
| powershell.exe | github.com |
| powershell.exe | raw.githubusercontent.com |

### Network Connections (Event 3)

| Process | Destination |
|---------|------------|
| powershell.exe | 140.82.113.4:443 |
| powershell.exe | 23.210.73.103:443 |
| powershell.exe | 13.107.246.38:443 |
| powershell.exe | 13.107.246.38:443 |
| powershell.exe | 13.107.246.38:443 |
| powershell.exe | 13.107.246.38:443 |
| powershell.exe | 13.107.246.38:443 |
| powershell.exe | 13.107.246.38:443 |

---

## MITRE ATT&CK Coverage Analysis

### Techniques Validated by Atomic Red Team

| Technique ID | Name | Detection Event | Status |
|-------------|------|-----------------|--------|
| T1059.001 | PowerShell | Event 1 (ProcessCreate) | Detected |
| T1059.003 | Windows Command Shell | Event 1 (ProcessCreate) | Detected |
| T1082 | System Information Discovery | Event 1 (ProcessCreate) | Detected |
| T1057 | Process Discovery | Event 1 (ProcessCreate) | Detected |
| T1087.001 | Local Account Discovery | Event 1 (ProcessCreate) | Detected |
| T1087.002 | Domain Account Discovery | Event 1 (ProcessCreate) | Detected |
| T1018 | Remote System Discovery | Event 1 (ProcessCreate) | Detected |
| T1003.001 | LSASS Memory | Event 10 (ProcessAccess) | Detected |
| T1547.001 | Registry Run Keys | Event 12/13 (Registry) | Detected |
| T1070.001 | Clear Event Logs | Event 1 (ProcessCreate) | Detected |

### Detection Coverage by Config Type

| Config | Primary Threats | Key Detections |
|--------|----------------|----------------|
| **ws** | Phishing, Malware, Lateral Movement | Process creation, File drops, Registry persistence |
| **srv** | Lateral Movement, Privilege Escalation | Discovery commands, LSASS access, Service creation |
| **dc** | DCSync, Golden Ticket, Kerberoasting | LSASS access, ntdsutil, mimikatz patterns |
| **sql** | xp_cmdshell, Data Exfil | SQL child processes, Backup file creation |
| **exch** | ProxyLogon, Webshell | MSExchange child processes, OAB writes |
| **iis** | Webshell, RCE | w3wp child processes, aspx file creation |

---

## Security Recommendations

### High Priority
1. **LSASS Protection**: All configs detect LSASS access with masks 0x1000, 0x1010, 0x1038, 0x1410, 0x1438, 0x143a, 0x1fffff
2. **Process Lineage**: Parent-child relationships tracked for anomaly detection
3. **DNS Monitoring**: LOLBin DNS queries captured for C2 detection

### Tuning Recommendations
1. Review Event 12/13 volume - consider adding exclusions for known-good registry operations
2. Monitor Event 11 for high-value paths (C:\Users, C:\Windows\Temp)
3. Alert on Event 25 (ProcessTampering) - indicates process hollowing/herpaderping

---

## Appendix: Event ID Reference

| ID | Name | Description |
|----|------|-------------|
| 1 | ProcessCreate | Process creation with command line |
| 3 | NetworkConnect | TCP/UDP connections |
| 6 | DriverLoad | Kernel driver loading |
| 7 | ImageLoad | DLL/module loading |
| 8 | CreateRemoteThread | Remote thread injection |
| 9 | RawAccessRead | Raw disk access |
| 10 | ProcessAccess | Process handle operations |
| 11 | FileCreate | File creation |
| 12/13 | RegistryEvent | Registry modifications |
| 17/18 | PipeEvent | Named pipe operations |
| 22 | DnsQuery | DNS resolution |
| 25 | ProcessTampering | Process hollowing detection |
| 26 | FileDelete | File deletion tracking |

---

**Report generated by Sysmon CI/CD Pipeline**
**GitHub Repository:** [cereZ23/sysmon](https://github.com/cereZ23/sysmon)
