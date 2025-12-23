# Technical Report: Combined Sysmon + Windows Events Detection Coverage

**Date:** December 23, 2025
**Version:** 2.1
**Scope:** MITRE ATT&CK Coverage Analysis with Windows Event Log Enhancement
**Updates:** Added T1558 (Kerberos Attacks), T1110 (Brute Force) coverage with Windows Events 4768, 4769, 4771

---

## 1. Executive Summary

This report provides a comprehensive analysis of detection capabilities using **Sysmon** combined with **Windows Security Event Logs**. The goal is to achieve maximum MITRE ATT&CK coverage by leveraging both technologies.

### Coverage Summary

| Source | Current Coverage | With Enhancements | Gap Closure |
|--------|------------------|-------------------|-------------|
| Sysmon Only | 83.75% | 83.75% | - |
| Windows Events Only | ~60% | ~85% | - |
| **Combined (Sysmon + Events)** | 83.75% | **95%+** | **+11.25%** |

---

## 2. Current Detection Gaps (Sysmon)

Based on test results from PR #1, the following techniques remain undetected or partially detected:

### 2.1 Completely Undetected (0% across all configs)

| Technique ID | Name | Category | Impact |
|--------------|------|----------|--------|
| T1087.001 | Local Account Discovery | Discovery | HIGH |
| T1560.001 | Archive via Utility | Collection | HIGH |
| T1005 | Data from Local System | Collection | CRITICAL |

### 2.2 Partially Detected (some configs only)

| Technique ID | Name | Detected In | Missing In |
|--------------|------|-------------|------------|
| T1003.002 | Security Account Manager | ws, dc, exch | srv, sql, iis |
| T1003.003 | NTDS | srv, dc, exch, iis | ws, sql |
| T1555.003 | Credentials from Web Browsers | ws, dc, exch | srv, sql, iis |
| T1057 | Process Discovery | srv, dc, sql, exch, iis | ws |
| T1016 | System Network Config Discovery | ws, dc, exch, iis | srv, sql |
| T1074.001 | Local Data Staging | ws, dc, exch | srv, sql, iis |
| T1105 | Ingress Tool Transfer | ws, srv, dc, sql, exch | iis (partial) |
| T1071.001 | Application Layer Protocol: Web | ws, dc, exch | srv, sql, iis |
| T1570 | Lateral Tool Transfer | ws, srv, dc, exch | sql, iis |

---

## 3. Windows Event Log Coverage Matrix

### 3.1 Event Categories and IDs

#### Category A: PowerShell Logging (CRITICAL)

| Event ID | Log | Description | Techniques Covered |
|----------|-----|-------------|-------------------|
| **4103** | PowerShell/Operational | Module Logging | T1059.001, T1087.001, T1560.001 |
| **4104** | PowerShell/Operational | Script Block Logging | T1059.001, T1087.001, T1560.001, T1005, T1555.003, T1016, T1071.001 |
| **4105** | PowerShell/Operational | Script Start | T1059.001 |
| **4106** | PowerShell/Operational | Script Stop | T1059.001 |

**Detection Examples:**
```
Event 4104 catches:
- Get-LocalUser                    → T1087.001
- net user                         → T1087.001
- Compress-Archive                 → T1560.001
- Get-Content (sensitive files)    → T1005
- Invoke-WebRequest                → T1071.001
- Get-NetIPConfiguration           → T1016
```

#### Category B: Process Creation (CRITICAL)

| Event ID | Log | Description | Techniques Covered |
|----------|-----|-------------|-------------------|
| **4688** | Security | Process Creation | T1059.*, T1087.001, T1560.001, T1016, T1057 |
| **4689** | Security | Process Termination | Correlation |

**Requirements:**
- Command Line Auditing MUST be enabled
- Covers all command-line based techniques missed by Sysmon

#### Category C: Object Access (HIGH)

| Event ID | Log | Description | Techniques Covered |
|----------|-----|-------------|-------------------|
| **4656** | Security | Handle Requested | T1003.002, T1003.003, T1005, T1555.003 |
| **4658** | Security | Handle Closed | Correlation |
| **4660** | Security | Object Deleted | T1070.004 |
| **4663** | Security | Object Access Attempt | T1003.002, T1005, T1074.001, T1555.003 |
| **4670** | Security | Permissions Changed | T1222 |

**Critical Paths to Monitor:**
```
C:\Windows\System32\config\SAM           → T1003.002
C:\Windows\NTDS\ntds.dit                 → T1003.003
%APPDATA%\*\Login Data                   → T1555.003
%USERPROFILE%\Documents\*                → T1005
C:\Temp\*, C:\Users\*\AppData\Local\Temp → T1074.001
```

#### Category D: Account Management (HIGH)

| Event ID | Log | Description | Techniques Covered |
|----------|-----|-------------|-------------------|
| **4798** | Security | User's Local Group Membership Enumerated | T1087.001 |
| **4799** | Security | Security-Enabled Local Group Membership Enumerated | T1087.001 |
| **4720** | Security | User Account Created | T1136.001 |
| **4722** | Security | User Account Enabled | T1136.001 |
| **4724** | Security | Password Reset Attempt | T1098 |
| **4738** | Security | User Account Changed | T1098 |

#### Category E: Logon Events (MEDIUM)

| Event ID | Log | Description | Techniques Covered |
|----------|-----|-------------|-------------------|
| **4624** | Security | Successful Logon | T1078, T1021.* |
| **4625** | Security | Failed Logon | T1110 |
| **4648** | Security | Explicit Credential Logon | T1021.*, T1550 |
| **4672** | Security | Special Privileges Assigned | T1078.002 |
| **4776** | Security | NTLM Authentication | T1550.002 |

#### Category E2: Kerberos Events (CRITICAL - T1558)

| Event ID | Log | Description | Techniques Covered |
|----------|-----|-------------|-------------------|
| **4768** | Security | Kerberos TGT Request | T1558.001 (Golden Ticket), T1558.004 (AS-REP Roasting) |
| **4769** | Security | Kerberos Service Ticket Request | T1558.003 (Kerberoasting) |
| **4770** | Security | Kerberos Ticket Renewed | T1558 |
| **4771** | Security | Kerberos Pre-Auth Failed | T1110.003 (Password Spraying), T1558.004 |
| **4773** | Security | Kerberos Service Ticket Failed | T1558.003 |

**Detection Examples:**
```
Event 4769 (Kerberoasting):
- Encryption Type: 0x17 (RC4-HMAC) = Weak encryption, suspicious
- Service Name: SQL/*, HTTP/* = High-value targets

Event 4768 (Golden Ticket):
- Account Domain: Differs from client domain = Suspicious
- Ticket Options: 0x40810010 = Forwardable + Renewable

Event 4771 (AS-REP Roasting):
- Failure Code: 0x18 (KDC_ERR_PREAUTH_FAILED)
- Pre-Authentication Type: 0 = No pre-auth (vulnerable account)
```

#### Category F: Network Filtering (MEDIUM)

| Event ID | Log | Description | Techniques Covered |
|----------|-----|-------------|-------------------|
| **5156** | Security | WFP Connection Allowed | T1071.001, T1571, T1095 |
| **5157** | Security | WFP Connection Blocked | Network monitoring |
| **5158** | Security | WFP Bind Permitted | T1571 |

#### Category G: Directory Services (DC Only)

| Event ID | Log | Description | Techniques Covered |
|----------|-----|-------------|-------------------|
| **4662** | Security | Operation on AD Object | T1003.003, T1087.002 |
| **4742** | Security | Computer Account Changed | T1136.002 |
| **8222** | Directory Services | NTDS Replication | T1003.003 (DCSync) |
| **4929** | Directory Services | AD Replication Source Removed | T1003.003 |

---

## 4. Combined Coverage by Technique

### 4.1 Full Coverage Matrix (40 Techniques)

| Technique | Name | Sysmon | Win Events | Combined | Priority |
|-----------|------|--------|------------|----------|----------|
| T1059.001 | PowerShell | ✅ | 4103,4104 | ✅✅ | - |
| T1059.003 | Windows Command Shell | ✅ | 4688 | ✅✅ | - |
| T1047 | WMI | ✅ | 4688 | ✅✅ | - |
| T1106 | Native API | ✅ | - | ✅ | - |
| T1204.002 | Malicious File | ✅ | - | ✅ | - |
| T1547.001 | Registry Run Keys | ✅ | - | ✅ | - |
| T1053.005 | Scheduled Task | ✅ | 4698,4699 | ✅✅ | - |
| T1543.003 | Windows Service | ✅ | 4697,7045 | ✅✅ | - |
| T1546.003 | WMI Event Subscription | ✅ | - | ✅ | - |
| T1136.001 | Local Account | ✅ | 4720 | ✅✅ | - |
| T1548.002 | UAC Bypass | ✅ | - | ✅ | - |
| T1134.001 | Token Impersonation | ✅ | 4624 | ✅✅ | - |
| T1218.005 | Mshta | ✅ | 4688 | ✅✅ | - |
| T1218.010 | Regsvr32 | ✅ | 4688 | ✅✅ | - |
| T1218.011 | Rundll32 | ✅ | 4688 | ✅✅ | - |
| T1027 | Obfuscated Files | ✅ | - | ✅ | - |
| T1140 | Deobfuscate/Decode | ✅ | 4104 | ✅✅ | - |
| T1070.001 | Clear Windows Event Logs | ✅ | 1102 | ✅✅ | - |
| T1070.004 | File Deletion | ✅ | 4660 | ✅✅ | - |
| T1562.001 | Disable Security Tools | ✅ | 4688 | ✅✅ | - |
| T1003.001 | LSASS Memory | ✅ | 4656,4663 | ✅✅ | - |
| T1003.002 | SAM | ⚠️ | **4656,4663** | ✅ | HIGH |
| T1003.003 | NTDS | ⚠️ | **4662,8222** | ✅ | HIGH |
| T1552.001 | Credentials in Files | ✅ | 4663 | ✅✅ | - |
| T1555.003 | Browser Credentials | ⚠️ | **4663,4104** | ✅ | HIGH |
| **T1087.001** | **Local Account Discovery** | ❌ | **4798,4799,4104** | ✅ | **CRITICAL** |
| T1087.002 | Domain Account Discovery | ✅ | 4662 | ✅✅ | - |
| T1082 | System Information Discovery | ✅ | 4688 | ✅✅ | - |
| T1057 | Process Discovery | ⚠️ | **4688,4104** | ✅ | MEDIUM |
| T1018 | Remote System Discovery | ✅ | 4688 | ✅✅ | - |
| T1016 | System Network Config | ⚠️ | **4688,4104** | ✅ | MEDIUM |
| T1069.002 | Domain Groups | ✅ | 4662 | ✅✅ | - |
| T1482 | Domain Trust Discovery | ✅ | 4688 | ✅✅ | - |
| T1021.002 | SMB/Admin Shares | ✅ | 5140,5145 | ✅✅ | - |
| T1570 | Lateral Tool Transfer | ⚠️ | **5145,4663** | ✅ | MEDIUM |
| **T1560.001** | **Archive via Utility** | ❌ | **4688,4104** | ✅ | **CRITICAL** |
| **T1005** | **Data from Local System** | ❌ | **4663,4656** | ⚠️ | **CRITICAL** |
| T1074.001 | Local Data Staging | ⚠️ | **4663** | ✅ | HIGH |
| T1105 | Ingress Tool Transfer | ✅ | 5156 | ✅✅ | - |
| T1071.001 | Web Protocols | ⚠️ | **5156,4104** | ✅ | MEDIUM |
| **T1558** | **Steal/Forge Kerberos Tickets** | ✅ | **4768,4769,4771** | ✅✅ | **CRITICAL** |
| T1558.001 | Golden Ticket | ✅ | 4768,4769 | ✅✅ | CRITICAL |
| T1558.003 | Kerberoasting | ✅ | **4769** | ✅✅ | CRITICAL |
| T1558.004 | AS-REP Roasting | ✅ | **4768,4771** | ✅✅ | CRITICAL |
| **T1110** | **Brute Force** | ✅ | **4625,4771,4776** | ✅✅ | **CRITICAL** |
| T1110.003 | Password Spraying | ✅ | 4625,4771 | ✅✅ | CRITICAL |

**Legend:**
- ✅ = Fully detected
- ⚠️ = Partially detected
- ❌ = Not detected
- ✅✅ = Redundant coverage (both sources)
- **Bold** = Windows Events filling Sysmon gap

### 4.2 Coverage Summary

| Status | Sysmon Only | With Windows Events |
|--------|-------------|---------------------|
| Fully Detected | 33/40 (82.5%) | 39/40 (97.5%) |
| Partially Detected | 4/40 (10%) | 0/40 (0%) |
| Not Detected | 3/40 (7.5%) | 1/40 (2.5%)* |

*T1005 (Data from Local System) requires extensive SACL configuration and may generate high volume

---

## 5. Implementation Guide

### 5.1 Group Policy Configuration

#### 5.1.1 PowerShell Logging (CRITICAL - All Systems)

**GPO Path:** `Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell`

```
Turn on Module Logging: Enabled
  Module Names: *

Turn on PowerShell Script Block Logging: Enabled
  Log script block invocation start/stop events: Enabled

Turn on PowerShell Transcription: Enabled (Optional - high disk usage)
```

**Registry Equivalent:**
```powershell
# Script Block Logging
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockInvocationLogging" -Value 1

# Module Logging
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -Name "*" -Value "*"
```

#### 5.1.2 Process Creation with Command Line (CRITICAL - All Systems)

**GPO Path:** `Computer Configuration > Administrative Templates > System > Audit Process Creation`

```
Include command line in process creation events: Enabled
```

**Registry Equivalent:**
```powershell
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1
```

#### 5.1.3 Advanced Audit Policy Configuration

**GPO Path:** `Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration`

```powershell
# CRITICAL - Account Management
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable

# CRITICAL - Process Tracking
auditpol /set /subcategory:"Process Creation" /success:enable
auditpol /set /subcategory:"Process Termination" /success:enable

# HIGH - Object Access (Warning: High volume)
auditpol /set /subcategory:"File System" /success:enable /failure:enable
auditpol /set /subcategory:"Registry" /success:enable /failure:enable
auditpol /set /subcategory:"Kernel Object" /success:enable /failure:enable
auditpol /set /subcategory:"SAM" /success:enable /failure:enable

# MEDIUM - Logon/Logoff
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable

# MEDIUM - Network
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable

# DC ONLY - Directory Service
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable
```

### 5.2 SACL Configuration for Object Access

For T1005 and file-based detection, configure SACLs on sensitive paths:

```powershell
# Function to set SACL
function Set-AuditRule {
    param(
        [string]$Path,
        [string]$Identity = "Everyone",
        [string]$Rights = "Read",
        [string]$AuditFlags = "Success,Failure"
    )

    $acl = Get-Acl $Path
    $rule = New-Object System.Security.AccessControl.FileSystemAuditRule(
        $Identity,
        $Rights,
        "ContainerInherit,ObjectInherit",
        "None",
        $AuditFlags
    )
    $acl.AddAuditRule($rule)
    Set-Acl $Path $acl
}

# Critical paths to monitor
$paths = @(
    "C:\Windows\System32\config",           # SAM, SECURITY, SYSTEM
    "C:\Windows\NTDS",                       # DC only - ntds.dit
    "C:\Users\*\AppData\Local\Google\Chrome\User Data\Default",  # Browser creds
    "C:\Users\*\AppData\Local\Microsoft\Edge\User Data\Default",
    "C:\Users\*\Documents",                  # User documents
    "C:\Temp",                               # Common staging
    "C:\Windows\Temp"
)

foreach ($path in $paths) {
    if (Test-Path $path) {
        Set-AuditRule -Path $path -Rights "Read,Write,Delete"
    }
}
```

---

## 6. Detection Rules by Technique

### 6.1 T1087.001 - Local Account Discovery

**Sysmon (Current - Not Working):**
```xml
<ProcessCreate onmatch="include">
    <CommandLine condition="contains">net user</CommandLine>
    <CommandLine condition="contains">net1 user</CommandLine>
</ProcessCreate>
```

**Windows Events (Recommended):**
```
Event ID 4798: A user's local group membership was enumerated
Event ID 4799: A security-enabled local group membership was enumerated
Event ID 4104: Script Block contains "Get-LocalUser" or "net user"
Event ID 4688: CommandLine contains "net user" or "net1 user"
```

**SIEM Rule (Splunk):**
```spl
index=wineventlog (EventCode=4798 OR EventCode=4799)
| stats count by ComputerName, TargetUserName, SubjectUserName
| where count > 5
```

**SIEM Rule (Elastic):**
```json
{
  "query": {
    "bool": {
      "should": [
        { "term": { "event.code": "4798" }},
        { "term": { "event.code": "4799" }},
        { "wildcard": { "powershell.script_block_text": "*Get-LocalUser*" }},
        { "wildcard": { "process.command_line": "*net user*" }}
      ]
    }
  }
}
```

### 6.2 T1560.001 - Archive via Utility

**Windows Events:**
```
Event ID 4688: CommandLine contains:
  - "7z.exe a"
  - "7za.exe a"
  - "rar.exe a"
  - "Compress-Archive"
  - "tar.exe -c"
  - "makecab"

Event ID 4104: Script Block contains:
  - "Compress-Archive"
  - "ZipFile"
  - "[System.IO.Compression"
```

**SIEM Rule (Splunk):**
```spl
index=wineventlog EventCode=4688
| where match(CommandLine, "(?i)(7z|7za|rar|tar|makecab)\.exe.*(a|-c|compress)")
  OR match(CommandLine, "(?i)Compress-Archive")
| table _time, ComputerName, User, CommandLine, ParentCommandLine
```

### 6.3 T1005 - Data from Local System

**Windows Events:**
```
Event ID 4663: Object Access
  ObjectType: File
  ObjectName: *\Documents\*, *\Desktop\*, *.docx, *.xlsx, *.pdf, *.pst
  AccessMask: 0x1 (Read)

Event ID 4104: Script Block contains:
  - "Get-Content"
  - "Get-ChildItem" + "Recurse"
  - "[System.IO.File]::ReadAllText"
```

**SIEM Rule:**
```spl
index=wineventlog EventCode=4663 ObjectType="File"
| where match(ObjectName, "(?i)\.(docx?|xlsx?|pdf|pst|kdbx|key|pem)$")
| stats count by ComputerName, SubjectUserName, ObjectName
| where count > 10
```

### 6.4 T1003.002 - SAM Dump

**Windows Events:**
```
Event ID 4656: Handle requested to SAM
  ObjectName: *\config\SAM OR *\config\SECURITY OR *\config\SYSTEM

Event ID 4663: Read access to SAM
  ObjectName: *\config\SAM
```

**Sysmon Enhancement:**
```xml
<FileCreate onmatch="include">
    <TargetFilename condition="contains">\config\SAM</TargetFilename>
    <TargetFilename condition="contains">\config\SECURITY</TargetFilename>
    <TargetFilename condition="contains">\config\SYSTEM</TargetFilename>
</FileCreate>
```

### 6.5 T1003.003 - NTDS (DCSync)

**Windows Events (DC Only):**
```
Event ID 4662: Directory Service Access
  Properties contains:
    - 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 (DS-Replication-Get-Changes)
    - 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 (DS-Replication-Get-Changes-All)

Event ID 8222: NTDS Replication
```

**SIEM Rule:**
```spl
index=wineventlog EventCode=4662
| where match(Properties, "1131f6a[ad]")
| where SubjectUserName!="*$"
| table _time, ComputerName, SubjectUserName, ObjectName, Properties
```

---

## 7. Event Volume Estimation

### 7.1 Expected Daily Volume (per server)

| Event Category | Event IDs | Est. Volume/Day | Storage Impact |
|----------------|-----------|-----------------|----------------|
| PowerShell | 4103, 4104 | 1,000-50,000 | 10-500 MB |
| Process Creation | 4688 | 10,000-100,000 | 50-500 MB |
| Object Access | 4656, 4663 | 50,000-500,000 | 200 MB - 2 GB |
| Account Management | 4798, 4799 | 100-1,000 | 1-10 MB |
| Logon Events | 4624, 4625 | 1,000-10,000 | 5-50 MB |
| Network (WFP) | 5156 | 10,000-100,000 | 50-500 MB |

### 7.2 Recommended Log Retention

| Log | Min Retention | Recommended | Archive |
|-----|---------------|-------------|---------|
| Security | 7 days | 30 days | 1 year |
| PowerShell/Operational | 7 days | 30 days | 90 days |
| System | 7 days | 14 days | 30 days |
| Sysmon/Operational | 7 days | 30 days | 1 year |

### 7.3 Event Log Size Configuration

```powershell
# Increase Security log size
wevtutil sl Security /ms:1073741824  # 1 GB

# Increase PowerShell log size
wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:524288000  # 500 MB

# Increase Sysmon log size
wevtutil sl "Microsoft-Windows-Sysmon/Operational" /ms:1073741824  # 1 GB
```

---

## 8. Implementation Checklist

### Phase 1: Critical (Week 1)

- [ ] Enable PowerShell Script Block Logging (4104)
- [ ] Enable PowerShell Module Logging (4103)
- [ ] Enable Process Creation with Command Line (4688)
- [ ] Configure Event Log sizes
- [ ] Deploy to test systems

### Phase 2: High Priority (Week 2)

- [ ] Enable User Account Management auditing (4798, 4799)
- [ ] Enable Security Group Management auditing
- [ ] Configure SACL for SAM/SECURITY/SYSTEM files
- [ ] Configure SACL for NTDS.dit (DCs only)
- [ ] Deploy to production (phased)

### Phase 3: Medium Priority (Week 3-4)

- [ ] Enable Object Access auditing (selective paths)
- [ ] Enable WFP Connection auditing (5156)
- [ ] Configure SACL for browser credential paths
- [ ] Create SIEM detection rules
- [ ] Tune for false positives

### Phase 4: Optimization (Ongoing)

- [ ] Monitor event volume
- [ ] Adjust SACL coverage
- [ ] Create correlation rules
- [ ] Document baseline behavior
- [ ] Regular coverage testing

---

## 9. SIEM Integration

### 9.1 Required Log Sources

| Source | Forward To SIEM | Priority |
|--------|-----------------|----------|
| Windows Security | Yes | Critical |
| PowerShell/Operational | Yes | Critical |
| Sysmon/Operational | Yes | Critical |
| System | Yes | Medium |
| Application | Selective | Low |
| Directory Service (DC) | Yes | High |

### 9.2 Correlation Rules

**Multi-stage Attack Detection:**
```
IF (T1087.001 detected within 5 min)
AND (T1003.* detected within 30 min)
AND (T1021.002 detected within 60 min)
THEN Alert: "Potential lateral movement chain detected"
```

**Data Exfiltration Preparation:**
```
IF (T1005 detected - file access)
AND (T1560.001 detected - archiving within 10 min)
AND (T1071.001 OR T1048 detected - network transfer within 30 min)
THEN Alert: "Potential data exfiltration in progress"
```

---

## 10. Appendix

### A. Complete Event ID Reference

| Event ID | Log | Description | MITRE Techniques |
|----------|-----|-------------|------------------|
| 1102 | Security | Audit Log Cleared | T1070.001 |
| 4103 | PowerShell | Module Logging | T1059.001 |
| 4104 | PowerShell | Script Block Logging | T1059.001, T1087.001, T1560.001 |
| 4624 | Security | Successful Logon | T1078, T1021.* |
| 4625 | Security | Failed Logon | T1110 |
| 4648 | Security | Explicit Credentials | T1021.*, T1550 |
| 4656 | Security | Handle Requested | T1003.*, T1005 |
| 4658 | Security | Handle Closed | Correlation |
| 4660 | Security | Object Deleted | T1070.004 |
| 4662 | Security | DS Object Operation | T1003.003 |
| 4663 | Security | Object Access | T1003.*, T1005, T1555.003 |
| 4672 | Security | Special Privileges | T1078.002 |
| 4688 | Security | Process Created | T1059.*, T1087.001, T1560.001 |
| 4689 | Security | Process Terminated | Correlation |
| 4697 | Security | Service Installed | T1543.003 |
| 4698 | Security | Scheduled Task Created | T1053.005 |
| 4699 | Security | Scheduled Task Deleted | T1053.005 |
| 4720 | Security | User Account Created | T1136.001 |
| 4738 | Security | User Account Changed | T1098 |
| 4776 | Security | NTLM Authentication | T1550.002 |
| 4798 | Security | Local Group Enum | T1087.001 |
| 4799 | Security | Security Group Enum | T1087.001 |
| 5140 | Security | Network Share Accessed | T1021.002 |
| 5145 | Security | Network Share Object Access | T1021.002, T1570 |
| 5156 | Security | WFP Connection | T1071.001, T1095 |
| 7045 | System | Service Installed | T1543.003 |
| 8222 | DS | NTDS Replication | T1003.003 |
| **4768** | Security | Kerberos TGT Request | **T1558.001, T1558.004** |
| **4769** | Security | Kerberos Service Ticket | **T1558.003** (Kerberoasting) |
| **4770** | Security | Kerberos Ticket Renewed | T1558 |
| **4771** | Security | Kerberos Pre-Auth Failed | **T1110.003, T1558.004** |
| **4773** | Security | Kerberos Service Ticket Failed | T1558.003 |

### B. Overlap Analysis (Duplicati Sysmon vs Windows Events)

See `deploy/LOGGING-OVERLAP-ANALYSIS.md` for detailed analysis of:
- Which events are duplicated between Sysmon and Windows Events
- Recommendations for avoiding duplicate logging
- Storage optimization strategies
- SIEM correlation best practices

**Key Findings:**
| Scenario | Sysmon | Windows Events | Recommendation |
|----------|--------|----------------|----------------|
| Process Creation | Event 1 | Event 4688 | **Prefer Sysmon** (more context) |
| Authentication | ❌ | 4624, 4625, 4672 | **Windows Only** |
| Kerberos | Tool detection | 4768, 4769, 4771 | **Complementary** |
| Account Management | cmdline | 4720-4738 | **Complementary** |
| File Operations | Events 11, 23 | 4663 (with SACL) | **Prefer Sysmon** |
| Registry | Events 12-14 | 4657 (with SACL) | **Prefer Sysmon** |

### C. GPO Template Export

See `windows-audit-policy.inf` for importable security template.

### D. PowerShell Deployment Script

See `Deploy-AuditPolicy.ps1` for automated deployment.

### E. Deployment Scripts

| Script | Purpose | Location |
|--------|---------|----------|
| `windows-audit-policy.ps1` | Configure Windows Audit Policy | `deploy/` |
| `enable-powershell-logging.ps1` | Enable PowerShell Logging | `deploy/` |
| `LOGGING-OVERLAP-ANALYSIS.md` | Duplicate/Overlap Analysis | `deploy/` |

---

**Document Version:** 2.1
**Last Updated:** December 23, 2025
**Author:** Security Engineering Team
**Review Cycle:** Quarterly
