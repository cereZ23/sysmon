# Sysmon Enterprise Security Monitoring - Complete Technical Guide

**Version:** 2.1.0
**Date:** 29 December 2025
**Classification:** Internal Use
**Author:** Security Engineering Team

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Project Overview](#2-project-overview)
3. [Architecture & Design Approach](#3-architecture--design-approach)
4. [Role-Specific Configurations](#4-role-specific-configurations)
5. [Threat Detection & MITRE ATT&CK Coverage](#5-threat-detection--mitre-attck-coverage)
6. [Windows Security Events Integration](#6-windows-security-events-integration)
7. [Deployment Scripts](#7-deployment-scripts)
8. [Testing Framework](#8-testing-framework)
9. [SIEM Integration](#9-siem-integration)
10. [Production Readiness Assessment](#10-production-readiness-assessment)
11. [Appendices](#11-appendices)

---

## 1. Executive Summary

### 1.1 Purpose

This document provides a comprehensive technical guide for deploying and managing Sysmon-based security monitoring across enterprise Windows infrastructure. It consolidates all project documentation into a single authoritative reference.

### 1.2 Key Achievements

| Metric | Value | Status |
|--------|-------|--------|
| **Production Readiness Score** | 92/100 | Ready |
| **MITRE ATT&CK Coverage** | 81-90% | Excellent |
| **Configurations Available** | 6 role-specific | Complete |
| **Languages Supported** | 5 (EN, IT, DE, FR, ES) | Multi-language |
| **CI/CD Integration** | GitHub Actions | Automated |

### 1.3 Solution Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                    ENTERPRISE SECURITY MONITORING                    │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐            │
│   │  Sysmon     │    │  Windows    │    │  PowerShell │            │
│   │  Events     │ +  │  Security   │ +  │  Logging    │ = 95%+     │
│   │  (1-26)     │    │  Events     │    │  (4103/4104)│   Coverage │
│   └─────────────┘    └─────────────┘    └─────────────┘            │
│                                                                      │
│   ┌──────────────────────────────────────────────────────────┐     │
│   │                    SPLUNK SIEM                            │     │
│   │   - Real-time correlation                                 │     │
│   │   - Threat hunting                                        │     │
│   │   - Incident response                                     │     │
│   └──────────────────────────────────────────────────────────┘     │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 1.4 Quick Start

```powershell
# 1. Install Sysmon with workstation configuration
sysmon.exe -accepteula -i sysmon-ws.xml

# 2. Configure Windows Audit Policy (multi-language support)
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/cereZ23/sysmon/main/sysmon/deploy/windows-audit-policy.ps1" -OutFile "audit-policy.ps1"
powershell.exe -ExecutionPolicy Bypass -File .\audit-policy.ps1

# 3. Enable PowerShell logging
powershell.exe -ExecutionPolicy Bypass -File .\enable-powershell-logging.ps1
```

---

## 2. Project Overview

### 2.1 Objectives

1. **Comprehensive Threat Detection** - Cover 40+ MITRE ATT&CK techniques
2. **Role-Based Optimization** - Tailored configurations for each system type
3. **Noise Reduction** - 60-70% event volume reduction on workstations
4. **Multi-Language Support** - Works on all Windows language versions
5. **Production Ready** - Tested and validated for enterprise deployment

### 2.2 Project Structure

```
sysmon-repo/
├── README.md                          # Main project overview
├── sysmon/
│   ├── sysmon-ws.xml                  # Workstation configuration
│   ├── sysmon-srv.xml                 # Generic server configuration
│   ├── sysmon-dc.xml                  # Domain controller configuration
│   ├── sysmon-sql.xml                 # SQL Server configuration
│   ├── sysmon-exch.xml                # Exchange Server configuration
│   ├── sysmon-iis.xml                 # IIS Web Server configuration
│   │
│   ├── deploy/                        # Deployment scripts
│   │   ├── windows-audit-policy.ps1   # Windows Audit Policy (v2.1.0)
│   │   ├── enable-powershell-logging.ps1
│   │   └── README.md
│   │
│   ├── tests/                         # Testing framework
│   │   ├── Test-SysmonDetection.ps1   # Quick validation
│   │   ├── Run-AtomicTests.ps1        # Atomic Red Team
│   │   └── README.md
│   │
│   ├── docs/                          # Technical documentation
│   │   └── WINDOWS-EVENT-RAW-DATA-REFERENCE.md
│   │
│   └── manuali/                       # Italian language manuals
│       └── MANUALE-*.md
│
└── .github/workflows/
    └── sysmon-test.yml                # CI/CD automation
```

### 2.3 Requirements

| Component | Minimum Version | Recommended |
|-----------|-----------------|-------------|
| Sysmon | v15.0 | v15.15+ |
| Schema Version | 4.50 | 4.90 |
| Windows Workstation | Windows 10 | Windows 11 |
| Windows Server | Server 2016 | Server 2022 |
| PowerShell | 5.1 | 7.x |

---

## 3. Architecture & Design Approach

### 3.1 Defense-in-Depth Strategy

The solution implements a **three-layer logging architecture**:

```
Layer 1: Sysmon (Process & System Activity)
         ├── Process Creation/Termination (Event 1, 5)
         ├── Network Connections (Event 3)
         ├── File Operations (Event 11, 23, 26)
         ├── Registry Changes (Event 12, 13, 14)
         ├── DLL Loading (Event 7)
         ├── Process Injection (Event 8, 10)
         └── WMI Events (Event 19, 20, 21)

Layer 2: Windows Security Events (Authentication & Authorization)
         ├── Logon/Logoff (Event 4624, 4625, 4634)
         ├── Account Management (Event 4720-4738)
         ├── Privilege Use (Event 4672, 4673)
         ├── Object Access (Event 4656, 4663)
         └── Policy Changes (Event 4719, 4739)

Layer 3: PowerShell Logging (Script Execution)
         ├── Module Logging (Event 4103)
         └── Script Block Logging (Event 4104)
```

### 3.2 Role-Based Configuration Philosophy

| System Type | Monitoring Posture | Noise Tolerance | Key Focus |
|-------------|-------------------|-----------------|-----------|
| **Workstation** | Balanced | Low | User activity, phishing, LOLBins |
| **Generic Server** | Aggressive | Medium | Lateral movement, persistence |
| **Domain Controller** | Maximum | High | AD attacks, credential theft |
| **SQL Server** | Database-focused | Medium | SQL injection, xp_cmdshell |
| **Exchange Server** | Email-focused | Medium | Webshells, ProxyLogon |
| **IIS Web Server** | Web-focused | Medium | RCE, web shells, C2 |

### 3.3 Event ID Coverage Matrix

| Event ID | Name | WS | SRV | DC | SQL | EXCH | IIS |
|----------|------|:--:|:---:|:--:|:---:|:----:|:---:|
| 1 | ProcessCreate | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 2 | FileCreateTime | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 3 | NetworkConnect | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 5 | ProcessTerminate | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 6 | DriverLoad | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 7 | ImageLoad | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 8 | CreateRemoteThread | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 9 | RawAccessRead | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 10 | ProcessAccess | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 11 | FileCreate | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 12 | RegistryAddDelete | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 13 | RegistryValueSet | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 14 | RegistryRename | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 15 | FileCreateStreamHash | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 17 | PipeCreated | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 18 | PipeConnected | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 19 | WmiFilter | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 20 | WmiConsumer | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 21 | WmiBinding | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 22 | DnsQuery | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 23 | FileDelete | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 25 | ProcessTampering | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 26 | FileDeleteDetected | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

---

## 4. Role-Specific Configurations

### 4.1 Workstation (sysmon-ws.xml)

**Target:** Windows 10/11 client endpoints
**Size:** 56.5 KB
**Noise Reduction:** 60-70%

**Key Detections:**
- Office macro execution → cmd/powershell
- Phishing payload execution
- Credential dumping (LSASS access)
- LOLBins abuse (certutil, mshta, etc.)
- Browser-based attacks

**Exclusions Applied:**
- Chrome, Edge, Firefox browser activity
- Microsoft Teams background processes
- OneDrive sync operations
- Windows Update/Search Indexer

**Installation:**
```powershell
sysmon.exe -accepteula -i sysmon-ws.xml
```

### 4.2 Generic Server (sysmon-srv.xml)

**Target:** Windows Server 2016/2019/2022
**Size:** 45.2 KB
**Monitoring Posture:** Aggressive

**Key Detections:**
- Lateral movement via PsExec, WMI
- Persistence mechanisms (services, tasks)
- Discovery commands (net, nltest)
- Suspicious RDP client usage

**Installation:**
```powershell
sysmon.exe -accepteula -i sysmon-srv.xml
```

### 4.3 Domain Controller (sysmon-dc.xml)

**Target:** Active Directory Domain Services
**Size:** 25.1 KB
**Monitoring Posture:** Maximum (Tier-0 Asset)

**Key Detections:**
- DCSync attacks (DRSUAPI)
- Golden Ticket creation
- Kerberoasting
- AD reconnaissance (ADFind, BloodHound)
- Skeleton Key malware
- ntdsutil.exe abuse

**Critical Named Pipes Monitored:**
```
\\.\pipe\drsuapi
\\.\pipe\samr
\\.\pipe\lsarpc
\\.\pipe\netlogon
```

**Installation:**
```powershell
sysmon.exe -accepteula -i sysmon-dc.xml
```

### 4.4 SQL Server (sysmon-sql.xml)

**Target:** SQL Server 2016/2019/2022
**Size:** 38.7 KB

**Key Detections:**
- xp_cmdshell execution
- SQL injection → OS command
- Database backup exfiltration
- sqlservr.exe spawning cmd/powershell
- Suspicious stored procedure execution

**Installation:**
```powershell
sysmon.exe -accepteula -i sysmon-sql.xml
```

### 4.5 Exchange Server (sysmon-exch.xml)

**Target:** Exchange Server 2016/2019
**Size:** 24.3 KB

**Key Detections:**
- ProxyLogon/ProxyShell exploitation
- Webshell deployment
- w3wp.exe → cmd/powershell chains
- Email collection activities
- Suspicious OWA activity

**Installation:**
```powershell
sysmon.exe -accepteula -i sysmon-exch.xml
```

### 4.6 IIS Web Server (sysmon-iis.xml)

**Target:** IIS Web Servers
**Size:** 29.8 KB

**Key Detections:**
- Webshell execution
- RCE via w3wp.exe
- Suspicious aspx/php file creation
- C2 communication patterns
- Directory traversal attempts

**Installation:**
```powershell
sysmon.exe -accepteula -i sysmon-iis.xml
```

---

## 5. Threat Detection & MITRE ATT&CK Coverage

### 5.1 Coverage by Tactic

| Tactic | Techniques Covered | Detection Rate |
|--------|-------------------|----------------|
| **Execution** | T1059, T1047, T1106, T1204 | 90%+ |
| **Persistence** | T1547, T1053, T1543, T1546, T1136 | 85%+ |
| **Privilege Escalation** | T1548, T1134 | 80%+ |
| **Defense Evasion** | T1218, T1027, T1070, T1562 | 85%+ |
| **Credential Access** | T1003, T1552, T1555 | 90%+ |
| **Discovery** | T1087, T1018, T1082, T1057 | 75%+ |
| **Lateral Movement** | T1021, T1570 | 85%+ |
| **Collection** | T1114, T1056, T1560 | 80%+ |
| **Command & Control** | T1071, T1105 | 75%+ |

### 5.2 Detection Rate by Configuration

| Configuration | Techniques Tested | Detected | Rate |
|---------------|-------------------|----------|------|
| Workstation (ws) | 40 | 33 | 82.5% |
| Generic Server (srv) | 40 | 35 | 87.5% |
| Domain Controller (dc) | 40 | 36 | 90.0% |
| SQL Server (sql) | 40 | 33 | 82.5% |
| Exchange (exch) | 40 | 32 | 80.0% |
| IIS (iis) | 40 | 29 | 72.5% |

### 5.3 Critical Technique Detection

#### T1003.001 - LSASS Memory Credential Dumping

**Detection Method:** ProcessAccess (Event 10)
```xml
<ProcessAccess onmatch="include">
  <TargetImage condition="is">C:\Windows\System32\lsass.exe</TargetImage>
</ProcessAccess>
```

**Splunk Query:**
```spl
index=sysmon EventCode=10 TargetImage="*lsass.exe"
| where NOT match(SourceImage, "(?i)(MsMpEng|csrss|services|wininit)\.exe$")
| table _time, Computer, SourceImage, GrantedAccess
```

#### T1059.001 - PowerShell Execution

**Detection Method:** ProcessCreate (Event 1) + Script Block Logging (4104)
```xml
<ProcessCreate onmatch="include">
  <CommandLine condition="contains">-enc</CommandLine>
  <CommandLine condition="contains">-encodedcommand</CommandLine>
</ProcessCreate>
```

**Splunk Query:**
```spl
index=sysmon EventCode=1
| search CommandLine="*-enc*" OR CommandLine="*-encodedcommand*"
| table _time, Computer, User, ParentImage, Image, CommandLine
```

#### T1543.003 - Windows Service Persistence

**Detection Method:** Windows Security Event 4697
```
Event 4697: A service was installed in the system
- ServiceName: Name of the malicious service
- ServiceFileName: Path to malicious executable
- ServiceType: Type of service
```

**Splunk Query:**
```spl
index=wineventlog EventCode=4697
| where NOT match(ServiceFileName, "(?i)^C:\\(Windows|Program Files)")
| table _time, Computer, ServiceName, ServiceFileName, SubjectUserName
```

#### T1021.002 - SMB/Windows Admin Shares

**Detection Method:** NetworkConnect (Event 3) + Named Pipes (Event 17/18)
```xml
<NetworkConnect onmatch="include">
  <DestinationPort condition="is">445</DestinationPort>
</NetworkConnect>
<PipeEvent onmatch="include">
  <PipeName condition="contains">psexec</PipeName>
</PipeEvent>
```

---

## 6. Windows Security Events Integration

### 6.1 Complementary Strategy

Sysmon and Windows Security Events provide **complementary coverage**:

| Capability | Sysmon | Windows Events | Combined |
|------------|--------|----------------|----------|
| Process Creation | ✓✓✓ (hash, parent) | ✓ (basic) | ✓✓✓ |
| Authentication | - | ✓✓✓ | ✓✓✓ |
| Account Management | - | ✓✓✓ | ✓✓✓ |
| Service Installation | - | ✓✓✓ (Event 4697) | ✓✓✓ |
| Network Connections | ✓✓✓ | ✓ (firewall logs) | ✓✓✓ |
| Registry Changes | ✓✓✓ | ✓ (limited) | ✓✓✓ |
| PowerShell | ✓ (process) | ✓✓✓ (script content) | ✓✓✓ |

**Combined Coverage: 95%+**

### 6.2 Key Windows Security Events

| Event ID | Description | MITRE ATT&CK |
|----------|-------------|--------------|
| 4625 | Failed Logon | T1110 Brute Force |
| 4648 | Explicit Credentials | T1078 Valid Accounts |
| 4672 | Special Privileges | T1134 Token Manipulation |
| 4697 | Service Installed | T1543.003 Windows Service |
| 4698 | Scheduled Task Created | T1053.005 Scheduled Task |
| 4720 | User Account Created | T1136.001 Local Account |
| 4722 | User Account Enabled | T1098 Account Manipulation |
| 4724 | Password Reset | T1098 Account Manipulation |
| 4732 | Member Added to Group | T1098 Privilege Escalation |

### 6.3 PowerShell Logging Events

| Event ID | Log | Description | Detection Value |
|----------|-----|-------------|-----------------|
| 4103 | PowerShell/Operational | Module Logging | Command pipeline execution |
| 4104 | PowerShell/Operational | Script Block Logging | Full script content (critical) |

**Detectable Patterns in Event 4104:**
- `-EncodedCommand` (Base64 obfuscation)
- `Invoke-Expression` / `IEX` (dynamic execution)
- `DownloadString` / `DownloadFile` (remote content)
- `FromBase64String` (payload decoding)
- `Invoke-Mimikatz` (credential dumping)
- `[Reflection.Assembly]::Load` (in-memory loading)

---

## 7. Deployment Scripts

### 7.1 Windows Audit Policy Script (v2.1.0)

**File:** `sysmon/deploy/windows-audit-policy.ps1`

#### Multi-Language Support

The script uses **GUIDs instead of localized names**, ensuring compatibility with ALL Windows languages:

| Language | Status | Tested in CI |
|----------|--------|--------------|
| English (en-US) | ✓ Supported | ✓ |
| Italian (it-IT) | ✓ Supported | ✓ |
| German (de-DE) | ✓ Supported | ✓ |
| French (fr-FR) | ✓ Supported | ✓ |
| Spanish (es-ES) | ✓ Supported | ✓ |

**Technical Implementation:**
```powershell
# Before v2.1.0 (failed on non-English Windows):
auditpol /set /subcategory:"Logon" /success:enable
# Error 0x00000057 on Italian Windows

# After v2.1.0 (works on ALL languages):
auditpol /set /subcategory:{0CCE9215-69AE-11D9-BED3-505054503030} /success:enable
```

#### Usage

```powershell
# Standard configuration
.\windows-audit-policy.ps1

# With Sysmon installed (skip duplicate events)
.\windows-audit-policy.ps1 -SysmonInstalled

# Restore default policy
.\windows-audit-policy.ps1 -RestoreDefaults

# Custom log path
.\windows-audit-policy.ps1 -LogPath "D:\Logs\Audit"
```

#### Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-LogPath` | `C:\SecurityBaseline\Logs` | Backup and log location |
| `-BackupExisting` | `$true` | Create backup before changes |
| `-RestoreDefaults` | `$false` | Restore Windows default policy |
| `-SysmonInstalled` | `$false` | Skip Process Creation/Termination |

#### Output Example

```
[2025-12-29 15:59:40] [Info] Windows Audit Policy Configuration Script
[2025-12-29 15:59:40] [Info] Version 2.1.0 (Multi-Language Support)
[2025-12-29 15:59:40] [Success] Backup created successfully
[2025-12-29 15:59:41] [Info] Configuring: Logon (Success: True, Failure: True)
...
[2025-12-29 15:59:42] [Success] Configuration Complete
[2025-12-29 15:59:42] [Info] Policies configured successfully: 55
[2025-12-29 15:59:42] [Info] Policies failed: 0
```

### 7.2 PowerShell Logging Script (v1.0.0)

**File:** `sysmon/deploy/enable-powershell-logging.ps1`

#### Usage

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\enable-powershell-logging.ps1
```

#### Registry Changes Applied

```
HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging
  EnableModuleLogging = 1
  ModuleNames = *

HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
  EnableScriptBlockLogging = 1
  EnableScriptBlockInvocationLogging = 1
```

---

## 8. Testing Framework

### 8.1 Testing Approach Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         TESTING STRATEGY                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────────────┐    ┌──────────────────┐    ┌───────────────┐ │
│  │  Quick Validation │    │  Atomic Red Team │    │  CI/CD        │ │
│  │  (Simulated)      │    │  (Real Attacks)  │    │  (Automated)  │ │
│  │                   │    │                   │    │               │ │
│  │  - 5-10 minutes   │    │  - 30-60 minutes │    │  - On commit  │ │
│  │  - No artifacts   │    │  - Full artifacts │    │  - All configs│ │
│  │  - Safe           │    │  - Sandbox req'd  │    │  - Multi-lang │ │
│  └──────────────────┘    └──────────────────┘    └───────────────┘ │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 8.2 Quick Validation (Test-SysmonDetection.ps1)

**Purpose:** Fast validation without live threats
**Duration:** 5-10 minutes
**Safety:** No malicious artifacts created

```powershell
# Run quick validation
.\sysmon\tests\Test-SysmonDetection.ps1 -ConfigType ws -CI

# Supported config types: ws, srv, dc, sql, exch, iis
```

**Techniques Tested:**
- Process creation with suspicious arguments
- Registry Run key creation
- Named pipe creation (C2 patterns)
- DNS queries to suspicious domains
- File creation in sensitive locations

### 8.3 Atomic Red Team Testing (Run-AtomicTests.ps1)

**Purpose:** Comprehensive testing with real attack techniques
**Duration:** 30-60 minutes
**Requirement:** Isolated sandbox environment

```powershell
# Install Atomic Red Team
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1')
Install-AtomicRedTeam -getAtomics -Force

# Run comprehensive tests
.\sysmon\tests\Run-AtomicTests.ps1 -ConfigType ws
```

**40 MITRE ATT&CK Techniques Tested:**

| Category | Techniques |
|----------|------------|
| Execution | T1059.001, T1059.003, T1047, T1106, T1204.002 |
| Persistence | T1547.001, T1053.005, T1543.003, T1546.003, T1136.001 |
| Privilege Escalation | T1548.002, T1134.001 |
| Defense Evasion | T1218.005/010/011, T1027, T1140, T1070.001/004, T1562.001 |
| Credential Access | T1003.001/002/003, T1552.001, T1555.003 |
| Discovery | T1087.001/002, T1082, T1057, T1018, T1016, T1069.002, T1482 |
| Lateral Movement | T1021.002, T1570 |
| Collection | T1560.001, T1005, T1074.001 |
| C2 | T1105, T1071.001 |

### 8.4 Sandbox Environments

#### Option 1: Windows Sandbox (Recommended)

```powershell
# Enable Windows Sandbox
Enable-WindowsOptionalFeature -Online -FeatureName "Containers-DisposableClientVM"

# Run sandbox setup
.\sysmon\tests\setup-sandbox.ps1
```

**Advantages:**
- Disposable (clean state each launch)
- No persistence
- Fast startup
- No additional licensing

#### Option 2: Hyper-V VM

**Advantages:**
- Full Windows features
- Snapshot/restore capability
- Network isolation
- Persistent test environment

#### Option 3: GitHub Actions (CI/CD)

**Trigger:** Automatic on code changes
**Environment:** Windows Server 2025
**Coverage:** All 6 configurations + multi-language tests

### 8.5 CI/CD Workflow

**File:** `.github/workflows/sysmon-test.yml`

**Jobs Executed:**

| Job | Trigger | Purpose |
|-----|---------|---------|
| `validate-xml` | Push/PR | XML syntax validation |
| `test-sysmon-configs` | Push/PR | Install/verify all 6 configs |
| `atomic-red-team` | Manual | Full Atomic Red Team testing |
| `windows-event-tests` | Manual | Windows Security Event testing |
| `multilang-audit-test` | Manual | Multi-language audit policy testing |

**Manual Trigger:**
```bash
gh workflow run "Sysmon Detection Testing" --field config_type=all
```

---

## 9. SIEM Integration

### 9.1 Splunk Index Configuration

```
[sysmon]
homePath = $SPLUNK_DB/sysmon/db
coldPath = $SPLUNK_DB/sysmon/colddb
thawedPath = $SPLUNK_DB/sysmon/thaweddb

[wineventlog]
homePath = $SPLUNK_DB/wineventlog/db
coldPath = $SPLUNK_DB/wineventlog/colddb
thawedPath = $SPLUNK_DB/wineventlog/thaweddb
```

### 9.2 Key Detection Queries

#### Encoded PowerShell Detection
```spl
index=sysmon EventCode=1
| search CommandLine="*-enc*" OR CommandLine="*-encodedcommand*"
| table _time, Computer, User, ParentImage, Image, CommandLine
```

#### LSASS Credential Access
```spl
index=sysmon EventCode=10 TargetImage="*lsass.exe"
| where NOT match(SourceImage, "(?i)(MsMpEng|csrss|services|wininit)\.exe$")
| table _time, Computer, SourceImage, GrantedAccess
```

#### Office Macro Execution
```spl
index=sysmon EventCode=1
| search ParentImage IN ("*winword.exe", "*excel.exe", "*powerpnt.exe")
| search Image IN ("*cmd.exe", "*powershell.exe", "*wscript.exe", "*mshta.exe")
| table _time, Computer, ParentImage, Image, CommandLine
```

#### Cobalt Strike Named Pipes
```spl
index=sysmon EventCode=17 OR EventCode=18
| search PipeName IN ("*msagent_*", "*MSSE-*", "*postex_*", "*meterpreter*")
| table _time, Computer, Image, PipeName
```

#### Discovery Command Burst
```spl
index=sysmon EventCode=1
| search Image IN ("*whoami.exe", "*net.exe", "*nltest.exe", "*systeminfo.exe")
| bucket _time span=5m
| stats count by _time, Computer, User
| where count > 5
```

#### Brute Force Detection
```spl
index=wineventlog EventCode=4625
| stats count by TargetUserName, IpAddress, LogonType
| where count > 5
| sort -count
```

#### Service Installation (Persistence)
```spl
index=wineventlog EventCode=4697
| where NOT match(ServiceFileName, "(?i)^C:\\(Windows|Program Files)")
| table _time, Computer, ServiceName, ServiceFileName, SubjectUserName
```

#### PowerShell Script Block Analysis
```spl
index=wineventlog EventCode=4104 LogName="Microsoft-Windows-PowerShell/Operational"
| where match(ScriptBlockText, "(?i)(-enc|downloadstring|invoke-expression|frombase64)")
| table _time, Computer, ScriptBlockId, ScriptBlockText
```

---

## 10. Production Readiness Assessment

### 10.1 Overall Score

**Production Readiness: 92/100**

| Category | Score | Weight | Weighted |
|----------|-------|--------|----------|
| Detection Coverage | 97 | 25% | 24.25 |
| Schema/Syntax Validity | 95 | 15% | 14.25 |
| Performance Optimization | 90 | 20% | 18.00 |
| Deployment Readiness | 90 | 15% | 13.50 |
| Documentation Quality | 95 | 10% | 9.50 |
| Compliance Alignment | 95 | 10% | 9.50 |
| Exclusion Safety | 70 | 5% | 3.50 |
| **TOTAL** | - | 100% | **92.50** |

### 10.2 Detailed Assessment

#### Detection Coverage (97/100)

**Strengths:**
- 13 MITRE ATT&CK techniques explicitly covered
- Credential dumping detection (procdump, comsvcs.dll, LSASS)
- LOLBins monitoring (certutil, mshta, regsvr32, etc.)
- Persistence detection (Run keys, Tasks, WMI)
- Lateral movement (PsExec, named pipes)

**Areas for Improvement:**
- DLL sideloading detection could be enhanced
- Some techniques rely on specific signatures

#### Performance Optimization (90/100)

**Strengths:**
- 60-70% event reduction on workstations
- Browser noise filtered effectively
- Background process exclusions

**Areas for Improvement:**
- Some exclusions may be overly broad
- Consider per-environment tuning

#### Exclusion Safety (70/100)

**Concerns Identified:**
- Some exclusions could be exploited
- Recommend path-specific exclusions
- Regular review of exclusion effectiveness

### 10.3 Deployment Checklist

- [ ] Review all exclusions for your environment
- [ ] Test in sandbox before production
- [ ] Configure SIEM correlation rules
- [ ] Set up alerting for critical events
- [ ] Document local customizations
- [ ] Establish review cadence (quarterly)
- [ ] Train SOC on new detection capabilities

---

## 11. Appendices

### 11.1 Windows Logon Type Codes

| Code | Type | Description |
|------|------|-------------|
| 2 | Interactive | Console logon |
| 3 | Network | SMB/IPC$ connection |
| 4 | Batch | Scheduled task |
| 5 | Service | Service startup |
| 7 | Unlock | Workstation unlock |
| 8 | NetworkCleartext | IIS basic auth |
| 9 | NewCredentials | RunAs /netonly |
| 10 | RemoteInteractive | RDP |
| 11 | CachedInteractive | Cached credentials |

### 11.2 Windows Logon Failure Status Codes

| Status | Description |
|--------|-------------|
| 0xc000006d | Bad username or password |
| 0xc0000064 | User does not exist |
| 0xc000006a | Wrong password |
| 0xc0000234 | Account locked out |
| 0xc0000072 | Account disabled |
| 0xc000006f | Logon outside allowed hours |
| 0xc0000070 | Unauthorized workstation |
| 0xc0000193 | Account expired |

### 11.3 Windows Service Type Codes

| Type | Description |
|------|-------------|
| 0x1 | Kernel Driver |
| 0x2 | File System Driver |
| 0x10 | Own Process |
| 0x20 | Share Process |
| 0x100 | Interactive |

### 11.4 Audit Subcategory GUIDs

```powershell
# Account Logon
"Credential Validation"              = "{0CCE923F-69AE-11D9-BED3-505054503030}"
"Kerberos Authentication Service"    = "{0CCE9242-69AE-11D9-BED3-505054503030}"
"Kerberos Service Ticket Operations" = "{0CCE9240-69AE-11D9-BED3-505054503030}"

# Logon/Logoff
"Logon"                              = "{0CCE9215-69AE-11D9-BED3-505054503030}"
"Logoff"                             = "{0CCE9216-69AE-11D9-BED3-505054503030}"
"Special Logon"                      = "{0CCE921B-69AE-11D9-BED3-505054503030}"

# Account Management
"User Account Management"            = "{0CCE9235-69AE-11D9-BED3-505054503030}"
"Security Group Management"          = "{0CCE9237-69AE-11D9-BED3-505054503030}"

# Policy Change
"Audit Policy Change"                = "{0CCE922F-69AE-11D9-BED3-505054503030}"

# System
"Security System Extension"          = "{0CCE9211-69AE-11D9-BED3-505054503030}"
```

### 11.5 Document References

| Document | Location | Purpose |
|----------|----------|---------|
| README.md | `/` | Project overview |
| README-{role}.md | `/sysmon/` | Role-specific guides |
| MITRE-COVERAGE-REPORT.md | `/sysmon/` | Detection rates |
| WINDOWS-EVENT-RAW-DATA-REFERENCE.md | `/sysmon/docs/` | Event examples |
| Deploy README | `/sysmon/deploy/` | Script documentation |
| Tests README | `/sysmon/tests/` | Testing guide |

---

## Changelog

### Version 2.1.0 (December 2025)

- **Multi-Language Support:** Audit policy script now uses GUIDs
- **CI/CD Enhancement:** Added multi-locale testing (IT, DE, FR, ES)
- **Documentation:** Consolidated all docs into single guide
- **Testing:** Enhanced Atomic Red Team coverage to 40 techniques

### Version 2.0.0 (December 2025)

- **Initial Release:** 6 role-specific configurations
- **Windows Events:** Added complementary security event monitoring
- **PowerShell Logging:** Script Block and Module logging enabled
- **Splunk Integration:** Sample queries and index configuration

---

**Document Classification:** Internal Use
**Last Updated:** 29 December 2025
**Next Review:** March 2026
**Author:** Security Engineering Team

---

*This document consolidates all project documentation. For detailed information on specific topics, refer to the individual documents listed in Appendix 11.5.*
