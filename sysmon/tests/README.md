# Sysmon Detection Testing

Test framework for validating MITRE ATT&CK detection coverage of Sysmon configurations.

## Overview

This directory contains two complementary testing approaches:

| Script | Purpose | Requirements |
|--------|---------|--------------|
| `Test-SysmonDetection.ps1` | Quick validation with simulated attacks | PowerShell, Sysmon installed |
| `Run-AtomicTests.ps1` | Comprehensive testing with Atomic Red Team | PowerShell, Sysmon, Atomic Red Team |

## Quick Start

### 1. Test-SysmonDetection.ps1 (Recommended First)

Lightweight testing script that simulates common attack techniques and verifies Sysmon event generation.

```powershell
# Run all tests for a specific config type
.\Test-SysmonDetection.ps1 -ConfigType "srv"

# Available config types: ws, srv, dc, sql, exch, iis

# Dry run (show what would be tested)
.\Test-SysmonDetection.ps1 -ConfigType "dc" -DryRun
```

**Tests Included:**
- Process Creation (cmd.exe, powershell.exe, discovery commands)
- File Creation (executables, scripts, webshells)
- Registry Modifications (Run keys, services)
- Network Connections (suspicious ports)
- Credential Access (LSASS simulation)
- Remote Thread Injection

### 2. Run-AtomicTests.ps1 (Comprehensive)

Uses [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) to run actual MITRE ATT&CK techniques.

```powershell
# First time: Install Atomic Red Team
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics -Force

# Run tests for a config type
.\Run-AtomicTests.ps1 -ConfigType "iis"

# Dry run (show techniques without execution)
.\Run-AtomicTests.ps1 -ConfigType "dc" -TestOnly
```

## Sandbox Environment

### Option 1: Windows Sandbox (Recommended)

Windows Sandbox provides an isolated, disposable environment.

```powershell
# Enable Windows Sandbox (requires Windows 10/11 Pro/Enterprise)
Enable-WindowsOptionalFeature -FeatureName "Containers-DisposableClientVM" -Online

# Create sandbox config
@"
<Configuration>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>C:\Path\To\sysmon-repo</HostFolder>
      <SandboxFolder>C:\sysmon</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>powershell -ExecutionPolicy Bypass -Command "C:\sysmon\setup-sandbox.ps1"</Command>
  </LogonCommand>
</Configuration>
"@ | Out-File -FilePath "SysmonTest.wsb"

# Launch sandbox
Start-Process "SysmonTest.wsb"
```

### Option 2: Hyper-V VM

```powershell
# Create a Windows Server VM
New-VM -Name "SysmonTest" -MemoryStartupBytes 4GB -Generation 2
# Install Windows Server, then:
# 1. Install Sysmon with your config
# 2. Copy test scripts
# 3. Run tests
```

### Option 3: Docker (Linux Container with Wine)

For basic testing on non-Windows systems (limited):

```yaml
# docker-compose.yml in tests/sandbox/
version: '3.8'
services:
  sysmon-test:
    build: .
    volumes:
      - ../..:/sysmon:ro
    environment:
      - CONFIG_TYPE=srv
```

## Config-Specific Techniques

### Generic Server (srv)
| Technique ID | Name | Detection |
|-------------|------|-----------|
| T1059.001 | PowerShell | ProcessCreate |
| T1059.003 | Windows Command Shell | ProcessCreate |
| T1087.001/002 | Account Discovery | ProcessCreate |
| T1018 | Remote System Discovery | ProcessCreate |
| T1547.001 | Registry Run Keys | RegistryEvent |
| T1053.005 | Scheduled Task | ProcessCreate |
| T1003.001 | LSASS Memory | ProcessAccess |
| T1070.001 | Clear Event Logs | ProcessCreate |

### Domain Controller (dc)
| Technique ID | Name | Detection |
|-------------|------|-----------|
| T1003.006 | DCSync | NetworkConnect + ProcessCreate |
| T1558.001 | Golden Ticket | ProcessCreate + FileCreate |
| T1558.003 | Kerberoasting | ProcessCreate |
| T1484.001 | Group Policy Modification | FileCreate + RegistryEvent |
| T1003.003 | NTDS | ProcessCreate + FileCreate |

### SQL Server (sql)
| Technique ID | Name | Detection |
|-------------|------|-----------|
| T1059.003 | xp_cmdshell | ProcessCreate (sqlservr.exe parent) |
| T1005 | Data from Local System | FileCreate (.bak, .mdf) |
| T1190 | Exploit Public-Facing | ProcessCreate + NetworkConnect |

### Exchange Server (exch)
| Technique ID | Name | Detection |
|-------------|------|-----------|
| T1505.003 | Web Shell | FileCreate + ProcessCreate |
| T1114.002 | Remote Email Collection | ProcessAccess + FileCreate |
| T1070.006 | Timestomp | FileCreateTime |

### IIS Web Server (iis)
| Technique ID | Name | Detection |
|-------------|------|-----------|
| T1505.003 | Web Shell | ProcessCreate (w3wp.exe parent) |
| T1190 | RCE via Web App | ProcessCreate |
| T1071.001 | Web Protocols C2 | NetworkConnect |

## Interpreting Results

### Detection Rate

```
Techniques Tested: 16
Detected: 14
Not Detected: 2
Errors: 0
Detection Rate: 87.5%
```

**Target:** >85% detection rate for role-specific techniques.

### Sysmon Event IDs in Results

| Event ID | Meaning |
|----------|---------|
| 1 | Process created - technique executed |
| 3 | Network connection - C2/exfiltration |
| 7 | DLL loaded - code injection |
| 8 | Remote thread - injection |
| 10 | Process access - credential theft |
| 11 | File created - payload/webshell |
| 13 | Registry - persistence |
| 22 | DNS query - C2 resolution |

### Undetected Techniques

If a technique is not detected:

1. **Check Sysmon config** - Is the Event ID enabled?
2. **Check exclusions** - Is the technique being filtered?
3. **Add specific rule** - Create include rule for the technique
4. **Accept risk** - Document if detection causes too much noise

## Troubleshooting

### Sysmon Not Generating Events

```powershell
# Check Sysmon service
Get-Service Sysmon*

# Check current config
sysmon.exe -c

# Reload config
sysmon.exe -c .\sysmon-srv.xml

# Check event log
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10
```

### Atomic Red Team Issues

```powershell
# Check module installed
Get-Module -ListAvailable Invoke-AtomicRedTeam

# Reinstall atomics
Install-AtomicRedTeam -getAtomics -Force

# Check technique exists
Get-AtomicTechnique -AtomicTechnique T1059.001
```

### High Event Volume During Testing

Expected behavior - testing generates many events. After testing:

```powershell
# Clear Sysmon log
wevtutil cl "Microsoft-Windows-Sysmon/Operational"
```

## CI/CD Integration

For automated testing in CI pipelines:

```yaml
# Example GitHub Actions (requires self-hosted Windows runner)
- name: Test Sysmon Config
  shell: powershell
  run: |
    sysmon.exe -accepteula -i sysmon-srv.xml
    .\tests\Test-SysmonDetection.ps1 -ConfigType srv -DryRun
```

## Security Warning

These scripts execute attack simulations. Only run in:
- Isolated sandbox environments
- Test VMs with no production access
- Windows Sandbox instances

Never run on production systems.

---
**Version:** 1.0
**Last Updated:** December 2025
