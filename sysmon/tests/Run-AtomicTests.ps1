<#
.SYNOPSIS
    Run Atomic Red Team tests against Sysmon configuration

.DESCRIPTION
    Uses Atomic Red Team to simulate MITRE ATT&CK techniques
    and validates Sysmon detection coverage.

.NOTES
    Requires: Invoke-AtomicRedTeam module
    Install: IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)

.EXAMPLE
    .\Run-AtomicTests.ps1 -ConfigType "srv"
    .\Run-AtomicTests.ps1 -ConfigType "dc" -TestOnly
#>

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("ws", "srv", "dc", "sql", "exch", "iis")]
    [string]$ConfigType,

    [Parameter(Mandatory=$false)]
    [switch]$TestOnly,

    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "C:\AtomicTests\Results"
)

# ============================================
# MITRE TECHNIQUES PER CONFIG TYPE
# ============================================

$TechniquesByConfig = @{
    # Generic Server
    "srv" = @(
        "T1059.001"  # PowerShell
        "T1059.003"  # Windows Command Shell
        "T1087.001"  # Local Account Discovery
        "T1087.002"  # Domain Account Discovery
        "T1018"      # Remote System Discovery
        "T1057"      # Process Discovery
        "T1082"      # System Information Discovery
        "T1547.001"  # Registry Run Keys
        "T1053.005"  # Scheduled Task
        "T1543.003"  # Windows Service
        "T1003.001"  # LSASS Memory
        "T1070.001"  # Clear Windows Event Logs
        "T1562.001"  # Disable or Modify Tools
        "T1218.010"  # Regsvr32
        "T1218.011"  # Rundll32
        "T1218.005"  # Mshta
    )

    # Domain Controller
    "dc" = @(
        "T1059.001"  # PowerShell
        "T1087.002"  # Domain Account Discovery
        "T1482"      # Domain Trust Discovery
        "T1069.002"  # Domain Groups
        "T1003.001"  # LSASS Memory
        "T1003.002"  # Security Account Manager
        "T1003.003"  # NTDS
        "T1003.006"  # DCSync
        "T1558.001"  # Golden Ticket
        "T1558.003"  # Kerberoasting
        "T1547.001"  # Registry Run Keys
        "T1484.001"  # Group Policy Modification
    )

    # SQL Server
    "sql" = @(
        "T1059.001"  # PowerShell
        "T1059.003"  # Windows Command Shell (xp_cmdshell)
        "T1087.001"  # Local Account Discovery
        "T1005"      # Data from Local System
        "T1003.001"  # LSASS Memory
        "T1547.001"  # Registry Run Keys
        "T1543.003"  # Windows Service
        "T1190"      # Exploit Public-Facing Application
    )

    # Exchange Server
    "exch" = @(
        "T1059.001"  # PowerShell
        "T1505.003"  # Web Shell
        "T1003.001"  # LSASS Memory
        "T1087.002"  # Domain Account Discovery
        "T1114.002"  # Remote Email Collection
        "T1070.006"  # Timestomp
        "T1547.001"  # Registry Run Keys
    )

    # IIS Web Server
    "iis" = @(
        "T1059.001"  # PowerShell
        "T1059.003"  # Windows Command Shell
        "T1505.003"  # Web Shell
        "T1190"      # Exploit Public-Facing Application
        "T1003.001"  # LSASS Memory
        "T1070.006"  # Timestomp
        "T1547.001"  # Registry Run Keys
        "T1071.001"  # Web Protocols
    )

    # Workstation
    "ws" = @(
        "T1059.001"  # PowerShell
        "T1059.003"  # Windows Command Shell
        "T1087.001"  # Local Account Discovery
        "T1057"      # Process Discovery
        "T1082"      # System Information Discovery
        "T1547.001"  # Registry Run Keys
        "T1053.005"  # Scheduled Task
        "T1003.001"  # LSASS Memory
        "T1218.010"  # Regsvr32
        "T1218.011"  # Rundll32
        "T1218.005"  # Mshta
        "T1566.001"  # Spearphishing Attachment
    )
}

# ============================================
# FUNCTIONS
# ============================================

function Test-AtomicInstalled {
    try {
        $null = Get-Command Invoke-AtomicTest -ErrorAction Stop
        return $true
    }
    catch {
        return $false
    }
}

function Install-AtomicRedTeam {
    Write-Host "[*] Installing Atomic Red Team..." -ForegroundColor Yellow

    # Install module
    IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)

    # Install atomics
    Install-AtomicRedTeam -getAtomics -Force

    Write-Host "[+] Atomic Red Team installed" -ForegroundColor Green
}

function Get-SysmonEventCount {
    param(
        [int]$EventID,
        [datetime]$StartTime
    )

    try {
        $events = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -ErrorAction SilentlyContinue |
            Where-Object { $_.TimeCreated -ge $StartTime -and $_.Id -eq $EventID }
        return $events.Count
    }
    catch {
        return 0
    }
}

function Run-TechniqueTest {
    param(
        [string]$TechniqueID
    )

    $result = [PSCustomObject]@{
        TechniqueID = $TechniqueID
        TechniqueName = ""
        TestsRun = 0
        SysmonEvents = @{}
        Success = $false
        Error = $null
    }

    try {
        # Get technique info
        $atomicTests = Get-AtomicTechnique -AtomicTechnique $TechniqueID -ErrorAction SilentlyContinue

        if (-not $atomicTests) {
            $result.Error = "No atomic tests found"
            return $result
        }

        $result.TechniqueName = $atomicTests.display_name

        # Record start time for event correlation
        $startTime = Get-Date

        # Get number of tests
        $testCount = ($atomicTests.atomic_tests | Where-Object { $_.supported_platforms -contains "windows" }).Count
        $result.TestsRun = $testCount

        if ($TestOnly) {
            Write-Host "    [DRY RUN] Would run $testCount tests" -ForegroundColor DarkYellow
            return $result
        }

        # Run tests
        Write-Host "    Running $testCount atomic tests..." -ForegroundColor Gray

        Invoke-AtomicTest -AtomicTechnique $TechniqueID -ShowDetails -ErrorAction SilentlyContinue | Out-Null

        # Wait for Sysmon to process
        Start-Sleep -Seconds 5

        # Check Sysmon events
        $eventIDs = @(1, 3, 7, 8, 10, 11, 13, 17, 18, 22, 25, 26)
        foreach ($eventID in $eventIDs) {
            $count = Get-SysmonEventCount -EventID $eventID -StartTime $startTime
            if ($count -gt 0) {
                $result.SysmonEvents[$eventID] = $count
            }
        }

        $result.Success = $result.SysmonEvents.Count -gt 0

        # Cleanup
        Invoke-AtomicTest -AtomicTechnique $TechniqueID -Cleanup -ErrorAction SilentlyContinue | Out-Null
    }
    catch {
        $result.Error = $_.Exception.Message
    }

    return $result
}

# ============================================
# MAIN
# ============================================

Write-Host @"

    _  _____  ___  __  __ ___ ___
   /_\|_   _|/ _ \|  \/  |_ _/ __|
  / _ \ | | | (_) | |\/| || | (__
 /_/ \_\|_|  \___/|_|  |_|___\___|

   Sysmon Detection Validation

"@ -ForegroundColor Red

# Check for Atomic Red Team
if (-not (Test-AtomicInstalled)) {
    Write-Host "[!] Atomic Red Team not installed" -ForegroundColor Yellow
    $install = Read-Host "Install now? (Y/N)"
    if ($install -eq 'Y') {
        Install-AtomicRedTeam
    }
    else {
        Write-Host "[!] Cannot continue without Atomic Red Team" -ForegroundColor Red
        exit 1
    }
}

# Get techniques for this config type
$techniques = $TechniquesByConfig[$ConfigType]
Write-Host "`n[*] Testing configuration: $ConfigType" -ForegroundColor Cyan
Write-Host "[*] Techniques to test: $($techniques.Count)" -ForegroundColor Cyan
Write-Host "[*] Mode: $(if($TestOnly){'DRY RUN'}else{'LIVE EXECUTION'})" -ForegroundColor $(if($TestOnly){'Yellow'}else{'Red'})

if (-not $TestOnly) {
    Write-Host "`n[!] WARNING: This will execute attack simulations!" -ForegroundColor Red
    Write-Host "[!] Only run in isolated sandbox environments!" -ForegroundColor Red
    $confirm = Read-Host "`nType 'EXECUTE' to continue"
    if ($confirm -ne 'EXECUTE') {
        Write-Host "[*] Aborted" -ForegroundColor Yellow
        exit 0
    }
}

# Run tests
$results = @()
$totalStart = Get-Date

foreach ($technique in $techniques) {
    Write-Host "`n[*] Testing $technique" -ForegroundColor White
    $result = Run-TechniqueTest -TechniqueID $technique

    if ($result.Error) {
        Write-Host "    [ERROR] $($result.Error)" -ForegroundColor Red
    }
    elseif ($result.Success) {
        Write-Host "    [DETECTED] Sysmon events: $($result.SysmonEvents.Keys -join ', ')" -ForegroundColor Green
    }
    else {
        Write-Host "    [NOT DETECTED] No Sysmon events captured" -ForegroundColor Yellow
    }

    $results += $result
}

# Summary
Write-Host "`n" + "="*60 -ForegroundColor Cyan
Write-Host "DETECTION SUMMARY FOR: $ConfigType" -ForegroundColor Cyan
Write-Host "="*60 -ForegroundColor Cyan

$detected = ($results | Where-Object { $_.Success }).Count
$notDetected = ($results | Where-Object { -not $_.Success -and -not $_.Error }).Count
$errors = ($results | Where-Object { $_.Error }).Count
$total = $results.Count

Write-Host "`nTechniques Tested: $total" -ForegroundColor White
Write-Host "Detected: $detected" -ForegroundColor Green
Write-Host "Not Detected: $notDetected" -ForegroundColor Yellow
Write-Host "Errors: $errors" -ForegroundColor Red
Write-Host "Detection Rate: $([math]::Round(($detected/($total-$errors))*100, 1))%" -ForegroundColor Cyan

# List undetected
if ($notDetected -gt 0) {
    Write-Host "`nUndetected Techniques:" -ForegroundColor Yellow
    $results | Where-Object { -not $_.Success -and -not $_.Error } | ForEach-Object {
        Write-Host "  - $($_.TechniqueID): $($_.TechniqueName)" -ForegroundColor Yellow
    }
}

# Export results
if ($OutputPath) {
    New-Item -Path $OutputPath -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    $csvPath = Join-Path $OutputPath "AtomicTest_${ConfigType}_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"

    $results | Select-Object TechniqueID, TechniqueName, TestsRun, Success, Error,
        @{N='SysmonEvents';E={$_.SysmonEvents.Keys -join ','}} |
        Export-Csv -Path $csvPath -NoTypeInformation

    Write-Host "`nResults exported to: $csvPath" -ForegroundColor Cyan
}

Write-Host "`nTotal execution time: $([math]::Round(((Get-Date) - $totalStart).TotalMinutes, 2)) minutes" -ForegroundColor Gray
