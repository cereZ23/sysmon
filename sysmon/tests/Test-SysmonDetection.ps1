<#
.SYNOPSIS
    MITRE ATT&CK Detection Test Suite for Sysmon Configurations

.DESCRIPTION
    Simulates attack techniques to verify Sysmon detection coverage.
    Run in isolated sandbox environment only!

.NOTES
    Version: 1.0
    Author: Security Team
    WARNING: Run only in isolated test environments!
#>

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("All", "ProcessCreate", "FileCreate", "Registry", "Network", "Credential", "Injection")]
    [string]$TestCategory = "All",

    [Parameter(Mandatory=$false)]
    [switch]$DryRun,

    [Parameter(Mandatory=$false)]
    [string]$LogPath = "C:\SysmonTests\Results"
)

# ============================================
# CONFIGURATION
# ============================================
$Script:TestResults = @()
$Script:SysmonLogName = "Microsoft-Windows-Sysmon/Operational"

function Write-TestHeader {
    param([string]$TestName, [string]$MitreID)
    Write-Host "`n[TEST] $TestName" -ForegroundColor Cyan
    Write-Host "       MITRE: $MitreID" -ForegroundColor DarkGray
}

function Write-TestResult {
    param([string]$TestName, [string]$MitreID, [bool]$Detected, [int]$EventCount)
    $status = if ($Detected) { "[PASS]" } else { "[FAIL]" }
    $color = if ($Detected) { "Green" } else { "Red" }
    Write-Host "$status $TestName - Events: $EventCount" -ForegroundColor $color

    $Script:TestResults += [PSCustomObject]@{
        TestName = $TestName
        MitreID = $MitreID
        Detected = $Detected
        EventCount = $EventCount
        Timestamp = Get-Date
    }
}

function Get-SysmonEvents {
    param(
        [int]$EventID,
        [int]$SecondsBack = 30,
        [string]$FilterXPath = "*"
    )

    try {
        $startTime = (Get-Date).AddSeconds(-$SecondsBack)
        $events = Get-WinEvent -LogName $SysmonLogName -FilterXPath $FilterXPath -ErrorAction SilentlyContinue |
            Where-Object { $_.TimeCreated -ge $startTime -and $_.Id -eq $EventID }
        return $events
    }
    catch {
        return @()
    }
}

# ============================================
# EVENT ID 1: PROCESS CREATE TESTS
# ============================================
function Test-ProcessCreate {
    Write-Host "`n" + "="*60 -ForegroundColor Yellow
    Write-Host "EVENT ID 1: PROCESS CREATE TESTS" -ForegroundColor Yellow
    Write-Host "="*60 -ForegroundColor Yellow

    # T1059.001 - PowerShell with encoded command
    Write-TestHeader "PowerShell Encoded Command" "T1059.001"
    if (-not $DryRun) {
        $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("whoami"))
        Start-Process powershell.exe -ArgumentList "-enc $encoded" -WindowStyle Hidden -Wait
        Start-Sleep -Seconds 2
        $events = Get-SysmonEvents -EventID 1 -SecondsBack 10
        $detected = ($events | Where-Object { $_.Message -match "-enc" }).Count -gt 0
        Write-TestResult "PowerShell Encoded Command" "T1059.001" $detected $events.Count
    }

    # T1059.001 - PowerShell Download Cradle
    Write-TestHeader "PowerShell IEX Pattern" "T1059.001"
    if (-not $DryRun) {
        # Safe simulation - doesn't actually download
        Start-Process powershell.exe -ArgumentList "-c `"Write-Host 'IEX test'`"" -WindowStyle Hidden -Wait
        Start-Sleep -Seconds 2
        $events = Get-SysmonEvents -EventID 1 -SecondsBack 10
        Write-TestResult "PowerShell IEX Pattern" "T1059.001" ($events.Count -gt 0) $events.Count
    }

    # T1087 - Account Discovery
    Write-TestHeader "Account Discovery (whoami)" "T1087"
    if (-not $DryRun) {
        Start-Process whoami.exe -WindowStyle Hidden -Wait
        Start-Sleep -Seconds 2
        $events = Get-SysmonEvents -EventID 1 -SecondsBack 10
        $detected = ($events | Where-Object { $_.Message -match "whoami" }).Count -gt 0
        Write-TestResult "Account Discovery (whoami)" "T1087" $detected $events.Count
    }

    # T1087 - Network Discovery
    Write-TestHeader "Network Discovery (net user)" "T1087"
    if (-not $DryRun) {
        Start-Process net.exe -ArgumentList "user" -WindowStyle Hidden -Wait
        Start-Sleep -Seconds 2
        $events = Get-SysmonEvents -EventID 1 -SecondsBack 10
        $detected = ($events | Where-Object { $_.Message -match "net" }).Count -gt 0
        Write-TestResult "Network Discovery (net user)" "T1087" $detected $events.Count
    }

    # T1218.010 - Regsvr32
    Write-TestHeader "Regsvr32 Execution" "T1218.010"
    if (-not $DryRun) {
        Start-Process regsvr32.exe -ArgumentList "/s /n /u /i:test scrobj.dll" -WindowStyle Hidden -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        $events = Get-SysmonEvents -EventID 1 -SecondsBack 10
        $detected = ($events | Where-Object { $_.Message -match "regsvr32" }).Count -gt 0
        Write-TestResult "Regsvr32 Execution" "T1218.010" $detected $events.Count
    }

    # T1218.005 - Mshta
    Write-TestHeader "Mshta Execution" "T1218.005"
    if (-not $DryRun) {
        Start-Process mshta.exe -ArgumentList "about:blank" -WindowStyle Hidden -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
        Stop-Process -Name mshta -ErrorAction SilentlyContinue
        $events = Get-SysmonEvents -EventID 1 -SecondsBack 10
        $detected = ($events | Where-Object { $_.Message -match "mshta" }).Count -gt 0
        Write-TestResult "Mshta Execution" "T1218.005" $detected $events.Count
    }

    # T1218.011 - Rundll32
    Write-TestHeader "Rundll32 Execution" "T1218.011"
    if (-not $DryRun) {
        Start-Process rundll32.exe -ArgumentList "shell32.dll,Control_RunDLL" -WindowStyle Hidden -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        $events = Get-SysmonEvents -EventID 1 -SecondsBack 10
        $detected = ($events | Where-Object { $_.Message -match "rundll32" }).Count -gt 0
        Write-TestResult "Rundll32 Execution" "T1218.011" $detected $events.Count
    }

    # T1105 - Certutil Download
    Write-TestHeader "Certutil (potential download)" "T1105"
    if (-not $DryRun) {
        Start-Process certutil.exe -ArgumentList "-?" -WindowStyle Hidden -Wait
        Start-Sleep -Seconds 2
        $events = Get-SysmonEvents -EventID 1 -SecondsBack 10
        $detected = ($events | Where-Object { $_.Message -match "certutil" }).Count -gt 0
        Write-TestResult "Certutil Execution" "T1105" $detected $events.Count
    }

    # T1053.005 - Scheduled Task
    Write-TestHeader "Scheduled Task Creation" "T1053.005"
    if (-not $DryRun) {
        Start-Process schtasks.exe -ArgumentList "/query" -WindowStyle Hidden -Wait
        Start-Sleep -Seconds 2
        $events = Get-SysmonEvents -EventID 1 -SecondsBack 10
        $detected = ($events | Where-Object { $_.Message -match "schtasks" }).Count -gt 0
        Write-TestResult "Scheduled Task Query" "T1053.005" $detected $events.Count
    }
}

# ============================================
# EVENT ID 11: FILE CREATE TESTS
# ============================================
function Test-FileCreate {
    Write-Host "`n" + "="*60 -ForegroundColor Yellow
    Write-Host "EVENT ID 11: FILE CREATE TESTS" -ForegroundColor Yellow
    Write-Host "="*60 -ForegroundColor Yellow

    $testPath = "C:\Windows\Temp\SysmonTest"
    New-Item -Path $testPath -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null

    # T1059.001 - Script in Temp
    Write-TestHeader "Script in Temp Directory" "T1059.001"
    if (-not $DryRun) {
        $scriptPath = "$testPath\test_script.ps1"
        "Write-Host 'Test'" | Out-File -FilePath $scriptPath -Force
        Start-Sleep -Seconds 2
        $events = Get-SysmonEvents -EventID 11 -SecondsBack 10
        $detected = ($events | Where-Object { $_.Message -match "\.ps1" }).Count -gt 0
        Write-TestResult "Script in Temp" "T1059.001" $detected $events.Count
        Remove-Item $scriptPath -Force -ErrorAction SilentlyContinue
    }

    # T1547.001 - Startup Persistence
    Write-TestHeader "Startup Folder Detection" "T1547.001"
    if (-not $DryRun) {
        $startupPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\test_startup.bat"
        "@echo test" | Out-File -FilePath $startupPath -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        $events = Get-SysmonEvents -EventID 11 -SecondsBack 10
        $detected = ($events | Where-Object { $_.Message -match "Startup" }).Count -gt 0
        Write-TestResult "Startup Folder File" "T1547.001" $detected $events.Count
        Remove-Item $startupPath -Force -ErrorAction SilentlyContinue
    }

    # T1505.003 - Webshell (IIS context)
    Write-TestHeader "ASPX File Creation" "T1505.003"
    if (-not $DryRun) {
        $webPath = "C:\inetpub\wwwroot"
        if (Test-Path $webPath) {
            $aspxPath = "$webPath\test_shell.aspx"
            "<%@ Page Language='C#' %>" | Out-File -FilePath $aspxPath -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
            $events = Get-SysmonEvents -EventID 11 -SecondsBack 10
            $detected = ($events | Where-Object { $_.Message -match "\.aspx" }).Count -gt 0
            Write-TestResult "ASPX Webshell" "T1505.003" $detected $events.Count
            Remove-Item $aspxPath -Force -ErrorAction SilentlyContinue
        } else {
            Write-Host "       [SKIP] IIS not installed" -ForegroundColor DarkYellow
        }
    }

    # Cleanup
    Remove-Item $testPath -Recurse -Force -ErrorAction SilentlyContinue
}

# ============================================
# EVENT ID 13: REGISTRY TESTS
# ============================================
function Test-Registry {
    Write-Host "`n" + "="*60 -ForegroundColor Yellow
    Write-Host "EVENT ID 13: REGISTRY TESTS" -ForegroundColor Yellow
    Write-Host "="*60 -ForegroundColor Yellow

    # T1547.001 - Run Key Persistence
    Write-TestHeader "Run Key Modification" "T1547.001"
    if (-not $DryRun) {
        $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
        $valueName = "SysmonTest_$(Get-Random)"
        Set-ItemProperty -Path $regPath -Name $valueName -Value "C:\test.exe" -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        $events = Get-SysmonEvents -EventID 13 -SecondsBack 10
        $detected = ($events | Where-Object { $_.Message -match "CurrentVersion\\Run" }).Count -gt 0
        Write-TestResult "Run Key Persistence" "T1547.001" $detected $events.Count
        Remove-ItemProperty -Path $regPath -Name $valueName -ErrorAction SilentlyContinue
    }

    # T1562.001 - Defender Tampering
    Write-TestHeader "Defender Exclusion (Read)" "T1562.001"
    if (-not $DryRun) {
        # Only read, don't modify
        Get-ItemProperty "HKLM:\Software\Microsoft\Windows Defender\Exclusions\Paths" -ErrorAction SilentlyContinue | Out-Null
        Start-Sleep -Seconds 2
        Write-Host "       [INFO] Read-only test - check for registry access logging" -ForegroundColor DarkYellow
    }

    # T1546.012 - IFEO Debugging
    Write-TestHeader "IFEO Debugger Key" "T1546.012"
    if (-not $DryRun) {
        $ifeoPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe"
        if (-not (Test-Path $ifeoPath)) {
            New-Item -Path $ifeoPath -Force -ErrorAction SilentlyContinue | Out-Null
        }
        # Create and immediately remove
        Set-ItemProperty -Path $ifeoPath -Name "Debugger" -Value "cmd.exe" -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        $events = Get-SysmonEvents -EventID 13 -SecondsBack 10
        $detected = ($events | Where-Object { $_.Message -match "Image File Execution" }).Count -gt 0
        Write-TestResult "IFEO Debugger" "T1546.012" $detected $events.Count
        Remove-ItemProperty -Path $ifeoPath -Name "Debugger" -ErrorAction SilentlyContinue
    }
}

# ============================================
# EVENT ID 3: NETWORK TESTS
# ============================================
function Test-Network {
    Write-Host "`n" + "="*60 -ForegroundColor Yellow
    Write-Host "EVENT ID 3: NETWORK TESTS" -ForegroundColor Yellow
    Write-Host "="*60 -ForegroundColor Yellow

    # T1071 - PowerShell Network Connection
    Write-TestHeader "PowerShell Network Connection" "T1071"
    if (-not $DryRun) {
        # Safe test to localhost
        Start-Process powershell.exe -ArgumentList "-c `"Test-NetConnection -ComputerName localhost -Port 445`"" -WindowStyle Hidden -Wait
        Start-Sleep -Seconds 3
        $events = Get-SysmonEvents -EventID 3 -SecondsBack 10
        $detected = ($events | Where-Object { $_.Message -match "powershell" }).Count -gt 0
        Write-TestResult "PowerShell Network" "T1071" $detected $events.Count
    }

    # T1105 - Certutil Network
    Write-TestHeader "Certutil Network Activity" "T1105"
    if (-not $DryRun) {
        Start-Process certutil.exe -ArgumentList "-urlcache -split -f http://localhost/test" -WindowStyle Hidden -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
        $events = Get-SysmonEvents -EventID 3 -SecondsBack 10
        $detected = ($events | Where-Object { $_.Message -match "certutil" }).Count -gt 0
        Write-TestResult "Certutil Network" "T1105" $detected $events.Count
    }
}

# ============================================
# EVENT ID 10: PROCESS ACCESS (CREDENTIAL)
# ============================================
function Test-Credential {
    Write-Host "`n" + "="*60 -ForegroundColor Yellow
    Write-Host "EVENT ID 10: CREDENTIAL ACCESS TESTS" -ForegroundColor Yellow
    Write-Host "="*60 -ForegroundColor Yellow

    # T1003.001 - LSASS Access Detection
    Write-TestHeader "LSASS Process Access" "T1003.001"
    if (-not $DryRun) {
        # This is a detection test - we're checking if Sysmon logs any LSASS access
        # Not actually dumping credentials
        $lsass = Get-Process lsass -ErrorAction SilentlyContinue
        if ($lsass) {
            # Just getting process info triggers some access
            $lsass.Handle | Out-Null
        }
        Start-Sleep -Seconds 2
        $events = Get-SysmonEvents -EventID 10 -SecondsBack 10
        $detected = ($events | Where-Object { $_.Message -match "lsass" }).Count -gt 0
        Write-TestResult "LSASS Access Monitoring" "T1003.001" $detected $events.Count
    }
}

# ============================================
# EVENT ID 8: INJECTION TESTS
# ============================================
function Test-Injection {
    Write-Host "`n" + "="*60 -ForegroundColor Yellow
    Write-Host "EVENT ID 8: INJECTION TESTS" -ForegroundColor Yellow
    Write-Host "="*60 -ForegroundColor Yellow

    Write-TestHeader "CreateRemoteThread Detection" "T1055"
    Write-Host "       [INFO] Injection tests require specialized tools" -ForegroundColor DarkYellow
    Write-Host "       [INFO] Use Atomic Red Team for comprehensive testing" -ForegroundColor DarkYellow

    # Check if any Event 8 logged recently
    if (-not $DryRun) {
        $events = Get-SysmonEvents -EventID 8 -SecondsBack 60
        Write-Host "       Event 8 count (last 60s): $($events.Count)" -ForegroundColor DarkGray
    }
}

# ============================================
# ADDITIONAL EVENT TESTS
# ============================================
function Test-AdditionalEvents {
    Write-Host "`n" + "="*60 -ForegroundColor Yellow
    Write-Host "ADDITIONAL EVENT TESTS" -ForegroundColor Yellow
    Write-Host "="*60 -ForegroundColor Yellow

    # Event 6 - Driver Load
    Write-TestHeader "Driver Load Monitoring (Event 6)" "T1014"
    if (-not $DryRun) {
        $events = Get-SysmonEvents -EventID 6 -SecondsBack 300
        Write-Host "       Event 6 count (last 5min): $($events.Count)" -ForegroundColor DarkGray
    }

    # Event 22 - DNS Query
    Write-TestHeader "DNS Query Monitoring (Event 22)" "T1071.004"
    if (-not $DryRun) {
        Resolve-DnsName "test.local" -ErrorAction SilentlyContinue | Out-Null
        Start-Sleep -Seconds 2
        $events = Get-SysmonEvents -EventID 22 -SecondsBack 10
        Write-Host "       Event 22 count (last 10s): $($events.Count)" -ForegroundColor DarkGray
    }

    # Event 17/18 - Named Pipes
    Write-TestHeader "Named Pipe Monitoring (Event 17/18)" "T1570"
    if (-not $DryRun) {
        $events17 = Get-SysmonEvents -EventID 17 -SecondsBack 60
        $events18 = Get-SysmonEvents -EventID 18 -SecondsBack 60
        Write-Host "       Event 17 count: $($events17.Count), Event 18 count: $($events18.Count)" -ForegroundColor DarkGray
    }

    # Event 25 - Process Tampering
    Write-TestHeader "Process Tampering Detection (Event 25)" "T1055.012"
    if (-not $DryRun) {
        $events = Get-SysmonEvents -EventID 25 -SecondsBack 300
        Write-Host "       Event 25 count (last 5min): $($events.Count)" -ForegroundColor DarkGray
    }

    # Event 26 - File Delete
    Write-TestHeader "File Delete Monitoring (Event 26)" "T1070.004"
    if (-not $DryRun) {
        $testFile = "C:\Windows\Temp\sysmon_delete_test.txt"
        "test" | Out-File $testFile -Force
        Remove-Item $testFile -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        $events = Get-SysmonEvents -EventID 26 -SecondsBack 10
        $detected = $events.Count -gt 0
        Write-TestResult "File Delete Detection" "T1070.004" $detected $events.Count
    }
}

# ============================================
# MAIN EXECUTION
# ============================================
function Show-Banner {
    Write-Host @"

 _____ _   _ _____ __  __  ___  _   _
/  ___| \ | /  ___|  \/  |/ _ \| \ | |
\ `--.|  \| \ `--. | .  . / /_\ \  \| |
 `--. \ . ` |`--. \| |\/| |  _  | . ` |
/\__/ / |\  /\__/ /| |  | | | | | |\  |
\____/\_| \_\____/ \_|  |_\_| |_\_| \_/

    MITRE ATT&CK Detection Test Suite

"@ -ForegroundColor Cyan
}

function Show-Summary {
    Write-Host "`n" + "="*60 -ForegroundColor Green
    Write-Host "TEST SUMMARY" -ForegroundColor Green
    Write-Host "="*60 -ForegroundColor Green

    $passed = ($Script:TestResults | Where-Object { $_.Detected }).Count
    $failed = ($Script:TestResults | Where-Object { -not $_.Detected }).Count
    $total = $Script:TestResults.Count

    Write-Host "`nTotal Tests: $total" -ForegroundColor White
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Detection Rate: $([math]::Round(($passed/$total)*100, 1))%" -ForegroundColor Yellow

    if ($failed -gt 0) {
        Write-Host "`nFailed Detections:" -ForegroundColor Red
        $Script:TestResults | Where-Object { -not $_.Detected } | ForEach-Object {
            Write-Host "  - $($_.TestName) [$($_.MitreID)]" -ForegroundColor Red
        }
    }

    # Export results
    if ($LogPath) {
        New-Item -Path $LogPath -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
        $resultFile = Join-Path $LogPath "SysmonTest_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $Script:TestResults | Export-Csv -Path $resultFile -NoTypeInformation
        Write-Host "`nResults exported to: $resultFile" -ForegroundColor Cyan
    }
}

# Main
Show-Banner

# Check if running as admin
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[WARNING] Some tests require Administrator privileges" -ForegroundColor Yellow
}

# Check if Sysmon is running
$sysmonService = Get-Service Sysmon* -ErrorAction SilentlyContinue
if (-not $sysmonService -or $sysmonService.Status -ne 'Running') {
    Write-Host "[ERROR] Sysmon service not running!" -ForegroundColor Red
    exit 1
}

Write-Host "Sysmon Service: $($sysmonService.Name) - $($sysmonService.Status)" -ForegroundColor Green
Write-Host "Test Mode: $(if($DryRun){'DRY RUN'}else{'LIVE'})" -ForegroundColor $(if($DryRun){'Yellow'}else{'Green'})

# Run tests based on category
switch ($TestCategory) {
    "ProcessCreate" { Test-ProcessCreate }
    "FileCreate" { Test-FileCreate }
    "Registry" { Test-Registry }
    "Network" { Test-Network }
    "Credential" { Test-Credential }
    "Injection" { Test-Injection }
    "All" {
        Test-ProcessCreate
        Test-FileCreate
        Test-Registry
        Test-Network
        Test-Credential
        Test-Injection
        Test-AdditionalEvents
    }
}

Show-Summary
