<#
.SYNOPSIS
    Setup script for Sysmon testing sandbox

.DESCRIPTION
    Automatically configures a Windows Sandbox or VM for Sysmon detection testing.
    - Downloads and installs Sysmon
    - Applies the specified configuration
    - Optionally installs Atomic Red Team

.PARAMETER ConfigType
    Sysmon configuration to apply: ws, srv, dc, sql, exch, iis

.PARAMETER InstallAtomic
    Install Atomic Red Team for comprehensive testing

.EXAMPLE
    .\setup-sandbox.ps1 -ConfigType "srv"
    .\setup-sandbox.ps1 -ConfigType "iis" -InstallAtomic
#>

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("ws", "srv", "dc", "sql", "exch", "iis")]
    [string]$ConfigType = "srv",

    [Parameter(Mandatory=$false)]
    [switch]$InstallAtomic
)

$ErrorActionPreference = "Stop"

Write-Host @"

  _____ _   _ ___ __  __  ___  _  _
 / ____\ \ / / __|  \/  |/ _ \| \| |
 \____ \\   /\__ \ |\/| | | | |  \ |
 |____) || | |___/_|  |_|_|_|_|_|\_|
       |_|
       Detection Testing Sandbox

"@ -ForegroundColor Cyan

# ============================================
# PATHS
# ============================================

$SysmonDir = "C:\sysmon"
$SysmonExe = "$SysmonDir\Sysmon64.exe"
$ConfigFile = "$SysmonDir\sysmon-$ConfigType.xml"
$SysmonDownload = "https://download.sysinternals.com/files/Sysmon.zip"
$TempDir = "$env:TEMP\sysmon-setup"

# ============================================
# FUNCTIONS
# ============================================

function Install-Sysmon {
    Write-Host "[*] Installing Sysmon..." -ForegroundColor Yellow

    # Create temp directory
    New-Item -Path $TempDir -ItemType Directory -Force | Out-Null

    # Download Sysmon
    Write-Host "    Downloading from Sysinternals..." -ForegroundColor Gray
    $zipPath = "$TempDir\Sysmon.zip"
    Invoke-WebRequest -Uri $SysmonDownload -OutFile $zipPath -UseBasicParsing

    # Extract
    Write-Host "    Extracting..." -ForegroundColor Gray
    Expand-Archive -Path $zipPath -DestinationPath $TempDir -Force

    # Copy to install location
    if (-not (Test-Path $SysmonDir)) {
        New-Item -Path $SysmonDir -ItemType Directory -Force | Out-Null
    }

    Copy-Item "$TempDir\Sysmon64.exe" -Destination $SysmonExe -Force
    Copy-Item "$TempDir\Sysmon.exe" -Destination "$SysmonDir\Sysmon.exe" -Force

    # Cleanup
    Remove-Item -Path $TempDir -Recurse -Force

    Write-Host "[+] Sysmon downloaded to $SysmonDir" -ForegroundColor Green
}

function Install-SysmonConfig {
    Write-Host "[*] Installing Sysmon with config: $ConfigType" -ForegroundColor Yellow

    # Check config exists
    if (-not (Test-Path $ConfigFile)) {
        Write-Host "[!] Config file not found: $ConfigFile" -ForegroundColor Red
        Write-Host "    Available configs:" -ForegroundColor Yellow
        Get-ChildItem "$SysmonDir\sysmon-*.xml" | ForEach-Object { Write-Host "    - $($_.Name)" }
        exit 1
    }

    # Check if Sysmon already installed
    $sysmonService = Get-Service -Name Sysmon* -ErrorAction SilentlyContinue

    if ($sysmonService) {
        Write-Host "    Updating existing Sysmon installation..." -ForegroundColor Gray
        & $SysmonExe -c $ConfigFile
    }
    else {
        Write-Host "    Fresh installation..." -ForegroundColor Gray
        & $SysmonExe -accepteula -i $ConfigFile
    }

    # Verify
    Start-Sleep -Seconds 2
    $sysmonService = Get-Service -Name Sysmon* -ErrorAction SilentlyContinue

    if ($sysmonService -and $sysmonService.Status -eq "Running") {
        Write-Host "[+] Sysmon installed and running" -ForegroundColor Green
    }
    else {
        Write-Host "[!] Sysmon installation may have failed" -ForegroundColor Red
        exit 1
    }
}

function Install-AtomicRedTeam {
    Write-Host "[*] Installing Atomic Red Team..." -ForegroundColor Yellow

    # Check if already installed
    $atomicModule = Get-Module -ListAvailable Invoke-AtomicRedTeam -ErrorAction SilentlyContinue

    if ($atomicModule) {
        Write-Host "[+] Atomic Red Team already installed" -ForegroundColor Green
        return
    }

    # Install
    Write-Host "    Downloading installer..." -ForegroundColor Gray
    IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)

    Write-Host "    Installing atomics (this may take a while)..." -ForegroundColor Gray
    Install-AtomicRedTeam -getAtomics -Force

    Write-Host "[+] Atomic Red Team installed" -ForegroundColor Green
}

function Test-SysmonEvents {
    Write-Host "[*] Verifying Sysmon event generation..." -ForegroundColor Yellow

    # Generate a test event
    $testPath = "$env:TEMP\sysmon-test-$(Get-Random).txt"
    "test" | Out-File $testPath
    Remove-Item $testPath -Force

    Start-Sleep -Seconds 2

    # Check for events
    try {
        $events = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10 -ErrorAction SilentlyContinue
        if ($events) {
            Write-Host "[+] Sysmon is generating events ($($events.Count) recent events)" -ForegroundColor Green
        }
        else {
            Write-Host "[!] No Sysmon events found - config may be too restrictive" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "[!] Cannot read Sysmon event log" -ForegroundColor Red
    }
}

function Show-TestInstructions {
    Write-Host @"

============================================
SANDBOX READY FOR TESTING
============================================

Configuration: $ConfigType
Sysmon Status: Running

Quick Test Commands:
--------------------

1. Basic Detection Test:
   cd C:\sysmon\tests
   .\Test-SysmonDetection.ps1 -ConfigType $ConfigType

2. View Recent Sysmon Events:
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 20 |
       Select-Object TimeCreated, Id, Message | Format-Table -AutoSize

3. Check Detection Rate:
   .\Test-SysmonDetection.ps1 -ConfigType $ConfigType | Select-Object -Last 10

"@ -ForegroundColor Cyan

    if ($InstallAtomic) {
        Write-Host @"
4. Run Atomic Red Team Tests:
   .\Run-AtomicTests.ps1 -ConfigType $ConfigType -TestOnly  # Dry run
   .\Run-AtomicTests.ps1 -ConfigType $ConfigType            # Live execution

"@ -ForegroundColor Cyan
    }

    Write-Host @"
IMPORTANT: This is a sandbox environment for testing only.
Do NOT run attack simulations on production systems.

============================================
"@ -ForegroundColor Yellow
}

# ============================================
# MAIN
# ============================================

Write-Host "[*] Setting up Sysmon testing sandbox" -ForegroundColor Cyan
Write-Host "[*] Configuration type: $ConfigType" -ForegroundColor Cyan

# Check for admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[!] This script requires Administrator privileges" -ForegroundColor Red
    Write-Host "[!] Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Red
    exit 1
}

# Check if Sysmon binary exists
if (-not (Test-Path $SysmonExe)) {
    Install-Sysmon
}

# Install/Update config
Install-SysmonConfig

# Optional: Install Atomic Red Team
if ($InstallAtomic) {
    Install-AtomicRedTeam
}

# Verify events
Test-SysmonEvents

# Show instructions
Show-TestInstructions

Write-Host "[+] Setup complete!" -ForegroundColor Green
