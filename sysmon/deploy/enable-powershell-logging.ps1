<#
.SYNOPSIS
    Enables comprehensive PowerShell logging for security monitoring.

.DESCRIPTION
    Configures PowerShell logging settings including:
    - Module Logging: Logs pipeline execution details
    - Script Block Logging: Logs scripts/commands before execution
    - Transcription: Creates text transcripts of all sessions

    These logs are CRITICAL for detecting:
    - Encoded PowerShell attacks (T1059.001)
    - Fileless malware
    - Obfuscated commands
    - Living-off-the-land attacks

.PARAMETER TranscriptPath
    Path for PowerShell transcription logs.
    Default: C:\PSLogs\Transcripts

.PARAMETER EnableTranscription
    Enable PowerShell transcription. Creates text files of all sessions.
    Default: $true

.PARAMETER ModulesToLog
    Array of module names to log. Use "*" for all modules.
    Default: @("*")

.EXAMPLE
    .\enable-powershell-logging.ps1

.EXAMPLE
    .\enable-powershell-logging.ps1 -TranscriptPath "D:\PSLogs" -Verbose

.NOTES
    Author: Security Engineering Team
    Version: 2.0.0
    Last Updated: 2024-12-17

    SECURITY CONSIDERATIONS:
    - Transcript files may contain sensitive data
    - Ensure proper NTFS permissions on transcript directory
    - Consider log rotation for transcript files
    - Module logging can impact performance

    MITRE ATT&CK:
    - T1059.001: PowerShell
    - T1027: Obfuscated Files or Information
    - T1562.003: Impair Command History Logging
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter()]
    [string]$TranscriptPath = "C:\PSLogs\Transcripts",

    [Parameter()]
    [bool]$EnableTranscription = $true,

    [Parameter()]
    [string[]]$ModulesToLog = @("*"),

    [Parameter()]
    [switch]$RestoreDefaults
)

#Requires -RunAsAdministrator
#Requires -Version 5.1

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ============================================================================
# CONFIGURATION
# ============================================================================

$Script:Config = @{
    # Registry paths for PowerShell logging
    ScriptBlockLogging = @{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
        Values = @{
            EnableScriptBlockLogging = 1
            EnableScriptBlockInvocationLogging = 1  # Detailed start/stop events
        }
    }

    ModuleLogging = @{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
        ModuleNamesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames"
        Values = @{
            EnableModuleLogging = 1
        }
    }

    Transcription = @{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
        Values = @{
            EnableTranscripting = 1
            EnableInvocationHeader = 1  # Include timestamp and command
            OutputDirectory = $TranscriptPath
        }
    }

    # Protected Event Logging (encrypts sensitive logs with certificate)
    # Disabled by default - requires PKI infrastructure
    ProtectedEventLogging = @{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\ProtectedEventLogging"
        Enabled = $false  # Enable if you have PKI
    }
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Write-Log {
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet("Info", "Warning", "Error", "Success")]
        [string]$Level = "Info"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "Info"    { "White" }
        "Warning" { "Yellow" }
        "Error"   { "Red" }
        "Success" { "Green" }
    }

    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

function Test-AdminPrivilege {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function New-RegistryPath {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path $Path)) {
        $null = New-Item -Path $Path -Force
        Write-Log "Created registry path: $Path" -Level Info
    }
}

function Set-RegistryValues {
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [hashtable]$Values
    )

    New-RegistryPath -Path $Path

    foreach ($name in $Values.Keys) {
        $value = $Values[$name]
        $type = if ($value -is [int]) { "DWord" } else { "String" }

        if ($PSCmdlet.ShouldProcess("$Path\$name", "Set to $value")) {
            Set-ItemProperty -Path $Path -Name $name -Value $value -Type $type
            Write-Log "Set $name = $value" -Level Info
        }
    }
}

function Enable-ScriptBlockLogging {
    <#
    .SYNOPSIS
        Enables PowerShell Script Block Logging.
    .DESCRIPTION
        Script Block Logging captures the content of all script blocks
        processed by the PowerShell engine. This includes:
        - Deobfuscated commands (captures AFTER deobfuscation)
        - Encoded command contents
        - Dynamic code execution
        - Remote commands

        Events are logged to:
        Microsoft-Windows-PowerShell/Operational
        Event ID: 4104 (Script Block), 4105 (Script Block Start), 4106 (Script Block Complete)
    #>

    Write-Log "Configuring Script Block Logging..." -Level Info

    $config = $Script:Config.ScriptBlockLogging
    Set-RegistryValues -Path $config.Path -Values $config.Values

    Write-Log "Script Block Logging enabled" -Level Success
}

function Enable-ModuleLogging {
    <#
    .SYNOPSIS
        Enables PowerShell Module Logging.
    .DESCRIPTION
        Module Logging captures detailed pipeline execution information
        including:
        - Parameter bindings
        - Command invocations
        - Module load events

        Events are logged to:
        Microsoft-Windows-PowerShell/Operational
        Event ID: 4103 (Module Logging)
    #>

    Write-Log "Configuring Module Logging..." -Level Info

    $config = $Script:Config.ModuleLogging

    # Enable module logging
    Set-RegistryValues -Path $config.Path -Values $config.Values

    # Configure modules to log
    New-RegistryPath -Path $config.ModuleNamesPath

    foreach ($module in $ModulesToLog) {
        if ($PSCmdlet.ShouldProcess($module, "Enable module logging")) {
            Set-ItemProperty -Path $config.ModuleNamesPath -Name $module -Value $module -Type String
            Write-Log "Added module to logging: $module" -Level Info
        }
    }

    Write-Log "Module Logging enabled for: $($ModulesToLog -join ', ')" -Level Success
}

function Enable-Transcription {
    <#
    .SYNOPSIS
        Enables PowerShell Transcription.
    .DESCRIPTION
        Transcription creates text files containing a complete record
        of all PowerShell sessions including:
        - All commands entered
        - All output produced
        - Timestamps
        - User context

        Files are stored in the specified transcript directory.

        NOTE: Transcription generates significant disk I/O and storage.
        Ensure adequate disk space and implement log rotation.
    #>

    if (-not $EnableTranscription) {
        Write-Log "Transcription disabled by parameter" -Level Info
        return
    }

    Write-Log "Configuring PowerShell Transcription..." -Level Info

    # Create transcript directory
    if (-not (Test-Path $TranscriptPath)) {
        if ($PSCmdlet.ShouldProcess($TranscriptPath, "Create transcript directory")) {
            New-Item -Path $TranscriptPath -ItemType Directory -Force | Out-Null
            Write-Log "Created transcript directory: $TranscriptPath" -Level Info

            # Set secure permissions - Administrators and SYSTEM only
            $acl = Get-Acl $TranscriptPath

            # Remove inheritance and clear existing rules
            $acl.SetAccessRuleProtection($true, $false)

            # Add Administrators - Full Control
            $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                "BUILTIN\Administrators",
                "FullControl",
                "ContainerInherit,ObjectInherit",
                "None",
                "Allow"
            )
            $acl.AddAccessRule($adminRule)

            # Add SYSTEM - Full Control
            $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                "NT AUTHORITY\SYSTEM",
                "FullControl",
                "ContainerInherit,ObjectInherit",
                "None",
                "Allow"
            )
            $acl.AddAccessRule($systemRule)

            Set-Acl -Path $TranscriptPath -AclObject $acl
            Write-Log "Secured transcript directory permissions" -Level Info
        }
    }

    # Configure transcription registry
    $config = $Script:Config.Transcription
    $config.Values.OutputDirectory = $TranscriptPath
    Set-RegistryValues -Path $config.Path -Values $config.Values

    Write-Log "Transcription enabled to: $TranscriptPath" -Level Success
}

function Configure-EventLogSize {
    <#
    .SYNOPSIS
        Configures PowerShell event log sizes.
    .DESCRIPTION
        Increases the maximum size of PowerShell event logs to prevent
        event loss during high-volume logging periods.
    #>

    Write-Log "Configuring PowerShell event log sizes..." -Level Info

    $logs = @{
        "Microsoft-Windows-PowerShell/Operational" = 1073741824  # 1GB
        "PowerShellCore/Operational" = 1073741824  # 1GB for PS7
        "Windows PowerShell" = 536870912  # 512MB legacy log
    }

    foreach ($logName in $logs.Keys) {
        $maxSize = $logs[$logName]

        try {
            if ($PSCmdlet.ShouldProcess($logName, "Set max size to $($maxSize / 1MB)MB")) {
                $result = wevtutil sl $logName /ms:$maxSize 2>&1
                if ($LASTEXITCODE -eq 0) {
                    Write-Log "Configured $logName : MaxSize=$($maxSize / 1MB)MB" -Level Success
                }
                else {
                    Write-Log "Could not configure $logName (may not exist)" -Level Warning
                }
            }
        }
        catch {
            Write-Log "Failed to configure $logName : $_" -Level Warning
        }
    }
}

function Enable-WindowsEventLogging {
    <#
    .SYNOPSIS
        Enables Windows PowerShell event logs.
    .DESCRIPTION
        Ensures the PowerShell event logs are enabled and accessible.
    #>

    Write-Log "Enabling PowerShell event logs..." -Level Info

    $logs = @(
        "Microsoft-Windows-PowerShell/Operational",
        "Microsoft-Windows-PowerShell/Admin",
        "PowerShellCore/Operational"
    )

    foreach ($logName in $logs) {
        try {
            if ($PSCmdlet.ShouldProcess($logName, "Enable event log")) {
                $result = wevtutil sl $logName /e:true 2>&1
                if ($LASTEXITCODE -eq 0) {
                    Write-Log "Enabled log: $logName" -Level Success
                }
            }
        }
        catch {
            Write-Log "Could not enable $logName (may not exist)" -Level Warning
        }
    }
}

function Restore-Defaults {
    <#
    .SYNOPSIS
        Restores PowerShell logging to defaults.
    #>

    Write-Log "Restoring PowerShell logging defaults..." -Level Warning

    $paths = @(
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
    )

    foreach ($path in $paths) {
        if (Test-Path $path) {
            if ($PSCmdlet.ShouldProcess($path, "Remove registry key")) {
                Remove-Item -Path $path -Recurse -Force
                Write-Log "Removed: $path" -Level Info
            }
        }
    }

    Write-Log "PowerShell logging restored to defaults" -Level Success
}

function Test-PowerShellLogging {
    <#
    .SYNOPSIS
        Tests PowerShell logging configuration.
    #>

    Write-Log "Testing PowerShell logging configuration..." -Level Info

    $tests = @(
        @{
            Name = "Script Block Logging"
            Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
            Property = "EnableScriptBlockLogging"
            Expected = 1
        },
        @{
            Name = "Module Logging"
            Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
            Property = "EnableModuleLogging"
            Expected = 1
        },
        @{
            Name = "Transcription"
            Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
            Property = "EnableTranscripting"
            Expected = 1
        }
    )

    $allPassed = $true

    foreach ($test in $tests) {
        try {
            if (Test-Path $test.Path) {
                $value = Get-ItemProperty -Path $test.Path -Name $test.Property -ErrorAction SilentlyContinue
                if ($value.($test.Property) -eq $test.Expected) {
                    Write-Log "$($test.Name): PASSED" -Level Success
                }
                else {
                    Write-Log "$($test.Name): FAILED (Expected: $($test.Expected), Got: $($value.($test.Property)))" -Level Error
                    $allPassed = $false
                }
            }
            else {
                Write-Log "$($test.Name): FAILED (Registry path not found)" -Level Error
                $allPassed = $false
            }
        }
        catch {
            Write-Log "$($test.Name): FAILED ($_)" -Level Error
            $allPassed = $false
        }
    }

    return $allPassed
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

function Main {
    Write-Log "============================================" -Level Info
    Write-Log "PowerShell Logging Configuration Script" -Level Info
    Write-Log "Version 2.0.0" -Level Info
    Write-Log "============================================" -Level Info

    # Verify admin privileges
    if (-not (Test-AdminPrivilege)) {
        Write-Log "This script requires administrative privileges." -Level Error
        throw "Administrative privileges required"
    }

    # Handle restore defaults
    if ($RestoreDefaults) {
        Restore-Defaults
        return
    }

    # Display configuration
    Write-Log "Configuration:" -Level Info
    Write-Log "  - Transcript Path: $TranscriptPath" -Level Info
    Write-Log "  - Enable Transcription: $EnableTranscription" -Level Info
    Write-Log "  - Modules to Log: $($ModulesToLog -join ', ')" -Level Info

    # Enable Windows event logs
    Enable-WindowsEventLogging

    # Configure event log sizes
    Configure-EventLogSize

    # Enable Script Block Logging
    Enable-ScriptBlockLogging

    # Enable Module Logging
    Enable-ModuleLogging

    # Enable Transcription
    Enable-Transcription

    # Verify configuration
    Write-Log "============================================" -Level Info
    Write-Log "Verifying Configuration..." -Level Info

    if (Test-PowerShellLogging) {
        Write-Log "============================================" -Level Info
        Write-Log "PowerShell logging configuration complete!" -Level Success
        Write-Log "============================================" -Level Info

        Write-Log "" -Level Info
        Write-Log "Event Logs to Monitor:" -Level Info
        Write-Log "  - Microsoft-Windows-PowerShell/Operational (Event ID 4104: Script Block)" -Level Info
        Write-Log "  - Microsoft-Windows-PowerShell/Operational (Event ID 4103: Module Logging)" -Level Info
        Write-Log "  - Windows PowerShell (Event ID 400: Engine Start, 403: Engine Stop)" -Level Info

        if ($EnableTranscription) {
            Write-Log "" -Level Info
            Write-Log "Transcripts Location: $TranscriptPath" -Level Info
            Write-Log "SECURITY NOTE: Ensure NTFS permissions restrict access to Administrators only" -Level Warning
        }
    }
    else {
        Write-Log "Some configurations may not have applied correctly" -Level Warning
        exit 1
    }
}

# Run main function
Main
