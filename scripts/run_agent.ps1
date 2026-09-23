<#
.SYNOPSIS
    Installer Engine Endpoint Agent Runner (Windows 11 & Server)

.DESCRIPTION
    PowerShell automation script to build and execute Installer Engine operations on Windows,
    including installed application inventory scans, real-time application control & blocking checks,
    local MSI/EXE installation tests, and daemon execution.

.PARAMETER Action
    Operation to perform: Inventory, InventoryJson, SyncInventory, TestBlock, Install, Daemon, OneShot, Build

.PARAMETER Target
    Application name (for TestBlock) or local installer file path (for Install) - supports paths with spaces.

.PARAMETER OrgId
    Organization ID (default: 1)

.PARAMETER DeviceId
    Device identifier (default: endpoint-<hostname>)

.PARAMETER ControlPlaneUrl
    Remote Control Plane HTTP base URL

.PARAMETER PollInterval
    Daemon polling interval in seconds (default: 10)

.PARAMETER AllowNonRoot
    Allow running unprivileged without Administrator elevation

.EXAMPLE
    .\scripts\run_agent.ps1 -Action Inventory
    .\scripts\run_agent.ps1 -Action TestBlock -Target "uTorrent"
    .\scripts\run_agent.ps1 -Action TestBlock -Target "Microsoft Teams"
    .\scripts\run_agent.ps1 -Action Install -Target "C:\Users\robert1\Documents\Firefox Installer.exe"
    .\scripts\run_agent.ps1 -Action Daemon
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0, Mandatory = $false)]
    [ValidateSet("Inventory", "InventoryJson", "SyncInventory", "TestBlock", "Install", "Daemon", "OneShot", "Build", "Help")]
    [string]$Action = "Help",

    [Parameter(Position = 1, Mandatory = $false, ValueFromRemainingArguments = $true)]
    [string[]]$Target = @(),

    [Parameter(Mandatory = $false)]
    [uint64]$OrgId = 1,

    [Parameter(Mandatory = $false)]
    [string]$DeviceId = "",

    [Parameter(Mandatory = $false)]
    [string]$ControlPlaneUrl = "",

    [Parameter(Mandatory = $false)]
    [uint64]$PollInterval = 10,

    [Parameter(Mandatory = $false)]
    [switch]$AllowNonRoot
)

$ErrorActionPreference = "Stop"

# Flatten Target parameter if multiple tokens or quotes were split across arguments
$TargetStr = if ($Target -is [array]) { ($Target -join " ").Trim('"').Trim('\'') } else { [string]$Target }

# Paths
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $ScriptDir
$TargetBin = Join-Path $RootDir "target\release\installer-agent.exe"

function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "[SUCCESS] $Message" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Message)
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Write-Err {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

function Test-IsAdministrator {
    $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = [Security.Principal.WindowsPrincipal]$Identity
    return $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Build-Agent {
    if (-not (Test-Path $TargetBin)) {
        Write-Info "Binary not found. Compiling installer-agent in release mode..."
        Push-Location $RootDir
        try {
            cargo build --release --bin installer-agent
            if ($LASTEXITCODE -ne 0) {
                Write-Err "Compilation failed."
                exit 1
            }
            Write-Success "Build completed successfully: $TargetBin"
        }
        finally {
            Pop-Location
        }
    }
}

function Show-Help {
    Write-Host @"
=============================================================================
         Installer Engine Endpoint Agent PowerShell Runner (Windows)         
=============================================================================

Usage:
  .\scripts\run_agent.ps1 -Action <Action> [-Target <Target>] [Options]

Actions:
  Inventory         Scan and display installed software inventory table
  InventoryJson     Scan and export installed software inventory as JSON
  SyncInventory     Scan and synchronize installed applications with Control Plane
  TestBlock         Evaluate application name or path against security block policies
  Install           Execute local package installation (.msi, .exe)
  Daemon            Start agent daemon in real-time task polling and application control mode
  OneShot           Poll Control Plane once, execute pending tasks, and exit
  Build             Recompile release binary

Options:
  -Target <string>          Application name (for TestBlock) or installer path (for Install)
  -OrgId <uint64>           Organization ID (default: 1)
  -DeviceId <string>        Device identifier (default: endpoint-<hostname>)
  -ControlPlaneUrl <string> Remote Control Plane HTTP endpoint URL
  -PollInterval <uint64>    Daemon polling interval in seconds (default: 10)
  -AllowNonRoot             Allow running without Administrator elevation

Examples:
  .\scripts\run_agent.ps1 -Action Inventory
  .\scripts\run_agent.ps1 -Action TestBlock -Target "uTorrent"
  .\scripts\run_agent.ps1 -Action TestBlock -Target "Microsoft Teams"
  .\scripts\run_agent.ps1 -Action Install -Target "C:\Users\robert1\Documents\Firefox Installer.exe"
  .\scripts\run_agent.ps1 -Action Daemon
=============================================================================
"@
}

if ($Action -eq "Help") {
    Show-Help
    exit 0
}

if ($Action -eq "Build") {
    Write-Info "Rebuilding release binary..."
    Push-Location $RootDir
    try {
        cargo build --release --bin installer-agent
        Write-Success "Release binary ready at: $TargetBin"
    }
    finally {
        Pop-Location
    }
    exit 0
}

# Ensure binary is built
Build-Agent

# Prepare arguments
$AgentArgs = @()

if ($OrgId) {
    $AgentArgs += "--org-id"
    $AgentArgs += "$OrgId"
}

if ($DeviceId) {
    $AgentArgs += "--device-id"
    $AgentArgs += "$DeviceId"
}

if ($ControlPlaneUrl) {
    $AgentArgs += "--control-plane-url"
    $AgentArgs += "$ControlPlaneUrl"
}

$IsAdmin = Test-IsAdministrator
$RequiresElevation = $true

switch ($Action) {
    "Inventory" {
        $RequiresElevation = $false
        $AgentArgs += "--inventory"
        $AgentArgs += "--allow-non-root"
    }
    "InventoryJson" {
        $RequiresElevation = $false
        $AgentArgs += "--inventory"
        $AgentArgs += "--json"
        $AgentArgs += "--allow-non-root"
    }
    "SyncInventory" {
        $AgentArgs += "--sync-inventory"
    }
    "TestBlock" {
        if ([string]::IsNullOrWhiteSpace($TargetStr)) {
            Write-Err "Missing -Target parameter for TestBlock action (e.g. -Target 'uTorrent')."
            exit 1
        }
        $RequiresElevation = $false
        $AgentArgs += "--test-block"
        $AgentArgs += $TargetStr
        $AgentArgs += "--allow-non-root"
    }
    "Install" {
        if ([string]::IsNullOrWhiteSpace($TargetStr)) {
            Write-Err "Missing -Target parameter for Install action (e.g. -Target 'C:\path\to\setup.msi')."
            exit 1
        }
        $AgentArgs += "--pkg"
        $AgentArgs += $TargetStr
    }
    "Daemon" {
        $AgentArgs += "--poll-interval"
        $AgentArgs += "$PollInterval"
        $AgentArgs += "--enable-blocking"
    }
    "OneShot" {
        $AgentArgs += "--one-shot"
    }
}

if ($AllowNonRoot) {
    $AgentArgs += "--allow-non-root"
    $RequiresElevation = $false
}

if ($RequiresElevation -and -not $IsAdmin) {
    Write-Warn "This operation requires Administrator privileges."
    Write-Info "Re-launching script in an elevated PowerShell session..."
    
    $EscapedScript = $PSCommandPath.Replace('"', '\"')
    $ElevatedArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$EscapedScript`" -Action $Action"
    if (-not [string]::IsNullOrWhiteSpace($TargetStr)) { 
        $CleanTarget = $TargetStr.Replace('"', '\"')
        $ElevatedArgs += " -Target `"$CleanTarget`"" 
    }
    if ($OrgId) { $ElevatedArgs += " -OrgId $OrgId" }
    if ($DeviceId) { $ElevatedArgs += " -DeviceId `"$DeviceId`"" }
    if ($ControlPlaneUrl) { $ElevatedArgs += " -ControlPlaneUrl `"$ControlPlaneUrl`"" }
    if ($PollInterval) { $ElevatedArgs += " -PollInterval $PollInterval" }

    Start-Process powershell -Verb RunAs -ArgumentList $ElevatedArgs
    exit 0
}

Write-Info "Executing: $TargetBin $($AgentArgs -join ' ')"
& $TargetBin @AgentArgs
exit $LASTEXITCODE
