# SPDX-License-Identifier: MIT
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs Vitrine for all users of a device without the MSI (e.g. as an Intune Win32 app). The MSI is the
    recommended way; this script does the same steps.

.DESCRIPTION
    - copies the program files to %ProgramFiles%\Vitrine (only administrators may write there - important for plugins)
    - creates %ProgramData%\ICT-Baden\Vitrine: configuration writable by administrators only
    - log folder: with the service users may only READ (the service writes and signs the log);
      with -NoService users may only APPEND, not change or delete (hash chain + file permissions)
    - registers the event source "ICT-Baden Vitrine"
    - installs the service "ICT-Baden Vitrine": it starts Vitrine at every sign-in and supervises it
      (-NoService: no service, autostart through HKLM\...\Run as before)
    Older installations kept their configuration in %ProgramData%\Vitrine; Vitrine still reads it there until the
    settings are saved again (docs/installation.md, "Upgrading from earlier builds").

.EXAMPLE
    .\deploy\install.ps1                     # from the unpacked Vitrine-win-x64-framework.zip
    .\deploy\install.ps1 -Source ..\publish -Config .\config.json
    .\deploy\install.ps1 -Uninstall
#>
param(
    [string]$Source,
    [string]$Config,
    [switch]$NoAutostart,
    [switch]$NoService,
    [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'
$target  = Join-Path $env:ProgramFiles 'Vitrine'
$data    = Join-Path $env:ProgramData 'ICT-Baden\Vitrine'
$logs    = Join-Path $data 'Logs'
$runKey  = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
$source  = 'ICT-Baden Vitrine'
$service = 'ICT-Baden.Vitrine'

function Remove-VitrineService {
    if (Get-Service $service -ErrorAction SilentlyContinue) {
        Stop-Service $service -Force -ErrorAction SilentlyContinue
        sc.exe delete $service | Out-Null
    }
}

if ($Uninstall) {
    Remove-VitrineService
    Get-Process Vitrine -ErrorAction SilentlyContinue | Stop-Process -Force
    Remove-ItemProperty -Path $runKey -Name 'Vitrine' -ErrorAction SilentlyContinue
    Remove-Item $target -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "Vitrine removed. Configuration and audit logs in $data remain."
    return
}

# Standard: the folder above deploy\ (ZIP), otherwise ..\publish (repository)
if (-not $Source) {
    $Source = Join-Path $PSScriptRoot '..'
    if (-not (Test-Path (Join-Path $Source 'Vitrine.exe'))) { $Source = Join-Path $PSScriptRoot '..\publish' }
}
if (-not (Test-Path (Join-Path $Source 'Vitrine.exe'))) { throw "Vitrine.exe not found in $Source" }
# Check the configuration before changing anything: a broken file would otherwise only show up as VIT-0001 on the device.
# Only a warning: Vitrine also accepts comments and trailing commas, which ConvertFrom-Json in Windows PowerShell rejects.
if ($Config) {
    if (-not (Test-Path $Config)) { throw "$Config not found" }
    try { $null = Get-Content $Config -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop }
    catch { Write-Warning "$Config may not be valid JSON: $($_.Exception.Message)" }
}

# 1) Program files
Remove-VitrineService
Get-Process Vitrine -ErrorAction SilentlyContinue | Stop-Process -Force
New-Item -ItemType Directory -Force -Path $target, (Join-Path $target 'Plugins') | Out-Null
# Only the program files: the ZIP also contains deploy\ and README.md, which do not belong in Program Files
Get-ChildItem -LiteralPath $Source | Where-Object Name -notin 'deploy', 'README.md' | Copy-Item -Destination $target -Recurse -Force

# 2) Data folder with permissions
New-Item -ItemType Directory -Force -Path $data, $logs | Out-Null

$sidAdmins  = New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-544'
$sidSystem  = New-Object Security.Principal.SecurityIdentifier 'S-1-5-18'
$sidUsers   = New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-545'
$sidOwner   = New-Object Security.Principal.SecurityIdentifier 'S-1-3-4'   # OWNER RIGHTS
$inherit    = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
$none       = [Security.AccessControl.PropagationFlags]::None
$allow      = [Security.AccessControl.AccessControlType]::Allow

function New-Rule($sid, $rights) {
    New-Object Security.AccessControl.FileSystemAccessRule($sid, [Security.AccessControl.FileSystemRights]$rights, $inherit, $none, $allow)
}

# ProgramData\ICT-Baden\Vitrine: administrators/SYSTEM full control, users read. Owner: administrators, so that a
# user who created the folder beforehand cannot change the permissions again.
$acl = New-Object Security.AccessControl.DirectorySecurity
$acl.SetOwner($sidAdmins)
$acl.SetAccessRuleProtection($true, $false)
$acl.AddAccessRule((New-Rule $sidAdmins 'FullControl'))
$acl.AddAccessRule((New-Rule $sidSystem 'FullControl'))
$acl.AddAccessRule((New-Rule $sidUsers  'ReadAndExecute'))
Set-Acl -Path $data -AclObject $acl

# Logs: users may create and append files - but not change or delete anything.
# OWNER RIGHTS removes the creator's implicit right to change the permissions of a file.
$acl = New-Object Security.AccessControl.DirectorySecurity
$acl.SetOwner($sidAdmins)
$acl.SetAccessRuleProtection($true, $false)
$acl.AddAccessRule((New-Rule $sidAdmins 'FullControl'))
$acl.AddAccessRule((New-Rule $sidSystem 'FullControl'))
if ($NoService) {
    # Without the service, Vitrine writes the log in the user's session (format 2, not Part 11 capable).
    # Ordner selbst: Dateien anlegen. Dateien (nur vererbt): lesen und anhängen – CreateFiles wäre bei Dateien WriteData
    # (Überschreiben), deshalb getrennt.
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sidUsers, [Security.AccessControl.FileSystemRights]'ReadAndExecute, CreateFiles, Synchronize', [Security.AccessControl.InheritanceFlags]::None, $none, $allow)))
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sidUsers, [Security.AccessControl.FileSystemRights]'ReadAndExecute, AppendData, Synchronize', [Security.AccessControl.InheritanceFlags]::ObjectInherit, [Security.AccessControl.PropagationFlags]::InheritOnly, $allow)))
} else {
    # With the service, only the service writes and signs the log (format 3): users may only read.
    $acl.AddAccessRule((New-Rule $sidUsers 'ReadAndExecute, Synchronize'))
}
$acl.AddAccessRule((New-Rule $sidOwner  'ReadAndExecute, Synchronize'))
Set-Acl -Path $logs -AclObject $acl

if ($Config) { Copy-Item $Config (Join-Path $data 'config.json') -Force }

# 3) Event source
# .NET instead of New-EventLog: that cmdlet exists only in Windows PowerShell 5.1, not in PowerShell 7
if (-not [Diagnostics.EventLog]::SourceExists($source)) {
    [Diagnostics.EventLog]::CreateEventSource($source, 'Application')
}

# 4) Service (starts and supervises Vitrine in every session), otherwise autostart for all users
$exe = Join-Path $target 'Vitrine.exe'
if (-not $NoService) {
    Remove-ItemProperty -Path $runKey -Name 'Vitrine' -ErrorAction SilentlyContinue
    New-Service -Name $service -DisplayName 'ICT-Baden Vitrine' -BinaryPathName ('"{0}" --service' -f $exe) `
        -StartupType Automatic -Description 'Starts and supervises the Vitrine screen lock in every user session.' | Out-Null
    sc.exe failure $service reset= 86400 actions= restart/5000/restart/5000/restart/5000 | Out-Null
    Start-Service $service
} elseif (-not $NoAutostart) {
    # --autostart: a second instance (already running) exits silently instead of opening the settings
    Set-ItemProperty -Path $runKey -Name 'Vitrine' -Value ('"{0}" --autostart' -f $exe)
}

Write-Host "Vitrine installed to $target"
Write-Host "Configuration: $data\config.json   Audit logs: $logs"
Write-Host "Group Policy: copy policy\Vitrine.admx and the language folders to C:\Windows\PolicyDefinitions."
