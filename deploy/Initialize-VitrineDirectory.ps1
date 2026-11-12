# SPDX-License-Identifier: MIT
#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Prepares Active Directory for Vitrine security keys stored centrally (Fido.Store = ActiveDirectory).

.DESCRIPTION
    - creates the container CN=Vitrine,CN=Program Data,<domain> (or -Container) and CN=SecurityKeys below it
    - registrars group (-RegistrarsGroup) on CN=SecurityKeys: read; create and delete serviceConnectionPoint objects;
      on those objects (inherited) write keywords, serviceBindingInformation and description
    - readers group (-ReadersGroup, default "Domain Computers") on CN=Vitrine and below: read - the Vitrine service
      reads the keys as the computer account
    No schema extension; nothing is removed. Running it again changes nothing that is already in place.
    Run as a domain administrator (or with rights to create containers and change permissions there).
    Details: docs/security-keys.md, section "Active Directory".

.PARAMETER RegistrarsGroup
    Group whose members register and revoke keys (same people as Roles.Registrars in Vitrine), e.g. 'Vitrine Registrars'.

.PARAMETER ReadersGroup
    Group of the computers that use the keys. Default: Domain Computers of the domain (found by its well-known RID, so
    it works in every language).

.PARAMETER Container
    Distinguished name of the Vitrine container (Fido.DirectoryContainer). Default: CN=Vitrine,CN=Program Data,<domain DN>.

.PARAMETER Server
    Domain controller or domain to use (optional).

.EXAMPLE
    .\Initialize-VitrineDirectory.ps1 -RegistrarsGroup 'Vitrine Registrars' -WhatIf
.EXAMPLE
    .\Initialize-VitrineDirectory.ps1 -RegistrarsGroup 'Vitrine Registrars'
.EXAMPLE
    .\Initialize-VitrineDirectory.ps1 -RegistrarsGroup 'Vitrine Registrars' -ReadersGroup 'Lab Computers' -Container 'CN=Vitrine,OU=Lab,DC=contoso,DC=com'
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$RegistrarsGroup,
    [string]$ReadersGroup = 'Domain Computers',
    [string]$Container,
    [string]$Server
)

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
$ad = @{}
if ($Server) { $ad.Server = $Server }

$domain = Get-ADDomain @ad
if (-not $Container) { $Container = "CN=Vitrine,CN=Program Data,$($domain.DistinguishedName)" }
$keys = "CN=SecurityKeys,$Container"

# Kennungen aus dem Schema lesen statt fest eintragen
$schema = (Get-ADRootDSE @ad).schemaNamingContext
function Get-SchemaGuid([string]$name) {
    $o = Get-ADObject -SearchBase $schema -LDAPFilter "(lDAPDisplayName=$name)" -Properties schemaIDGUID @ad
    if (-not $o) { throw "Schema object $name not found" }
    [guid]$o.schemaIDGUID
}
$scp = Get-SchemaGuid 'serviceConnectionPoint'
$attributes = 'keywords', 'serviceBindingInformation', 'description' | ForEach-Object { Get-SchemaGuid $_ }

# Gruppen als SID; „Domain Computers“ über die bekannte RID 515 (Name ist sprachabhängig)
$registrars = (Get-ADGroup -Identity $RegistrarsGroup @ad).SID
$readers = if ($ReadersGroup -eq 'Domain Computers') {
    New-Object System.Security.Principal.SecurityIdentifier "$($domain.DomainSID.Value)-515"
} else {
    (Get-ADGroup -Identity $ReadersGroup @ad).SID
}

# Container anlegen, falls er fehlt (auch CN=Program Data, falls jemand es gelöscht hat). DN ohne maskierte Kommas.
function Confirm-Container([string]$dn) {
    if (Get-ADObject -Filter "distinguishedName -eq '$dn'" @ad) { Write-Host "exists:  $dn"; return }
    $comma = $dn.IndexOf(',')
    $parent = $dn.Substring($comma + 1)
    $name = $dn.Substring(3, $comma - 3)
    if ($parent -like 'CN=*') { Confirm-Container $parent }
    if ($PSCmdlet.ShouldProcess($dn, 'Create container')) {
        New-ADObject -Name $name -Type container -Path $parent @ad
        Write-Host "created: $dn"
    }
}

Confirm-Container $Container
Confirm-Container $keys

# Rechte ergänzen (vorhandene Einträge bleiben); geschrieben wird nur bei einer Änderung
function Add-Rules([string]$dn, [System.DirectoryServices.ActiveDirectoryAccessRule[]]$rules, [string]$what) {
    $o = Get-ADObject -Identity $dn -Properties nTSecurityDescriptor @ad -ErrorAction SilentlyContinue
    if (-not $o) { Write-Host "skipped: $what on $dn (container not created, -WhatIf?)"; return }
    $sd = $o.nTSecurityDescriptor
    $before = $sd.GetSecurityDescriptorSddlForm('Access')
    foreach ($r in $rules) { $sd.AddAccessRule($r) }
    if ($sd.GetSecurityDescriptorSddlForm('Access') -eq $before) { Write-Host "in place: $what on $dn"; return }
    if ($PSCmdlet.ShouldProcess($dn, $what)) {
        Set-ADObject -Identity $dn -Replace @{ nTSecurityDescriptor = $sd } @ad
        Write-Host "set:     $what on $dn"
    }
}

$allow = [System.Security.AccessControl.AccessControlType]::Allow
$rights = [System.DirectoryServices.ActiveDirectoryRights]
$inherit = [System.DirectoryServices.ActiveDirectorySecurityInheritance]

# Lesende Rechner: CN=Vitrine und alles darunter lesen
Add-Rules $Container @(
    New-Object System.DirectoryServices.ActiveDirectoryAccessRule $readers, $rights::GenericRead, $allow, $inherit::All
) "read for $ReadersGroup"

# Registrierende: lesen, Schlüssel-Objekte anlegen und löschen, an diesen Objekten die drei Attribute schreiben
$registrarRules = @(
    New-Object System.DirectoryServices.ActiveDirectoryAccessRule $registrars, $rights::GenericRead, $allow, $inherit::All
    New-Object System.DirectoryServices.ActiveDirectoryAccessRule $registrars, ($rights::CreateChild -bor $rights::DeleteChild), $allow, $scp, $inherit::None
)
foreach ($a in $attributes) {
    $registrarRules += New-Object System.DirectoryServices.ActiveDirectoryAccessRule $registrars, $rights::WriteProperty, $allow, $a, $inherit::Descendents, $scp
}
Add-Rules $keys $registrarRules "create/delete security key objects for $RegistrarsGroup"

Write-Host ''
Write-Host "Container for Vitrine: $Container"
if ($Container -ne "CN=Vitrine,CN=Program Data,$($domain.DistinguishedName)") {
    Write-Host "Set the policy 'Active Directory container' (Fido.DirectoryContainer) to this DN."
}
Write-Host "Then set the policy 'Security key store' (Fido.Store) to 'Active Directory' and restart the Vitrine service."
