# SPDX-License-Identifier: MIT
<#
.SYNOPSIS
    Example: a line-of-business application talks to Vitrine through the local interface (docs/interface.md).
.EXAMPLE
    .\Vitrine.Client.ps1 status
    .\Vitrine.Client.ps1 lock
    .\Vitrine.Client.ps1 sign -Reason "Release batch 4711" -Meaning "Reviewed and approved"
    .\Vitrine.Client.ps1 subscribe
#>
param(
    [Parameter(Mandatory)][ValidateSet('status','lock','sign','subscribe')][string]$Command,
    [string]$Reason,
    [string]$Meaning,
    [string]$Requester = 'PowerShell'
)

$session = (Get-Process -Id $PID).SessionId
# Name seit 0.1.0: ICT-Baden.Vitrine.<Sitzung> (vorher Vitrine-<Sitzung>)
$pipe = New-Object IO.Pipes.NamedPipeClientStream('.', "ICT-Baden.Vitrine.$session", [IO.Pipes.PipeDirection]::InOut)
$pipe.Connect(3000)
$w = New-Object IO.StreamWriter($pipe); $w.AutoFlush = $true
$r = New-Object IO.StreamReader($pipe)

$req = switch ($Command) {
    'sign'  { @{ cmd = 'authenticate'; reason = $Reason; meaning = $Meaning; requester = $Requester } }
    default { @{ cmd = $Command } }
}
$w.WriteLine(($req | ConvertTo-Json -Compress))

if ($Command -eq 'subscribe') {
    Write-Host 'Waiting for events (Ctrl+C to stop) ...'
    while ($null -ne ($line = $r.ReadLine())) { $line | ConvertFrom-Json | Format-List }
} else {
    $r.ReadLine() | ConvertFrom-Json | Format-List
}
$pipe.Dispose()
