# SPDX-License-Identifier: MIT
<#
.SYNOPSIS
    Schreibt die Release-Notizen eines Tags aus dem CHANGELOG.md (Abschnitt „## [x.y.z]“ bis zum nächsten „## [“).

.DESCRIPTION
    Für den Release-Job (Tag vX.Y.Z). Vorher erzeugte GitHub die Notizen aus den Commit-Titeln (--generate-notes); jetzt
    stehen im Release dieselben Angaben wie im CHANGELOG. Fehlt der Abschnitt oder ist er leer, bricht das Skript ab –
    lieber kein Release als eines ohne Beschreibung (Richtlinie 04: „Unveröffentlicht“ vor dem Tag umbenennen).

.EXAMPLE
    ./.github/scripts/release-notes.ps1 -Version 0.1.0 -Out dist-notes.md
#>
param(
    [Parameter(Mandatory)] [string] $Version,
    [Parameter(Mandatory)] [string] $Out,
    [string] $Changelog = 'CHANGELOG.md'
)
$ErrorActionPreference = 'Stop'
$lines = Get-Content $Changelog -Encoding utf8
$start = -1
for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -match "^## \[$([regex]::Escape($Version))\]") { $start = $i; break }
}
if ($start -lt 0) { throw "$Changelog hat keinen Abschnitt '## [$Version]' – vor dem Tag 'Unveröffentlicht' umbenennen." }
$end = $lines.Count
for ($i = $start + 1; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -match '^## \[') { $end = $i; break }
}
if ($end -le $start + 1) { throw "Abschnitt '## [$Version]' in $Changelog ist leer." }
$body = @($lines[($start + 1)..($end - 1)] | Where-Object { $_ -notmatch '^<!--.*-->$' })
$text = ($body -join "`n").Trim()
if (-not $text) { throw "Abschnitt '## [$Version]' in $Changelog ist leer." }
$repo = $env:GITHUB_REPOSITORY
# Relative Links (docs/…, SUPPORT.md) zeigten im Release-Text auf /releases/tag/… und liefen ins Leere: auf den Stand des Tags
if ($repo) {
    $text = [regex]::Replace($text, '\]\((?!https?://|mailto:|#)([^)\s]+)\)', { param($m) "](https://github.com/$repo/blob/v$Version/$($m.Groups[1].Value))" })
}
$footer = if ($repo) { "`n`n---`nPrüfsummen: SHA256SUMS.txt · Stückliste: *-sbom.cdx.json · Vollständige Änderungen: https://github.com/$repo/blob/v$Version/CHANGELOG.md" } else { '' }
[IO.File]::WriteAllText((Join-Path (Get-Location) $Out), $text + $footer + "`n", [Text.UTF8Encoding]::new($false))
Write-Host "Release-Notizen aus $Changelog ($($body.Count) Zeilen) nach $Out"
