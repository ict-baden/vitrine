# SPDX-License-Identifier: MIT
<#
.SYNOPSIS
    Prüft den Windows-Kontobroker (msalruntime.dll) in den Release-Paketen: Version, Lizenz und Prüfsumme.

.DESCRIPTION
    msalruntime.dll kommt aus dem NuGet-Paket Microsoft.Identity.Client.NativeInterop. Bis 0.20.4 steht es unter MIT
    (nuspec: <license type="expression">MIT</license>), ab 0.20.6 unter Microsoft Software License Terms, die die
    Weitergabe verbieten (Abschnitt 3 e). Vitrine liefert deshalb genau 0.20.4 aus
    (https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/issues/6118). Das Skript scheitert, wenn
      - in project.assets.json eine andere NativeInterop-Version als 0.20.4 aufgelöst ist (oder keine, oder mehrere),
      - die nuspec dieser Version im NuGet-Cache keine Lizenz-Expression „MIT“ nennt (z. B. type="file"),
      - MSAL (Microsoft.Identity.Client, .Broker) nicht 4.84.1 ist oder nicht unter MIT steht,
      - msalruntime.dll in einem angegebenen Paket fehlt oder eine andere SHA-256-Prüfsumme hat als die aus dem Paket
        0.20.4 (b17764a7…).
    Dazu der Lader des eigenen Anmeldefensters (WebView2Loader.dll aus Microsoft.Web.WebView2, seit 2026-10): Das Skript
    scheitert, wenn eine andere Version als 1.0.4258.31 aufgelöst ist, die nuspec nicht auf die Lizenzdatei LICENSE.txt
    verweist, deren Text sich geändert hat (BSD-artige Lizenz, Prüfsumme) oder WebView2Loader.dll in einem Paket fehlt
    bzw. eine andere Prüfsumme hat.
    Pakete: Ordner (-Directory), ZIP (-Zip), Einzeldatei-Exe (-SingleFile, liest das Bundle-Verzeichnis der .NET-Exe)
    und MSI (-Msi: Zeile in der Tabelle File, Inhalt über eine administrative Installation, die nur entpackt;
    die installierte Datei prüft zusätzlich msi-test.ps1).

.EXAMPLE
    ./.github/scripts/check-broker-licence.ps1 -AssetsJson src/Vitrine/obj/project.assets.json -Directory out/framework,out/self-contained `
        -Zip dist/Vitrine-win-x64-framework.zip -SingleFile dist/Vitrine.exe -Msi dist/Vitrine-x64.msi
#>
param(
    [Parameter(Mandatory)] [string] $AssetsJson,
    [string[]] $Directory = @(),
    [string] $Zip,
    [string] $SingleFile,
    [string] $Msi
)

$ErrorActionPreference = 'Stop'

# Einzige Stelle für die erlaubten Stände. Ändern nur nach Lizenzprüfung (CLAUDE.md, docs/entra-id.md).
$NativeInteropVersion = '0.20.4'
$MsalVersion = '4.84.1'
$ExpectedHash = 'b17764a728a8a182bf1dd442ddbf579ec1c8890acdd463ac9419d2a4dd8944a9' # runtimes/win-x64/native/msalruntime.dll aus 0.20.4
$ExpectedNupkgHash = '5b89bba3da0ba3c934e8ef441053717c635668c887bcbc62187ef2612f696ec2' # microsoft.identity.client.nativeinterop.0.20.4.nupkg
$DllName = 'msalruntime.dll'

# Lader des Anmeldefensters (Microsoft.Web.WebView2). Ändern nur nach Lizenzprüfung (LICENSE.txt im Paket, THIRD-PARTY-NOTICES.txt).
$WebView2Version = '1.0.4258.31'
$WebView2LicenceHash = '0af8f1b807512aae39c2ac1aa4d0cae65cabecb6fd554b8439a5162a0d6eca55' # LICENSE.txt im Paket (BSD-artig)
$LoaderName = 'WebView2Loader.dll'
$LoaderHash = '3426dcc55fdfb8b5e7ac623cf33b4ccf283fbf68a0c5a65bddfdb4d749a8abee' # runtimes/win-x64/native/WebView2Loader.dll
# Jede ausgelieferte Datei mit der erwarteten Prüfsumme
$Expected = [ordered]@{ $DllName = $ExpectedHash; $LoaderName = $LoaderHash }

$failures = [Collections.Generic.List[string]]::new()
function Fail([string] $message) { $failures.Add($message); Write-Host "::error::$message" }
function Ok([string] $message) { Write-Host "OK  $message" }
function Get-Sha256([byte[]] $bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-', '').ToLowerInvariant() } finally { $sha.Dispose() }
}
function Test-Hash([string] $what, [string] $hash, [string] $name = $DllName) {
    $want = $Expected[$name]
    if ($hash -eq $want) { Ok "$what`: $name $hash" }
    else { Fail "$what`: $name hat SHA-256 $hash, erwartet $want" }
}

# ---------- 1. Aufgelöste Pakete und ihre Lizenz ----------
$assets = Get-Content $AssetsJson -Raw | ConvertFrom-Json
$libraries = @($assets.libraries.PSObject.Properties.Name)
$folders = @($assets.packageFolders.PSObject.Properties.Name)

function Test-Package([string] $id, [string] $version) {
    $found = @($libraries | Where-Object { $_ -like "$id/*" })
    if ($found.Count -ne 1 -or $found[0] -ne "$id/$version") {
        Fail "$id`: aufgelöst $(if ($found) { $found -join ', ' } else { 'nichts' }), erwartet genau $version"
        return $null
    }
    $lib = $assets.libraries.PSObject.Properties[$found[0]].Value
    $dir = $null
    foreach ($f in $folders) {
        $candidate = Join-Path $f $lib.path
        if (Test-Path $candidate) { $dir = $candidate; break }
    }
    if (-not $dir) { Fail "$id $version`: nicht im NuGet-Cache gefunden ($($folders -join ', '))"; return $null }
    $nuspec = Join-Path $dir "$($id.ToLowerInvariant()).nuspec"
    if (-not (Test-Path $nuspec)) { Fail "$id $version`: nuspec fehlt ($nuspec)"; return $null }
    $license = ([xml](Get-Content $nuspec -Raw)).package.metadata.license
    $type = if ($license) { $license.type } else { '' }
    $value = if ($license) { "$($license.'#text')".Trim() } else { '' }
    if ($type -ne 'expression' -or $value -ne 'MIT') {
        Fail "$id $version`: Lizenz in der nuspec ist type='$type' '$value', erwartet die Expression MIT"
        return $null
    }
    Ok "$id $version, Lizenz-Expression MIT ($nuspec)"
    return $dir
}

Test-Package 'Microsoft.Identity.Client' $MsalVersion | Out-Null
Test-Package 'Microsoft.Identity.Client.Broker' $MsalVersion | Out-Null
$niDir = Test-Package 'Microsoft.Identity.Client.NativeInterop' $NativeInteropVersion
if ($niDir) {
    $nupkg = Join-Path $niDir "microsoft.identity.client.nativeinterop.$NativeInteropVersion.nupkg"
    if (Test-Path $nupkg) {
        $h = (Get-FileHash $nupkg -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($h -eq $ExpectedNupkgHash) { Ok "nupkg $h" } else { Fail "nupkg hat SHA-256 $h, erwartet $ExpectedNupkgHash" }
    } else { Fail "nupkg fehlt im NuGet-Cache ($nupkg)" }
    Test-Hash 'NuGet-Cache' (Get-FileHash (Join-Path $niDir "runtimes/win-x64/native/$DllName") -Algorithm SHA256).Hash.ToLowerInvariant()
}

# WebView2: genau diese Version, Lizenz als Datei mit bekanntem Text, Lader mit bekannter Prüfsumme
$found = @($libraries | Where-Object { $_ -like 'Microsoft.Web.WebView2/*' })
if ($found.Count -ne 1 -or $found[0] -ne "Microsoft.Web.WebView2/$WebView2Version") {
    Fail "Microsoft.Web.WebView2: aufgelöst $(if ($found) { $found -join ', ' } else { 'nichts' }), erwartet genau $WebView2Version"
} else {
    $lib = $assets.libraries.PSObject.Properties[$found[0]].Value
    $wvDir = $folders | ForEach-Object { Join-Path $_ $lib.path } | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $wvDir) { Fail "Microsoft.Web.WebView2 $WebView2Version`: nicht im NuGet-Cache gefunden" }
    else {
        $license = ([xml](Get-Content (Join-Path $wvDir 'microsoft.web.webview2.nuspec') -Raw)).package.metadata.license
        $type = if ($license) { $license.type } else { '' }
        $value = if ($license) { "$($license.'#text')".Trim() } else { '' }
        if ($type -ne 'file' -or $value -ne 'LICENSE.txt') { Fail "Microsoft.Web.WebView2 $WebView2Version`: Lizenz in der nuspec ist type='$type' '$value', erwartet die Datei LICENSE.txt" }
        else {
            $h = (Get-FileHash (Join-Path $wvDir 'LICENSE.txt') -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($h -eq $WebView2LicenceHash) { Ok "Microsoft.Web.WebView2 $WebView2Version, LICENSE.txt unverändert ($h)" }
            else { Fail "Microsoft.Web.WebView2 $WebView2Version`: LICENSE.txt hat SHA-256 $h, erwartet $WebView2LicenceHash – Lizenz neu prüfen" }
        }
        Test-Hash 'NuGet-Cache' (Get-FileHash (Join-Path $wvDir "runtimes/win-x64/native/$LoaderName") -Algorithm SHA256).Hash.ToLowerInvariant() $LoaderName
    }
}

# ---------- 2. Ordner (Grundlage für ZIP und MSI) ----------
foreach ($d in $Directory) {
    foreach ($name in $Expected.Keys) {
        $file = Join-Path $d $name
        if (Test-Path $file) { Test-Hash $d (Get-FileHash $file -Algorithm SHA256).Hash.ToLowerInvariant() $name }
        else { Fail "$d`: $name fehlt" }
    }
}

# ---------- 3. ZIP ----------
if ($Zip) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::OpenRead((Resolve-Path $Zip))
    try {
        foreach ($name in $Expected.Keys) {
            $entry = $archive.Entries | Where-Object FullName -eq $name
            if (-not $entry) { Fail "$Zip`: $name fehlt (neben Vitrine.exe)" }
            else {
                $stream = $entry.Open(); $ms = [IO.MemoryStream]::new()
                try { $stream.CopyTo($ms) } finally { $stream.Dispose() }
                Test-Hash $Zip (Get-Sha256 $ms.ToArray()) $name
            }
        }
    } finally { $archive.Dispose() }
}

# ---------- 4. Einzeldatei: Verzeichnis des .NET-Bundles lesen ----------
# Aufbau (dotnet/runtime, src/installer/managed/Microsoft.NET.HostModel/Bundle): Im Apphost steht vor der Signatur
# (feste 32 Bytes aus HostWriter.cs) der Offset des Bundle-Kopfs. Kopf: Version (2 × UInt32), Anzahl Dateien, Bundle-ID,
# ab Version 2 Offsets von deps.json/runtimeconfig.json und Flags; je Datei Offset, Größe, ab Version 6 komprimierte
# Größe (0 = unkomprimiert), Typ, relativer Pfad.
if ($SingleFile) {
    $bytes = [IO.File]::ReadAllBytes((Resolve-Path $SingleFile))
    [byte[]] $signature = 0x8b, 0x12, 0x02, 0xb9, 0x6a, 0x61, 0x20, 0x38, 0x72, 0x7b, 0x93, 0x02, 0x14, 0xd7, 0xa0, 0x32,
                          0x13, 0xf5, 0xb9, 0xe6, 0xef, 0xae, 0x33, 0x18, 0xee, 0x3b, 0x2d, 0xce, 0x24, 0xb3, 0x6a, 0xae
    # Suche über Span (schnell auch bei ~190 MB); PowerShell selbst kann keine Spans
    Add-Type -TypeDefinition 'public static class BundleSearch { public static int Find(byte[] a, byte[] b) => System.MemoryExtensions.IndexOf<byte>(a, b); }'
    $pos = [BundleSearch]::Find($bytes, $signature)
    $headerOffset = if ($pos -ge 8) { [BitConverter]::ToInt64($bytes, $pos - 8) } else { 0 }
    if ($headerOffset -le 0) { Fail "$SingleFile`: kein .NET-Einzeldatei-Bundle" }
    else {
        $reader = [IO.BinaryReader]::new([IO.MemoryStream]::new($bytes, $false))
        try {
            $reader.BaseStream.Position = $headerOffset
            $major = $reader.ReadUInt32(); [void]$reader.ReadUInt32()
            $count = $reader.ReadInt32(); [void]$reader.ReadString()
            if ($major -ge 2) { [void]$reader.ReadBytes(8 * 5) }
            $hits = @{}
            for ($n = 0; $n -lt $count; $n++) {
                $offset = $reader.ReadInt64(); $size = $reader.ReadInt64()
                $compressed = if ($major -ge 6) { $reader.ReadInt64() } else { 0 }
                [void]$reader.ReadByte(); $path = $reader.ReadString()
                if ($Expected.Contains($path)) { $hits[$path] = [pscustomobject]@{ Offset = $offset; Size = $size; Compressed = $compressed } }
            }
            foreach ($name in $Expected.Keys) {
            $hit = $hits[$name]
            if (-not $hit) { Fail "$SingleFile`: $name ist nicht im Bundle ($count Dateien)" }
            else {
                $length = if ($hit.Compressed -gt 0) { $hit.Compressed } else { $hit.Size }
                $data = [byte[]]::new($length)
                [Array]::Copy($bytes, $hit.Offset, $data, 0, $length)
                if ($hit.Compressed -gt 0) {
                    $inflate = [IO.Compression.DeflateStream]::new([IO.MemoryStream]::new($data), [IO.Compression.CompressionMode]::Decompress)
                    $ms = [IO.MemoryStream]::new()
                    try { $inflate.CopyTo($ms) } finally { $inflate.Dispose() }
                    $data = $ms.ToArray()
                }
                Test-Hash "$SingleFile (Bundle v$major, $count Dateien)" (Get-Sha256 $data) $name
            }
            }
        } finally { $reader.Dispose() }
    }
}

# ---------- 5. MSI: Tabelle File ----------
if ($Msi) {
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $db = $installer.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $installer, @((Resolve-Path $Msi).Path, 0))
    $view = $db.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $db, @('SELECT `FileName`, `FileSize` FROM `File`'))
    $view.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $view, $null) | Out-Null
    $rows = @()
    $loaderRows = 0
    while ($true) {
        $record = $view.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $view, $null)
        if ($null -eq $record) { break }
        $name = $record.GetType().InvokeMember('StringData', 'GetProperty', $null, $record, 1)
        $size = $record.GetType().InvokeMember('IntegerData', 'GetProperty', $null, $record, 2)
        # FileName steht als „kurz|lang“ oder nur lang
        if ((($name -split '\|')[-1]) -eq $DllName) { $rows += [pscustomobject]@{ FileName = $name; FileSize = $size } }
        if ((($name -split '\|')[-1]) -eq $LoaderName) { $loaderRows++ }
    }
    $view.GetType().InvokeMember('Close', 'InvokeMethod', $null, $view, $null) | Out-Null
    [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($db)
    if ($rows.Count -ne 1) { Fail "$Msi`: $($rows.Count) Zeilen für $DllName in der Tabelle File, erwartet 1" }
    else { Ok "$Msi`: Tabelle File enthält $($rows[0].FileName) ($($rows[0].FileSize) Bytes)" }
    if ($loaderRows -ne 1) { Fail "$Msi`: $loaderRows Zeilen für $LoaderName in der Tabelle File, erwartet 1" }
    # Inhalt: administrative Installation entpackt nur die Dateien (kein Dienst, keine Registry, keine Rechte nötig)
    $target = Join-Path ([IO.Path]::GetTempPath()) "vitrine-msi-admin-$([guid]::NewGuid().ToString('N'))"
    $p = Start-Process msiexec -ArgumentList '/a', "`"$((Resolve-Path $Msi).Path)`"", '/qn', "TARGETDIR=`"$target`"" -Wait -PassThru
    if ($p.ExitCode -ne 0) { Fail "$Msi`: administrative Installation fehlgeschlagen ($($p.ExitCode))" }
    else {
        foreach ($name in $Expected.Keys) {
            $extracted = @(Get-ChildItem $target -Recurse -File -Filter $name -ErrorAction SilentlyContinue)
            if ($extracted.Count -ne 1) { Fail "$Msi`: $($extracted.Count)-mal $name nach dem Entpacken, erwartet 1" }
            else { Test-Hash "$Msi (entpackt)" (Get-FileHash $extracted[0].FullName -Algorithm SHA256).Hash.ToLowerInvariant() $name }
        }
    }
    Remove-Item $target -Recurse -Force -ErrorAction SilentlyContinue
}

if ($failures.Count -gt 0) { throw "Windows-Kontobroker: $($failures.Count) Fehler – siehe oben" }
Write-Host "Windows-Kontobroker: NativeInterop $NativeInteropVersion (MIT), MSAL $MsalVersion, $DllName $ExpectedHash"
Write-Host "Anmeldefenster: Microsoft.Web.WebView2 $WebView2Version (LICENSE.txt $WebView2LicenceHash), $LoaderName $LoaderHash"
