# SPDX-License-Identifier: MIT
<#
.SYNOPSIS
    Installiert, aktualisiert und deinstalliert die MSI auf dem Windows-Runner und prüft das Ergebnis
    (Prüfung vom 2026-10-20: Die MSI mit dem Dienst war nie installiert worden).

.DESCRIPTION
    Für GitHub Actions auf einem frischen windows-latest-Runner (Administrator, wird danach verworfen). Ablauf:
    1. Stille Installation wie bei Intune (Standard: mit Dienst): Dienst automatisch, LocalSystem, läuft und überwacht.
       Ist auf dem Runner ein Benutzer angemeldet, startet der Dienst Vitrine dort; geprüft wird, dass sich die App beim
       Dienst meldet (AgentConnected im Protokoll) und über die Startfrist des Dienstes (60 s) hinaus kein gescheiterter
       Start, kein Verlust und kein Fehler der Dienst-Pipe protokolliert wird.
    2. Programmdateien: Exe, Lizenzen, ADMX vorhanden; Windows-Kontobroker msalruntime.dll mit der Prüfsumme aus
       NativeInterop 0.20.4 (MIT, Wert aus check-broker-licence.ps1); Lader des Anmeldefensters WebView2Loader.dll
       mit der Prüfsumme aus Microsoft.Web.WebView2 (ebenfalls aus check-broker-licence.ps1).
    3. Die installierte Exe startet (Screenshot-Modus, sperrt nie) und schreibt Bilder.
    4. Update mit einem zweiten Build derselben Version (anderer ProductCode, also eine echte große Aktualisierung)
       ohne Eigenschaften: Dienst läuft wieder, überwacht weiter, App meldet sich erneut.
    5. Deinstallation: Dienst, Programmordner, Registry-Einträge, Autostart, Ereignisquelle und Startmenü weg;
       Konfiguration und Protokolle unter %ProgramData%\ICT-Baden\Vitrine bleiben (dokumentiert). Keine
       Strg+Alt+Entf-Einschränkungen und keine Richtlinienwerte zurückgelassen.
    6. Installation mit SERVICE=0 AUTOSTART=1: Dienst überwacht nicht (Supervise=0), Autostart mit --autostart.
    7. Update ohne Eigenschaften: Die Wahl aus 6 bleibt (Befund: ein Update schaltete den Dienst wieder ein).
    8. Deinstallation des aktualisierten Stands.
    9. Mit -PreviousMsi (die zuletzt veröffentlichte MSI): Installation mit SERVICE=0 AUTOSTART=0, Update mit der neuen
       MSI ohne Eigenschaften – die Wahl bleibt, auch wenn die alte MSI sie noch nicht gemerkt hat; Deinstallation.
       Lässt sich die alte MSI nicht installieren, nur eine Warnung (sie ist schon veröffentlicht).
    Nach jeder Installation und jedem Update: Vitrine.exe ist da und hat die Dateiversion des neuen Pakets
    (-ExpectedFileVersion) – sonst hätte Windows Installer sie wegen einer neueren Datei des Vorgängers nicht kopiert.
    10. Mit -HigherFileVersionMsi: Installation eines Pakets, dessen Exe eine höhere Dateiversion hat (wie die alten
       1.0.0.x-Builds oder ein späterer CI-Build), Update mit der neuen MSI – die Exe muss danach die neue sein.
    Jede Phase und alle 15 s während eines Programms ein Commit-Status „MSI-Test (Fortschritt)“.
    Jeder msiexec-Lauf schreibt ein ausführliches Protokoll nach -LogDir; bei einem Fehler steht dessen Ende in der
    Ausgabe.

.EXAMPLE
    ./.github/scripts/msi-test.ps1 -Msi dist/Vitrine-x64.msi -SecondMsi out/msi-upgrade/Vitrine.msi -PreviousMsi prev/Vitrine-x64.msi -LogDir out/msi-logs
#>
param(
    [Parameter(Mandatory)] [string] $Msi,
    [Parameter(Mandatory)] [string] $SecondMsi,
    [string] $PreviousMsi,
    [string] $LogDir = 'out/msi-logs',
    # Dateiversion der Exe im neuen Paket (z. B. 0.1.0.42); leer = nur prüfen, dass die Exe da ist
    [string] $ExpectedFileVersion,
    # Gleiche MSI-Version, aber Exe mit höherer Dateiversion (1.0.0.0): Das Update muss sie trotzdem ersetzen
    [string] $HigherFileVersionMsi
)
$ErrorActionPreference = 'Stop'
trap { Report-Phase "Abbruch: $($_.Exception.Message)" 'failure'; break }

$service     = 'ICT-Baden.Vitrine'
$installDir  = Join-Path $env:ProgramFiles 'Vitrine'
$exe         = Join-Path $installDir 'Vitrine.exe'
$productKey  = 'HKLM:\SOFTWARE\ICT-Baden\Vitrine'
$runKey      = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
$eventSource = 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\ICT-Baden Vitrine'
$dataDir     = Join-Path $env:ProgramData 'ICT-Baden\Vitrine'
$shortcut    = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Vitrine.lnk'
$failures    = [System.Collections.Generic.List[string]]::new()

New-Item -ItemType Directory -Force $LogDir | Out-Null
$Msi = (Resolve-Path $Msi).Path
$SecondMsi = (Resolve-Path $SecondMsi).Path
if ($PreviousMsi) { $PreviousMsi = (Resolve-Path $PreviousMsi).Path }
if ($HigherFileVersionMsi) { $HigherFileVersionMsi = (Resolve-Path $HigherFileVersionMsi).Path }
$phases = 8 + [int][bool]$PreviousMsi + [int][bool]$HigherFileVersionMsi

# Zwischenstand als Commit-Status „MSI-Test (Fortschritt)“ (falls GH_TOKEN und STATUS_SHA gesetzt sind): Fällt der Runner
# mitten im Test aus, ist so trotzdem zu sehen, bis wohin er kam.
$script:phase = ''
function Report-Phase([string] $text, [string] $state = 'pending') {
    if ($text -match '^\d+/\d+') { $script:phase = $text }
    Write-Host "$(Get-Date -Format HH:mm:ss) $text"
    if (-not $env:GH_TOKEN -or -not $env:STATUS_SHA -or -not $env:GITHUB_REPOSITORY) { return }
    $short = if ($text.Length -gt 135) { $text.Substring(0, 135) } else { $text }
    try {
        gh api "repos/$env:GITHUB_REPOSITORY/statuses/$env:STATUS_SHA" -f "state=$state" -f 'context=MSI-Test (Fortschritt)' -f "description=$short" | Out-Null
    } catch { Write-Host "  (Status nicht gesetzt: $($_.Exception.Message))" }
}

function Check([bool] $ok, [string] $what) {
    if ($ok) { Write-Host "  ok    $what" }
    else { Write-Host "::error::$what"; $failures.Add($what) }
}

# Prozess starten und höchstens $seconds warten. Nicht Start-Process -Wait: Das wartet auch auf alle Nachkommen des
# Prozesses und hängt, wenn einer weiterläuft.
function Invoke-Timed([string] $file, [string[]] $arguments, [int] $seconds) {
    $started = Get-Date
    $p = Start-Process -FilePath $file -ArgumentList $arguments -PassThru
    $null = $p.Handle # sonst ist ExitCode nach dem Ende leer
    # Alle 15 s ein Lebenszeichen als Commit-Status: Bleibt es aus, ist der Runner selbst ausgefallen
    while (-not $p.WaitForExit(15000)) {
        $elapsed = [int]((Get-Date) - $started).TotalSeconds
        Report-Phase "$script:phase – $([IO.Path]::GetFileName($file)) läuft seit $elapsed s"
        if ($elapsed -lt $seconds) { continue }
        Write-Host "::error::$file lief länger als $seconds s – beendet"
        Get-Process | Where-Object { $_.ProcessName -match 'msiexec|Vitrine' } | Format-Table Id, ProcessName, SessionId, StartTime -AutoSize | Out-String | Write-Host
        try { $p.Kill($true) } catch { }
        throw "$file hängt"
    }
    Write-Host "  ($([int]((Get-Date) - $started).TotalSeconds) s)"
    return $p.ExitCode
}

function Invoke-Msi([string] $name, [string[]] $arguments) {
    $log = Join-Path $LogDir "$name.log"
    Write-Host "$(Get-Date -Format HH:mm:ss) msiexec $($arguments -join ' ')"
    $exit = Invoke-Timed msiexec.exe ($arguments + @('/qn', '/norestart', '/l*v', "`"$log`"")) 300
    # 0 = erfolgreich, 3010 = erfolgreich, Neustart nötig
    if ($exit -notin 0, 3010) {
        Get-Content $log -ErrorAction SilentlyContinue | Select-String -Pattern 'error|failed|return value 3' -CaseSensitive:$false |
            Select-Object -Last 40 | ForEach-Object { Write-Host $_.Line }
        throw "msiexec ${name}: Exitcode $exit (Protokoll $log)"
    }
    Write-Host "  ok    msiexec $name (Exitcode $exit)"
    return $exit
}

function Wait-ServiceRunning([int] $seconds = 60) {
    $deadline = (Get-Date).AddSeconds($seconds)
    do {
        $s = Get-Service $service -ErrorAction SilentlyContinue
        if ($s -and $s.Status -eq 'Running') { return $true }
        Start-Sleep -Seconds 2
    } while ((Get-Date) -lt $deadline)
    return $false
}

function Get-Value([string] $key, [string] $name) {
    (Get-ItemProperty -Path $key -Name $name -ErrorAction SilentlyContinue).$name
}

function Show-Audit {
    # Protokoll des Dienstes zur Fehlersuche (Hash-Kette, eine JSON-Zeile je Eintrag)
    Get-ChildItem (Join-Path $dataDir 'Logs') -Filter 'audit-*.jsonl' -ErrorAction SilentlyContinue |
        ForEach-Object { Get-Content $_.FullName | Select-Object -Last 25 }
}

# Einträge im Protokoll, die $text enthalten (z. B. '"Event":"AgentConnected"'), über alle Dateien
function Count-Audit([string] $text) {
    @(Get-ChildItem (Join-Path $dataDir 'Logs') -Filter 'audit-*.jsonl' -ErrorAction SilentlyContinue |
        Select-String -SimpleMatch $text -ErrorAction SilentlyContinue).Count
}

function Wait-Audit([string] $text, [int] $atLeast, [int] $seconds) {
    $deadline = (Get-Date).AddSeconds($seconds)
    do {
        if ((Count-Audit $text) -ge $atLeast) { return $true }
        Start-Sleep -Seconds 3
    } while ((Get-Date) -lt $deadline)
    return $false
}

# Sitzungen mit angemeldetem Benutzer (Explorer läuft): Dort startet der Dienst Vitrine
$userSessions = @(Get-Process explorer -ErrorAction SilentlyContinue | Where-Object SessionId -gt 0 | Select-Object -ExpandProperty SessionId -Unique)
$connectedEvent = '"Event":"AgentConnected"'

# Die App in den Sitzungen meldet sich beim Dienst ($expected-ter Eintrag), und bis $since + 75 s (über die Startfrist des
# Dienstes von 60 s hinaus) kommt keiner der Einträge, die eine fehlende oder abgebrochene Überwachung zeigen.
function Check-Supervision([int] $expected, [datetime] $since, [hashtable] $before, [string] $label) {
    if ($userSessions.Count -eq 0) {
        Write-Host "::warning::Keine angemeldete Sitzung auf dem Runner – $label nicht geprüft"
        return
    }
    Check (Wait-Audit $connectedEvent $expected 90) "${label}: Vitrine meldet sich beim Dienst (AgentConnected, Sitzung $($userSessions -join ', '))"
    $wait = 75 - [int]((Get-Date) - $since).TotalSeconds
    if ($wait -gt 0) { Start-Sleep -Seconds $wait }
    foreach ($text in $before.Keys) {
        Check ((Count-Audit $text) -eq $before[$text]) "${label}: kein neuer Eintrag $text"
    }
    $running = @(Get-Process Vitrine -ErrorAction SilentlyContinue | Where-Object SessionId -in $userSessions)
    Check ($running.Count -ge 1) "${label}: Vitrine läuft in der Sitzung des Runners ($($running.Count))"
}

# Exe nach Installation oder Update: vorhanden und mit der Version des neuen Pakets
function Check-Exe([string] $label) {
    $present = Test-Path $exe
    Check $present "${label}: Vitrine.exe vorhanden"
    if (-not $present -or -not $ExpectedFileVersion) { return }
    $actual = (Get-Item $exe).VersionInfo.FileVersion
    Check ($actual -eq $ExpectedFileVersion) "${label}: Dateiversion $actual (erwartet $ExpectedFileVersion)"
}

function Bad-Audit {
    $counts = @{}
    foreach ($text in '"Event":"AgentStartFailed"', '"Event":"AgentLost"', 'Service pipe:') { $counts[$text] = Count-Audit $text }
    return $counts
}

Check (-not (Get-Service $service -ErrorAction SilentlyContinue)) 'Vorher: kein Dienst installiert'
Write-Host 'Sitzungen auf dem Runner (Prozesse mit Sitzungsnummer):'
Get-Process -IncludeUserName -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -in 'explorer', 'winlogon', 'Runner.Worker', 'pwsh' } |
    Format-Table Id, ProcessName, SessionId, UserName -AutoSize | Out-String | Write-Host

# ---------- 1. Frische Installation mit Dienst (Standard) ----------
Report-Phase "1/$phases Installation mit Dienst (Standard)"
$bad = Bad-Audit
$null = Invoke-Msi 'install' @('/i', "`"$Msi`"")
$installed = Get-Date
Check (Wait-ServiceRunning) 'Dienst läuft (mit Überwachung)'
$svc = Get-CimInstance Win32_Service -Filter "Name='$service'"
Check ($svc.StartMode -eq 'Auto') "Dienst startet automatisch ($($svc.StartMode))"
Check ($svc.StartName -eq 'LocalSystem') "Dienst läuft als LocalSystem ($($svc.StartName))"
Check ($svc.PathName -like "*Vitrine.exe*--service*") "Befehlszeile des Dienstes ($($svc.PathName))"
Check-Exe 'Installation'
Check ((Get-Value $productKey 'Supervise') -eq 1) 'Supervise = 1'
Check ((Get-Value $productKey 'Service') -eq '1') 'Wahl SERVICE=1 gemerkt'
Check ($null -eq (Get-Value $runKey 'Vitrine')) 'Kein Autostart neben dem Dienst'
Check ($null -ne (Get-Value $eventSource 'EventMessageFile')) 'Ereignisquelle registriert'
Check (Test-Path $shortcut) 'Startmenü-Verknüpfung'
sc.exe qfailure $service | ForEach-Object { Write-Host "  $_" }
Check-Supervision 1 $installed $bad 'Installation'

# Protokoll des Dienstes (#15): signiert, Schlüssel exportiert, Benutzer dürfen den Ordner nur lesen, Prüfung grün
$logs = Join-Path $dataDir 'Logs'
Check ((Count-Audit '"V":3') -gt 0) 'Protokoll: signierte Einträge (Format 3)'
Check (Test-Path (Join-Path $logs 'audit-keys.json')) 'Protokoll: audit-keys.json mit dem öffentlichen Schlüssel'
Check ($null -ne (Get-ItemProperty 'HKLM:\SOFTWARE\ICT-Baden\Vitrine\Audit' -ErrorAction SilentlyContinue).CurrentKey) 'Protokoll: Schlüssel und Anker in der Registry'
$usersWrite = @((Get-Acl $logs).Access | Where-Object {
        $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -eq 'S-1-5-32-545' -and
        ($_.FileSystemRights -band ([Security.AccessControl.FileSystemRights]'WriteData, AppendData, Delete')) })
Check ($usersWrite.Count -eq 0) 'Protokoll: Benutzer dürfen den Ordner nur lesen'
$current = Get-ChildItem $logs -Filter 'audit-*.jsonl' | Sort-Object Name | Select-Object -Last 1
if ($current) {
    $verify = Invoke-Timed $exe @('--verify-log', "`"$($current.FullName)`"", '--quiet') 60
    Check ($verify -eq 0) "Protokoll: --verify-log $($current.Name) (Exitcode $verify)"
}

# ---------- 2. Programmdateien ----------
Report-Phase "2/$phases Programmdateien"
foreach ($f in 'Vitrine.exe', 'LICENSE', 'THIRD-PARTY-NOTICES.txt', 'policy\Vitrine.admx', 'policy\en-US\Vitrine.adml', 'policy\de-DE\Vitrine.adml') {
    Check (Test-Path (Join-Path $installDir $f)) "Datei $f"
}
# Windows-Kontobroker: genau die msalruntime.dll aus NativeInterop 0.20.4 (letzte Version unter MIT); die erwartete
# Prüfsumme steht nur in check-broker-licence.ps1
$brokerHash = [regex]::Match((Get-Content (Join-Path $PSScriptRoot 'check-broker-licence.ps1') -Raw), "\`$ExpectedHash = '([0-9a-f]{64})'").Groups[1].Value
$broker = @(Get-ChildItem $installDir -Recurse -File -Filter 'msalruntime*.dll')
$brokerActual = if ($broker.Count -eq 1) { (Get-FileHash $broker[0].FullName -Algorithm SHA256).Hash.ToLowerInvariant() } else { '' }
Check ($brokerHash.Length -eq 64 -and $broker.Count -eq 1 -and $broker[0].Name -eq 'msalruntime.dll' -and $brokerActual -eq $brokerHash) `
    "Windows-Kontobroker msalruntime.dll installiert, SHA-256 $brokerActual (erwartet $brokerHash; gefunden: $($broker.Name -join ', '))"
# Anmeldefenster für Microsoft: WebView2Loader.dll genau einmal (neben Vitrine.exe), Prüfsumme aus check-broker-licence.ps1
$loaderHash = [regex]::Match((Get-Content (Join-Path $PSScriptRoot 'check-broker-licence.ps1') -Raw), "\`$LoaderHash = '([0-9a-f]{64})'").Groups[1].Value
$loader = @(Get-ChildItem $installDir -Recurse -File -Filter 'WebView2Loader.dll')
$loaderActual = if ($loader.Count -eq 1) { (Get-FileHash $loader[0].FullName -Algorithm SHA256).Hash.ToLowerInvariant() } else { '' }
Check ($loaderHash.Length -eq 64 -and $loader.Count -eq 1 -and $loaderActual -eq $loaderHash) `
    "Anmeldefenster WebView2Loader.dll installiert, SHA-256 $loaderActual (erwartet $loaderHash; gefunden: $($loader.FullName -join ', '))"
Check (Test-Path (Join-Path $installDir 'Plugins')) 'Ordner Plugins'

# ---------- 3. Installierte Exe startet ----------
Report-Phase "3/$phases Installierte Exe im Screenshot-Modus"
$shots = Join-Path $env:RUNNER_TEMP 'vitrine-installed-shots'
$env:VITRINE_LANGUAGE = 'en'
$exit = Invoke-Timed $exe @('--screenshots', "`"$shots`"", '--theme', 'light') 180
Get-ChildItem $shots -Recurse -Filter error.txt -ErrorAction SilentlyContinue | ForEach-Object { Get-Content $_.FullName }
$images = @(Get-ChildItem $shots -Recurse -Filter '*.png' -ErrorAction SilentlyContinue)
Check ($exit -eq 0 -and $images.Count -gt 0) "Installierte Exe startet (Exitcode $exit, $($images.Count) Bilder)"
Show-Audit
Write-Host 'Vitrine-Prozesse vor dem Update:'
Get-Process Vitrine -ErrorAction SilentlyContinue | Format-Table Id, SessionId, StartTime -AutoSize | Out-String | Write-Host

# ---------- 4. Update mit Dienst (Standard), ohne Eigenschaften ----------
Report-Phase "4/$phases Update mit Dienst ohne Eigenschaften"
$connected = Count-Audit $connectedEvent
$exit = Invoke-Msi 'upgrade-service1' @('/i', "`"$SecondMsi`"")
# 3010 hieße: Dateien in Benutzung (z. B. eine vom alten Dienst neu gestartete App), neue Exe erst nach Neustart
Check ($exit -eq 0) "Update ohne Neustart (Exitcode $exit)"
$upgraded = Get-Date
$bad = Bad-Audit # Das Update beendet die App; das darf vorkommen
Check (Wait-ServiceRunning) 'Update: Dienst läuft wieder'
Check-Exe 'Update'
Check ((Get-Value $productKey 'Supervise') -eq 1) 'Update: Supervise bleibt 1'
Check ($null -eq (Get-Value $runKey 'Vitrine')) 'Update: kein Autostart neben dem Dienst'
$products = @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' |
    Where-Object { (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).DisplayName -eq 'Vitrine' })
Check ($products.Count -eq 1) "Update: genau eine Vitrine-Installation ($($products.Count))"
Check-Supervision ($connected + 1) $upgraded $bad 'Update'
Show-Audit

# ---------- 5. Deinstallation ----------
Report-Phase "5/$phases Deinstallation"
$null = Invoke-Msi 'uninstall' @('/x', "`"$SecondMsi`"")
Start-Sleep -Seconds 2
Check (-not (Get-Service $service -ErrorAction SilentlyContinue)) 'Dienst entfernt'
Check (-not (Test-Path $exe)) 'Vitrine.exe entfernt'
Check (-not (Test-Path $installDir) -or @(Get-ChildItem $installDir -Recurse -File).Count -eq 0) 'Programmordner leer oder entfernt'
foreach ($name in 'Supervise', 'Service', 'Autostart', 'StartMenuShortcut') {
    Check ($null -eq (Get-Value $productKey $name)) "Registry-Wert $name entfernt"
}
Check ($null -eq (Get-Value $runKey 'Vitrine')) 'Autostart entfernt'
Check ($null -eq (Get-Value $eventSource 'EventMessageFile')) 'Ereignisquelle entfernt'
Check (-not (Test-Path $shortcut)) 'Startmenü-Verknüpfung entfernt'
Check (-not (Get-Process Vitrine -ErrorAction SilentlyContinue)) 'Kein Vitrine-Prozess mehr'
# Win+L: Vitrines DisableLockWorkstation (erkennbar am Merkwert) in keinem geladenen Benutzerprofil zurückgelassen
$winLockLeft = @(Get-ChildItem Registry::HKEY_USERS -ErrorAction SilentlyContinue |
    Where-Object { $_.PSChildName -like 'S-1-*' -and $_.PSChildName -notlike '*_Classes' } |
    Where-Object { $null -ne (Get-ItemProperty "Registry::$($_.Name)\Software\ICT-Baden\Vitrine\State" -Name 'DisableLockWorkstationBefore' -ErrorAction SilentlyContinue) })
Check ($winLockLeft.Count -eq 0) "Kein DisableLockWorkstation von Vitrine in geladenen Profilen ($($winLockLeft.PSChildName -join ', '))"
# Bewusst behalten (docs/installation.md): Konfiguration und Protokolle
Check (Test-Path $dataDir) 'Daten unter %ProgramData%\ICT-Baden\Vitrine bleiben erhalten'
# Strg+Alt+Entf-Einschränkungen des angemeldeten Benutzers und Richtlinien: nichts zurückgelassen
foreach ($v in @(('System', 'DisableTaskMgr'), ('System', 'DisableChangePassword'), ('Explorer', 'NoLogoff'))) {
    Check ((Get-Value "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\$($v[0])" $v[1]) -ne 1) "Kein $($v[1]) zurückgelassen"
}
Check (-not (Test-Path 'HKLM:\SOFTWARE\Policies\ICT-Baden\Vitrine')) 'Keine Richtlinienwerte (HKLM) angelegt'

# ---------- 6. Installation ohne Überwachung ----------
Report-Phase "6/$phases Installation mit SERVICE=0 AUTOSTART=1"
$null = Invoke-Msi 'install-service0' @('/i', "`"$Msi`"", 'SERVICE=0', 'AUTOSTART=1')
Check (Wait-ServiceRunning) 'Dienst läuft (ohne Überwachung)'
Check ((Get-Value $productKey 'Supervise') -eq 0) 'Supervise = 0'
Check ((Get-Value $productKey 'Service') -eq '0') 'Wahl SERVICE=0 gemerkt'
Check ((Get-Value $runKey 'Vitrine') -eq "`"$exe`" --autostart") 'Autostart für alle Benutzer mit --autostart'

# ---------- 7. Update ohne Eigenschaften behält die Wahl ----------
Report-Phase "7/$phases Update ohne Eigenschaften (SERVICE=0)"
$null = Invoke-Msi 'upgrade-remembered' @('/i', "`"$SecondMsi`"")
Check (Wait-ServiceRunning) 'Update: Dienst läuft (ohne Überwachung)'
Check-Exe 'Update (SERVICE=0)'
Check ((Get-Value $productKey 'Supervise') -eq 0) 'Update: Supervise bleibt 0'
Check ($null -ne (Get-Value $runKey 'Vitrine')) 'Update: Autostart bleibt'
$products = @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' |
    Where-Object { (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).DisplayName -eq 'Vitrine' })
Check ($products.Count -eq 1) "Update: genau eine Vitrine-Installation ($($products.Count))"

# ---------- 8. Deinstallation des aktualisierten Stands ----------
Report-Phase "8/$phases Deinstallation nach dem Update"
$null = Invoke-Msi 'uninstall-after-upgrade' @('/x', "`"$SecondMsi`"")
Check (-not (Get-Service $service -ErrorAction SilentlyContinue)) 'Nach dem Update: Dienst entfernt'
Check ($null -eq (Get-Value $runKey 'Vitrine')) 'Nach dem Update: Autostart entfernt'

# ---------- 9. Update von der zuletzt veröffentlichten MSI ----------
if ($PreviousMsi) {
    Report-Phase "9/$phases Update von der veröffentlichten MSI (SERVICE=0 AUTOSTART=0)"
    $previousOk = $true
    try { $null = Invoke-Msi 'previous-install' @('/i', "`"$PreviousMsi`"", 'SERVICE=0', 'AUTOSTART=0') }
    catch {
        # Schon veröffentlicht: ein Fehler dort hält den neuen Stand nicht auf, soll aber auffallen
        Write-Host "::warning::Die zuletzt veröffentlichte MSI ließ sich nicht installieren: $($_.Exception.Message)"
        $previousOk = $false
    }
    if ($previousOk) {
        Check ((Get-Value $productKey 'Supervise') -eq 0) 'Vorgänger: Supervise = 0'
        $null = Invoke-Msi 'previous-upgrade' @('/i', "`"$Msi`"")
        Check-Exe 'Update vom Vorgänger'
        Check (Wait-ServiceRunning) 'Update vom Vorgänger: Dienst läuft'
        Check ((Get-Value $productKey 'Supervise') -eq 0) 'Update vom Vorgänger: Supervise bleibt 0 (SERVICE=0 erkannt)'
        Check ((Get-Value $productKey 'Service') -eq '0') 'Update vom Vorgänger: Wahl SERVICE=0 jetzt gemerkt'
        Check ($null -eq (Get-Value $runKey 'Vitrine')) 'Update vom Vorgänger: kein Autostart (AUTOSTART=0 erkannt)'
        Check ((Get-Value $productKey 'Autostart') -eq '0') 'Update vom Vorgänger: Wahl AUTOSTART=0 jetzt gemerkt'
        $null = Invoke-Msi 'previous-uninstall' @('/x', "`"$Msi`"")
        Check (-not (Get-Service $service -ErrorAction SilentlyContinue)) 'Update vom Vorgänger: Dienst nach Deinstallation entfernt'
    }
}

# ---------- 10. Update über eine Exe mit höherer Dateiversion ----------
if ($HigherFileVersionMsi) {
    Report-Phase "$phases/$phases Update über eine Exe mit höherer Dateiversion"
    $null = Invoke-Msi 'highver-install' @('/i', "`"$HigherFileVersionMsi`"", 'SERVICE=0', 'AUTOSTART=0')
    Check ((Get-Item $exe -ErrorAction SilentlyContinue).VersionInfo.FileVersion -eq '1.0.0.0') 'Höhere Dateiversion installiert (1.0.0.0)'
    $null = Invoke-Msi 'highver-upgrade' @('/i', "`"$Msi`"")
    Check-Exe 'Update über höhere Dateiversion'
    Check (Wait-ServiceRunning) 'Update über höhere Dateiversion: Dienst läuft'
    $null = Invoke-Msi 'highver-uninstall' @('/x', "`"$Msi`"")
    Check (-not (Test-Path $exe)) 'Update über höhere Dateiversion: Exe nach Deinstallation entfernt'
}

if ($failures.Count -gt 0) {
    Show-Audit
    Report-Phase "$($failures.Count) Prüfungen fehlgeschlagen: $($failures -join '; ')" 'failure'
    throw "$($failures.Count) Prüfungen fehlgeschlagen: $($failures -join '; ')"
}
Report-Phase 'Installation, Update und Deinstallation in Ordnung' 'success'
