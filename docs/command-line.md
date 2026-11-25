[Vitrine](../README.md) › Command line

# Command line

`Vitrine.exe` is a Windows program with a user interface. A few switches let it lock, open the settings, check an audit log or do an administrative task – for shortcuts, deployment scripts and scheduled tasks.

**Contents:** [Overview](#overview) · [Starting and the running instance](#starting-and-the-running-instance) · [Switches](#switches) · [Exit codes](#exit-codes) · [Waiting for the result](#waiting-for-the-result) · [Screen saver](#screen-saver) · [Environment variable VITRINE_LANGUAGE](#environment-variable-vitrine_language) · [Examples](#examples)

## Overview

```text
Vitrine.exe                                   start in the notification area
Vitrine.exe --lock                            lock now
Vitrine.exe --settings                        open the settings
Vitrine.exe --verify-log <file|folder> [--keys <file>] [--quiet]   verify an audit log file or folder (signatures, chain, anchors)
Vitrine.exe --export-audit-key [<file>]       public key and anchors of the audit log for a reviewer
Vitrine.exe --rotate-audit-key                new key of the audit log (as administrator, service must run)
Vitrine.exe --register-eventlog               register the event source (administrator)
Vitrine.exe --authorization-report <file> [--quiet]   authorization report as HTML (+ CSV) or CSV
Vitrine.exe --screenshots <folder> [--theme dark]   draw the documentation screenshots
Vitrine.scr /s | /c | /p                      screen saver mode (Vitrine.exe renamed to .scr)

internal, started by Vitrine itself:
Vitrine.exe --apply-config <file> --sha256 <hex>   save the settings with administrator rights
Vitrine.exe --watchdog <pid>                  watchdog process
Vitrine.exe --service                         the Windows service
Vitrine.exe --agent [--lock]                  started by the service in a session
Vitrine.exe --autostart                       started by an autostart entry (Run key)
```

- Switches are not case-sensitive. A switch that needs a value (`--verify-log`, `--apply-config`, `--watchdog`, `--screenshots`) is ignored without one, and Vitrine starts normally.
- Unknown switches are ignored without a message.
- There is no `--help` or `--version`. Version and build are in the **About Vitrine** window ([Usage](usage.md#about-window-and-language)); Settings › About › *Command line* shows a short reference.
- Messages and dialogs appear in the language of the user interface; the audit log stays English.

## Starting and the running instance

Only **one instance runs per Windows session** (mutex `Local\ICT-Baden.Vitrine.SingleInstance`). When Vitrine is already running in the session, a second start hands its request to the running instance over the local interface (`\\.\pipe\ICT-Baden.Vitrine.<session>`) and ends. It hands over only if the process serving the pipe (checked with `GetNamedPipeServerProcessId`) is the same file or another Vitrine build of the same publisher (version information: product *Vitrine*, company *ICT Baden GmbH*, or *ICT-Baden* as in builds up to 0.5.1) – e.g. the `.scr` copy for the screen saver. If the hand-over fails (another program owns the pipe name or the running instance does not answer), `--lock` and the screen saver lock **Windows** instead, so a lock request is never lost; a settings request is dropped:

| Call | Vitrine not running | Vitrine already running |
|---|---|---|
| `Vitrine.exe` | starts in the notification area | the running instance opens its settings |
| `Vitrine.exe --lock` | starts and locks at once (trigger `startup`) | the running instance locks (trigger `api`) |
| `Vitrine.exe --settings` | starts and opens the settings | the running instance opens its settings |

`lock` and `settings` are always accepted by the running instance, also when *Local interface (named pipe)* (`Integration.PipeEnabled`) is off. Opening the settings asks for an administrator when *Settings for administrators only* is on and the user is not one. While locked, the settings do not open.

`--verify-log`, `--export-audit-key`, `--rotate-audit-key`, `--register-eventlog`, `--authorization-report`, `--apply-config`, `--watchdog` and `--screenshots` run on their own, also next to a running instance, and end when they are done.

## Switches

### `--lock`

Locks immediately with the configured appearance (`Appearance.Visual`). See the table above for what happens when Vitrine is already running. In the audit log the trigger is `startup` or `api`.

### `--settings`

Opens the settings window – same as the gear icon in the flyout.

### `--verify-log <file|folder> [--keys <file>]`

Checks one audit log file (`audit-yyyy-MM.jsonl`, also a network copy `<COMPUTER>-audit-yyyy-MM.jsonl`) or all monthly files of a folder and shows the result in a message box. Signed lines (format 3, written by the service) are checked with the public keys from `--keys` (a file from `--export-audit-key`), otherwise from `audit-keys.json` next to the file, otherwise from the registry of this computer; on the computer that wrote the log, the anchors of the service are checked too (cut-off end, deleted or swapped file) – details in [Audit log › Verifying](audit-log.md#verifying):

- *Audit log intact* – *Entries: N · chain complete · n signed by the service (key …)*, exit code **0**. Lines without signature (format 1/2) are counted as *not signed*.
- *Audit log changed!* – the first line that does not fit, exit code **2**:
  - `Line N cannot be read. (VIT-0020)`
  - `Line N (sequence S): chain broken – the entry before it is missing or was changed. (VIT-0021)`
  - `Line N (sequence S): the content was changed. (VIT-0022)`
  - `The log file cannot be read: … (VIT-0023)` – also exit code 2.
  - format 3: VIT-0301 to VIT-0310 (signature, key, sequence, anchor, missing file, month, unsigned line) – [Error codes](error-codes.md#vit-03xx--audit-service-and-signed-audit-log).

### `--export-audit-key [<file>]`

Writes the public keys of the audit log of this computer (ID, SHA-256 fingerprint, SubjectPublicKeyInfo) and the current anchors (last sequence number and hash per month) to `<file>`, as JSON in the format of `audit-keys.json`, and shows the fingerprint; without a file it only shows the fingerprint. No administrator rights needed; nothing secret is exported. Use the file with `--verify-log … --keys <file>` on another computer, and record the fingerprint in your validation documents. Exit code **0**, **1** if the service has not created a key yet (no service, or `SERVICE=0`; message VIT-0310) or the file cannot be written.

### `--rotate-audit-key`

Asks the service to create a new key for the audit log. The service writes an `AuditKeyRotated` entry with the new public key, signed with the old key, and signs everything after it with the new one; `audit-keys.json` then lists both. Must be started **as administrator** (VIT-0142 otherwise); the service must be running (VIT-0300). Shows the new fingerprint; exit code **0**, **1** on failure.
Every Windows user who can read the file can check it; no administrator rights are needed. The message box waits until it is closed. With `--quiet` there is no message box, only the exit code – use that in scheduled tasks and monitoring. A chain break does not always mean tampering: a last line that could not be read, lines from the per-user fallback folder in a network copy, or the switch from an earlier build also break the chain (several sessions writing into the same file no longer do) – see [Audit log](audit-log.md) and [Installation › Upgrading](installation.md#upgrading-from-earlier-builds-100-and-older).

### `--register-eventlog`

Registers the event source `ICT-Baden Vitrine` in the Windows *Application* log, if it does not exist yet. Needed only without MSI or script, e.g. for the single `Vitrine.exe`. Needs administrator rights and does **not** request them itself – start it from an elevated prompt. Shows *Event source “ICT-Baden Vitrine” registered.* and ends with exit code **0**; on failure it shows the error with `VIT-0009` and ends with **1**.

### `--authorization-report <file> [--quiet]`

Writes the [authorization report](roles-and-governance.md#authorization-report): who may unlock, emergency sign-in
groups, roles with their current group members, sign-in methods and whether each value comes from policy – in the
language of the user interface (`VITRINE_LANGUAGE` works). If `<file>` ends in `.csv`, only CSV is written; otherwise
HTML into `<file>` and CSV next to it with the same name and `.csv`. The generating account (the account running the
command) is named in the report.

With `Security.SettingsAdminOnly` on (default), only a configuration administrator or auditor may run it (checked with
the groups of the running account, no dialog; VIT-0431 otherwise). Shows a message unless `--quiet` is given. Needs no
administrator rights, and resolving domain groups needs access to a domain controller.

### `--screenshots <folder> [--theme light|dark]`

Draws every window of the real application with sample data as PNG files: `settings-<page>-<light|dark>.png` for the nine settings pages (`home`, `lock`, `unlock`, `look`, `security`, `entra`, `audit`, `integration`, `info`), `about-*`, `tray-*`, `unlock-*`, `unlock-error-*`, `sign-*`, `sign-entra-*`, `lock-*`, `lock-masked-*` and `blank-*`. Paths in the pictures are the defaults of an installation, not those of the computer that draws them. One run draws one language (the UI language, e.g. set with `VITRINE_LANGUAGE`) and one colour scheme (`--theme`, default light). English goes to `<folder>` (the source of `docs/assets/screenshots`), every other language to `<folder>\<language>`.

This mode never locks, installs no keyboard or mouse hooks, and neither reads nor writes the real configuration or audit log; it works in a temporary folder that it deletes afterwards. Exit code **0**, or **1** on an error (written to standard error). Details: [Development](development.md).

### `--apply-config <file>` (internal)

Full form: `--apply-config <file> --sha256 <hex>`. Used by the settings window to save when the user may not write `%ProgramData%\ICT-Baden\Vitrine`: Vitrine writes the configuration to a temporary file, computes its SHA-256 and starts itself elevated through UAC with both. The elevated process writes only if the SHA-256 of the file matches `<hex>` (hex, not case-sensitive) – so the temporary file in the user's folder cannot be swapped after the UAC prompt. Without `--sha256` or with a different checksum, nothing is written and *The configuration was not applied: it was changed after the administrator approved it. (VIT-0014)* appears. Then the file is checked; if it is not valid, nothing is written and *The configuration file is not valid: … (VIT-0008)* appears. When saving, Vitrine secures the folder and the folder above it if needed (owner Administrators; Administrators and SYSTEM full control, Users read), refuses junctions, writes a new file and makes Administrators its owner – see [Settings › File locations](settings.md#file-locations). Exit code **0** when saved, **1** otherwise; the settings window then shows *Saving failed: exit 1 (VIT-0006)* instead of *Saved*. The switch is internal; use `deploy\install.ps1 -Config` or a policy in your own scripts.

### `--service` (internal)

Runs Vitrine as the Windows service *ICT-Baden Vitrine*; only the Service Control Manager starts it this way
([Installation › Service](installation.md#service)).

### `--agent` (internal)

Set by the service when it starts Vitrine in a session. If Vitrine already runs in the session, the new process exits
quietly instead of opening the settings of the running one. Combined with `--lock` after Vitrine ended while locked.

### `--autostart` (internal)

Written into the autostart entries (`HKLM\…\Run` of the MSI with `SERVICE=0` and of `install.ps1 -NoService`, and
`HKCU\…\Run` of *Start with Windows*). Like `--agent`: if Vitrine already runs in the session – for example started by
the service – the new process exits quietly instead of opening the settings (or the administrator prompt) of the
running one. Entries written by builds before 2026-10-20 have no switch; when the service supervises Vitrine, Vitrine
removes the per-user entry.

### `--watchdog <pid>` (internal)

The watchdog process that Vitrine starts for itself when *Watchdog* (`Security.Watchdog`) is on. Vitrine reports every lock and unlock to it through its standard input; the file `%LocalAppData%\Vitrine\locked` is only a fallback if nothing arrived that way, so deleting the file does not stop the watchdog. If the process `<pid>` ends while locked, the watchdog locks Windows and restores the Ctrl+Alt+Del menu and the mouse pointers. Do not start it yourself.

## Exit codes

| Switch | `0` | `1` | `2` |
|---|---|---|---|
| `--verify-log <file|folder>` | chain complete | – | changed, unreadable line, file not readable or missing |
| `--export-audit-key [<file>]` | exported | no key or not written | – |
| `--rotate-audit-key` | new key | not administrator, service not reachable or failed | – |
| `--register-eventlog` | registered or already present | failed (e.g. no administrator rights) | – |
| `--authorization-report <file>` | written | no file given, not written (VIT-0435) or no role (VIT-0431) | – |
| `--apply-config <file> --sha256 <hex>` | saved | checksum wrong (VIT-0014), not valid (VIT-0008) or not saved | – |
| `--screenshots <folder>` | all images drawn | error | – |

Normal starts, `--lock` and `--settings` have no meaningful exit code.

## Waiting for the result

Because `Vitrine.exe` is a Windows program, `cmd.exe` does not wait for it and `%ERRORLEVEL%` stays empty. Wait explicitly:

```bat
start "" /wait "C:\Program Files\Vitrine\Vitrine.exe" --verify-log "C:\ProgramData\ICT-Baden\Vitrine\Logs\audit-2026-10.jsonl"
echo %ERRORLEVEL%
```

```powershell
$p = Start-Process "$env:ProgramFiles\Vitrine\Vitrine.exe" -ArgumentList '--verify-log', '"C:\ProgramData\ICT-Baden\Vitrine\Logs\audit-2026-10.jsonl"' -Wait -PassThru
$p.ExitCode   # 0 = intact, 2 = changed
```

## Screen saver

Copy `Vitrine.exe` to `Vitrine.scr` and choose it as the screen saver. Windows then calls it with these parameters:

| Parameter | Effect |
|---|---|
| `/s` | Locks at once, without a notification area icon, and ends Vitrine after unlocking. Trigger in the audit log: `screensaver`. If Vitrine is already running in the session, only the running instance locks. |
| `/c` | Opens the settings (of the running instance, if there is one). |
| `/p` | Preview in the Windows dialog: Vitrine ends at once and shows nothing. |

- On its own, only the **single file** `Vitrine.exe` from the release works as a `.scr`. A copy from the MSI installation or the ZIP needs the files next to it (the libraries and, for the MSI installation, the runtime files) – so create the `.scr` in the same folder, e.g. `%ProgramFiles%\Vitrine\Vitrine.scr`. The MSI does not know this file and does not remove it on uninstall.
- Plugins are loaded from the `Plugins` folder next to the `.scr`.
- Centrally, the screen saver can be set with the Windows policy *Force specific screen saver* (User Configuration › Administrative Templates › Control Panel › Personalization). With *Keep the screen on* (`Lock.KeepAwake`, default on) the screen saver does not start again while Vitrine is locked.

## Environment variable VITRINE_LANGUAGE

`VITRINE_LANGUAGE` sets the language of the user interface for one start and overrides everything else – also the policy *Language of the user interface*. Values: `en`, `de`, `es`, `fr`, `zh-Hans`. Culture names are mapped to these (`de-AT` → `de`, `zh-CN` and `zh` → `zh-Hans`); an unknown value is ignored. Meant for tests, screenshots and special cases, not for normal operation – use the [About window or the policy](usage.md#about-window-and-language) for that.

```bat
set VITRINE_LANGUAGE=fr
"C:\Program Files\Vitrine\Vitrine.exe" --settings
```

The variable only affects the started process. If Vitrine is already running, the second start hands its request over to the running instance, which keeps its language.

## Examples

**Lock every weekday at 18:00 with a scheduled task.** The built-in *Schedule* (Settings › Lock, `Lock.Schedule`) does the same without a task and is the simpler way. If you prefer Task Scheduler, the task must run **in the user's session** (only when the user is logged on), because Vitrine runs per session:

```bat
schtasks /create /tn "Vitrine lock 18:00" /sc weekly /d MON,TUE,WED,THU,FRI /st 18:00 /it ^
  /tr "\"C:\Program Files\Vitrine\Vitrine.exe\" --lock"
```

To roll this out to many users, create the task through Group Policy Preferences (*User Configuration › Preferences › Control Panel Settings › Scheduled Tasks*) running as the logged-on user.

**Lock at sign-in on a control-room PC** – no task needed: set *Lock immediately at startup* (`Lock.LockOnStartup`); with the MSI autostart Vitrine locks right after sign-in.

**Register the event source after copying the single exe** (elevated prompt):

```bat
start "" /wait C:\Tools\Vitrine\Vitrine.exe --register-eventlog
```

**Quarterly authorization report for review** (scheduled task as an account in `Roles.Auditors`):

```powershell
$out = "\\fileserver\qa$\Vitrine\$env:COMPUTERNAME-authorizations-$(Get-Date -Format yyyy-MM-dd).html"
$p = Start-Process "$env:ProgramFiles\Vitrine\Vitrine.exe" -ArgumentList '--authorization-report', "`"$out`"", '--quiet' -Wait -PassThru
if ($p.ExitCode -ne 0) { Write-Warning "Report not written ($($p.ExitCode))" }
```

**Check last month's audit log and the network copy** (with `--quiet`, suitable for a scheduled task):

```powershell
$exe  = "$env:ProgramFiles\Vitrine\Vitrine.exe"
$month = (Get-Date).ToUniversalTime().AddMonths(-1).ToString('yyyy-MM', [Globalization.CultureInfo]::InvariantCulture)   # UTC month, Gregorian
$files = @(
    "$env:ProgramData\ICT-Baden\Vitrine\Logs\audit-$month.jsonl"
    "\\fileserver\audit$\Vitrine\LAB-PC-07-audit-$month.jsonl"
)
foreach ($f in $files | Where-Object { Test-Path $_ }) {
    $p = Start-Process $exe -ArgumentList '--verify-log', "`"$f`"", '--quiet' -Wait -PassThru
    '{0}  {1}' -f $(if ($p.ExitCode -eq 0) { 'intact ' } else { 'CHANGED' }), $f
}
```

> [!NOTE]
> Without `--quiet`, `--verify-log` shows a message box and waits until it is closed – a scheduled task without a logged-on user would hang. Always add `--quiet` there.
