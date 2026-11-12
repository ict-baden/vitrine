[Vitrine](../README.md) › Installation

# Installation

Which file to download, how to check it, how to roll it out, and what changes when you upgrade from an earlier build.

**Contents:** [Requirements](#requirements) · [Downloads](#downloads) · [Verifying the download](#verifying-the-download) · [MSI installer](#msi-installer) · [Script installation](#script-installation-installps1) · [Folder permissions](#folder-permissions) · [Deploying with Intune or Group Policy](#deploying-with-intune-or-group-policy) · [ADMX templates](#admx-templates-for-group-policy-and-intune) · [Single exe](#single-exe-without-installation) · [Autostart](#autostart) · [Upgrading from earlier builds](#upgrading-from-earlier-builds-100-and-older) · [Pitfalls](#pitfalls-for-administrators) · [Test checklist](#tested-so-far--still-to-test-on-real-devices)

> [!IMPORTANT]
> **Not code-signed yet, not yet tested on real devices.** Vitrine 0.5.1 is built and unit-tested in GitHub Actions (the Windows build nightly when `main` changed), but it has not been tested end to end on real devices yet – see the [checklist](#tested-so-far--still-to-test-on-real-devices). Program and MSI are signed as soon as code signing is set up for ICT-Baden; until then Windows SmartScreen warns when you start them. Check the files against `SHA256SUMS.txt` – see [Verifying the download](#verifying-the-download).

## Requirements

| Topic | Requirement |
|---|---|
| **Operating system** | 64-bit Windows 10 version 1809 (build 17763) or later, or Windows 11. Builds are produced for `win-x64` only. |
| **.NET** | None for the MSI and for `Vitrine.exe` – both carry the .NET 10 runtime. The ZIP needs the [.NET 10 Desktop Runtime](https://dotnet.microsoft.com/download/dotnet/10.0). |
| **Rights** | Installing needs administrator rights. Vitrine itself runs as a normal user process in the session of the signed-in user. |
| **Network** | Only for the Microsoft Entra ID sign-in (to Microsoft) and for an optional copy of the audit log on a network share. See [Data and privacy](data-and-privacy.md). |

## Downloads

The **current version** is the release marked *Latest* on the [Releases page](https://github.com/ict-baden/vitrine/releases/latest) (for example `v0.1.0`). **[latest](https://github.com/ict-baden/vitrine/releases/tag/latest)** (a pre-release) is the newest full build of `main`, updated in place – nightly when `main` changed, so it is at most a day behind. Its file names never change, so these links always give the newest build:

| File | Runtime | Use it for |
|---|---|---|
| [`Vitrine-x64.msi`](https://github.com/ict-baden/vitrine/releases/download/latest/Vitrine-x64.msi) | included | Installing for all users of a PC, also through Intune or Group Policy. **Recommended.** |
| [`Vitrine.exe`](https://github.com/ict-baden/vitrine/releases/download/latest/Vitrine.exe) | included | Trying Vitrine without installation. Not recommended for operation – see [Single exe](#single-exe-without-installation). |
| [`Vitrine-win-x64-framework.zip`](https://github.com/ict-baden/vitrine/releases/download/latest/Vitrine-win-x64-framework.zip) | .NET 10 Desktop Runtime | Program files plus `deploy\install.ps1`, the ADMX templates in `policy\`, `LICENSE`, `THIRD-PARTY-NOTICES.txt` and `README.md`. For the [script installation](#script-installation-installps1). |
| [`SHA256SUMS.txt`](https://github.com/ict-baden/vitrine/releases/download/latest/SHA256SUMS.txt) | – | SHA-256 checksums of all files in the release. |
| [`Vitrine-sbom.cdx.json`](https://github.com/ict-baden/vitrine/releases/download/latest/Vitrine-sbom.cdx.json) | – | Bill of materials (CycloneDX) of the components in the program. |

Builds from `main` carry versions like `0.1.0-ci.12` (12 = the number of the build run); the MSI gets the product version `0.1.0.12`. A **tagged version** `v0.1.0` gets its own release whose file names contain the version: `Vitrine-0.1.0-x64.msi`, `Vitrine-0.1.0.exe`, `Vitrine-0.1.0-win-x64-framework.zip`, `Vitrine-0.1.0-sbom.cdx.json`, plus `SHA256SUMS.txt`. It becomes *Latest*, and the rolling `latest` becomes a pre-release. Tags with a hyphen (`v0.1.0-rc1`) are marked as pre-releases.

There is no self-contained ZIP and no ZIP with the sample plugin any more; the [sample plugin](plugins.md) is available as source code in the repository.

The installed version and build (commit) are shown in the **About Vitrine** window – see [Usage › About window](usage.md#about-window-and-language).

## Verifying the download

Until the files are code-signed, the checksum is the only way to make sure a download is the file the build produced. Each release has a `SHA256SUMS.txt` with one line per file: the checksum and the file name.

**PowerShell** – compare one file:

```powershell
(Get-FileHash .\Vitrine-x64.msi -Algorithm SHA256).Hash.ToLower()
Select-String Vitrine-x64.msi .\SHA256SUMS.txt
```

Or check every file of the release that is in the current folder:

```powershell
Get-Content .\SHA256SUMS.txt | ForEach-Object {
    $hash, $name = $_ -split '\s+', 2
    if (Test-Path $name) {
        $ok = (Get-FileHash $name -Algorithm SHA256).Hash -eq $hash
        '{0}  {1}' -f $(if ($ok) { 'OK  ' } else { 'FAIL' }), $name
    }
}
```

**Linux, macOS or Git Bash** – `SHA256SUMS.txt` uses LF line endings, so `sha256sum` reads it directly:

```bash
sha256sum -c --ignore-missing SHA256SUMS.txt
```

**SmartScreen.** On the first start Windows may show *Windows protected your PC*. After checking the checksum, choose *More info › Run anyway*. In managed environments, AppLocker or WDAC may block unsigned programs entirely; allow the files by hash until signed builds are available.

## MSI installer

```powershell
msiexec /i Vitrine-x64.msi /qn                # silent, with the service (starts Vitrine at every sign-in)
msiexec /i Vitrine-x64.msi /qn SERVICE=0      # without supervision: autostart through HKLM\...\Run as before
msiexec /i Vitrine-x64.msi /qn SERVICE=0 AUTOSTART=0   # neither service supervision nor autostart
msiexec /x Vitrine-x64.msi /qn                # remove (configuration and audit logs remain)
```

**What the MSI sets up:**

| What | Where |
|---|---|
| Program files, licence texts and the ADMX templates | `%ProgramFiles%\Vitrine`, ADMX/ADML in `%ProgramFiles%\Vitrine\policy` |
| Empty plugin folder, writable by administrators only | `%ProgramFiles%\Vitrine\Plugins` – important for [plugins](plugins.md) |
| Device configuration folder with protected permissions | `%ProgramData%\ICT-Baden\Vitrine` |
| Audit log folder with protected permissions | `%ProgramData%\ICT-Baden\Vitrine\Logs` |
| Event source `ICT-Baden Vitrine` in the *Application* log | `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\ICT-Baden Vitrine` |
| Service *ICT-Baden Vitrine* (`ICT-Baden.Vitrine`, LocalSystem, automatic, restarted by Windows after a failure) | `"%ProgramFiles%\Vitrine\Vitrine.exe" --service`; `HKLM\SOFTWARE\ICT-Baden\Vitrine`, value `Supervise` (`0` with `SERVICE=0`) and the remembered options `Service`, `Autostart` |
| Autostart for all users (only with `SERVICE=0`, unless `AUTOSTART=0`) | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, value `Vitrine` = `"…\Vitrine.exe" --autostart` |
| Start menu shortcut *Vitrine* for all users | marker value under `HKLM\SOFTWARE\ICT-Baden\Vitrine` |

Permissions of the data folders: see [Folder permissions](#folder-permissions).

- The MSI is x64 and installs per machine (for all users). It has no dialogs: options such as `AUTOSTART` are passed on the command line only. A `config.json` cannot be passed to the MSI – use [policies](#admx-templates-for-group-policy-and-intune), the [script](#script-installation-installps1) or the settings window.
- Before installing, the MSI closes running `Vitrine.exe` processes (with the service running, a locked session is disconnected first, see [Service](#service)).
- **With the service (default) Vitrine starts right away:** the MSI starts the service, and the service starts Vitrine in every session that is signed in – also during a silent rollout by Intune or GPO. If `Lock.LockOnStartup` is already set (policy or `config.json`), those sessions are **locked at once**. Roll out that policy after the MSI, or tell the users. With `SERVICE=0` the MSI does not start Vitrine; the autostart takes effect at the next sign-in (to start at once: Start menu › Vitrine).
- The MSI starts the service **without waiting** for it to be running: if the service itself fails, the installation still completes, Windows restarts the service, and the reason is in the audit log and the event log. Only if the service cannot be registered at all does the installation roll back.
- **Uninstalling** stops and removes the service and removes the program files, the event source, the autostart and the shortcut. The folders `%ProgramData%\ICT-Baden\Vitrine` and `…\Logs` with the configuration and the audit logs stay, as do older folders from earlier builds (`%ProgramData%\Vitrine`).
- `msiexec /x <file>` only removes the build that is in that exact MSI file, because every build gets its own product code. With a different MSI file it ends with error 1605 (*This action is only valid for products that are currently installed*). Remove it through *Settings › Apps* or with `msiexec /x {ProductCode}` instead.

**Updates.** A newer MSI replaces an older one automatically (major upgrade, same upgrade code). CI builds of the same base version replace each other in both directions – an older CI build also overwrites a newer one without a message. A tagged release `v0.1.1` is always newer than every `0.1.0` CI build. Installing a lower version over a higher one (e.g. a 0.1.0 MSI over 0.1.1) ends with *A newer version of Vitrine is already installed.* The [earlier 1.0.0 builds](#upgrading-from-earlier-builds-100-and-older) are the exception: the MSI replaces them although their version number is higher.

> [!NOTE]
> The MSI remembers `SERVICE` and `AUTOSTART` (values `Service` and `Autostart` under `HKLM\SOFTWARE\ICT-Baden\Vitrine`):
> an update without these properties keeps the choice of the first installation; a value on the command line wins.
> Installations from the MSIs published before (without these values) are recognised by the value `Supervise` and by
> the autostart entry: `SERVICE=0` stays, and `AUTOSTART=0` stays if there was no autostart entry. The CI tests this
> update from the last published MSI.

Building the MSI yourself: [Development](development.md).

## Script installation (`install.ps1`)

For the ZIP `Vitrine-win-x64-framework.zip` (needs the .NET 10 Desktop Runtime) or your own build. Unpack the ZIP and run the script from an elevated PowerShell. The script is not signed: if the execution policy blocks it, unblock the downloaded ZIP before unpacking (`Unblock-File`, enough for `RemoteSigned`) or call it like this: `powershell -ExecutionPolicy Bypass -File .\deploy\install.ps1 …`

```powershell
.\deploy\install.ps1                              # install from the unpacked ZIP
.\deploy\install.ps1 -Config .\config.json        # with a prepared device configuration
.\deploy\install.ps1 -NoService                   # without the service, autostart through HKLM\...\Run
.\deploy\install.ps1 -NoService -NoAutostart      # neither
.\deploy\install.ps1 -Uninstall                   # remove
```

| Parameter | Meaning |
|---|---|
| `-Source <folder>` | Folder with `Vitrine.exe`. Default: the folder above `deploy\` (the root of the unpacked ZIP), otherwise `..\publish` relative to the script (repository layout). |
| `-Config <file>` | Copies the file to `%ProgramData%\ICT-Baden\Vitrine\config.json`. |
| `-NoService` | Does not install the [service](#service); sets up the autostart instead (unless `-NoAutostart`). Without it the script installs and starts the service and removes the `HKLM\…\Run` entry. |
| `-NoAutostart` | With `-NoService`: does not set up the autostart. An existing entry is **not** removed. |
| `-Uninstall` | Stops and removes the service, ends Vitrine, removes the autostart entry and the program folder. |

**What the script does:**

- ends running Vitrine processes and copies the program to `%ProgramFiles%\Vitrine`, with an empty `Plugins` folder. It sets no permissions of its own there and relies on the default permissions of *Program Files* (only administrators may write).
- creates `%ProgramData%\ICT-Baden\Vitrine` and `…\Logs` with the same protected permissions as the MSI, and makes *Administrators* the owner of both folders – so a user who created the folder beforehand cannot change the permissions again.
- registers the event source `ICT-Baden Vitrine` and the autostart for all users.
- prints the target folder, the configuration and the audit log path, and reminds you to copy the ADMX templates – neither script nor MSI install them into `C:\Windows\PolicyDefinitions`.

Without `Vitrine.exe` in the source folder the script stops with *Vitrine.exe not found in …*. With `-Uninstall`, `%ProgramData%\ICT-Baden\Vitrine` (configuration and audit logs) and – unlike with the MSI – the event source remain.

| Feature | MSI | `install.ps1` |
|---|:---:|:---:|
| Program folder, data folders with permissions, event source, autostart | ✔ | ✔ |
| Without the service | `SERVICE=0` | `-NoService` |
| Turn off autostart (without the service) | `SERVICE=0 AUTOSTART=0` | `-NoService -NoAutostart` |
| Pass a `config.json` | – | `-Config` |
| Start menu and *Settings › Apps* entry | ✔ | – |
| Removes the event source on uninstall | ✔ | – |
| .NET runtime needed | no | yes (.NET 10 Desktop Runtime) |

## Folder permissions

MSI and script set the permissions of the data folders as protected, that is without inheritance from *ProgramData*:

| Folder | Administrators, SYSTEM | Users |
|---|---|---|
| `%ProgramFiles%\Vitrine` | Full control | Read and execute (default of *Program Files*) |
| `%ProgramData%\ICT-Baden\Vitrine` – configuration | Full control | Read and execute |
| `%ProgramData%\ICT-Baden\Vitrine\Logs` – audit logs, **with the service** (default) | Full control | Read and execute only · *OWNER RIGHTS*: read and execute only |
| `%ProgramData%\ICT-Baden\Vitrine\Logs` – audit logs, without the service (`SERVICE=0`, `-NoService`) | Full control | Folder: read and execute, create files · Files: read and append only · *OWNER RIGHTS*: read and execute only |

With the service, only the service writes the audit log and signs every entry ([Audit log › Signed audit log](audit-log.md#signed-audit-log-format-3)); it sets the read-only permissions again at every start, also for folders created by earlier builds or by `install.ps1`. It also creates `HKLM\SOFTWARE\ICT-Baden\Vitrine\Audit` (anchors and public keys; only SYSTEM may write) and a CNG machine key for SYSTEM; both are kept on uninstallation, like the logs. When the service stops writing the log (`SERVICE=0`, key not loadable), it restores the append permissions below. A folder set with `Audit.Directory` is used by the service only if users cannot change it or its parent folder (VIT-0323 otherwise).

**Win+L after uninstallation.** While locked (and with `Lock.ReplaceWinL`), Vitrine sets `DisableLockWorkstation` for the user and removes it when it ends. If Vitrine crashed, the service removes it when it notices, and when the service stops (also before uninstallation) it removes it in all loaded user profiles without a running Vitrine. A profile that is not loaded at that moment (user signed out after a crash) keeps the value until that user signs in to Vitrine again – after an uninstallation, remove `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableLockWorkstation` for such users where `HKCU\Software\ICT-Baden\Vitrine\State` has the value `DisableLockWorkstationBefore` (for example with a sign-in script). A network copy (`Audit.NetworkDirectory`) is then written by the computer account, not by the user.

Without the service, *OWNER RIGHTS* with read access only makes sure that the creator of a log file can neither change its permissions nor delete it. Users get *Create files* on the folder only and *Append data* (not *Write data*) on the files, so they can neither overwrite nor shorten a log file – but they can append lines with a valid hash (not Part 11 capable). Administrators can change anything in both cases; that is why the log is only tamper-evident – the copy on a network share and the Windows event log serve as independent records ([Audit log](audit-log.md#what-the-log-does-and-does-not-prove)).

> [!IMPORTANT]
> **Log folders from earlier builds keep the old, weaker permissions.** Earlier MSIs and scripts gave users *Create files* on the files as well, which is the same right as *Write data*: users could overwrite existing entries or shorten a file. Install the current MSI again or run `deploy\install.ps1` again, or set the permissions by hand with the SDDL from [`installer/Package.wxs`](../installer/Package.wxs) (component `LogsFolder`: the list with the condition `SERVICE = 1` with the service, the other without).

**Why the device configuration must be protected.** Vitrine uses `%ProgramData%\ICT-Baden\Vitrine\config.json` (and the old `%ProgramData%\Vitrine\config.json`) only if the file, its folder and the folder above are owned by Administrators, SYSTEM or TrustedInstaller, are not junctions or other reparse points, and no other account may change, delete, rename or re-permission them (creating new files in the folder is allowed). Otherwise the file is ignored with **VIT-0012** – a standard user could else set rules, scripts and the unlock password for everyone. The same check applies to plugin DLLs (VIT-0013, [Plugins](plugins.md)). Saving as administrator in the settings window repairs a folder that a user created beforehand – details in [Settings › File locations](settings.md#file-locations).

## Deploying with Intune or Group Policy

**Intune – as a line-of-business app (MSI), recommended.** Upload `Vitrine-x64.msi`; Intune detects the installation by its product code (every build has a new one). Put options such as `AUTOSTART=0` into the command-line arguments.

**Intune – as a Win32 app (`.intunewin`).** Pack the content of the unpacked ZIP (the .NET 10 Desktop Runtime must be on the devices).

| Field | Value |
|---|---|
| Install command | `powershell -ExecutionPolicy Bypass -File deploy\install.ps1` |
| Uninstall command | `powershell -ExecutionPolicy Bypass -File deploy\install.ps1 -Uninstall` |
| Detection | File `%ProgramFiles%\Vitrine\Vitrine.exe` exists |

**Group Policy software installation** – assign `Vitrine-x64.msi` to computers (*Computer Configuration › Policies › Software Settings › Software installation*). Group Policy software installation cannot pass properties such as `AUTOSTART=0` directly; that needs a transform (`.mst`), which is not provided.

**Other tools** (Configuration Manager, other software deployment): `msiexec /i Vitrine-x64.msi /qn` as above.

**Settings** come in every case through the ADMX templates.

## ADMX templates for Group Policy and Intune

The templates are in the `policy\` folder: in the installation folder (`%ProgramFiles%\Vitrine\policy`), in the ZIP and in the repository.

| File | Copy to |
|---|---|
| `policy\Vitrine.admx` | `C:\Windows\PolicyDefinitions\` or the central store `\\contoso.com\SYSVOL\contoso.com\Policies\PolicyDefinitions\` |
| `policy\en-US\Vitrine.adml` | `…\PolicyDefinitions\en-US\` |
| `policy\de-DE\Vitrine.adml` | `…\PolicyDefinitions\de-DE\` (optional) |

```powershell
Copy-Item "$env:ProgramFiles\Vitrine\policy\Vitrine.admx"       C:\Windows\PolicyDefinitions\
Copy-Item "$env:ProgramFiles\Vitrine\policy\en-US\Vitrine.adml" C:\Windows\PolicyDefinitions\en-US\
```

Then configure under *Computer Configuration* (or *User Configuration*) *› Administrative Templates › Vitrine*. The template has 76 policies in ten categories – Locking, Unlocking, Appearance, Security, Audit, Microsoft Entra ID, Integration, Scripts, Roles and governance, Security keys – each available for computers and users, except the three Active Directory settings of Security keys (*Security key store*, *Active Directory container*, *Synchronization with Active Directory*), which the Vitrine service reads and which exist for computers only. Values set by computer policy win over user policy.

**Intune:** in the Intune admin center under *Devices › Configuration › Import ADMX*, upload `Vitrine.admx` and `en-US\Vitrine.adml`, then create a profile from the imported template (*Templates › Imported Administrative templates*).

The template has namespace `ICTBaden.Policies.Vitrine`, revision 2.7, and writes to `SOFTWARE\Policies\ICT-Baden\Vitrine`. Templates from builds before 0.1.0 wrote to `SOFTWARE\Policies\Vitrine` – see [Upgrading](#upgrading-from-earlier-builds-100-and-older).

Which values exist, which are in the template and how they map to the registry: [Settings](settings.md). Good first policies:

| Category | Policy | Example |
|---|---|---|
| Microsoft Entra ID | *Tenant ID*, *Client ID* | GUIDs of your tenant and app registration – [Entra ID setup](entra-id.md) |
| Unlocking | *Who may unlock (bit mask)* | `7` = signed-in person + administrators + groups |
| Unlocking | *Allowed groups* | `Vitrine.Unlock` or `CONTOSO\Lab-Leads` |
| Security | *Action after too many failures* | *Lock workstation* (default: *None*) |
| Audit | *Network copy* | `\\fileserver\audit$\Vitrine` |
| Appearance | *Language of the user interface* | only if every user must see the same language |

Vitrine reads policies at start, after saving the settings and on *Reload policies* (Settings › About) – not automatically after a Group Policy refresh.

## Security keys in Active Directory

Optional, for the sign-in method *Security key* with `Fido.Store = ActiveDirectory` (a key registered once works on all
computers of the domain). Prepare the domain once with `deploy/Initialize-VitrineDirectory.ps1` (in the source and the
release ZIP; needs the ActiveDirectory PowerShell module and a domain administrator):

```powershell
.\Initialize-VitrineDirectory.ps1 -RegistrarsGroup 'Vitrine Registrars' -WhatIf   # show what would change
.\Initialize-VitrineDirectory.ps1 -RegistrarsGroup 'Vitrine Registrars'
```

It creates `CN=Vitrine,CN=Program Data,<domain>` and `CN=SecurityKeys` below it, gives the registrars group the right to
create, change and delete key objects there and *Domain Computers* (`-ReadersGroup`) the right to read. Then set the
policy *Security key store* to *Active Directory* and restart the Vitrine service. Details and the permissions:
[Security keys › Active Directory](security-keys.md#active-directory).

## Single exe without installation

`Vitrine.exe` from the release starts without an installed .NET runtime. .NET unpacks the embedded native libraries into a cache folder at start (by default under `%TEMP%\.net`). Good for trying Vitrine; for operation use the MSI or the script, because:

- Configuration and audit logs still go to `%ProgramData%\ICT-Baden\Vitrine`, but the audit log folder gets the default permissions of *ProgramData*: whoever creates it first owns it with full control, so the audit log is not protected. A device configuration in a folder that a standard user created is ignored (VIT-0012) until it is saved once as administrator.
- If that folder is not writable, the audit log falls back to `%LocalAppData%\Vitrine\Logs`.
- Without a registered event source, entries in the Windows event log are missing – silently. Register it with `Vitrine.exe --register-eventlog` as administrator ([Command line](command-line.md#--register-eventlog)).
- Plugins next to an exe in a user folder (e.g. *Downloads*) are not loaded (VIT-0013): the `Plugins` folder and the folder above must be protected – see [Plugins](plugins.md).
- The ADMX templates are not included; take them from the ZIP or the repository.

Vitrine as a **screen saver**: [Command line › Screen saver](command-line.md#screen-saver).

## Service

> [!NOTE]
> The company guideline says that an app sets up its autostart per user, not the installer. Vitrine deviates on
> purpose: a screen lock must run in every session regardless of the user, so the MSI installs the service (or, with
> `SERVICE=0`, the autostart for all users).

From this version the MSI and `install.ps1` install the Windows service **ICT-Baden Vitrine** (service name
`ICT-Baden.Vitrine`). It runs as LocalSystem without a user interface and

- starts Vitrine in every session at sign-in (also for sessions that are already signed in when it starts, and after
  reconnecting), as the signed-in user (`Vitrine.exe --agent`),
- receives the lock state and a heartbeat from it through `\\.\pipe\ICT-Baden.Vitrine.Service`,
- restarts Vitrine at once if it ends while unlocked (crash, Task Manager). Repeated crashes are slowed down
  (1 s, 5 s, 15 s, 30 s, 1 min, then every 5 min), and after five failed starts in a row only every twelfth is logged.
  If the session is reconnected during such a wait, Vitrine starts at once – locked, if it was locked,
- **disconnects the session** if Vitrine ends or stops responding (no heartbeat for 30 s) **while locked**: Windows
  shows its sign-in screen, programs keep running. Vitrine is started again locked, so after signing in again the
  Vitrine lock is still there. Ending Vitrine therefore never opens the workstation,
- does not count sleep or hibernation as "not responding": its timers run on a clock that stops while Windows sleeps,
  and after waking up Vitrine has 60 s to report back,
- ignores Vitrine ending at shutdown and at a sign-out that really happens. Vitrine announces a sign-out when Windows
  asks; if the session has not signed out 20 s later (sign-out cancelled, or the message did not come from Windows),
  the end counts as a loss: disconnect and locked restart while locked, otherwise a restart,
- **disconnects locked sessions when the service itself is stopped** (by an administrator, an update or uninstalling
  the MSI) – the setup ends Vitrine right after that. The service remembers these sessions in the volatile registry key
  `HKLM\SOFTWARE\ICT-Baden\Vitrine\ServiceState` (gone after a Windows restart); after an update the new service starts
  Vitrine **locked** there,
- does not restart Vitrine after *Exit* confirmed by an administrator, until the next sign-in or until Vitrine is
  started again by hand.

Every step is written to the audit log (`ServiceStarted`, `AgentConnected`, `AgentLost`, `SessionDisconnected`, …,
[Audit log](audit-log.md#events)). Without the service – single exe, `SERVICE=0`, `-NoService` or a stopped service –
Vitrine falls back to the [watchdog](limitations.md#watchdog). Administrators can stop the service; standard users
cannot.

## Autostart

With `SERVICE=0` (MSI) or `-NoService` (script), MSI and script set up the autostart for **all users** under `HKLM\…\Run` instead of the service. The switch *Start with Windows* in the settings window (page *Lock*) reads and writes only the user's **own** entry under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.

> [!WARNING]
> After an installation the switch therefore shows *Off*, and at every sign-in the balloon *Vitrine is running* appears. Do **not** also turn the switch on on installed devices: Vitrine then starts twice, and the second start opens the settings of the first instance (or the administrator prompt) at sign-in. Uninstalling does not remove such `HKCU` entries.

## Upgrading from earlier builds (1.0.0 and older)

Builds up to October 2026 carried the version **1.0.0** (CI builds `1.0.0-ci.N`), were published under a different repository and stored everything under the name *Vitrine* without a vendor prefix. Version 0.1.0 is the first build under ICT-Baden. It moved paths and identifiers to the ICT-Baden naming scheme and set the version back to 0.x because it has not been tested on real devices yet. Most old locations are still **read**, so a device keeps working – but some changes need action.

| Area | Before (≤ 1.0.0) | Now (0.1.0) | What Vitrine does | What you need to do |
|---|---|---|---|---|
| **MSI version** | `1.0.0.N` | `0.1.0.N` | The new MSI replaces installed `1.0.0.x` builds (same upgrade code) although their version is higher; only versions above 0.1.0 other than `1.0.0.x` count as newer. | Nothing – install `Vitrine-x64.msi` over the old build. In Intune, configure the new app to supersede the old one. Configuration and audit logs remain. Not yet tested on a real machine (see checklist below). |
| **Release files** | `Vitrine-1.0.0-ci.N-x64.msi`, `…-framework.zip`, `…-self-contained.zip`, `Vitrine.Plugin.HttpAuth-….zip` | `Vitrine-x64.msi`, `Vitrine.exe`, `Vitrine-win-x64-framework.zip`, `SHA256SUMS.txt`, `Vitrine-sbom.cdx.json` | – | Update download links and deployment scripts. Use `github.com/ict-baden/vitrine`. The self-contained ZIP and the plugin ZIP no longer exist. |
| **Policies** | `HKLM`/`HKCU\SOFTWARE\Policies\Vitrine` | `HKLM`/`HKCU\SOFTWARE\Policies\ICT-Baden\Vitrine` | Reads both. Order, lowest first: HKCU old, HKCU new, HKLM old, HKLM new. As long as any value comes from the old path, *Overview* shows **Old policy path in use**. | Import the new ADMX (namespace `ICTBaden.Policies.Vitrine`, revision 2.7) – it replaces `Vitrine.admx` in `PolicyDefinitions`. Set the policies again in the new template; values already written by existing GPOs stay in the old key until you remove them there (in the GPO editor they then appear as extra registry settings). |
| **Language policy** | – | *Language of the user interface* | New policy, new key only. | Optional. |
| **Device configuration** | `%ProgramData%\Vitrine\config.json` | `%ProgramData%\ICT-Baden\Vitrine\config.json` | Reads the old file as long as the new one does not exist – but only if it is protected (see [Folder permissions](#folder-permissions)) – and shows **Configuration still in the old folder** on *Overview*. A file that the old MSI or `install.ps1` created as administrator is fine; a file that a standard user copied there is ignored with VIT-0012. The next *Save* writes to the new location; the old file stays untouched. | Open the settings and save once as administrator, or deploy the file to the new location (`install.ps1 -Config`). Delete the old file afterwards if you like. |
| **User configuration** (only with `Security.AllowUserConfig`) | `%AppData%\Vitrine\config.json` | `%LocalAppData%\Vitrine\config.json` | Reads the old file as long as the new one does not exist. Only the sections `Appearance` and `Lock` are used. | Move the file if you use per-user configuration. |
| **Audit log folder** (default) | `%ProgramData%\Vitrine\Logs` | `%ProgramData%\ICT-Baden\Vitrine\Logs` | New entries go to the new folder; a new hash chain starts there. Old files are not moved. The *Audit log* page shows the newest file of the old folder until the new folder has one. An explicitly set `Audit.Directory` is unchanged. | Keep the old folder for your retention period. Include the new path in backups and monitoring. A `…\ICT-Baden\Vitrine\Logs` folder set up by an earlier 0.1.0 build keeps the weaker permissions – [Folder permissions](#folder-permissions). |
| **Audit log format** | local time with offset, file per local month, CRLF | UTC times, file `audit-yyyy-MM.jsonl` per UTC month, LF | – | Adjust evaluations that parse times. In the month of the switch, the network copy `<COMPUTER>-audit-yyyy-MM.jsonl` gets a second chain that starts again at sequence 1, so `--verify-log` reports a chain break at that line. |
| **Event source** | `Vitrine` | `ICT-Baden Vitrine` | Writes to the new source if it is registered, otherwise to the old one. The new MSI and script register the new source; uninstalling the old MSI removes the old one. | Update filters in the event log, SIEM or monitoring to the new source (or to both during the transition). Without MSI: `Vitrine.exe --register-eventlog`. |
| **Named pipe** | `\\.\pipe\Vitrine-<session>` | `\\.\pipe\ICT-Baden.Vitrine.<session>` | Listens only on the new name. **Breaks existing integrations.** | Update line-of-business applications and scripts that talk to Vitrine – [Interface](interface.md). The sample `samples/clients/Vitrine.Client.ps1` already uses the new name. |
| **Single-instance mutex** | `Local\Vitrine-<session>` | `Local\ICT-Baden.Vitrine.SingleInstance` | An old and a new build do not see each other. | Do not run old and new builds side by side. |
| **Scripts** | `%VITRINE_TIME%` in local time | `%VITRINE_TIME%` in UTC, new `%VITRINE_TRIGGER%` values in English, new `%VITRINE_CODE%` | – | Check scripts that use these variables – [Settings › Scripts](settings.md#scripts). |
| **Plugins** | – | `AuthOutcome.ErrorCode` and `AuthOutcome.Fail(error, code)` new; the HttpAuth sample reads `SOFTWARE\Policies\ICT-Baden\Vitrine\Plugins\HttpAuth` (old path as fallback) | – | Optional: return an error code from your own plugins – [Plugins](plugins.md). |

## Pitfalls for administrators

| Observation | Cause | Remedy |
|---|---|---|
| Installing `Vitrine-x64.msi` stops with *A newer version of Vitrine is already installed.* | A newer Vitrine version (not an old 1.0.0 build) is installed | Uninstall it first if you really want to go back |
| *Old policy path in use* on the Overview page | Values still come from `SOFTWARE\Policies\Vitrine` | Import the new ADMX and set the policies there |
| Line-of-business application cannot reach Vitrine any more | New pipe name `ICT-Baden.Vitrine.<session>` | Update the client |
| App role `Vitrine.Unlock` or a group has no effect | *Specific groups* under *Authorised people* is off | Add `Groups` (4) to `Unlock.Allowed` – [Sign-in](sign-in.md) |
| *Microsoft* is missing in the unlock dialog | `Entra.ClientId` is empty | Enter the application ID – [Entra ID](entra-id.md) |
| A plugin is missing in the dialog | ID not in `Unlock.Methods`, `Integration.LoadPlugins` off, or Vitrine not restarted | Add the ID through `config.json` or the policy *Sign-in methods*, restart – [Plugins](plugins.md) |
| Nothing happens after 5 failed attempts | `Security.FailureAction` is `None` by default | Choose an action – [Sign-in](sign-in.md) |
| The unlock dialog cannot be opened | `Unlock.Trigger = HotkeyOnly` with an empty `Lock.Hotkey` | Set a shortcut or change the trigger |
| Balloon *Vitrine is running* at every sign-in, *Start with Windows* is *Off* | The switch only knows `HKCU`; MSI and script write `HKLM` | Leave it – do **not** turn the switch on ([Autostart](#autostart)) |
| Vitrine starts automatically again after an MSI update | An MSI from before 2026-10-20 did not remember `AUTOSTART=0`; the current MSI does, also for installations from those builds | Use the current MSI; a value on the command line still wins |
| Unlocking with Microsoft is not offered; only the Windows password is offered (VIT-0016, VIT-0190) | The Microsoft Edge WebView2 Runtime is missing and the broker is not used (up to 0.3.0: every configuration without the broker) | Install the WebView2 Runtime – [Entra ID › When Microsoft is not offered for unlocking](entra-id.md#when-microsoft-is-not-offered-for-unlocking) |
| Microsoft sign-in fails after the update with an `AADSTS` error about the redirect URI | The app registration has only `http://localhost`; the broker uses `ms-appx-web://microsoft.aad.brokerplugin/<application ID>` | Add that redirect URI under *Mobile and desktop applications* – [Entra ID › App registration](entra-id.md#app-registration) |
| Nobody can unlock, *VIT-0141* (Microsoft not offered) | `Unlock.AllowedDomains` only has UPN suffixes such as `contoso.com`, Windows reports `CONTOSO\name` (VIT-0017) | Add `CONTOSO` to the list – [Entra ID › When Microsoft is not offered for unlocking](entra-id.md#when-microsoft-is-not-offered-for-unlocking) |
| A Group Policy change does not arrive | Policies are read at start and after saving only | Settings › About › *Reload policies*, or restart Vitrine |
| *Configuration has errors* with VIT-0012, settings from `config.json` have no effect | The device file, its folder or `%ProgramData%\ICT-Baden` can be changed by standard users – e.g. a user created the folder or copied the file | Save the settings once as administrator (confirm the UAC prompt); this secures the folders and the file – [Settings › File locations](settings.md#file-locations) |
| A plugin is missing, *Plugin not loaded* with VIT-0013 | The plugin is not in a protected folder (e.g. single exe in a user folder) | Install with the MSI and put the plugin into `%ProgramFiles%\Vitrine\Plugins` – [Plugins](plugins.md) |
| Users can overwrite or shorten audit log files | Log folder set up by an earlier build | Reinstall the MSI or run `deploy\install.ps1` again – [Folder permissions](#folder-permissions) |
| `--verify-log` reports a chain break in the network copy | Lines from the per-user fallback folder (own chain) were also appended to the copy | Check why the main folder was not writable – [Audit log](audit-log.md) |
| *Test the lock* ignores changes | It locks with the saved settings | Save first |

## Tested so far / still to test on real devices

Vitrine is built and its unit tests run under Windows in GitHub Actions; the screenshots are drawn by the real application on the build runner. Since 2026-10-20 the build also installs the MSI silently on a fresh runner and checks the service, files and registry; on the runner's signed-in session it checks that the service starts Vitrine and that Vitrine connects to it (`AgentConnected`, and no failed start, loss or pipe error beyond the service's start timeout). It updates that installation with a second build (service on, no reboot needed), uninstalls it without leftovers, installs with `SERVICE=0 AUTOSTART=1` and updates without properties (the choice stays), and finally installs the last published MSI with `SERVICE=0 AUTOSTART=0` and updates it to the new build (`.github/scripts/msi-test.ps1`). Releases wait for this test. That covers the mechanics on an administrator account, not a real device with a standard user, a locked session or sleep. A complete functional test on real devices is still **open** for every item below. Please go through it once before a rollout and report results as an [issue](https://github.com/ict-baden/vitrine/issues).

**Installation**

- [ ] MSI on a clean machine (Windows 10 1809 and Windows 11): install silently with a user signed in, the service starts Vitrine in that session at once, Start menu entry, event source `ICT-Baden Vitrine` registered, folder permissions as in [Folder permissions](#folder-permissions)
- [ ] Service as a **standard user** (not administrator): Vitrine connects to the service (no `AgentStartFailed … no connection` in the audit log after a minute)
- [ ] Update and uninstall **while a session is locked**: the session is disconnected, after signing in again Vitrine is locked (with the service); with `SERVICE=0` the lock is open during the update – distribute updates outside locked sessions
- [ ] Sleep and hibernate while locked and unlocked: after waking up, no `SessionDisconnected` and no restart of Vitrine
- [ ] MSI with `SERVICE=0` and with `SERVICE=0 AUTOSTART=0`: service idle (`supervision off` in the audit log), `HKLM\…\Run` entry only without `AUTOSTART=0`
- [ ] Service: Vitrine starts at sign-in through the service; ending it in Task Manager while unlocked → restarted; while locked → session disconnected, after signing in again Vitrine is locked; *Exit* as administrator → not restarted; RDP and fast user switching
- [ ] MSI uninstall: program folder, event source and autostart removed, configuration and audit logs remain
- [ ] Upgrade from an old 1.0.0 build: install the new MSI over it (no prior uninstall); old `config.json` and old policy path are read and flagged; *Save* writes to the new folder
- [ ] Update from one 0.1.0 CI build to the next replaces it without a second entry in *Settings › Apps*
- [ ] `install.ps1` from the unpacked ZIP, with and without `-Config`, and `-Uninstall`
- [ ] ADMX import in Group Policy and Intune; values arrive and are locked in the settings

**Locking**

- [ ] Lock by shortcut, notification area, idle time, schedule, `--lock`, at startup and as screen saver (`.scr` with `/s`)
- [ ] Multiple monitors with different scaling: the overlays cover each monitor exactly; plugging a monitor in or out while locked
- [ ] Covered areas: drawing on two monitors with different scaling, the areas cover exactly the drawn rectangles while locked; *Only selected programs*: the program's window stays visible when moved, a window on top of it stays covered
- [ ] While locked, clicks and keys do not arrive; Win key, Alt+Tab, Alt+Esc, Alt+F4, Ctrl+Esc and the menu key have no effect
- [ ] Ctrl+Alt+Del while locked: Task Manager, Sign out and Change a password are hidden, and back after unlocking; after a crash the three values are restored at the next start
- [ ] Watchdog after a crash: end Vitrine in Task Manager (as administrator, while locked) → Windows locks, also after deleting `%LocalAppData%\Vitrine\locked`
- [ ] VIT-0012: a `config.json` copied by a standard user is ignored; saving as administrator secures it

**Unlocking and signing**

- [ ] Windows password (local account, Active Directory, Entra-joined device with UPN)
- [ ] Entra ID sign-in with MFA and passkey: the Microsoft window appears in front and accepts input; FIDO2 key (USB, NFC), passkey on a phone via QR code, Authenticator passwordless, certificate-based authentication
- [ ] Authentication context (`c1`) with a Conditional Access policy *Phishing-resistant MFA*: password + MFA refused, passkey accepted
- [ ] Interface: `idToken` with `ShareIdToken`, `accessToken` for an allowed scope, VIT-0211 for another scope
- [ ] Windows Hello (face, fingerprint, PIN)
- [ ] Wrong person or wrong password: rejected, audit log entry, waiting time, action after N attempts (choose an action first)
- [ ] Remote Desktop sessions: lock and unlock inside an RDP session; disconnecting and reconnecting while locked
- [ ] Signature through `samples/clients/Vitrine.Client.ps1 sign …`
- [ ] Security keys in Active Directory: `Initialize-VitrineDirectory.ps1` (with `-WhatIf`, then for real), register on one computer (Windows password and Entra registrar), unlock on a second computer, revoke on the second and see it refused at once on the first, offline laptop uses the local copy, wrong password VIT-0472

**Audit log and languages**

- [ ] `--verify-log` on the original file → intact; after changing one line → changed (exit code 2)
- [ ] Network copy and Windows event log receive every entry
- [ ] Every window in all five languages, especially Chinese (fonts, text length)
