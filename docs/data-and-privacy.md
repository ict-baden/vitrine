[Vitrine](../README.md) › Data and privacy

# Data and privacy

What Vitrine stores where, which personal data is in it, which connections are made, and how to delete everything.

**Contents:** [In short](#in-short) · [Files on the computer](#files-on-the-computer) · [Personal data in the audit log](#personal-data-in-the-audit-log) ·
[Data passed to local applications](#data-passed-to-local-applications) · [The service](#the-service) ·
[Registry](#registry) · [Network connections](#network-connections) · [Deleting everything](#deleting-everything) ·
[Retention](#retention) · [Works council and co-determination](#works-council-and-co-determination) · [Who is responsible](#who-is-responsible)

## In short

- **Vitrine sends no data to ICT Baden.** No telemetry, no crash reports, no usage statistics, no update check. The
  About window says so: "This software sends no data to ICT-Baden."
- **Microsoft Entra ID sign-ins go to Microsoft.** When someone chooses *Continue with Microsoft* (or *Test sign-in*),
  MSAL shows Microsoft's sign-in page in Vitrine's own sign-in window (Microsoft Edge WebView2), which talks to
  Microsoft's sign-in service; with `Entra.UseBroker = true` the Windows account broker does this instead. The sign-in
  window uses a temporary profile that is deleted after each sign-in. The broker's runtime `msalruntime.dll` (version
  0.20.4, MIT licence) has no telemetry upload and no self-update that we could find; it is replaced only by a Vitrine
  update ([details](#network-connections)).
- **Applications on the same computer** that request a signature through the local interface receive the identity of
  the person who signed, and – only if the administrator allows it – Microsoft tokens
  ([details](#data-passed-to-local-applications)).
- **The audit log contains personal data:** who locked and unlocked when, who failed to sign in, who signed what.
- **The operator is responsible for the data** – the organisation that runs Vitrine is the controller in the sense of
  the GDPR. ICT Baden processes none of it through the software.
- **Vitrine never deletes audit logs.** Retention is up to the operator.

## Files on the computer

| What | Where | Content | Removed by |
|---|---|---|---|
| Device configuration | `%ProgramData%\ICT-Baden\Vitrine\config.json` | all settings; can contain account, group and domain names (`Unlock.AllowedUsers`, `AllowedGroups`, `AllowedDomains`), the Entra tenant and application ID, the hash of the shared unlock password, the network share path, script commands, a logo path. Readable by every user of the computer; only used if standard users cannot change it ([Settings](settings.md#file-locations)) | you; uninstalling leaves it |
| Old device configuration | `%ProgramData%\Vitrine\config.json` | as above, from builds before 0.1.0; read only as long as the new file does not exist | you |
| User configuration | `%LocalAppData%\Vitrine\config.json` (old: `%AppData%\Vitrine\config.json`) | only read when `Security.AllowUserConfig` is on, and then only the sections `Appearance` and `Lock` | you |
| Security keys | `%ProgramData%\ICT-Baden\Vitrine\fido-credentials.json` | only with the method `fido`: for every registered key the public key, credential ID, model (AAGUID), attestation certificate subject, signature counter, label and reason; the person's account name, SID and UPN; who registered or revoked it, when and why; time of last use; and per person the group SIDs read last (for sign-in without a domain controller). No PINs or private keys. Written only by the service, readable only by SYSTEM and administrators (in the settings: only registrars, configuration administrators and auditors see the list) ([Security keys](security-keys.md#where-the-keys-are-stored)) | you (revoked keys stay in the file as a record); uninstalling leaves it |
| Security keys in Active Directory | `CN=SecurityKeys,CN=Vitrine,CN=Program Data,<domain>` (with `Fido.Store = ActiveDirectory`); local copy `%ProgramData%\ICT-Baden\Vitrine\fido-directory-cache.json`, counters in `HKLM\SOFTWARE\ICT-Baden\Vitrine\FidoCounters` | the same data per key as the file above, except the signature counter and the last use (kept per computer); readable by the computers of the domain (by default *Domain Computers*) and the registrars ([Security keys › Active Directory](security-keys.md#active-directory)) | you; delete the objects in Active Directory to remove them; the local copy and counters stay until uninstalled or deleted |
| Language choice | `%LocalAppData%\Vitrine\preferences.json` | the language chosen in the About window | you |
| Ctrl+Alt+Del backup | `%LocalAppData%\Vitrine\sas-backup.json` | the previous values of three Windows policy values while the workstation is locked ([Registry](#registry)) | Vitrine, when unlocking or at the next start |
| Lock marker | `%LocalAppData%\Vitrine\locked` | UTC time the lock started; fallback for the watchdog – Vitrine reports the lock state to the watchdog through its standard input | Vitrine, when unlocking or at the next start |
| Audit log | `%ProgramData%\ICT-Baden\Vitrine\Logs\audit-YYYY-MM.jsonl`, or the folder in `Audit.Directory` | see [below](#personal-data-in-the-audit-log) | you – never deleted by Vitrine or by uninstalling |
| Audit log, per-user fallback | `%LocalAppData%\Vitrine\Logs\` | as above, when the main folder cannot be written | you |
| Audit log, old folder | `%ProgramData%\Vitrine\Logs\` | logs of builds before 0.1.0; no longer written | you |
| Temporary settings file | `%TEMP%\vitrine-<random>.json` | the settings to be saved, when saving needs administrator rights | Vitrine, right after saving |
| Temporary profile of the Microsoft sign-in window | `%LocalAppData%\ICT-Baden\Vitrine\WebView\<random>\` | WebView2 browser profile for one Microsoft sign-in (opened in private mode: cookies and site data stay in memory; the folder holds browser settings, caches and crash-report folders) | Vitrine, right after the sign-in window closes and the browser processes have ended; leftovers older than 10 minutes at the next start or sign-in |

Not stored anywhere: passwords (only the salted hash of the shared unlock password), Microsoft tokens (Vitrine keeps no
token cache on disk and removes the accounts from MSAL after every attempt; tokens passed to an application are only
in that answer), Windows Hello data (handled by Windows). The Windows account broker keeps the Windows user's
Microsoft accounts and sign-in state as Windows does for every app that uses it; this is managed by Windows, not by
Vitrine. This applies only with `Entra.UseBroker = true`. The default sign-in window keeps **nothing** between sign-ins:
no account, no cookie, no "stay signed in" (since 0.4.0; before, without the broker, the default browser kept its own
data as for any other web sign-in).

## Personal data in the audit log

The [audit log](audit-log.md) is the main store of personal data. Depending on the event, an entry contains:

- **account names:** UPN (`jdoe@contoso.com`) or `DOMAIN\name` of the person, and of the Windows session user;
- **display names**, **Entra object IDs** and **Windows SIDs**, **Entra tenant IDs** and authentication method
  references (`amr`);
- the **computer name**;
- **times** of locking, unlocking, failed attempts and signatures (UTC);
- for **signatures:** the reason, meaning and requesting application sent by the line-of-business application – these
  texts can contain batch numbers, sample IDs or anything else the application sends – and the name and process ID of
  the requesting process (`clientProcess`);
- trigger texts sent by applications through the interface (`api: …`);
- for errors (`VIT-0010`): the exception text including the stack trace, which can contain file paths and user names;
- entries of the [service](#the-service) (session user `SYSTEM`): Windows session numbers, process starts and session
  disconnects (`ServiceStarted`, `AgentConnected`, `AgentLost`, `AgentStartFailed`, `SessionDisconnected` …).

The same data, without the `Data` part, goes to:

- the **Windows event log** (Application log, source "ICT-Baden Vitrine", or "Vitrine" on older installations), if
  `Audit.EventLog` is on (default) – and from there to any log collector you forward it to;
- the **network copy** `<COMPUTERNAME>-audit-YYYY-MM.jsonl` in `Audit.NetworkDirectory`, if set (with `Data`);
- **subscribers of the event stream** of the local [interface](interface.md#event-stream).

Scripts configured under `Scripts` receive the user name, method, trigger and error code in environment variables
(with `cmd` special characters replaced by `_`, [Settings › Scripts](settings.md#scripts)) and can pass them on.

## Data passed to local applications

Line-of-business applications on the same computer can ask Vitrine for a sign-in or signature through the local
[interface](interface.md) (`\\.\pipe\ICT-Baden.Vitrine.<session>`, only for the signed-in user, SYSTEM and
administrators; `Integration.PipeEnabled`). The answer goes only to the connection that asked and contains:

- always: user name, display name, user ID (Windows SID or Entra object ID), tenant ID, sign-in method, time, reason
  and meaning, the number and hash of the audit entry, and the authentication methods Microsoft reports (`amr`);
- with `Entra.ShareIdToken = true`: the **ID token** of the Microsoft sign-in (`idToken`);
- with scopes in the request that the administrator listed in `Entra.AllowedTokenScopes`: an **access token** for that
  API (`accessToken`, `expiresOn`, `scopes`).

Tokens are never written to the audit log, the event log, the network copy or the event stream. What the application
does with them is up to the application and its operator; treat them like passwords. Subscribers of the event stream
(`subscribe`) receive every audit entry without its `Data` part.

## The service

The MSI and `install.ps1` install the Windows service **ICT-Baden Vitrine** (`ICT-Baden.Vitrine`, runs as `SYSTEM`).
It starts Vitrine in every user session and supervises it through `\\.\pipe\ICT-Baden.Vitrine.Service`. To do so it
learns, for each session, the session number, the process ID of Vitrine and whether the session is locked. It keeps
this only in memory. It writes its own entries to the audit log and the event log (see above) and, if Vitrine
disappears while locked, disconnects that session (Windows sign-in screen). It opens no network connection.

## Registry

| Key | Content | Written by |
|---|---|---|
| `HKLM\SOFTWARE\Policies\ICT-Baden\Vitrine`, `HKCU\SOFTWARE\Policies\ICT-Baden\Vitrine` | policies | Group Policy or Intune (ADMX) |
| `HKLM\SOFTWARE\Policies\Vitrine`, `HKCU\SOFTWARE\Policies\Vitrine` | old policy path, still read | older ADMX |
| `HKLM\SOFTWARE\Policies\ICT-Baden\Vitrine\Plugins\HttpAuth` (old: `…\Policies\Vitrine\Plugins\HttpAuth`) | URL of the HttpAuth sample plugin | you |
| `HKLM\SOFTWARE\ICT-Baden\Vitrine` | `Supervise` (1 = the service supervises, 0 = `SERVICE=0`), `Service` and `Autostart` (the MSI options, kept for updates), `StartMenuShortcut` | MSI |
| `HKLM\SOFTWARE\ICT-Baden\Vitrine\ServiceState` (volatile: only in memory, gone after a Windows restart) | `LockedSessions`: numbers of the sessions that were locked when the service stopped, so that the next service starts Vitrine locked there; deleted when the service starts | the service |
| `HKLM\SYSTEM\CurrentControlSet\Services\ICT-Baden.Vitrine` | registration of the service (`"…\Vitrine.exe" --service`, LocalSystem, automatic start, restart after failure) | MSI, `install.ps1` |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, value `Vitrine` | autostart for all users without the service (`"…\Vitrine.exe" --autostart`) | MSI only with `SERVICE=0` (unless `AUTOSTART=0`), `install.ps1 -NoService` |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, value `Vitrine` | autostart for one user ("Start with Windows"); removed by Vitrine when the service supervises it | Vitrine |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System`, values `DisableTaskMgr`, `DisableChangePassword`; `…\Policies\Explorer`, value `NoLogoff` | set to 1 while locked, previous values restored when unlocking | Vitrine (`Security.RestrictCtrlAltDel`) |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System`, value `DisableLockWorkstation` | set to 1 while locked (with `Lock.ReplaceWinL` while Vitrine runs) unless a policy already set it; removed or reset on unlock, exit, next start, by the watchdog or by the service (in `HKU\<SID>`) | Vitrine (`Security.RestrictCtrlAltDel`, `Lock.ReplaceWinL`) |
| `HKCU\Software\ICT-Baden\Vitrine\State`, value `DisableLockWorkstationBefore` | previous `DisableLockWorkstation` (`-1` = not set) while Vitrine's value is set; deleted together with it | Vitrine |
| `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\ICT-Baden Vitrine` (old: `…\Application\Vitrine`) | event source registration | MSI, `install.ps1`, `Vitrine.exe --register-eventlog` |

## Network connections

**Vitrine itself** opens no connection to ICT Baden or any other service of its own. There is no telemetry, no crash
reporting and no update check. All other connections come from features you set up:

| Connection | When | To where |
|---|---|---|
| **Microsoft Entra ID sign-in** | someone uses *Continue with Microsoft* (unlock, signature, administrator confirmation), or *Test sign-in* in the settings | Microsoft's sign-in service (public Azure cloud) through MSAL and Vitrine's sign-in window (WebView2; with `Entra.UseBroker = true`: the Windows account broker). The WebView2 Runtime is part of Windows; its own diagnostic data follows the device's Windows/Edge diagnostic-data settings; MSAL sends its name, version and the operating system in request headers, as every MSAL application does; the account, the sign-in data and the information that Conditional Access needs go to Microsoft. Processing at Microsoft falls under your organisation's agreement with Microsoft. Access tokens for applications go to the API the administrator allowed. |
| **MSAL runtime (`msalruntime.dll`)** | in the release packages (`Microsoft.Identity.Client.NativeInterop` 0.20.4, MIT – [Entra ID](entra-id.md#windows-account-broker-wam-and-microsoft-licence-terms)); used only during a Microsoft sign-in with `Entra.UseBroker = true`; not in builds with `-p:WamBroker=false` | It passes the sign-in to the Windows account broker (WAM, part of Windows), which contacts Microsoft's sign-in service for the account. See [What the MSAL runtime sends](#what-the-msal-runtime-sends) below. |
| **Windows sign-in and group names** | Windows password sign-in; resolving `DOMAIN\group` entries | Windows contacts your domain controllers as for any logon |
| **Network copy of the audit log** | `Audit.NetworkDirectory` is set | your file server (SMB) |
| **Plugins** | a plugin is installed and used | wherever the plugin connects. The [HttpAuth sample](plugins.md#sample-httpauth) sends user name, **password**, reason and computer name to the https URL you configure. |
| **Scripts** | `Scripts.On…` commands are set | whatever the commands do |
| **Links in the About window** | only when someone clicks them | the browser opens fixed https addresses: the source code, help and support and the licences on GitHub (`github.com/ict-baden/vitrine`), the product page, the privacy notice and the legal notice on `ict-baden.de` |

### What the MSAL runtime sends

The MIT licence of version 0.20.4 contains no clauses on data collection or updates (unlike the terms of 0.20.6 and
later, which Vitrine does not ship). What the component does is a separate question. We checked the shipped file
(`msalruntime.dll`, SHA-256 `b17764a7…44a9`) and the MSAL.NET 4.84.1 code that calls it; this is **static analysis,
not a network capture**:

- **Addresses:** the only network addresses in the DLL are Microsoft sign-in endpoints (`login.microsoftonline.com`
  and its national-cloud variants, `login.windows.net`, `sts.windows.net`, `login.microsoft.com`, `live.com` for
  personal accounts) and the certificate URLs of its own code signature (`crl.microsoft.com`, `www.microsoft.com/pki…`,
  used by Windows when it checks the signature). There is **no telemetry collector** – no `events.data.microsoft.com`,
  `vortex`, `browser.events`, Aria/1DS/OneCollector or Application Insights address. Its own HTTP goes through Windows
  (WinINet).
- **Telemetry:** the runtime records telemetry about each sign-in (error codes, timings) and returns it to the caller
  (`MSALRUNTIME_GetTelemetryData`; a message in the DLL reads "Full MSALRuntime telemetry not yet implemented").
  MSAL.NET 4.84.1 only keeps it in the in-memory sign-in result (`AuthenticationResultMetadata.Telemetry`) and writes
  it to MSAL's log at verbose level. Vitrine sets no MSAL logger and no telemetry client and does not read the field,
  so it is discarded with the result. It cannot be switched off separately, and there is nothing to switch off.
- **Updates:** no update or installer code was found (no update addresses, no download-to-file or installer calls).
  The DLL is an ordinary file in the package; it changes only when Vitrine is updated, and the build fails if it is
  not exactly the 0.20.4 file.
- **Windows itself:** the account broker that does the actual sign-in (`Microsoft.AAD.BrokerPlugin`) is part of
  Windows. What it reports to Microsoft is governed by the device's Windows diagnostic-data settings, not by Vitrine.
- **Not determined:** what the closed-source runtime does at run time beyond what its strings and imports show.
  Microsoft publishes no source code or release notes for it. Organisations that need certainty can capture the
  traffic during a test sign-in, or build without the broker (`-p:WamBroker=false`).

## Deleting everything

1. **Exit Vitrine** in every session and uninstall it (MSI: *Apps & features*; script: `deploy\install.ps1 -Uninstall`).
   Uninstalling stops and removes the service and removes the program files, the autostart entry for all users and the
   Start menu entry, but **not** the configuration and the audit logs. Without the MSI or the script, remove the service
   as administrator with `sc.exe stop ICT-Baden.Vitrine` and `sc.exe delete ICT-Baden.Vitrine`.
2. **Delete the folders:**
   - `%ProgramData%\ICT-Baden\Vitrine` (configuration and audit logs) and `%ProgramData%\Vitrine` (older builds);
   - in every user profile `%LocalAppData%\Vitrine`, `%LocalAppData%\ICT-Baden\Vitrine` (leftovers of the sign-in window) and `%AppData%\Vitrine`;
   - the network copies `<COMPUTERNAME>-audit-*.jsonl` on the share, if used.
   Check your retention obligations first ([Retention](#retention)).
3. **Registry:** remove the policies by removing the Group Policy or Intune profile (keys
   `SOFTWARE\Policies\ICT-Baden\Vitrine` and `SOFTWARE\Policies\Vitrine` in HKLM and HKCU), the value `Vitrine` under
   `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` for each user who switched on "Start with Windows", and
   `HKLM\SOFTWARE\ICT-Baden\Vitrine` if it is still there. If Vitrine was removed while a workstation was locked, check
   the three Ctrl+Alt+Del values listed under [Registry](#registry) for that user; Vitrine normally restores them at
   the next start.
4. **Event source** (as administrator, in PowerShell):
   `[Diagnostics.EventLog]::DeleteEventSource("ICT-Baden Vitrine")` and, on older installations, the same with `"Vitrine"`.
   This removes only the registration; entries already in the Application log stay until the log is overwritten or
   cleared.

## Retention

Vitrine does not rotate, archive or delete audit logs; a new file starts each month and the old ones stay. How long
logs are kept – and when they must be deleted – is decided by the operator, balancing record-keeping obligations (for
example GxP) against data minimisation. The retention of the Windows event log follows its size and retention
settings in Windows.

## Works council and co-determination

Vitrine is a screen lock; it is **not intended to monitor the behaviour or performance of employees**. Its audit log
does record when people lock and unlock their workstation and when they fail to sign in. Whether introducing and using
Vitrine is subject to co-determination (in Germany for example § 87 (1) no. 6 BetrVG) is for the company to assess
with its works council and data protection officer where they exist. This is not legal advice. `Audit.LogLockState =
false` leaves out the `Locked` entries; unlocks, failed attempts and signatures are still recorded.

## Who is responsible

The operator – the organisation that installs and configures Vitrine – is the controller of the data in configuration
files, audit logs, event log entries and network copies; ICT Baden receives none of it through the software. When
ICT Baden processes such data on the operator's behalf, for example audit logs sent in for support, this needs a data
processing agreement as part of the support contract. Free support on GitHub is public: do not attach audit logs or
real names ([SUPPORT.md](../SUPPORT.md)). Security issues: [SECURITY.md](../SECURITY.md). Privacy notice of ICT Baden for
Vitrine: [ict-baden.de/datenschutz/vitrine](https://ict-baden.de/datenschutz/vitrine/) · legal notice:
[ict-baden.de/impressum](https://ict-baden.de/impressum/).

---

<p align="center"><sub>
<a href="installation.md">Installation</a> · <a href="usage.md">Usage</a> · <a href="command-line.md">Command line</a> · <a href="settings.md">Settings</a> · <a href="sign-in.md">Sign-in</a> · <a href="entra-id.md">Entra ID</a> · <a href="audit-log.md">Audit log</a> · <a href="interface.md">Interface</a> · <a href="plugins.md">Plugins</a> · <a href="gxp.md">GxP</a> · <b>Data and privacy</b> · <a href="error-codes.md">Error codes</a> · <a href="limitations.md">Limitations</a> · <a href="development.md">Development</a><br>
<a href="../README.md">← Back to Vitrine</a>
</sub></p>
