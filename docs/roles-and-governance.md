[Vitrine](../README.md) › Roles and governance

# Roles and governance

Since 0.5.0 Vitrine separates **who may change it**, **who may register security keys** and **who may review it**, offers
an **emergency sign-in** with a mandatory reason, keeps track of the **person responsible** for the computer, records
**configuration changes with reason and changed values**, and writes an **authorization report** for periodic review.
All of it is off or unchanged by default: without configuration Vitrine behaves exactly as 0.4.0.

**Contents:** [Roles](#roles) · [Local administrators](#local-administrators) · [Emergency sign-in](#emergency-sign-in) ·
[Reasons for administrator confirmations](#reasons-for-administrator-confirmations) ·
[Configuration changes with reason](#configuration-changes-with-reason) · [Responsible person](#responsible-person) ·
[Authorization report](#authorization-report) · [Settings](#settings) · [Example](#example)

## Roles

| Role | Setting | May | Default (empty) |
|---|---|---|---|
| **Configuration administrator** | `Roles.ConfigAdmins` | open and change the settings, exit Vitrine (with `Security.SettingsAdminOnly` and `Security.ExitRequiresAdmin`, both on by default) | administrators |
| **Security key registrar** | `Roles.Registrars` | register and revoke security keys for other persons (used by the security key method) | administrators |
| **Auditor** | `Roles.Auditors` | view and export the audit log and the authorization report; nothing else | configuration administrators |

Entries use the syntax of `Unlock.AllowedGroups` ([Sign-in › Who may unlock](sign-in.md#who-may-unlock)): `DOMAIN\group`,
a local group (`Vitrine-Auditors`, `.\Vitrine-Auditors`, `COMPUTER\group`, also with Entra accounts or groups as members –
see [local groups with Microsoft sign-in](sign-in.md#local-groups-with-microsoft-sign-in)), a SID, or an Entra group
object ID (needs the groups claim). A person has a role when:

- the sign-in succeeded and is **personal** – the shared unlock password never has a role;
- the account is in an allowed domain (`Unlock.AllowedDomains`, if set);
- and the person is a member of one of the role's groups, **or** a member of the local Administrators group while
  `Security.LocalAdministratorsArePrivileged` is on (default).

Configuration administrators are always auditors too. Roles are checked at each confirmation, with the sign-in of that
confirmation – group changes take effect at the next confirmation.

**Opening the settings** with `Security.SettingsAdminOnly` on: if the Windows session user is a configuration
administrator, the settings open directly (as before for administrators). Otherwise Vitrine asks for a sign-in
("Administrator required") and accepts a configuration administrator or an auditor. An auditor gets the settings
**read-only**: only the page *Audit log* (verify, open folder, authorization report), all switches locked, no *Save*.
**Exiting** with `Security.ExitRequiresAdmin` on needs a configuration administrator, as before always with a sign-in.

The interface name for other parts of Vitrine is `IRoleCheck` (`IsConfigAdmin`, `IsRegistrar`, `IsAuditor`) in
`Vitrine.Core.Auth`; the implementation is `RoleCheck`.

## Local administrators

`Security.LocalAdministratorsArePrivileged` (default `true`) keeps the behaviour of 0.4.0: members of the local
Administrators group (also Entra accounts and groups that are direct members, and Global Administrators recognised
through `wids`) hold all roles and may use the emergency sign-in.

Set it to `false` to separate duties: administrators then get no rights **in Vitrine** – settings, exit, key
registration, emergency sign-in – unless they are in a role group.

> [!IMPORTANT]
> **Trade-off.** This separates duties inside Vitrine, not on the computer. A local administrator can still stop the
> service, end Vitrine with Task Manager (the watchdog or the service then lock Windows), edit
> `%ProgramData%\ICT-Baden\Vitrine\config.json` or set policies. Limit and record administrator access to GxP
> workstations ([GxP › Points for your assessment](gxp.md#points-for-your-assessment)).

If `LocalAdministratorsArePrivileged` is `false` and `Roles.ConfigAdmins` is empty (with `Security.SettingsAdminOnly`
on), nobody can change the settings in Vitrine: the overview shows **VIT-0430**, and it is written once per start to the
audit log as `Error`. Settings can then only be changed by policy or in the configuration file.

`Unlock.Allowed` is not affected: if it contains `Administrators` (default), administrators may still **unlock**. Remove
the flag as well if that is not wanted.

## Emergency sign-in

`Unlock.BypassGroups` lists groups whose members may unlock with their **Windows password** even if the unlock rules
(`Unlock.Allowed`) do not allow them – for example a supervisor who has to stop an instrument at a workstation locked by
someone else. With `Security.LocalAdministratorsArePrivileged` on, local administrators may use it too. Empty (default):
no emergency sign-in.

- The unlock dialog shows the link **Emergency sign-in** below the buttons. It switches the dialog to the Windows
  password (also when `windows` is not among `Unlock.Methods`), clears the user name and shows a reason field and a
  note that the reason is recorded. **Back to normal sign-in** switches back.
- A **reason** is mandatory: at least `Unlock.BypassReasonMinLength` characters (default 10, at least 1; control
  characters removed, at most 500). A missing reason is not a failed attempt; the dialog asks again (VIT-0433).
- Only the Windows password counts (VIT-0434 otherwise): it is personal and checked by Windows. The shared unlock
  password never.
- A person who is not in a bypass group is refused with **VIT-0432** and an `UnlockDenied` entry with `"emergency":
  "true"`; it counts as a failed attempt.
- A successful emergency unlock is logged as **`UnlockBypass`** (instead of `Unlocked`) with the reason in `Data.reason`
  and `Data.emergency = "true"`, and **always** as a **warning** in the Windows event log (event ID 1024), also when
  `Audit.EventLog` is off. With the service, the entry has assurance `client`; the service checks the Windows password
  only for signatures.
- `Unlock.AllowedDomains` still applies.

## Reasons for administrator confirmations

With `Security.ReasonRequiredForAdminActions` (default off) the dialog **Administrator required** (opening the
settings, exiting Vitrine) shows a reason field. The reason needs at least `Security.ReasonMinLength` characters
(default 10) and is recorded in the `ConfigChanged` entry `Administrator approval: …` as `Data.reason`, together with
the roles of the person (`Data.roles`). When the session user is a configuration administrator, the settings open
without a dialog and therefore without a reason – changes are recorded with their own reason (next section).

## Configuration changes with reason

Every save in the settings window now records **which values changed**: the `ConfigChanged` entry has the detail
`Settings saved: <n> change(s)` and in `Data` one key per changed setting (`"Lock.IdleMinutes": "0 -> 10"`), the
number of changes (`changes`) and, if a reason was given, `reason`. Lists are written as JSON
(`["entra","windows"] -> ["windows"]`). Secrets – settings whose name ends in `Hash`, `Password` or `Secret`, today
`Unlock.PinHash` – appear only as `(hidden)` or `(not set)`. With the service at most 32 data fields of 500 characters
fit into an entry: values are shortened to 200 characters, and changes beyond 29 are listed by name under `more`.

The `Actor` is the person who opened the settings: the Windows session user when no confirmation was needed, otherwise
the person who confirmed.

With `Security.ReasonRequiredForConfigChanges` (default off) *Save* first opens a dialog that lists the changes and
asks for a reason (at least `Security.ReasonMinLength` characters). Without a reason nothing is saved. The setting
applies when it is on in the current configuration **or** in the one being saved.

The comparison is made on the JSON of the configuration that the settings window saves (defaults plus device file,
without policies and without the per-user file). Values set by policy are not part of it; changes to policies are
recorded by your Group Policy or Intune change management.

## Responsible person

Vitrine keeps track of who is **responsible for the computer right now** (GxP: who is accountable for what happens at
the workstation):

- At the start of the Windows session it is the signed-in Windows user.
- When **another person** unlocks, responsibility passes to that person and Vitrine writes **`ResponsibilityChanged`**
  with the detail `<from> -> <to>` and in `Data` `fromUser`, `fromName`, `fromMethod`, `fromSince` (UTC), `toUser`,
  `toName` and `method`. When the same person unlocks again, nothing is written and *since* stays.
- The same account with Microsoft sign-in and with Windows sign-in on an Entra-joined device counts as the same person
  (the object ID is converted to the `S-1-12-1-…` SID Windows uses).
- An unlock with the shared unlock password makes the **shared unlock password** responsible – i.e. nobody identifiable
  – and is recorded as a change.
- The notification area flyout and the settings overview show **"Responsible: \<name\> since \<time\>"**.
- On sign-out of the Windows session responsibility ends. It is kept in memory only: if Vitrine is restarted within a
  session (crash, update), it starts again with the session user.

## Authorization report

The authorization report lists, as configured at that moment:

- who may unlock (`Unlock.Allowed` in words, groups with their **current direct members**, accounts, domains, methods);
- where security keys are stored (`Fido.Store`: this computer, or Active Directory with the container and the last
  synchronization – the time comes from the Vitrine service, so it is "unknown" when the report is written from the
  command line or without the service);
- the emergency sign-in groups (with members) and the minimum reason length;
- the roles with their groups and members, whether local administrators are privileged, and the members of the local
  Administrators group;
- the confirmation and reason settings;
- for each setting whether it comes from **Group Policy** or from the configuration file (or default);
- computer, time (local and UTC), the account that generated it, the Vitrine version;
- a table for **Prepared by / Reviewed by / Approved by** with name, date and signature, for printing and signing.

Group members are resolved on the computer: local groups with `NetLocalGroupGetMembers` (Entra members appear as
`Entra ID <object ID>` if Windows has no name for them), domain groups with `NetGroupGetUsers` on a domain controller
(direct user members of global groups; other group types and nested groups appear as "members could not be
determined"). Entra ID groups and app roles are listed by ID – their members are managed in Entra ID; Vitrine does not
query Microsoft Graph.

Texts are in the user interface language. Two ways to create it:

- **Settings › Audit log › Authorization report** (auditors and configuration administrators): choose a file; Vitrine
  writes the HTML report and a CSV file with the same name next to it (or only CSV if you choose `.csv`) and opens the
  HTML file.
- **Command line:** `Vitrine.exe --authorization-report <file> [--quiet]` – see
  [Command line](command-line.md#--authorization-report-file---quiet).

The CSV has one line per setting and per group (`Section,Setting,Description,Value,Source,Group,Members`), RFC 4180
quoting, UTF-8 with BOM; cells starting with `=`, `+`, `-` or `@` are prefixed with `'` so that spreadsheet programs do
not run them as formulas.

## Settings

All settings are on the settings page **Roles** and in the policy category **Roles and governance**:

| Setting | Default | Meaning |
|---|---|---|
| `Roles.ConfigAdmins` | empty | Configuration administrators |
| `Roles.Registrars` | empty | Security key registrars |
| `Roles.Auditors` | empty | Auditors |
| `Security.LocalAdministratorsArePrivileged` | `true` | Local administrators hold all roles |
| `Unlock.BypassGroups` | empty | Emergency sign-in groups |
| `Unlock.BypassReasonMinLength` | `10` | Minimum length of the emergency reason |
| `Security.ReasonRequiredForAdminActions` | `false` | Reason for administrator confirmations |
| `Security.ReasonRequiredForConfigChanges` | `false` | Reason for configuration changes |
| `Security.ReasonMinLength` | `10` | Minimum length of these reasons |

Details and registry values: [Settings](settings.md#roles--category-roles-and-governance).

## Example

A GxP laboratory: QA reviews, IT configures, lab supervisors may unlock in an emergency, local administrators get no
rights in Vitrine.

```json
{
  "Roles": {
    "ConfigAdmins": [ "CONTOSO\\Vitrine-Config" ],
    "Auditors": [ "CONTOSO\\QA-Reviewers" ],
    "Registrars": [ "CONTOSO\\Vitrine-KeyDesk" ]
  },
  "Unlock": {
    "Allowed": "SessionUser",
    "BypassGroups": [ "CONTOSO\\Lab-Supervisors" ],
    "BypassReasonMinLength": 15
  },
  "Security": {
    "LocalAdministratorsArePrivileged": false,
    "ReasonRequiredForAdminActions": true,
    "ReasonRequiredForConfigChanges": true
  }
}
```

Review the authorization report periodically (e.g. quarterly), sign it and file it with your system documentation;
filter the audit log for `UnlockBypass`, `ResponsibilityChanged` and `ConfigChanged` in your periodic review.

---

<p align="center"><sub>
<a href="installation.md">Installation</a> · <a href="usage.md">Usage</a> · <a href="command-line.md">Command line</a> · <a href="settings.md">Settings</a> · <a href="sign-in.md">Sign-in</a> · <b>Roles and governance</b> · <a href="entra-id.md">Entra ID</a> · <a href="audit-log.md">Audit log</a> · <a href="interface.md">Interface</a> · <a href="plugins.md">Plugins</a> · <a href="gxp.md">GxP</a> · <a href="data-and-privacy.md">Data and privacy</a> · <a href="error-codes.md">Error codes</a> · <a href="limitations.md">Limitations</a> · <a href="development.md">Development</a><br>
<a href="../README.md">← Back to Vitrine</a>
</sub></p>
