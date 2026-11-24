[Vitrine](../README.md) › Pharma and GxP

# Pharma and GxP

**21 CFR Part 11 · EU GMP Annex 11.** Vitrine provides building blocks that GxP workstations ask for – access control,
an audit trail and electronic signatures with a meaning. It does **not** make a system compliant on its own.

**Contents:** [What Vitrine is not](#what-vitrine-is-not) · [Requirements and what Vitrine provides](#requirements-and-what-vitrine-provides) ·
[Signatures in detail](#signatures-in-detail) · [Points for your assessment](#points-for-your-assessment) ·
[What you still have to validate](#what-you-still-have-to-validate)

## What Vitrine is not

> [!CAUTION]
> Vitrine is **not a validated product**, and ICT Baden makes **no claim** that using it meets 21 CFR Part 11, EU GMP
> Annex 11 or any other regulation. Validation (computerised system validation, IQ/OQ/PQ), the risk assessment and the
> procedures around it are the responsibility of the operator. Version 0.5.1 has not yet been tested on real devices
> with real tenants ([Limitations](limitations.md)). Code and log format are kept simple so that a validation is
> feasible.

## Requirements and what Vitrine provides

| Requirement | What Vitrine provides |
|---|---|
| **Access limited to authorised people**<br><sub>Part 11 §11.10(d)</sub> | Unlocking only for defined people, groups or roles ([Who may unlock](sign-in.md#who-may-unlock)). Failed attempts: growing waiting time from the 3rd attempt; a limit with an action (lock Windows, sign out, shut down) must be switched on with `Security.FailureAction` – it is off by default. |
| **Unique identification of people**<br><sub>§11.100, §11.300</sub> | Personal sign-in with Microsoft Entra ID, Windows/Active Directory, Windows Hello or a security key registered for one person. The shared unlock password is **not attributable to a person**: it is refused for signatures and administrator actions, marked as shared in the log (`"shared": "true"`), and the settings warn "Shared unlock password active". Do not use it on GxP workstations. |
| **Audit trail**<br><sub>§11.10(e), Annex 11 §9</sub> | Every action with UTC time, person, method and result. **With the service** (MSI default): the service (LocalSystem) writes the log, sets time, sequence number and session user itself and **signs every entry** with a key only it holds (ECDSA P-256, CNG machine key for SYSTEM); users can only read the log folder; an anchor outside the file (registry, writable by SYSTEM only) makes a cut-off end or a deleted or swapped file visible. A reviewer verifies with the public key (`--export-audit-key`), without the secret. **Without the service** (single exe, `SERVICE=0`): hash chain without a key, **not Part 11 capable** – marked in the log, in the settings and in the interface answer. Both are **tamper-evident**: changes become visible, they are not prevented. Copies on a network share and in the Windows event log serve as second trail. [Audit log →](audit-log.md#signed-audit-log-format-3) |
| **Signature with meaning**<br><sub>§11.50, §11.70</sub> | `authenticate` through the local [interface](interface.md#electronic-signature): the dialog shows the reason, the **meaning** and the requesting application; the log records person, UTC time, reason and meaning. The response contains `auditSeq`, `auditHash` and `assurance` as a link to the log entry. Each signature needs a sign-in in the dialog; with Entra ID it is a fresh sign-in only while `Entra.ForceFreshSignIn` is on. With the service, the **service checks the sign-in itself** for the Windows password (`LogonUser` in the service) and Microsoft Entra ID (signature and claims of the ID token) and registered security keys (signature, PIN flag and counter of the key, [Security keys](security-keys.md)) – `assurance` `verified`. Windows Hello and plugins cannot be checked by the service (`client`) – see [Signatures in detail](#signatures-in-detail). |
| **Authority checks and segregation of duties**<br><sub>§11.10(g), Annex 11 §12.1</sub> | Since 0.5.0 [roles](roles-and-governance.md#roles): configuration administrators, security key registrars and auditors (read-only) as separate groups; optionally without rights for local administrators. An [authorization report](roles-and-governance.md#authorization-report) (HTML with signature lines, CSV) lists who may unlock and who holds which role, for periodic review. |
| **Emergency access**<br><sub>Annex 11 §12, §16</sub> | Since 0.5.0 an [emergency sign-in](roles-and-governance.md#emergency-sign-in) for defined groups, only with the Windows password and a reason; logged as `UnlockBypass` and always as event log warning. |
| **Accountability and change control**<br><sub>Annex 11 §10, §12.4</sub> | Since 0.5.0 `ResponsibilityChanged` records when another person takes over the computer ([responsible person](roles-and-governance.md#responsible-person)); every configuration change is recorded with old and new values and optionally with a mandatory reason ([configuration changes](roles-and-governance.md#configuration-changes-with-reason)). |
| **Automatic locking**<br><sub>§11.300, Annex 11 §12</sub> | Lock after idle time, on a schedule and at startup. The unlock dialog closes after a timeout. |

## Signatures in detail

- **Four-eyes principle at the same workstation:** any person with a successful personal sign-in may sign, including
  someone other than the session user. Restrict this with `Unlock.AllowedDomains` and the Entra tenant check
  ([Entra ID › Tenant check](entra-id.md#tenant-check)). `Unlock.Allowed`, groups and accounts do not apply to
  signatures.
- **What the dialog shows:** "You are signing electronically", the reason, "Meaning: …", "Requested by …" and "Your
  signature is recorded with name, time and meaning." The heading shows the name of the **session user**, not
  necessarily the person who signs. The dialog does not show the signer's name or the time; both are in the audit log
  and in the response to the application, which should display them in its own record.
- **Link:** with `auditSeq` and `auditHash` the application can tie the signature to one audit log entry. The `time`
  field of the response is the time of the response, not that of the log entry.
- **Failures:** every failed attempt in the signature dialog and the closing without a signature are logged as
  `SignatureFailed`.
- **Signature manifestation** (name, date and time, meaning shown with the signed record, §11.50) is the job of the
  application that requests the signature. Vitrine supplies the data.
- **Which methods count as Part 11 signatures.** Only signatures whose sign-in the **service** checked:
  **Windows password**, **Microsoft Entra ID** and **security keys registered for Vitrine** (`fido`, since 0.5.0: the
  service issues the challenge, verifies the key's signature, PIN flag and counter and resolves the person), on an
  installation with the service (`assurance` `verified` in the log and in the response). Registering and revoking
  keys is itself recorded (`FidoKeyRegistered`, `FidoKeyRevoked`, with registrar, person and reason) – include the
  registration procedure in your SOPs ([Security keys](security-keys.md)). The Windows security dialog shows only the
  RP ID, not what is signed; Vitrine allows a signature challenge only while its own signature dialog (reason,
  meaning) is open – the residual risk for sessions whose user controls Vitrine's process is described in
  [Security keys › Signatures](security-keys.md#signatures). **Windows Hello** and **plugins** are checked only inside the user's session; the service
  records them as `client` (reported by the app; for Hello always the session user). Treat them as not Part 11
  capable, or validate the plugin as part of your system and accept the risk in your assessment. The application can
  refuse anything but `verified` by checking `assurance`. Without the service, every signature is `local`.
- **Service not reachable:** signatures are refused (VIT-0300) – locking and unlocking keep working, their entries wait
  in memory ([Audit log › Service not reachable](audit-log.md#service-not-reachable)).

## Points for your assessment

These follow from how Vitrine behaves and belong in the operator's risk assessment:

| Topic | What applies |
|---|---|
| Failed attempts | `Security.FailureAction` is `None` by default – set it if you need a hard limit. The waiting time after failed attempts applies across dialogs – closing and reopening the dialog does not end it; only a successful unlock resets the counter ([Sign-in › Failed attempts](sign-in.md#failed-attempts)). |
| Entra tenant | Since 2026-10-21 Microsoft sign-in (also for signatures) works only with a tenant ID (GUID) in `Entra.TenantId` or `Entra.AllowedTenants` (VIT-0117). Every listed tenant is trusted equally. |
| Fresh sign-in | Leave `Entra.ForceFreshSignIn` on; `Entra.MaxAuthAgeSeconds` limits the age of the sign-in (only if the token carries `auth_time`). |
| Shared password | The shared unlock password bypasses `Unlock.Allowed` and `Unlock.AllowedDomains` and names no person. |
| Audit log with the service | Users cannot write the log; appended, changed, removed or reordered lines, a cut-off end, a deleted or swapped file are reported by `--verify-log` ([What the log does and does not prove](audit-log.md#what-the-log-does-and-does-not-prove)). **Administrators can** stop the service, take over the machine key and the registry anchors, and then write validly signed lines or rewrite a file with its anchor – this cannot be prevented on the computer. Limit and record administrator access to GxP workstations, and keep the **network copy** (computer accounts may only append) and the **event log forwarded to a collector** as second trail; compare sequence numbers and hashes in your periodic review. Record the key fingerprint (`--export-audit-key`) in your IQ documents. Entries marked `client` (lock, unlock, failed attempts, Hello and plugin signatures) are statements of the session app: a user who manipulates their own session can have wrong content recorded, always under their own session user. |
| Audit log without the service | The hash chain has no key; whoever can write a log file can recompute the chain or cut off its end, and **every user who may append to the file (under the installer's permissions: every user of the computer) can append forged entries with a valid hash** – e.g. a fake signature. Not Part 11 capable; do not use on GxP workstations. The per-user fallback folder has no protection at all. |
| Key management | The key is created at the first start of the service and kept on update, reinstallation and uninstallation; rotation with `--rotate-audit-key` (the change is signed with the old key). A new computer has a new key – archive old logs with their `audit-keys.json`. |
| Microsoft signatures and network | The service checks Entra ID tokens against Microsoft's signing keys and must reach `https://login.microsoftonline.com` as the computer (VIT-0312 otherwise). It reads `Entra.ClientId` and the tenant settings from the device configuration or computer policy only. The app registration must issue the optional claim **`auth_time`** (VIT-0320 otherwise); keep `Entra.ForceFreshSignIn` on, so that only a sign-in after the signature request counts – a single sign-on session of someone who signed earlier does not ([Entra ID › Signatures checked by the service](entra-id.md#signatures-checked-by-the-service)). |
| Failed attempts in the log | For Microsoft, Hello and plugins, the `Actor` of a failed attempt is the prefilled session user name, not necessarily the person who tried. |
| Time | Log times come from the computer's clock (UTC). Synchronise the clock (domain time or NTP) and restrict who can change it. |
| Several sessions | Several sessions on one computer (Remote Desktop, user switching) write one continuous chain into the same monthly file; each append waits until no other session writes. |
| Configuration | Set values centrally by [policy](settings.md); they are then locked in the user interface. Every save in the settings window is logged as `ConfigChanged` with the changed values (old and new, secrets hidden) and, with `Security.ReasonRequiredForConfigChanges`, a mandatory reason; the `Actor` is the person who opened the settings (since 0.5.0). Changes made by policy or directly in `config.json` are not in the Vitrine log – control them through your change management. The switch "Start with Windows" is not logged. |
| Roles and administrators | By default local administrators hold all Vitrine roles, as before 0.5.0. With `Security.LocalAdministratorsArePrivileged = false` they have no rights in Vitrine unless they are in a role group – but they can still stop the service or edit the configuration. Roles separate duties in Vitrine, not on the computer ([trade-off](roles-and-governance.md#local-administrators)). Review the [authorization report](roles-and-governance.md#authorization-report) periodically; it shows group members as found at that moment (direct members; nested domain groups and Entra groups not resolved). |
| Emergency sign-in | `UnlockBypass` entries come from the session app (`assurance` `client`); the reason is free text. Review every emergency unlock; the event log warning (ID 1024) is the second trail. |
| Responsible person | Kept in memory of the session app; restarts with the session user after a crash or update within a session. The shared unlock password makes nobody identifiable responsible. |
| Plugins | Plugins are fully trusted and not signature-checked ([Plugins › Security](plugins.md#security)). Treat each plugin as part of the validated system. |
| Third-party component | The release packages contain the Windows account broker again (`msalruntime.dll` from `Microsoft.Identity.Client.NativeInterop` 0.20.4, MIT, closed source; MSAL.NET pinned to 4.84.1). Microsoft Entra ID is offered for unlocking again; the packages from 2026-10-20 up to 0.2.0 did not offer it and fell back to the Windows password with Microsoft-only configurations (VIT-0016). Re-validate the unlock procedure after the update and register the broker redirect URI ([Entra ID](entra-id.md#windows-account-broker-wam-and-microsoft-licence-terms)). Since 0.4.0 the broker is used only with `Entra.UseBroker = true`; the default is Vitrine's own [sign-in window](entra-id.md#sign-in-window) (WebView2, `Microsoft.Web.WebView2` 1.0.4258.31, BSD-style licence, nothing remembered between sign-ins) – re-validate Microsoft unlocking and signatures, and note that device-based Conditional Access is not met by the sign-in window. What the runtime sends: [Data and privacy](data-and-privacy.md#what-the-msal-runtime-sends). |

Further technical limits: [Limitations](limitations.md).

## What you still have to validate

At least the following, on your own devices and with your own tenant, before productive use:

- sign-in with each method you enable (Entra with MFA and Conditional Access, Windows password, Windows Hello, plugins),
  and the refusals of people who must not unlock or sign;
- the failed-attempt action you configure;
- that the lock holds on your hardware, with several monitors, over Remote Desktop and after a crash (watchdog);
- that the service writes the log (`"V":3`, settings show *Written and signed by the service*), that users cannot
  write the log folder, and the key fingerprint (`--export-audit-key`);
- the detection: append, change, remove a line, cut off the end, delete and swap a file – `--verify-log` must report
  each (as administrator on a test machine);
- signatures with each method and the `assurance` your application accepts; signatures refused while the service is
  stopped;
- the folder permissions of the log folder and the network share (computer accounts), and your procedure for checking
  the log against the independent copies;
- the integration of your application with the interface, including how it displays and stores the signature;
- installation, upgrade from earlier builds and the configuration by policy.

---

<p align="center"><sub>
<a href="installation.md">Installation</a> · <a href="usage.md">Usage</a> · <a href="command-line.md">Command line</a> · <a href="settings.md">Settings</a> · <a href="sign-in.md">Sign-in</a> · <a href="entra-id.md">Entra ID</a> · <a href="audit-log.md">Audit log</a> · <a href="interface.md">Interface</a> · <a href="plugins.md">Plugins</a> · <b>GxP</b> · <a href="data-and-privacy.md">Data and privacy</a> · <a href="error-codes.md">Error codes</a> · <a href="limitations.md">Limitations</a> · <a href="development.md">Development</a><br>
<a href="../README.md">← Back to Vitrine</a>
</sub></p>
