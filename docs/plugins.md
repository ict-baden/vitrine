[Vitrine](../README.md) › Sign-in plugins

# Sign-in plugins

A plugin adds **a sign-in method of your own** to the dialog – for example against the user management of a LIMS or a
company GxP sign-in service. It is a .NET class library that implements `IAuthProvider`.

**Contents:** [IAuthProvider](#iauthprovider) · [Building a plugin](#building-a-plugin) · [Installing](#installing) ·
[Security](#security) · [Sample: HttpAuth](#sample-httpauth)

## IAuthProvider

The interface is in `Vitrine.Abstractions` ([`src/Vitrine.Abstractions/IAuthProvider.cs`](../src/Vitrine.Abstractions/IAuthProvider.cs), `net10.0`).

| Member | Meaning |
|---|---|
| `string Id` | unique, stable ID, e.g. `acme-lims`; this is what goes into `Unlock.Methods` |
| `string DisplayName` | label of the method button in the dialog |
| `string Glyph` | a character from the *Segoe Fluent Icons* font |
| `AuthInputKind Input` | `UsernamePassword`, `Secret` (password or PIN only) or `External` (no input fields; the plugin shows its own UI) |
| `Task<bool> IsAvailableAsync(ct)` | whether the method can be used right now; if not, it is not shown. An exception counts as "not available". |
| `Task<AuthOutcome> AuthenticateAsync(request, ct)` | the sign-in itself |

**`AuthRequest`** – what Vitrine passes in:

| Property | Content |
|---|---|
| `UserName` | the user name typed in the dialog (`UsernamePassword`); for `Secret` and `External` the prefilled name of the session user, or empty |
| `Secret` | the password typed in the dialog (empty for `External`) |
| `OwnerWindow` | window handle of the dialog, for your own windows |
| `Reason` | why the person signs in, **in the user interface language**: "Unlock workstation" when unlocking, the action ("Open settings", "Exit Vitrine") in the administrator dialog, the reason sent by the application for signatures. The default `"Unlock"` applies only to requests a plugin builds itself. |
| `SessionUser` | `DOMAIN\name` of the Windows session |
| `SessionUpn` | UPN of the session, if Windows knows one |

**`AuthOutcome`** – what the plugin returns:

| Property | Meaning |
|---|---|
| `Success` | `true` if the sign-in succeeded |
| `Error` | message for the dialog, **in the user interface language** (`CultureInfo.CurrentUICulture`) |
| `ErrorCode` | language-independent code, e.g. `ACME-0007`. The dialog appends it to `Error` ("… (ACME-0007)") unless the text already contains it; the audit log records only the code. Without a code, Vitrine logs VIT-0100. |
| `UserName` | canonical account name, e.g. `CONTOSO\jdoe` or `jdoe@contoso.com` |
| `DisplayName` | display name |
| `UserId` | stable ID (SID, object ID or the ID in your system) |
| `Groups` | groups and roles that `Unlock.AllowedGroups` is compared with |
| `IsAdministrator` | counts as administrator ([Sign-in › Administrators](sign-in.md#administrators)) |
| `TenantId` | tenant, if any |
| `IsSessionUser` | the identity is the user of the locked session (`Unlock.Allowed = SessionUser`) |
| `Details` | extra values for the audit log (`Data`). `Details["shared"] = "true"` marks a shared secret: Vitrine then treats it like the [shared unlock password](sign-in.md#shared-unlock-password) and never accepts it for signatures or administrator actions. |

Shortcuts: `AuthOutcome.Fail(error)` and `AuthOutcome.Fail(error, code)`. If `AuthenticateAsync` throws, Vitrine shows
the exception message with VIT-0100.

After a successful sign-in, the [unlock rules](sign-in.md#who-may-unlock) apply as for the built-in methods,
including `Unlock.AllowedDomains`: if it is set, return `UserName` as `DOMAIN\name` or UPN, otherwise the person is
always refused (VIT-0141).

## Building a plugin

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net10.0-windows</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
  </PropertyGroup>
  <ItemGroup>
    <!-- Vitrine.Abstractions is provided by Vitrine at runtime – do not copy it -->
    <ProjectReference Include="..\..\src\Vitrine.Abstractions\Vitrine.Abstractions.csproj" Private="false" />
  </ItemGroup>
</Project>
```

```csharp
using Vitrine.Abstractions;

public sealed class AcmeLimsProvider : IAuthProvider
{
    public string Id => "acme-lims";
    public string DisplayName => "LIMS account";
    public string Glyph => "";                 // "Contact" in Segoe Fluent Icons
    public AuthInputKind Input => AuthInputKind.UsernamePassword;

    public Task<bool> IsAvailableAsync(CancellationToken ct) => Task.FromResult(true);

    public async Task<AuthOutcome> AuthenticateAsync(AuthRequest request, CancellationToken ct)
    {
        bool ok = await CheckWithLimsAsync(request.UserName, request.Secret, ct);
        if (!ok) return AuthOutcome.Fail(Texts.SignInRefused, "ACME-0001");   // your own translated text

        return new AuthOutcome
        {
            Success = true,
            UserName = $"CONTOSO\\{request.UserName}",
            DisplayName = request.UserName,
            UserId = request.UserName,
            Groups = new[] { "Vitrine.Unlock" },       // for Unlock.AllowedGroups
        };
    }

    private Task<bool> CheckWithLimsAsync(string? user, string? secret, CancellationToken ct)
        => throw new NotImplementedException();
}
```

The class must be **public**, not abstract, and have a **public parameterless constructor**. A real plugin should
translate its messages into the five languages of Vitrine (en, de, es, fr, zh-Hans) and use its own error codes.

## Installing

1. Copy the DLL to the `Plugins` folder **next to `Vitrine.exe`** – with the MSI or `install.ps1`:
   `%ProgramFiles%\Vitrine\Plugins`. Vitrine loads every `*.dll` in that folder (not in subfolders).
2. Add the ID to **`Unlock.Methods`** in `config.json` or through the policy "Sign-in methods". The settings window
   only has switches for the four built-in methods.
3. **`Integration.LoadPlugins`** must be on (default; policy "Load plugins"). Vitrine loads plugins only when, in
   addition, `Unlock.Methods` contains at least one ID that is not a built-in method (`entra`, `windows`, `hello`,
   `pin`) – otherwise no plugin code runs at all.
4. **Restart Vitrine** – plugins are loaded only at program start.

```json
{ "Unlock": { "Methods": [ "entra", "windows", "acme-lims" ] } }
```

Each DLL is loaded only if the file, the `Plugins` folder and the folder above it are protected like the device
configuration: owned by Administrators, SYSTEM or TrustedInstaller, no junctions or reparse points, and no other
account may change, delete, rename or re-permission them. Otherwise the plugin is skipped with VIT-0013. An ID that is
already taken, also by a built-in method, is refused (VIT-0004); a DLL that cannot be loaded gives VIT-0003. All three
appear in the settings overview as "Plugin not loaded". Loaded plugins are listed on the page
*Integration & scripts*.

`External` plugins with their own windows: while the workstation is locked, those windows receive input only if their
process is listed in `Security.AuthUiProcesses`.

## Security

> [!WARNING]
> **Plugins are fully trusted.** Vitrine loads them **without any signature check** into its own process, where they
> run with the rights of the signed-in user. A plugin can report any identity, any group and administrator status,
> and it can do anything Vitrine can – including ending the lock. Install only plugins you trust and have reviewed.

- **Only administrators may write to the `Plugins` folder.** Under `%ProgramFiles%` this is the case. Anyone who can
  put a DLL into the folder can take over the lock – that is why Vitrine checks file and folders before loading
  (VIT-0013, see [Installing](#installing)).
- **The single `Vitrine.exe`** in a folder that users can write to (Downloads, desktop, a share) does not load plugins
  from `Plugins` next to it: the folder is not protected (VIT-0013). Install Vitrine with the MSI to use plugins.
- Anything a plugin returns in `Details` ends up in the audit log; do not put secrets there.

## Sample: HttpAuth

[`samples/Vitrine.Plugin.HttpAuth`](../samples/Vitrine.Plugin.HttpAuth) checks user name and password against an HTTP
service. It is **source code only** and is not part of the releases; build it yourself, for example with
`dotnet build samples/Vitrine.Plugin.HttpAuth -c Release`, and copy `Vitrine.Plugin.HttpAuth.dll`.

| Property | Value |
|---|---|
| **ID / button** | `httpauth` / "LIMS account", user name + password |
| **Service URL** | registry value `Url` (REG_SZ) under `HKLM\SOFTWARE\Policies\ICT-Baden\Vitrine\Plugins\HttpAuth`; if missing, the old path `HKLM\SOFTWARE\Policies\Vitrine\Plugins\HttpAuth` is read. Only an absolute **https** URL makes the method available. |
| **Timeout** | 15 s |

```text
POST {Url}   {"user":"…","password":"…","reason":"…","machine":"…"}
200          {"ok":true,"user":"CONTOSO\\jdoe","displayName":"Lab operator","roles":["QA","Vitrine.Unlock"],"admin":false}
200/401      {"ok":false,"error":"…"}
```

- The service receives the **password in clear text inside TLS**, plus the reason (in the user interface language) and
  the computer name. Use it only with a service you control.
- `roles` become groups (e.g. `Vitrine.Unlock` for `Unlock.AllowedGroups`), `admin` becomes administrator status.
- `IsSessionUser` is always `false`: an account in the line-of-business system is not automatically the Windows user.
  With the default rules (signed-in person + administrators), only people with `"admin": true` can unlock – use groups
  or accounts in `Unlock.Allowed` for everyone else.
- The audit log records `system=<host of the URL>` in `Data`.
- Messages are English, with the sample's own codes: `HTTPAUTH-0001` (user name or password missing),
  `HTTPAUTH-0002` (no https URL configured), `HTTPAUTH-0003` (sign-in rejected, with the service's message or the HTTP
  status), `HTTPAUTH-0004` (service not reachable).

> [!NOTE]
> The comment in the sample says to enable the ID "under Unlock → methods"; the settings window cannot do that. Add
> `httpauth` to `Unlock.Methods` as described under [Installing](#installing).

---

<p align="center"><sub>
<a href="installation.md">Installation</a> · <a href="usage.md">Usage</a> · <a href="command-line.md">Command line</a> · <a href="settings.md">Settings</a> · <a href="sign-in.md">Sign-in</a> · <a href="entra-id.md">Entra ID</a> · <a href="audit-log.md">Audit log</a> · <a href="interface.md">Interface</a> · <b>Plugins</b> · <a href="gxp.md">GxP</a> · <a href="data-and-privacy.md">Data and privacy</a> · <a href="error-codes.md">Error codes</a> · <a href="limitations.md">Limitations</a> · <a href="development.md">Development</a><br>
<a href="../README.md">← Back to Vitrine</a>
</sub></p>
