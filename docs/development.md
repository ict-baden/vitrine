[Vitrine](../README.md) › Development

# Development

**Contents:** [Requirements](#requirements) · [Build and test](#build-and-test) · [Project structure](#project-structure) · [Texts and languages](#texts-and-languages) · [Packages and MSI](#packages-and-msi) · [CI and releases](#ci-and-releases) · [Screenshots and banner](#screenshots-and-banner) · [Rules for changes](#rules-for-changes)

## Requirements

- **.NET 10 SDK.** `global.json` pins `10.0.100` with `rollForward: latestFeature`.
- Building works on Windows, Linux and macOS (`EnableWindowsTargeting`). **Running** the app needs Windows 10 1809 or later / Windows 11.
- The app targets `net10.0-windows10.0.19041.0` (WPF, Windows Forms only for the notification-area icon). The Windows SDK version is needed because Windows Hello uses a WinRT API; this is a documented exception to the company guideline for Windows targets.
- NuGet dependencies that ship: `Microsoft.Identity.Client` 4.84.1 (MSAL), `Microsoft.Identity.Client.Broker` 4.84.1 with `Microsoft.Identity.Client.NativeInterop` 0.20.4 (`msalruntime.dll`, Windows account broker), `System.ServiceProcess.ServiceController` 10.0.13, `System.Formats.Cbor` 10.0.15 (security keys, in Vitrine.Core) and `System.DirectoryServices.Protocols` 10.0.13 (security keys in Active Directory). See [THIRD-PARTY-NOTICES.txt](../THIRD-PARTY-NOTICES.txt).
- **The MSAL versions are pinned exactly** (`[4.84.1]`, `[0.20.4]`): NativeInterop 0.20.6 and later are under licence terms that forbid redistribution, and the broker package from 4.84.2 on requires them. Never raise these versions without checking the licence of the new NativeInterop package; Dependabot ignores them, and `.github/scripts/check-broker-licence.ps1` fails the build if the restored version, its licence expression or the hash of `msalruntime.dll` in the packages differs ([Entra ID](entra-id.md#windows-account-broker-wam-and-microsoft-licence-terms)).
- The Windows account broker is in the default build (defines `WAM_BROKER`). `-p:WamBroker=false` builds without it: Entra ID then signs in through the browser and is not offered for unlocking.

## Build and test

```bash
dotnet build Vitrine.sln
dotnet test Vitrine.sln                      # Windows: platform-neutral and app tests
dotnet test tests/Vitrine.Tests -f net10.0   # Linux/macOS: only Vitrine.Core (what CI runs on Linux)
```

```powershell
dotnet run --project src/Vitrine -- --settings
```

`./build.sh` (macOS/Linux) is a quick compile check that lists errors and warnings compactly.

Tests never lock the machine, install hooks, write to the registry or sign in with real accounts. Windows-specific parts are behind small interfaces (`IPolicySource`, `IUserPolicyStore`, `IAuditSink`) so the logic can be tested with fakes in `Vitrine.Core`.

## Project structure

```text
src/Vitrine.Abstractions   Plugin interface IAuthProvider (public API, keep backward compatible)
src/Vitrine.Core           Platform-neutral logic (net10.0):
  About/                   AppInfo (version, links), AppPaths (all identifiers and paths, guideline 12), licence texts
  Audit/                   Audit log with SHA-256 hash chain
  Auth/                    Unlock rules, Entra claim checks, shared unlock password (PBKDF2)
  Config/                  Configuration model, layering with policies, schedule, user preferences
  Integration/             Named-pipe protocol, bounded line reader
  Localization/            Language selection, CoreStrings access, error codes VIT-xxxx
  Lock/                    Ctrl+Alt+Del restrictions with backup, failed-attempt rules, trigger identifiers
  Resources/               CoreStrings*.resx (en, de, es, fr, zh-Hans)
src/Vitrine                WPF app (Windows):
  Services/                Input blocker (low-level hooks), lock controller, triggers, watchdog, sign-in
                           providers (Entra/MSAL, Windows password, Windows Hello), pipe server, Win32 interop
  Platform/                Registry policy source, HKCU store, event log
  UI/                      Overlay, unlock/signature dialog, settings, tray flyout, About window, screenshots
  Resources/               UiStrings*.resx (en, de, es, fr, zh-Hans)
tests/Vitrine.Tests        xUnit; Windows/** only in the Windows target
samples/                   HttpAuth plugin (source only) and PowerShell client for the interface
installer/                 MSI (WiX 5)
policy/                    ADMX/ADML (en-US, de-DE)
deploy/install.ps1         Installation without MSI, same folder permissions
tools/                     Banner generator
```

## Texts and languages

The user interface is available in English (fallback), German, Spanish, French and Chinese (simplified). No user-visible text is written in code:

- XAML: `{ui:T Key}`; C#: `Loc.T("Key")` / `Loc.F("Key", …)` for the app, `CoreText.T` / `CoreText.F` in `Vitrine.Core`.
- Every new key goes into all five `.resx` files of its owner. Uncertain translations: English text plus the comment `TODO-übersetzen`. Spanish, French and Chinese files carry a header comment that they are machine pre-translations until a native speaker has reviewed them.
- Error messages show a code: add a constant to `ErrorCodes` (`src/Vitrine.Core/Localization/CoreText.cs`), the text as `Error_VITnnnn` and a line in [error-codes.md](error-codes.md).
- Texts in the audit log, event log and pipe API stay language-independent (English identifiers, codes, UTC).
- `LocalizationTests` checks keys, placeholders, markings, that every used key exists, that XAML has no literal text, and that every error code is documented.

## Packages and MSI

```powershell
$v = '0.1.0'
dotnet publish src/Vitrine/Vitrine.csproj -c Release -r win-x64 -p:PublishSingleFile=true -p:DebugType=none -p:Version=$v --self-contained true -o out/self-contained
dotnet build installer/Vitrine.Installer.wixproj -c Release "-p:PublishDir=$PWD/out/self-contained/" -p:ProductVersion=$v
```

Every `dotnet publish` with a runtime identifier (`-r win-x64`) is ReadyToRun (precompiled, see `Vitrine.csproj`; not composite, and without the Windows SDK projection, which only Windows Hello uses); `dotnet build` and `dotnet run` stay plain IL. `Program.Main` starts the service (`--service`) and the watchdog (`--watchdog <pid>`) without WPF; everything else goes through `App`. Startup and idle measurements are in issue #18 and the CHANGELOG entry for it.

The publish output contains `Vitrine.exe`, `msalruntime.dll` (not in the single file with `IncludeNativeLibrariesForSelfExtract`, where it is bundled and extracted at start like the WPF native files), `LICENSE`, `THIRD-PARTY-NOTICES.txt` and `policy\` (ADMX/ADML). The MSI takes everything from the publish folder, creates the data folders with permissions, registers the event source and installs the service (or, with `SERVICE=0`, the autostart). The CI installs, upgrades and uninstalls the MSI on a fresh Windows runner before any release (`.github/scripts/msi-test.ps1`). `Manufacturer` comes from `Company` in `Directory.Build.props`. Never change the `UpgradeCode`; give components new GUIDs when their paths change.

## CI and releases

[`.github/workflows/build.yml`](../.github/workflows/build.yml):

| Job | Runs on | What |
|---|---|---|
| `gate` | `ubuntu-latest` | decides how much the run builds: only `portable`, or the full build (see below) |
| `portable` | `ubuntu-latest` | builds and tests `tests/Vitrine.Tests` for `net10.0` |
| `windows` | `windows-latest`, after `portable` | builds the solution, runs all tests, publishes three variants, renders screenshots (artifact), signs (only when `vars.SIGNING_ACCOUNT` is set), packs the ZIP, builds the MSI, creates the SBOM and `SHA256SUMS.txt`, attests provenance (public repo only), hands the packages to the next jobs through the repository's Actions cache and uploads an artifact for trying a pull request |
| `msi-test` | fresh `windows-latest`, after `windows` | installs, updates and uninstalls the MSI ([`.github/scripts/msi-test.ps1`](../.github/scripts/msi-test.ps1)), including the check that Vitrine connects to the service and the update from the last published MSI |
| `release` | `windows-latest`, after `windows` **and** `msi-test` | checks `SHA256SUMS.txt` against the packages and publishes the release; for pull requests it stops after the check |

Windows minutes are expensive, so pushes and pull requests build only `portable`; `windows`, `msi-test` and `release`
run only in a full build (ICT-Baden guideline 04, "Wann die CI baut"). Changes to documentation only (`**.md`,
`docs/**`, `LICENSE`, issue templates) start nothing.

| Trigger | Builds | Version | Files | Result |
|---|---|---|---|---|
| Push to `main` | `portable` only | – | – | – |
| Push to `main` with `[voll]` in the message of the last commit | full | `0.1.0-ci.<run>` (MSI `0.1.0.<run>`) | fixed names | updates the release **latest** in place ([`.github/scripts/release-latest.ps1`](../.github/scripts/release-latest.ps1)), which also moves the tag `latest` to the built commit |
| Nightly (02:43 UTC) | full, only if `main` changed more than documentation since the tag `latest` | `0.1.0-ci.<run>` | fixed names | updates **latest** |
| Manual run on `main` (`gh workflow run build.yml --ref main`) | full | `0.1.0-ci.<run>` | fixed names | updates **latest** |
| Tag `v0.1.0` | full | `0.1.0` (MSI `0.1.0`) | with version in the name | release "Vitrine v0.1.0", marked *Latest*; **latest** becomes a pre-release |
| Pull request | `portable` only; full if it changes anything outside `Vitrine.Core` and its tests (`FULL_PATHS` in the workflow: app, service, installer, packages, project files, `.github/`) or has the label `voll-bauen` | `0.1.0-ci.<run>` | – | artifact only (full build) |
| Manual run on another branch | full | `0.1.0-ci.<run>` | – | artifact only |

The file version of the exe is always `x.y.z.<run>`, also for tags: the MSI replaces files only by version, and an exe
with `x.y.z.0` would be older than one from an earlier CI build. In addition the MSI sets `REINSTALLMODE=dmus`, so an
update also replaces an exe with a *higher* version (the old 1.0.0.x builds). The MSI test checks the installed exe and
its version after every install and update.

Release steps: rename "Unveröffentlicht" in [CHANGELOG.md](../CHANGELOG.md) to `## [X.Y.Z] – YYYY-MM-DD` (the release
notes are taken from that section by [`.github/scripts/release-notes.ps1`](../.github/scripts/release-notes.ps1); without
it there is no release), make sure `<Version>` in `src/Vitrine/Vitrine.csproj` is `X.Y.Z`, tag `vX.Y.Z` and push the tag.
Then raise `<Version>` on `main` to the next patch version, and install the MSI from the release on a clean machine and
as an update over the last **latest** build.

## Screenshots and banner

All screenshots come from the real app:

```powershell
Vitrine.exe --screenshots out\shots                 # language of Windows, light
$env:VITRINE_LANGUAGE = 'de'; Vitrine.exe --screenshots out\shots --theme dark   # German, dark
```

`--mica` shows the windows on screen with the real Mica backdrop and copies them from the screen instead of rendering them off-screen (the normal run uses no Mica, because `RenderTargetBitmap` cannot see it). Use it to check the real start-up path in light and dark mode; it needs an interactive, unlocked session and is not meant for `docs/assets/`.

One run draws one language and one colour scheme, the way the app starts; the CI runs all ten combinations. English images go to the given folder, every other language into a sub-folder. Copy the English ones to `docs/assets/screenshots/`. The sub-folder `layout/` holds the unlock dialog with 2, 3, 4 and 5 sign-in methods (`unlock-<n>-<theme>.png`) for checking that the method tabs fit in every language; they are not used in the docs. The screenshots use example data only (configuration in a temporary folder, "Lab operator", `LAB-PC-07`, `contoso.com`); they never lock the machine. The CI renders them in every full build and uploads them as the artifact "Screenshots" – useful to review translations and layouts without Windows.

The README banner (`docs/assets/banner.png`) is rendered from [`tools/banner/`](../tools/banner/) with a real screenshot (`npm install && npm run banner` there; needs an installed Chrome).

## Rules for changes

Vitrine is a security product. Changes to the lock, the input blocker, unlock rules, sign-in, the audit log, the interface or plugin loading need a test where the logic lives in `Vitrine.Core` and an entry in [CHANGELOG.md](../CHANGELOG.md) under "Changed" or "Security". See also [CONTRIBUTING.md](../CONTRIBUTING.md) and [CLAUDE.md](../CLAUDE.md).
