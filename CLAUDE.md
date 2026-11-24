# CLAUDE.md – Vitrine

Vitrine: Transparente Bildschirmsperre für Windows – Programme bleiben sichtbar, Tastatur und Maus sind gesperrt; Entsperren mit Microsoft Entra ID, Windows-Kennwort, Windows Hello oder Plugin, elektronische Signatur für Fachanwendungen, manipulationserkennendes Protokoll.

Projekt von ICT Baden. Regeln für Beiträge stehen in [`CONTRIBUTING.md`](CONTRIBUTING.md), Bauen, Testen und CI in [`docs/development.md`](docs/development.md).

## Bauen und testen

```powershell
dotnet build Vitrine.sln
dotnet test Vitrine.sln                          # beide Zielplattformen; App-Tests nur unter Windows
dotnet test tests/Vitrine.Tests -f net10.0       # nur Vitrine.Core (so läuft es in der CI unter Linux, geht auch auf macOS)
dotnet run --project src/Vitrine -- --settings
dotnet run --project src/Vitrine -- --screenshots out/shots --theme dark   # Sprache über VITRINE_LANGUAGE
```

Mehr in [`docs/development.md`](docs/development.md).

## Aufbau

- `src/Vitrine` – WPF-App: Infobereich, Overlays, Entsperr-Dialog, Einstellungen, Info-Fenster (`UI/`), Windows-Anbindung (`Services/`: Hooks, Anmeldeverfahren, Pipe-Server, Wächter, Dienst `Supervisor/` für `--service`; `Platform/`: Registry, Ereignisprotokoll)
- `src/Vitrine.Core` – Logik ohne Oberfläche (`net10.0`): Konfiguration und Richtlinien-Schichten, Protokoll mit Hash-Kette, Entsperr-Regeln, Entra-Prüfung, Masken-Geometrie, Dienst-Entscheidungen (`Service/SessionSupervisor`), Strg+Alt+Entf-Sicherung, Schnittstellen-Protokoll, Sprachen, Fehlercodes, Kennungen (`About/AppPaths.cs`)
- `src/Vitrine.Abstractions` – Plugin-Schnittstelle `IAuthProvider` (öffentliche API, nur abwärtskompatibel ändern)
- `tests/Vitrine.Tests` – xUnit; `Windows/**` nur im Windows-Ziel
- `samples/` – Beispiel-Plugin (nicht im Release) und PowerShell-Client der Schnittstelle
- `installer/` – MSI (WiX 5), `policy/` – ADMX/ADML, `deploy/install.ps1` – Installation ohne MSI
- `docs/` – Doku (Englisch), Bilder in `docs/assets/`

## Besonderheiten

- **Windows-gebunden:** Low-Level-Hooks, Strg+Alt+Entf-Richtlinien, Windows-Anmeldung, Windows Hello, Gruppenrichtlinien. Deshalb WPF; plattformneutrale Logik in `Vitrine.Core`.
- **Ziel `net10.0-windows10.0.19041.0`** (begründete Abweichung): Windows Hello braucht die WinRT-API `UserConsentVerifier`. Dadurch liegt `Microsoft.Windows.SDK.NET.dll` (Lizenz des Windows SDK) in jedem Paket; steht in `THIRD-PARTY-NOTICES.txt`.
- **⚠ msalruntime.dll** (`Microsoft.Identity.Client.NativeInterop`, Windows-Kontobroker WAM) ist in allen Release-Paketen, **fest in Version 0.20.4 – der letzten unter MIT**. Ab 0.20.6 verbieten Microsofts Lizenzbedingungen die Weitergabe (Abschnitt 3 e), und `Microsoft.Identity.Client.Broker` ab 4.84.2 zieht 0.20.6 nach; deshalb MSAL und Broker fest auf `[4.84.1]`, NativeInterop fest auf `[0.20.4]` (Issue AzureAD/microsoft-authentication-library-for-dotnet#6118). **Nie anheben ohne Lizenzprüfung der neuen NativeInterop-Version.** Dependabot ignoriert die Pakete; `.github/scripts/check-broker-licence.ps1` lässt den Build scheitern bei anderer Version, Lizenz ≠ MIT-Expression oder anderer Prüfsumme von msalruntime.dll in ZIP, Einzeldatei oder MSI. `-p:WamBroker=false` baut ohne Broker. Seit 2026-10-27 ist der Broker ohnehin nur mit `Entra.UseBroker = true` aktiv (Standard `false`, Warnung VIT-0191); Standard ist das eigene Anmeldefenster (`UI/SignInWindow`, WebView2 `Microsoft.Web.WebView2` 1.0.4258.31, BSD-artige Lizenz, Profil pro Versuch gelöscht; ohne WebView2 Runtime VIT-0190). `check-broker-licence.ps1` prüft auch Version, Lizenztext und Prüfsumme von `WebView2Loader.dll`.
- **Sicherheitsprodukt:** Änderungen an Sperre, Eingabeblocker, Entsperr-Regeln, Protokoll, Schnittstelle oder Plugin-Laden nur mit Test (wo die Logik in `Vitrine.Core` liegt) und Eintrag im `CHANGELOG.md` unter „Geändert“ oder „Sicherheit“. Verhalten nie stillschweigend ändern.
- **Tests sperren nie den Rechner:** keine Hooks, kein `LockWorkStation`, keine Registry-Schreibzugriffe, keine echten Anmeldungen. Windows-Teile hinter Schnittstellen (`IPolicySource`, `IUserPolicyStore`, `IAuditSink`) und mit Attrappen testen.
- **Abweichungen, begründet:** Autostart richtet die MSI ein, nicht die App pro Benutzer: Eine Bildschirmsperre muss in jeder Sitzung laufen, unabhängig vom Benutzer – daher der Dienst bzw. mit `SERVICE=0` `HKLM\…\Run` (beide mit `--autostart`). Kein `--demo`: Vitrine braucht keine besondere Hardware; Beispieldaten zeigt `--screenshots`.
- **Kennungen und Pfade** nur über `AppPaths`. Die alten Orte (`SOFTWARE\Policies\Vitrine`, `%ProgramData%\Vitrine`, Pipe `Vitrine-<Sitzung>`) werden für den Übergang gelesen bzw. sind in `docs/installation.md` beschrieben.
- **Protokoll:** Texte sprachunabhängig (englische Kennungen, Fehlercodes), Zeiten UTC. Nie „manipulationssicher“ schreiben – die Kette erkennt Änderungen, verhindert sie nicht.
- **MSI:** `UpgradeCode` 7B3C2E51-9D4A-4F6B-8E2C-5A1D3F7C9B20 nie ändern. Komponenten-GUIDs bei geänderten Pfaden neu erzeugen. Manufacturer kommt aus `$(Company)`.
- **Firmierung:** im Fließtext „ICT Baden“, rechtlich „ICT Baden GmbH“ – so in `LICENSE` und in `<Company>` (`Directory.Build.props`: Info-Fenster, Versionsinfo, MSI-Hersteller; ein Test prüft Gleichheit). „ICT-Baden“ bleibt in technischen Kennungen (`AppPaths.Vendor`: Dienst, Ordner, Registry, Pipes, Ereignisquelle) – dort nie ändern, das bricht Updates. Builds bis 0.5.1 tragen „ICT-Baden“ als Firmennamen in der Versionsinfo; `AppInfo.IsOwnPublisher` erkennt beide.
- **Offen (⚠):** Impressum- und Datenschutz-URL (`AppInfo.ImpressumUrl` = `https://ict-baden.de/impressum/`, `PrivacyUrl` = `/datenschutz/vitrine/`, kommen mit der neuen Webseite), Support-/Security-Mail, Signierkonto (Schritte überspringen sich ohne `vars.SIGNING_ACCOUNT`), Muttersprachler-Prüfung es/fr/zh-Hans.
- **Keine Personennamen** in Oberfläche, Beispielen, Screenshots und Doku (Rollen wie „Lab operator“, `jdoe@contoso.com`, `LAB-PC-07`).

## Regeln

- Commit-Nachrichten auf Deutsch.
- Kein Text fest im Code: jeden neuen Text in alle Sprachdateien eintragen (`src/Vitrine/Resources/UiStrings*.resx`, `src/Vitrine.Core/Resources/CoreStrings*.resx`; en, de, es, fr, zh-Hans). Unsichere Übersetzung: englischen Text eintragen und mit `TODO-übersetzen` kommentieren. In XAML `{ui:T Schlüssel}`, in C# `Loc.T`/`Loc.F` bzw. `CoreText.T`/`CoreText.F`. Fehlermeldungen mit Code (`ErrorCodes`, Text `Error_VITnnnn`, Eintrag in `docs/error-codes.md`).
- Code-Kommentare Deutsch, README und `docs/` Englisch; jede `.cs`-Datei beginnt mit `// SPDX-License-Identifier: MIT`.
- Vor jedem Release: Abschnitt „Unveröffentlicht“ im `CHANGELOG.md` pflegen.
