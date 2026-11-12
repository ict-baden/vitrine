// SPDX-License-Identifier: MIT
using System.Text.Json.Serialization;
using Vitrine.Core.Lock;

namespace Vitrine.Core.Config;

/// <summary>
/// Gesamte Konfiguration. Wird geschichtet geladen:
/// Standardwerte → %ProgramData%\ICT-Baden\Vitrine\config.json → %LocalAppData%\Vitrine\config.json (falls erlaubt)
/// → Richtlinie HKCU, dann HKLM \SOFTWARE\Policies\ICT-Baden\Vitrine (GPO/Intune, hat immer Vorrang).
/// Alte Orte (%ProgramData%\Vitrine, %AppData%\Vitrine, \SOFTWARE\Policies\Vitrine) gelten weiter, siehe ConfigStore.
/// </summary>
public sealed class VitrineConfig
{
    public LockSettings Lock { get; set; } = new();
    public UnlockSettings Unlock { get; set; } = new();
    public AppearanceSettings Appearance { get; set; } = new();
    public SecuritySettings Security { get; set; } = new();
    public AuditSettings Audit { get; set; } = new();
    public EntraSettings Entra { get; set; } = new();
    public ScriptSettings Scripts { get; set; } = new();
    public IntegrationSettings Integration { get; set; } = new();

    /// <summary>Rollen: wer Einstellungen ändert, Sicherheitsschlüssel registriert, das Protokoll prüft (seit 0.5.0).</summary>
    public RoleSettings Roles { get; set; } = new();
    public FidoSettings Fido { get; set; } = new();
}

public sealed class LockSettings
{
    /// <summary>Tastenkürzel zum Sperren, z. B. "Ctrl+Alt+L". Leer = aus.</summary>
    public string Hotkey { get; set; } = "Ctrl+Alt+L";

    /// <summary>Nach so vielen Minuten ohne Eingabe sperren. 0 = aus.</summary>
    public int IdleMinutes { get; set; } = 0;

    /// <summary>Beim Programmstart sofort sperren (z. B. für Leitstand-PCs).</summary>
    public bool LockOnStartup { get; set; } = false;

    /// <summary>Bildschirm und System während der Sperre wach halten.</summary>
    public bool KeepAwake { get; set; } = true;

    /// <summary>Feste Zeiten, zu denen automatisch gesperrt wird.</summary>
    public List<ScheduleEntry> Schedule { get; set; } = new();

    /// <summary>Mausbewegung während der Sperre blockieren (Zeiger steht still).</summary>
    public bool BlockMouseMove { get; set; } = true;

    /// <summary>
    /// Win+L sperrt mit Vitrine statt mit Windows, auch im entsperrten Zustand: Solange Vitrine läuft, ist
    /// DisableLockWorkstation gesetzt und ein Tastatur-Hook erkennt Win+L (seit 2026-10-26).
    /// </summary>
    public bool ReplaceWinL { get; set; } = false;

    /// <summary>
    /// Wie gesperrt wird: <see cref="LockMode.Overlay"/> (Abdeckungen über dem Desktop, Programme bleiben sichtbar) oder
    /// <see cref="LockMode.Desktop"/> (eigener Desktop, Programme laufen unsichtbar weiter; seit 0.5.0).
    /// </summary>
    public LockMode Mode { get; set; } = LockMode.Overlay;

    /// <summary>Mit <see cref="LockMode.Desktop"/>: verkleinerte, regelmäßig erneuerte Vorschau des Windows-Desktops zeigen.</summary>
    public bool DesktopShowPreview { get; set; } = true;

    /// <summary>Mit <see cref="LockMode.Desktop"/>: Vorschau alle so viele Sekunden erneuern (1–60); 0 = nur beim Sperren.</summary>
    public int DesktopPreviewSeconds { get; set; } = 2;
}

public sealed class ScheduleEntry
{
    /// <summary>"HH:mm"</summary>
    public string Time { get; set; } = "18:00";

    /// <summary>Wochentage, leer = jeden Tag.</summary>
    public List<DayOfWeek> Days { get; set; } = new();
}

[Flags]
public enum UnlockAllowed
{
    None = 0,
    /// <summary>Der angemeldete Benutzer der Sitzung.</summary>
    SessionUser = 1,
    /// <summary>Lokale bzw. Domänen-Administratoren.</summary>
    Administrators = 2,
    /// <summary>Mitglieder der unter AllowedGroups genannten Gruppen.</summary>
    Groups = 4,
    /// <summary>Unter AllowedUsers genannte Konten.</summary>
    Users = 8,
    /// <summary>Jedes gültige Konto (ggf. auf Domänen/Mandanten eingeschränkt).</summary>
    AnyAuthenticated = 16,
}

public enum UnlockTrigger
{
    /// <summary>Taste oder Mausklick öffnet den Dialog.</summary>
    AnyInput,
    /// <summary>Nur eine Taste öffnet den Dialog, Mausklicks werden still verworfen.</summary>
    KeyOnly,
    /// <summary>Nur das Sperr-Tastenkürzel öffnet den Dialog.</summary>
    HotkeyOnly,
}

public sealed class UnlockSettings
{
    public UnlockAllowed Allowed { get; set; } = UnlockAllowed.SessionUser | UnlockAllowed.Administrators;

    /// <summary>Gruppen: "DOMAIN\Gruppe", lokale Gruppe, SID, Entra-Gruppen-ID oder Entra-App-Rolle.</summary>
    public List<string> AllowedGroups { get; set; } = new();

    /// <summary>Konten: "DOMAIN\name", UPN oder SID.</summary>
    public List<string> AllowedUsers { get; set; } = new();

    /// <summary>Nur Konten dieser Domänen bzw. UPN-Suffixe zulassen. Leer = alle.</summary>
    public List<string> AllowedDomains { get; set; } = new();

    /// <summary>Aktivierte Verfahren in Anzeigereihenfolge: windows, entra, hello, windowslogon, fido, pin oder Plugin-ID.</summary>
    public List<string> Methods { get; set; } = new() { "entra", "windows", "hello" };

    public UnlockTrigger Trigger { get; set; } = UnlockTrigger.AnyInput;

    /// <summary>Benutzername im Dialog vorausfüllen.</summary>
    public bool PrefillUserName { get; set; } = true;

    /// <summary>Dialog schließt sich nach so vielen Sekunden ohne Eingabe.</summary>
    public int PromptTimeoutSeconds { get; set; } = 30;

    /// <summary>PBKDF2-Hash des eigenen Entsperr-Kennworts (Verfahren "pin").</summary>
    public string? PinHash { get; set; }

    /// <summary>
    /// Notfall-Anmeldung: Mitglieder dieser Gruppen (Schreibweise wie <see cref="AllowedGroups"/>) dürfen mit dem
    /// Windows-Kennwort entsperren, auch wenn die Entsperr-Regeln sie nicht zulassen – nur mit Begründung, die ins
    /// Protokoll (UnlockBypass) und als Warnung ins Ereignisprotokoll kommt. Leer = keine Notfall-Anmeldung.
    /// </summary>
    public List<string> BypassGroups { get; set; } = new();

    /// <summary>Mindestlänge der Begründung einer Notfall-Anmeldung (Zeichen, mindestens 1).</summary>
    public int BypassReasonMinLength { get; set; } = 10;

    // ---- Komfort-Eigenschaften für die Einstellungen (nicht gespeichert) ----
    [JsonIgnore] public bool AllowSessionUser { get => Has(UnlockAllowed.SessionUser); set => Set(UnlockAllowed.SessionUser, value); }
    [JsonIgnore] public bool AllowAdministrators { get => Has(UnlockAllowed.Administrators); set => Set(UnlockAllowed.Administrators, value); }
    [JsonIgnore] public bool AllowGroups { get => Has(UnlockAllowed.Groups); set => Set(UnlockAllowed.Groups, value); }
    [JsonIgnore] public bool AllowUsers { get => Has(UnlockAllowed.Users); set => Set(UnlockAllowed.Users, value); }
    [JsonIgnore] public bool AllowAnyone { get => Has(UnlockAllowed.AnyAuthenticated); set => Set(UnlockAllowed.AnyAuthenticated, value); }

    [JsonIgnore] public bool MethodEntra { get => Methods.Contains("entra"); set => Toggle("entra", value); }
    [JsonIgnore] public bool MethodWindows { get => Methods.Contains("windows"); set => Toggle("windows", value); }
    [JsonIgnore] public bool MethodHello { get => Methods.Contains("hello"); set => Toggle("hello", value); }
    [JsonIgnore] public bool MethodWindowsLogon { get => Methods.Contains("windowslogon"); set => Toggle("windowslogon", value); }
    [JsonIgnore] public bool MethodFido { get => Methods.Contains("fido"); set => Toggle("fido", value); }
    [JsonIgnore] public bool MethodPin { get => Methods.Contains("pin"); set => Toggle("pin", value); }

    private bool Has(UnlockAllowed f) => (Allowed & f) != 0;
    private void Set(UnlockAllowed f, bool on) => Allowed = on ? Allowed | f : Allowed & ~f;

    private static readonly string[] MethodOrder = { "entra", "windows", "hello", "windowslogon", "fido", "pin" };

    private void Toggle(string id, bool on)
    {
        if (on && !Methods.Contains(id))
        {
            Methods.Add(id);
            // Eingebaute Verfahren in fester Reihenfolge halten, Plugins dahinter
            Methods = Methods.OrderBy(m => Array.IndexOf(MethodOrder, m) is var i && i < 0 ? 99 : i).ToList();
        }
        else if (!on) Methods.Remove(id);
    }
}

public enum LockVisual
{
    /// <summary>Desktop bleibt sichtbar, optional abgedunkelt.</summary>
    Transparent,
    /// <summary>Desktop wird verdeckt (vertrauliche Daten).</summary>
    Blank,
    /// <summary>Alles verdeckt außer den Fenstern der Programme in <see cref="AppearanceSettings.RevealProcesses"/>.</summary>
    Windows,
}

public sealed class AppearanceSettings
{
    public LockVisual Visual { get; set; } = LockVisual.Transparent;

    /// <summary>0 = völlig durchsichtig, 100 = schwarz.</summary>
    public int DimPercent { get; set; } = 8;

    /// <summary>Hinweis-Leiste unten anzeigen.</summary>
    public bool ShowStatusPill { get; set; } = true;

    /// <summary>Eigener Hinweistext, z. B. „Messung läuft – bitte nicht berühren“.</summary>
    public string? Message { get; set; }

    /// <summary>Akzentfarbe als #RRGGBB. Leer = Windows-Akzentfarbe.</summary>
    public string Accent { get; set; } = "";

    /// <summary>Pfad zu einem Logo (PNG/SVG nicht – nur PNG/JPG) für den Dialog.</summary>
    public string? LogoPath { get; set; }

    /// <summary>Mauszeiger während der Sperre ausblenden.</summary>
    public bool HideCursor { get; set; } = false;

    /// <summary>Uhr auf dem verdeckten Bildschirm.</summary>
    public bool ShowClock { get; set; } = true;

    /// <summary>
    /// Sprache der Oberfläche: en, de, es, fr, zh-Hans. Leer = Sprache von Windows. Als Gerätewert eine Vorgabe, die
    /// jeder Benutzer im Info-Fenster für sich ändern kann; als Richtlinie fest (richtlinien/13 Punkt 8).
    /// </summary>
    public string Language { get; set; } = "";

    /// <summary>
    /// Bereiche, die während der Sperre verdeckt sind (bei „durchsichtig“ und „nur freigegebene Programme“), z. B. ein
    /// Feld mit Patientendaten. Richtlinie: „Monitor:X,Y,Breite,Höhe“ in Prozent, siehe <see cref="MaskRegion"/>.
    /// </summary>
    public List<MaskRegion> Masks { get; set; } = new();

    /// <summary>Programme (Exe-Name), deren Fenster bei <see cref="LockVisual.Windows"/> sichtbar bleiben.</summary>
    public List<string> RevealProcesses { get; set; } = new();

    /// <summary>Flache Kopie mit eigenen Listen (für eine abweichende Darstellung einer einzelnen Sperre).</summary>
    public AppearanceSettings Clone()
    {
        var c = (AppearanceSettings)MemberwiseClone();
        c.Masks = Masks.Select(m => m.Normalized()).ToList();
        c.RevealProcesses = [.. RevealProcesses];
        return c;
    }
}

public enum FailureAction
{
    None,
    /// <summary>Windows-Sperrbildschirm (Sitzung bleibt erhalten).</summary>
    LockWorkstation,
    LogOff,
    Shutdown,
}

public sealed class SecuritySettings
{
    /// <summary>Nach so vielen Fehlversuchen greift FailureAction. 0 = nie.</summary>
    public int MaxFailedAttempts { get; set; } = 5;

    public FailureAction FailureAction { get; set; } = FailureAction.None;

    /// <summary>Wartezeit nach jedem Fehlversuch wächst (1 s, 2 s, 4 s …).</summary>
    public bool ProgressiveDelay { get; set; } = true;

    /// <summary>Während der Sperre Task-Manager, Abmelden und Kennwortändern im Strg+Alt+Entf-Menü ausblenden.</summary>
    public bool RestrictCtrlAltDel { get; set; } = true;

    /// <summary>Einstellungen nur für Administratoren.</summary>
    public bool SettingsAdminOnly { get; set; } = true;

    /// <summary>Beenden der App nur nach Anmeldung als Administrator.</summary>
    public bool ExitRequiresAdmin { get; set; } = true;

    /// <summary>Wächterprozess sperrt Windows, falls Vitrine während der Sperre abstürzt oder beendet wird.</summary>
    public bool Watchdog { get; set; } = true;

    /// <summary>Prozesse, deren Fenster während einer externen Anmeldung (Entra, Windows Hello) Eingaben erhalten dürfen.</summary>
    public List<string> AuthUiProcesses { get; set; } = new()
    {
        "CredentialUIBroker.exe",
        "Microsoft.AAD.BrokerPlugin.exe",
        "msedgewebview2.exe",
        // Kontoauswahl und Windows-Sicherheitsdialog neuerer Windows-Versionen (Systempakete Microsoft.AccountsControl und
        // Microsoft.CredDialogHost); ohne sie bekam das Broker-Fenster während der Sperre keine Eingaben (Gerätetest 2026-10-26)
        "AccountsControlHost.exe",
        "CredDialogHost.exe",
    };

    /// <summary>Nutzer-Konfiguration in %LocalAppData%\Vitrine zulassen.</summary>
    public bool AllowUserConfig { get; set; } = false;

    /// <summary>
    /// Mitglieder der lokalen Administratoren haben die Rechte aller Rollen (Einstellungen, Beenden, Sicherheitsschlüssel
    /// registrieren, Notfall-Anmeldung) – wie vor 0.5.0. Aus: nur noch Mitglieder der Rollengruppen (<see cref="RoleSettings"/>).
    /// Ein Administrator kann den Dienst trotzdem beenden; die Einstellung trennt Rollen in Vitrine, nicht auf dem Rechner.
    /// </summary>
    public bool LocalAdministratorsArePrivileged { get; set; } = true;

    /// <summary>Administrator-Bestätigungen (Einstellungen öffnen, Beenden) verlangen eine Begründung.</summary>
    public bool ReasonRequiredForAdminActions { get; set; } = false;

    /// <summary>Speichern der Einstellungen verlangt eine Begründung (steht mit den Änderungen im Protokoll).</summary>
    public bool ReasonRequiredForConfigChanges { get; set; } = false;

    /// <summary>Mindestlänge dieser Begründungen (Zeichen, mindestens 1).</summary>
    public int ReasonMinLength { get; set; } = 10;

}

public sealed class AuditSettings
{
    public bool Enabled { get; set; } = true;

    /// <summary>Ordner für das lokale Protokoll. Leer = %ProgramData%\ICT-Baden\Vitrine\Logs.</summary>
    public string? Directory { get; set; }

    /// <summary>Zusätzliche Kopie auf einer Freigabe, z. B. \\server\audit$\Vitrine.</summary>
    public string? NetworkDirectory { get; set; }

    /// <summary>Zusätzlich ins Windows-Ereignisprotokoll (Anwendung, Quelle „ICT-Baden Vitrine“).</summary>
    public bool EventLog { get; set; } = true;

    /// <summary>Gesperrt/entsperrt mitschreiben (nicht nur Fehlversuche).</summary>
    public bool LogLockState { get; set; } = true;
}

public sealed class EntraSettings
{
    /// <summary>Mandanten-ID (GUID) oder Domäne. "organizations" erlaubt jeden Arbeitskonto-Mandanten.</summary>
    public string TenantId { get; set; } = "organizations";

    /// <summary>Anwendungs-ID der App-Registrierung (öffentlicher Client).</summary>
    public string ClientId { get; set; } = "";

    /// <summary>
    /// Windows-Kontobroker (WAM) statt des eigenen Anmeldefensters. Standard seit 2026-10-27: aus – das eigene Fenster
    /// merkt sich nichts und meldet nie über das Konto der Windows-Sitzung an. Mit Broker: Windows Hello for Business und
    /// gerätebasierter bedingter Zugriff, aber WAM merkt sich Konten (VIT-0191) – nur für Geräte mit einem persönlichen Benutzer.
    /// </summary>
    public bool UseBroker { get; set; } = false;

    /// <summary>
    /// Mit Broker: neue Anmeldung erzwingen statt Kontoauswahl (empfohlen, sonst entsperrt SSO ohne Eingabe). Das eigene
    /// Anmeldefenster verlangt immer eine neue Anmeldung.
    /// </summary>
    public bool ForceFreshSignIn { get; set; } = true;

    /// <summary>Anmeldung darf höchstens so alt sein (auth_time), sonst abgelehnt.</summary>
    public int MaxAuthAgeSeconds { get; set; } = 300;

    /// <summary>Weitere erlaubte Mandanten-IDs (z. B. bei „organizations“).</summary>
    public List<string> AllowedTenants { get; set; } = new();

    /// <summary>
    /// Weitere Hosts, die das Anmeldefenster öffnen darf, z. B. der eigene Verbund-Anmeldedienst („adfs.contoso.com“,
    /// „*.okta.com“). Microsofts Anmeldeseiten sind immer erlaubt (EmbeddedSignIn.MicrosoftHosts); alles andere wird
    /// abgebrochen (VIT-0193). Nur HTTPS.
    /// </summary>
    public List<string> AllowedSignInHosts { get; set; } = new();

    /// <summary>
    /// ID-Token der Anmeldung an die anfragende Fachanwendung weitergeben (Schnittstelle, authenticate/sign). Die
    /// Anwendung kann damit selbst bei Microsoft prüfen, wer sich angemeldet hat. Nie im Protokoll.
    /// </summary>
    public bool ShareIdToken { get; set; } = false;

    /// <summary>
    /// Berechtigungen (Scopes), für die Fachanwendungen über die Schnittstelle ein Zugriffstoken anfordern dürfen,
    /// z. B. „api://lims/Signature.Write“. Leer = keine Zugriffstoken. Nur Scopes einer Ressource je Anfrage.
    /// </summary>
    public List<string> AllowedTokenScopes { get; set; } = new();

    /// <summary>
    /// Authentifizierungskontext für bedingten Zugriff (z. B. „c1“), der bei jeder Anmeldung angefordert wird. Mit einer
    /// Richtlinie für bedingten Zugriff verlangt Entra dafür z. B. Passkey oder FIDO2 (Authentifizierungsstärke). Leer = keiner.
    /// </summary>
    public string AuthenticationContext { get; set; } = "";

    /// <summary>Wie <see cref="AuthenticationContext"/>, nur für Signaturen (hat dort Vorrang). Leer = wie oben.</summary>
    public string SignatureAuthenticationContext { get; set; } = "";
}

public sealed class ScriptSettings
{
    public string? OnLock { get; set; }
    public string? OnUnlock { get; set; }
    public string? OnFailedAttempt { get; set; }
    public string? OnPromptShown { get; set; }
    public int TimeoutSeconds { get; set; } = 30;
}

public sealed class IntegrationSettings
{
    /// <summary>Lokale Schnittstelle (Named Pipe \\.\pipe\ICT-Baden.Vitrine.&lt;Sitzung&gt;) für Fachanwendungen.</summary>
    public bool PipeEnabled { get; set; } = true;

    /// <summary>Plugins aus dem Ordner „Plugins“ neben der EXE laden.</summary>
    public bool LoadPlugins { get; set; } = true;
}

/// <summary>
/// Rollen in Vitrine. Einträge wie Unlock.AllowedGroups: „DOMÄNE\Gruppe“, lokale Gruppe (auch mit Entra-Mitgliedern), SID
/// oder Entra-Gruppen-ID. Leer = nur Administratoren (wie vor 0.5.0, solange Security.LocalAdministratorsArePrivileged an ist).
/// </summary>
public sealed class RoleSettings
{
    /// <summary>Dürfen die Einstellungen öffnen und ändern und Vitrine beenden.</summary>
    public List<string> ConfigAdmins { get; set; } = new();

    /// <summary>Dürfen Sicherheitsschlüssel registrieren und widerrufen.</summary>
    public List<string> Registrars { get; set; } = new();

    /// <summary>Dürfen das Protokoll und den Berechtigungsbericht ansehen und exportieren, aber nichts ändern.</summary>
    public List<string> Auditors { get; set; } = new();
}
