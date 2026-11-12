// SPDX-License-Identifier: MIT
using Vitrine.Abstractions;
using Vitrine.Core.About;
using Vitrine.Core.Audit;
using Vitrine.Core.Localization;

namespace Vitrine.Core.Lock;

/// <summary>Wie Vitrine sperrt (<c>Lock.Mode</c>).</summary>
public enum LockMode
{
    /// <summary>Abdeckungen über dem Windows-Desktop; Programme bleiben sichtbar (Standard, Verhalten bis 0.4).</summary>
    Overlay,
    /// <summary>
    /// Eigener Desktop (CreateDesktop in WinSta0): Fenster anderer Programme bekommen dort keine Eingaben und zeichnen
    /// nicht darüber; die Programme laufen auf dem Windows-Desktop unsichtbar weiter (optional mit Vorschau).
    /// </summary>
    Desktop,
}

/// <summary>Welcher Desktop während der Sperre der Eingabe-Desktop sein soll.</summary>
public enum DesktopTarget
{
    /// <summary>Der Desktop von Windows („Default“) – im Abdeckungs-Modus und während einer externen Anmeldung.</summary>
    Default,
    /// <summary>Vitrines Sperr-Desktop.</summary>
    Lock,
}

/// <summary>Namen der Desktops in WinSta0 und ihre Einordnung.</summary>
public static class LockDesktopNames
{
    /// <summary>Desktop von Windows, auf dem die Programme des Benutzers laufen.</summary>
    public const string Default = "Default";

    /// <summary>Sichere Desktops von Windows: Anmeldung, Strg+Alt+Entf, Benutzerkontensteuerung, Bildschirmschoner, getrennt.</summary>
    private static readonly string[] Secure = ["Winlogon", "Screen-saver", "Disconnect"];

    /// <summary>
    /// Ein sicherer Desktop von Windows. <c>null</c> zählt dazu: Den Namen des Eingabe-Desktops darf Vitrine dann nicht
    /// lesen (OpenInputDesktop scheitert auf dem Winlogon-Desktop mit „Zugriff verweigert“).
    /// </summary>
    public static bool IsSecure(string? name) =>
        name is null || Secure.Any(s => string.Equals(s, name, StringComparison.OrdinalIgnoreCase));

    public static bool IsDefault(string? name) => string.Equals(name, Default, StringComparison.OrdinalIgnoreCase);

    /// <summary>Ein Sperr-Desktop von Vitrine (dieses oder eines abgestürzten Laufs): Name beginnt mit <see cref="AppPaths.LockDesktopPrefix"/>.</summary>
    public static bool IsOwnLockDesktop(string? name) =>
        name is not null && name.StartsWith(AppPaths.LockDesktopPrefix, StringComparison.OrdinalIgnoreCase);

    /// <summary>Neuer Name eines Sperr-Desktops mit zufälligem Teil (gegen vorab angelegte Desktops gleichen Namens).</summary>
    public static string NewLockDesktopName() => $"{AppPaths.LockDesktopPrefix}-{Guid.NewGuid():N}"[..(AppPaths.LockDesktopPrefix.Length + 17)];
}

/// <summary>Zugriff auf die Desktops von Windows (CreateDesktop, SwitchDesktop, OpenInputDesktop) – in Tests eine Attrappe.</summary>
public interface ILockDesktop
{
    /// <summary>Name des Sperr-Desktops (fest ab dem ersten <see cref="Create"/>).</summary>
    string LockDesktopName { get; }

    /// <summary>Sperr-Desktop anlegen, falls noch nicht geschehen; er bleibt bis zum Programmende bestehen.</summary>
    bool Create();

    /// <summary>Sperr-Desktop zum Eingabe-Desktop machen.</summary>
    bool SwitchToLock();

    /// <summary>Den Desktop von Windows („Default“) zum Eingabe-Desktop machen.</summary>
    bool SwitchToDefault();

    /// <summary>
    /// Name des aktuellen Eingabe-Desktops; null = nicht lesbar. Das ist der Winlogon-Desktop (Sperrbildschirm, Strg+Alt+Entf,
    /// UAC) – aber auch jeder Desktop, dessen Zugriffsliste den Benutzer aussperrt. Ob Windows gerade wirklich einen sicheren
    /// Desktop zeigt, sagt <see cref="SecureDesktopExpected"/>.
    /// </summary>
    string? InputDesktopName();

    /// <summary>
    /// Zeigt Windows gerade nachweislich einen sicheren Desktop? Aus dem Zustand der Sitzung, nicht aus dem Desktop selbst:
    /// Sitzung gesperrt oder nicht verbunden (WTSSessionInfoEx), oder LogonUI.exe bzw. consent.exe läuft in der Sitzung und
    /// gehört nicht dem Benutzer (ein selbst gestartetes consent.exe zählt nicht), oder ein Bildschirmschoner läuft.
    /// </summary>
    bool SecureDesktopExpected();

    /// <summary>Win32-Fehler des letzten gescheiterten Aufrufs.</summary>
    int LastError { get; }
}

/// <summary>Eintrag fürs Protokoll, den der Aufrufer schreibt (englischer Text, ggf. mit Fehlercode vorn).</summary>
public sealed record DesktopAudit(AuditEventType Event, string Detail)
{
    public static DesktopAudit Error(string code, string detail) => new(AuditEventType.Error, $"{code} {detail}");
}

/// <summary>Was nach einer Prüfung des Eingabe-Desktops zu tun bleibt.</summary>
public enum GuardAction
{
    None,
    /// <summary>Ein fremder Desktop war Eingabe-Desktop; Vitrine hat zurückgeschaltet.</summary>
    Restored,
    /// <summary>Zurückschalten ist <see cref="DesktopLockSession.MaxRestoreFailures"/>-mal gescheitert: Windows sperren (Rückfall).</summary>
    FallbackLock,
}

public sealed record GuardResult(GuardAction Action, IReadOnlyList<DesktopAudit> Audit)
{
    public static readonly GuardResult Nothing = new(GuardAction.None, []);
}

/// <summary>
/// Ablauf einer Sperre mit eigenem Desktop und die Erkennung von Desktop-Wechseln (Flucht), ohne Windows-Aufrufe
/// (<see cref="ILockDesktop"/>). Grundsätze:
/// <list type="bullet">
/// <item>Ausfallsicher: Scheitert Anlegen, Oberfläche oder Wechsel, läuft die Sperre mit Abdeckungen weiter
/// (VIT-0450, VIT-0453, VIT-0451) – die Abdeckungen und Hooks auf dem Windows-Desktop stehen schon, bevor gewechselt wird.</item>
/// <item>Der erwartete Desktop wird <i>vor</i> jedem eigenen Wechsel umgestellt; die Prüfung hält einen eigenen Wechsel
/// so nie für eine Flucht.</item>
/// <item>Fremder Eingabe-Desktop während der Sperre (in beiden Modi): einmal je Vorfall <see cref="AuditEventType.DesktopSwitchDetected"/>,
/// bei jeder Prüfung zurückschalten; nach <see cref="MaxRestoreFailures"/> gescheiterten Versuchen VIT-0452 und Windows sperren.</item>
/// <item>Sichere Desktops von Windows (Strg+Alt+Entf, Windows-Sperre, UAC) bleiben unberührt – dorthin kann und darf
/// Vitrine nicht zurückschalten; wer von dort zurückkommt, landet wieder bei der Prüfung.</item>
/// <item>Entsperrt: Ist noch ein Sperr-Desktop von Vitrine Eingabe-Desktop (Zurückschalten beim Entsperren gescheitert,
/// Absturz eines früheren Laufs), zurück auf den Windows-Desktop (VIT-0455).</item>
/// </list>
/// </summary>
public sealed class DesktopLockSession
{
    /// <summary>So oft darf das Zurückschalten nach einer Flucht hintereinander scheitern, dann wird Windows gesperrt.</summary>
    public const int MaxRestoreFailures = 3;

    /// <summary>
    /// So viele Prüfungen in Folge (≈ 1 s) darf ein nicht lesbarer bzw. „sicher“ benannter Desktop ohne Beleg aus der Sitzung
    /// (<see cref="ILockDesktop.SecureDesktopExpected"/>) Eingabe-Desktop sein, bevor er als fremd gilt. Windows wechselt bei
    /// Strg+Alt+Entf erst auf den Winlogon-Desktop und startet dann LogonUI; ohne Frist gäbe es Fehlalarme.
    /// </summary>
    public const int UnverifiedSecureGrace = 4;

    /// <summary>Windows-Sperre so kurz nach Vitrines eigenem Rückfall (LockWorkStation) gilt als dessen Folge.</summary>
    public static readonly TimeSpan FallbackLockWindow = TimeSpan.FromSeconds(15);

    private readonly ILockDesktop _desktop;
    private bool _incident, _afterSecure, _strandedLogged;
    private int _failures, _unverified;
    private DateTimeOffset? _fallbackAt;

    public DesktopLockSession(ILockDesktop desktop) => _desktop = desktop;

    /// <summary>Vitrine ist gesperrt (in welchem Modus auch immer).</summary>
    public bool Locked { get; private set; }

    /// <summary>Diese Sperre nutzt den eigenen Desktop (sonst Abdeckungen, auch nach einem Rückfall).</summary>
    public bool Engaged { get; private set; }

    /// <summary>Welcher Desktop gerade Eingabe-Desktop sein soll.</summary>
    public DesktopTarget Expected { get; private set; } = DesktopTarget.Default;

    /// <summary>Gesperrt auf dem eigenen Desktop (nicht vorübergehend auf dem Windows-Desktop).</summary>
    public bool OnLockDesktop => Engaged && Expected == DesktopTarget.Lock;

    /// <summary>Gesperrt mit eigenem Desktop, aber gerade auf dem Windows-Desktop (externe Anmeldung).</summary>
    public bool HandedOff => Engaged && Expected == DesktopTarget.Default;

    private string ExpectedName => Expected == DesktopTarget.Lock ? _desktop.LockDesktopName : LockDesktopNames.Default;

    /// <summary>
    /// Sperre beginnt. Mit <see cref="LockMode.Desktop"/>: Desktop anlegen, Oberfläche dort aufbauen, wechseln. Abdeckungen
    /// und Hooks auf dem Windows-Desktop stehen da schon (Rückfall und zweite Verteidigungslinie).
    /// </summary>
    /// <param name="showUi">Oberfläche auf dem Sperr-Desktop aufbauen; false oder Ausnahme = gescheitert.</param>
    /// <param name="closeUi">Oberfläche wieder abbauen (nach einem Fehlschlag).</param>
    public IReadOnlyList<DesktopAudit> Lock(LockMode mode, Func<bool> showUi, Action closeUi)
    {
        Locked = true;
        Engaged = false;
        Expected = DesktopTarget.Default;
        ResetIncident();
        if (mode != LockMode.Desktop) return [];

        if (!_desktop.Create())
            return [DesktopAudit.Error(ErrorCodes.LockDesktopCreateFailed, $"CreateDesktop failed (Win32 {_desktop.LastError}); this lock uses overlays")];

        bool ui;
        string? why = null;
        try { ui = showUi(); }
        catch (Exception ex) { ui = false; why = ex.Message; }
        if (!ui)
        {
            Try(closeUi);
            return [DesktopAudit.Error(ErrorCodes.LockDesktopUiFailed, $"Lock screen on the lock desktop could not be shown{(why is null ? "" : $": {why}")}; this lock uses overlays")];
        }

        // Erst erwarten, dann wechseln: Die Prüfung soll den eigenen Wechsel nicht für eine Flucht halten
        Engaged = true;
        Expected = DesktopTarget.Lock;
        if (_desktop.SwitchToLock()) return [];

        var error = _desktop.LastError;
        Engaged = false;
        Expected = DesktopTarget.Default;
        Try(closeUi);
        return [DesktopAudit.Error(ErrorCodes.LockDesktopSwitchFailed, $"SwitchDesktop to the lock desktop failed (Win32 {error}); this lock uses overlays")];
    }

    /// <summary>
    /// Vorübergehend auf den Windows-Desktop, z. B. für Windows Hello oder die Microsoft-Anmeldung, deren Fenster nur dort
    /// erscheinen (<see cref="DesktopSignIn"/>). Abdeckungen und Hooks schützen dort wie im Abdeckungs-Modus.
    /// </summary>
    /// <param name="reason">Englische Kennung fürs Protokoll, falls es scheitert.</param>
    public IReadOnlyList<DesktopAudit> HandOff(string reason)
    {
        if (!Locked || !OnLockDesktop) return [];
        Expected = DesktopTarget.Default;
        if (_desktop.SwitchToDefault()) return [];
        Expected = DesktopTarget.Lock;
        return [DesktopAudit.Error(ErrorCodes.LockDesktopReturnFailed, $"SwitchDesktop to Default failed ({reason}, Win32 {_desktop.LastError}); staying on the lock desktop")];
    }

    /// <summary>Nach der externen Anmeldung zurück auf den Sperr-Desktop. Scheitert das, bleibt diese Sperre bei den Abdeckungen.</summary>
    /// <param name="closeUi">Oberfläche auf dem Sperr-Desktop abbauen, wenn der Wechsel scheitert.</param>
    public IReadOnlyList<DesktopAudit> Resume(Action closeUi)
    {
        if (!Locked || !HandedOff) return [];
        Expected = DesktopTarget.Lock;
        if (_desktop.SwitchToLock()) return [];
        var error = _desktop.LastError;
        Engaged = false;
        Expected = DesktopTarget.Default;
        Try(closeUi);
        return [DesktopAudit.Error(ErrorCodes.LockDesktopSwitchFailed, $"SwitchDesktop back to the lock desktop failed (Win32 {error}); the rest of this lock uses overlays")];
    }

    /// <summary>
    /// Die Oberfläche auf dem Sperr-Desktop ist ausgefallen: zurück auf den Windows-Desktop, der Rest dieser Sperre läuft mit
    /// Abdeckungen. Scheitert der Wechsel, meldet die Prüfung (<see cref="Poll"/>) den Sperr-Desktop als fremd und versucht es weiter.
    /// </summary>
    public IReadOnlyList<DesktopAudit> Abandon()
    {
        if (!Engaged) return [];
        Engaged = false;
        Expected = DesktopTarget.Default;
        ResetIncident();
        for (int i = 0; i < 3; i++)
            if (_desktop.SwitchToDefault()) return [];
        return [DesktopAudit.Error(ErrorCodes.LockDesktopReturnFailed, $"SwitchDesktop to Default failed after the lock screen failed (Win32 {_desktop.LastError}); retrying")];
    }

    /// <summary>
    /// Entsperrt (oder Programmende): zurück auf den Windows-Desktop, bis zu drei Versuche. Scheitert es, wiederholt die
    /// Prüfung im entsperrten Zustand (<see cref="Poll"/>), solange der Sperr-Desktop Eingabe-Desktop ist.
    /// </summary>
    public IReadOnlyList<DesktopAudit> Unlock()
    {
        Locked = false;
        var engaged = Engaged;
        Engaged = false;
        Expected = DesktopTarget.Default;
        ResetIncident();
        if (!engaged) return [];
        for (int i = 0; i < 3; i++)
            if (_desktop.SwitchToDefault()) return [];
        return [DesktopAudit.Error(ErrorCodes.LockDesktopReturnFailed, $"SwitchDesktop to Default failed after unlocking (Win32 {_desktop.LastError}); retrying")];
    }

    /// <summary>
    /// Regelmäßige Prüfung des Eingabe-Desktops (gesperrt alle 250 ms, entsperrt seltener). Gesperrt: fremder Desktop →
    /// melden und zurückschalten. Entsperrt: nur ein liegen gebliebener Sperr-Desktop von Vitrine wird verlassen.
    /// </summary>
    public GuardResult Poll()
    {
        var name = _desktop.InputDesktopName();
        // Nicht lesbar oder „sicher“ benannt: nur dann ein sicherer Desktop von Windows, wenn der Zustand der Sitzung es belegt.
        // Sonst kann es ein Desktop eines Programms sein, dessen Zugriffsliste den Benutzer aussperrt (oder der „Screen-saver“
        // heißt) – nach kurzer Frist gilt er als fremd
        bool unverified = false;
        if (LockDesktopNames.IsSecure(name))
        {
            if (!Locked || _desktop.SecureDesktopExpected())
            {
                _unverified = 0;
                _afterSecure = true;
                return GuardResult.Nothing;
            }
            if (++_unverified < UnverifiedSecureGrace)
            {
                _afterSecure = true;
                return GuardResult.Nothing;
            }
            unverified = true;
        }
        else _unverified = 0;
        var shown = name ?? "(unreadable desktop)";

        if (!Locked)
        {
            _afterSecure = false;
            if (!LockDesktopNames.IsOwnLockDesktop(name))
            {
                _strandedLogged = false;
                return GuardResult.Nothing;
            }
            var ok = _desktop.SwitchToDefault();
            // Je Vorfall einmal ins Protokoll; scheitert es, wird es bei der nächsten Prüfung wieder versucht
            if (_strandedLogged) return new(ok ? GuardAction.Restored : GuardAction.None, []);
            _strandedLogged = true;
            return new(ok ? GuardAction.Restored : GuardAction.None,
                [DesktopAudit.Error(ErrorCodes.LockDesktopStranded, $"Lock desktop {name} was still the input desktop while unlocked; " +
                    (ok ? "switched to Default" : $"switching to Default failed (Win32 {_desktop.LastError}), retrying"))]);
        }

        if (string.Equals(name, ExpectedName, StringComparison.OrdinalIgnoreCase))
        {
            ResetIncident();
            return GuardResult.Nothing;
        }

        var audit = new List<DesktopAudit>();
        if (!_incident)
        {
            _incident = true;
            audit.Add(new(AuditEventType.DesktopSwitchDetected,
                $"Input desktop {shown}, expected {ExpectedName}" +
                (unverified ? " (no Windows sign-in, Ctrl+Alt+Del, lock or UAC screen active in the session)"
                    : _afterSecure ? " (after a secure desktop: Ctrl+Alt+Del, Windows lock or UAC)" : "") + "; switching back"));
        }
        var restored = Expected == DesktopTarget.Lock ? _desktop.SwitchToLock() : _desktop.SwitchToDefault();
        if (restored)
        {
            _failures = 0;
            return new(GuardAction.Restored, audit);
        }
        _failures++;
        if (_failures < MaxRestoreFailures) return new(GuardAction.None, audit);
        _failures = 0;
        audit.Add(DesktopAudit.Error(ErrorCodes.LockDesktopRestoreFailed,
            $"Could not switch back from desktop {shown} to {ExpectedName} ({MaxRestoreFailures} attempts, Win32 {_desktop.LastError}); locking Windows"));
        return new(GuardAction.FallbackLock, audit);
    }

    /// <summary>Vitrine sperrt gerade selbst Windows (Rückfall); die folgende Windows-Sperre ist dann erwartet.</summary>
    public void NoteFallbackLock(DateTimeOffset now) => _fallbackAt = now;

    /// <summary>
    /// Windows meldet „Sitzung gesperrt“ (WTS_SESSION_LOCK). Während einer Vitrine-Sperre ein Eintrag
    /// <see cref="AuditEventType.WindowsLockDetected"/>, sonst nichts.
    /// </summary>
    public DesktopAudit? WindowsLocked(DateTimeOffset now)
    {
        if (!Locked) return null;
        var cause = _fallbackAt is { } at && now - at >= TimeSpan.Zero && now - at <= FallbackLockWindow
            ? "caused by Vitrine's fallback lock"
            : "not caused by Vitrine (Win+L, Ctrl+Alt+Del, another program or a policy)";
        var where = Engaged ? (Expected == DesktopTarget.Lock ? "desktop mode, on the lock desktop" : "desktop mode, during sign-in on the Windows desktop")
            : "overlay mode";
        return new(AuditEventType.WindowsLockDetected, $"Windows locked while Vitrine was locked: {cause}; {where}");
    }

    private void ResetIncident()
    {
        _incident = false;
        _afterSecure = false;
        _failures = 0;
        _unverified = 0;
    }

    private static void Try(Action a)
    {
        try { a(); } catch { /* Abbau darf den Rückfall auf die Abdeckungen nicht verhindern */ }
    }
}

/// <summary>
/// Welche Anmeldungen auf dem Sperr-Desktop gehen. Die Eingabe im Entsperr-Dialog (Windows-Kennwort, Entsperr-Kennwort,
/// Plugins mit Kennwortfeld) läuft in Vitrines eigenem Fenster und damit auf dem Sperr-Desktop. Externe Anmeldungen
/// zeigen Fenster anderer Prozesse: Windows Hello und der Windows-Sicherheitsdialog (CredentialUIBroker, CredDialogHost
/// – von Windows gestartet, immer auf dem Windows-Desktop), der Windows-Kontobroker (WAM) und das Microsoft-Anmeldefenster
/// (WebView2-Prozesse erben den Desktop des Prozesses, nicht den des Threads; ein Fenster kann keinem Fenster auf einem
/// anderen Desktop gehören). Für sie schaltet Vitrine vorübergehend auf den Windows-Desktop zurück, wo Abdeckungen und
/// Hooks wie im Abdeckungs-Modus schützen.
/// </summary>
public static class DesktopSignIn
{
    /// <summary>Braucht dieses Verfahren den Windows-Desktop (Fenster eines anderen Prozesses)?</summary>
    public static bool NeedsWindowsDesktop(AuthInputKind input) => input == AuthInputKind.External;

    /// <summary>
    /// Eingebaute Verfahren, deren Fenster immer auf dem Windows-Desktop erscheinen – unabhängig davon, was der Anbieter als
    /// Eingabeart meldet: Microsoft, Windows Hello, Windows-Anmeldedialog und Sicherheitsschlüssel (der Windows-Sicherheitsdialog
    /// von webauthn.dll läuft in CredentialUIBroker.exe bzw. CredDialogHost.exe).
    /// </summary>
    public static readonly IReadOnlySet<string> WindowsDesktopMethods =
        new HashSet<string>(["entra", "hello", Auth.WindowsLogonDialog.MethodId, Fido.FidoProtocol.MethodId], StringComparer.OrdinalIgnoreCase);

    /// <summary>Braucht dieses Verfahren (Kennung und Eingabeart) den Windows-Desktop?</summary>
    public static bool NeedsWindowsDesktop(string methodId, AuthInputKind input) =>
        NeedsWindowsDesktop(input) || WindowsDesktopMethods.Contains(methodId);
}

/// <summary>Aufräumen nach einem Absturz (Wächter, Neustart der App): Ist ein Sperr-Desktop von Vitrine noch Eingabe-Desktop?</summary>
public static class DesktopRecovery
{
    /// <summary>Muss auf den Windows-Desktop zurückgeschaltet werden, bevor Windows gesperrt wird bzw. Vitrine neu sperrt?</summary>
    public static bool MustSwitchToDefault(string? inputDesktop) => LockDesktopNames.IsOwnLockDesktop(inputDesktop);
}
