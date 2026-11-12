// SPDX-License-Identifier: MIT
using System.Globalization;
using System.Windows.Threading;
using Microsoft.Win32;
using Vitrine.Abstractions;
using Vitrine.Core.Audit;
using Vitrine.Core.Auth;
using Vitrine.Core.Config;
using Vitrine.Core.Governance;
using Vitrine.Core.Fido;
using Vitrine.Core.Localization;
using Vitrine.Core.Lock;
using Vitrine.Platform;
using Vitrine.Services.Auth;
using Vitrine.Services.Interop;
using Vitrine.Services.Supervisor;
using Vitrine.UI;

namespace Vitrine.Services.Lock;

public enum LockStatus { Unlocked, Locked }

public sealed class LockController : IDisposable
{
    private readonly ConfigStore _store;
    private readonly SessionInfo _session;
    private readonly AuthRegistry _auth;
    private readonly AuditLog _audit;
    private readonly Dispatcher _ui;
    private readonly InputBlocker _blocker = new();
    private readonly SasRestrictions _sas = new(new RegistryUserPolicyStore());
    // Win+L abschalten (während der Sperre, mit Lock.ReplaceWinL dauerhaft). Vor jedem LockWorkStation-Rückfall entfernen.
    private readonly LockWorkstationPolicy _winLock = WorkstationLocker.CreatePolicy();
    private bool _winLockFailureLogged, _winLockMachineLogged;
    private readonly List<OverlayWindow> _overlays = new();
    private readonly DispatcherTimer _topmostTimer;
    private UnlockWindow? _prompt;
    private bool _externalFlow;
    private readonly FailureThrottle _throttle = new();
    private DateTime _lastNudge;
    // Eigener Sperr-Desktop (Lock.Mode = Desktop) und Erkennung von Desktop-Wechseln (beide Modi)
    private readonly WindowsLockDesktop _desktop = new();
    private readonly DesktopLockSession _desk;
    private LockDesktopHost? _host;
    private DesktopPreviewCapture? _preview;
    private readonly DispatcherTimer _guardTimer;
    private int _guardTicks;
    private bool _previewFailureLogged;
    // Kennung des Entsperr-Dialogs auf dem Sperr-Desktop (null = keiner); Rückmeldungen eines alten Dialogs werden so erkannt
    private object? _desktopPrompt;

    public LockController(ConfigStore store, SessionInfo session, AuthRegistry auth, AuditLog audit, Dispatcher ui)
    {
        _store = store;
        _session = session;
        _auth = auth;
        _audit = audit;
        _ui = ui;
        Roles = new RoleCheck(() => _store.Current, WindowsAccounts.ToSid, () => new LocalGroupDirectory());
        // Zu Beginn ist verantwortlich, wer an Windows angemeldet ist (GxP: wer ist jetzt für den Rechner verantwortlich)
        Responsibility.Begin(session.UserName, session.Sid, session.DisplayName, DateTimeOffset.UtcNow);

        _blocker.Activity += kind => _ui.BeginInvoke(() => OnActivity(kind));
        // Eigenes Anmeldefenster für Microsoft: wie der Dialog per Handle freigeben (seine WebView2-Inhalte sind Kindfenster
        // und zählen mit; der Windows-Sicherheitsdialog für Sicherheitsschlüssel kommt über Security.AuthUiProcesses)
        SignInWindow.InteractiveChanged += (hwnd, open) =>
        {
            if (open) _blocker.AllowWindow(hwnd);
            else _blocker.DisallowWindow(hwnd);
        };
        SignInWindow.BrowserProcessChanged += pid => _blocker.SetWebViewBrowser(pid);
        _topmostTimer = new DispatcherTimer(DispatcherPriority.Background, _ui) { Interval = TimeSpan.FromMilliseconds(500) };
        _topmostTimer.Tick += (_, _) => HoldShield();
        _desk = new DesktopLockSession(_desktop);
        // Gesperrt alle 250 ms, entsperrt jede Sekunde (nur ein liegen gebliebener Sperr-Desktop wird dann verlassen)
        _guardTimer = new DispatcherTimer(DispatcherPriority.Background, _ui) { Interval = TimeSpan.FromMilliseconds(250) };
        _guardTimer.Tick += (_, _) => GuardDesktop();
        _guardTimer.Start();

        SystemEvents.DisplaySettingsChanged += (_, _) => _ui.BeginInvoke(() =>
        {
            if (Status != LockStatus.Locked) return;
            RebuildOverlays();
            if (_desk.Engaged) ShowDesktopUi();
        });
        // Nach einem Rückfall (Windows gesperrt bzw. Sitzung getrennt) war der eigene Win+L-Wert entfernt: wieder setzen,
        // sobald Windows entsperrt bzw. die Sitzung wieder verbunden ist – nicht vorher, sonst liefe die Sperre ins Leere
        SystemEvents.SessionSwitch += (_, e) =>
        {
            if (e.Reason is SessionSwitchReason.SessionUnlock or SessionSwitchReason.ConsoleConnect or SessionSwitchReason.RemoteConnect)
                _ui.BeginInvoke(() => { if (_winLock.Held) ReportWinLock(_winLock.Apply()); });
            // Windows gesperrt, während Vitrine gesperrt ist: protokollieren (WindowsLockDetected), mit Ursache
            if (e.Reason == SessionSwitchReason.SessionLock)
                _ui.BeginInvoke(() => { if (_desk.WindowsLocked(DateTimeOffset.UtcNow) is { } a) Log(a.Event, detail: a.Detail); });
        };
        ApplyConfig(store.Current);
        store.Changed += cfg => _ui.BeginInvoke(() => ApplyConfig(cfg));
    }

    public LockStatus Status { get; private set; } = LockStatus.Unlocked;
    public DateTimeOffset? LockedSince { get; private set; }
    public string? LockedBy { get; private set; }
    public string? LastUnlockedBy { get; private set; }

    /// <summary>Rollenprüfung (Roles.*, Security.LocalAdministratorsArePrivileged); auch für andere Teile der App.</summary>
    public RoleCheck Roles { get; }

    /// <summary>Freigabe der Zwecke Signatur/Registrar für den Sicherheitsschlüssel (nur bei offenem Dialog dafür).</summary>
    private FidoPurposeGate? FidoGate => (_auth.Get(FidoProtocol.MethodId) as FidoProvider)?.Gate;

    /// <summary>Wer gerade für den Rechner verantwortlich ist (zuletzt entsperrt bzw. an Windows angemeldet).</summary>
    public ResponsibilityTracker Responsibility { get; } = new();

    /// <summary>Die verantwortliche Person hat gewechselt (für Infobereich und Einstellungen).</summary>
    public event Action? ResponsibilityChanged;

    /// <summary>Ein Dialog (Entsperren, Signatur, Admin) ist offen.</summary>
    public bool PromptOpen => _prompt is not null || _desktopPrompt is not null;

    public event Action<LockStatus>? StatusChanged;
    public event Action<AuditEntry>? Audited;

    /// <summary>Im Bildschirmschoner-Modus (/s) Programm nach dem Entsperren beenden.</summary>
    public bool ExitOnUnlock { get; set; }

    /// <summary>
    /// Verbindung zum Dienst, wenn er das Protokoll schreibt (#15). Dann prüft der Dienst die Anmeldung einer Signatur und
    /// trägt sie selbst ein; ist er nicht erreichbar, gibt es keine Signatur (VIT-0300).
    /// </summary>
    public AuditLink? AuditLink { get; set; }

    /// <summary>Signaturen laufen über den Dienst (er schreibt das Protokoll).</summary>
    private AuditLink? SignatureService => _audit.Forwarding ? AuditLink : null;

    /// <summary>Strg+Alt+Entf-Einschränkungen (auch für die Aufräumarbeit beim Start).</summary>
    public SasRestrictions Sas => _sas;

    private VitrineConfig Cfg => _store.Current;

    private void ApplyConfig(VitrineConfig cfg)
    {
        _blocker.BlockMouseMove = cfg.Lock.BlockMouseMove;
        _blocker.SetAllowedProcesses(cfg.Security.AuthUiProcesses);
        var hk = Hotkey.Parse(cfg.Lock.Hotkey);
        _blocker.SetHotkey(hk.Modifiers, hk.VirtualKey);
        _audit.Update(cfg.Audit);
        if (cfg.Lock.ReplaceWinL) ReportWinLock(_winLock.Hold(WinLockReason.ReplaceWinL));
        else _winLock.Release(WinLockReason.ReplaceWinL);
    }

    /// <summary>Probleme beim Abschalten von Win+L je einmal protokollieren (VIT-0162, VIT-0163).</summary>
    private void ReportWinLock(WinLockStatus status)
    {
        switch (status)
        {
            case WinLockStatus.Failed when !_winLockFailureLogged:
                _winLockFailureLogged = true;
                Log(AuditEventType.Error, detail: $"{ErrorCodes.WinLNotDisabled} DisableLockWorkstation could not be set");
                break;
            case WinLockStatus.Applied:
                _winLockFailureLogged = false;
                break;
            case WinLockStatus.MachinePolicy when !_winLockMachineLogged:
                _winLockMachineLogged = true;
                Log(AuditEventType.Error, detail: $"{ErrorCodes.WinLMachinePolicy} HKLM DisableLockWorkstation is set, left unchanged");
                break;
        }
    }

    /// <summary>
    /// Rückfall „Windows sperren“ über <see cref="WorkstationLocker"/>: eigener Win+L-Wert zuerst weg, dann sperren, sonst
    /// trennen. Läuft im Hintergrund (wartet bis zu 3 s auf den Sperrbildschirm); das Ergebnis kommt ins Protokoll.
    /// </summary>
    /// <param name="always">Auch ein gelungenes Sperren protokollieren (sonst nur Trennen und Fehlschlag).</param>
    private void FallbackLock(string cause, bool always)
    {
        // Die gleich folgende Windows-Sperre ist Vitrines eigene (WindowsLockDetected nennt die Ursache)
        _desk.NoteFallbackLock(DateTimeOffset.UtcNow);
        _ = Task.Run(() =>
        {
            var (outcome, detail) = WorkstationLocker.Lock(_winLock, cause);
            if (always || outcome != FallbackLockOutcome.Locked)
                _ui.BeginInvoke(() => Log(AuditEventType.Error, detail: detail));
        });
    }

    // ================= Sperren =================

    private LockVisual? _visualOverride;

    /// <param name="trigger">Auslöser als Kennung aus <see cref="LockTriggers"/> (steht so im Protokoll).</param>
    public void Lock(string trigger, LockVisual? visual = null)
    {
        if (Status == LockStatus.Locked) return;
        _visualOverride = visual;
        Status = LockStatus.Locked;
        LockedSince = DateTimeOffset.Now;
        LockedBy = trigger;
        // Eine noch laufende externe Anmeldung eines Signatur- oder Admin-Dialogs gilt für die Sperre nicht
        _externalFlow = false;
        // Fehlversuche aus Signatur- und Admin-Dialogen vor der Sperre zählen nicht für die neue Sperre
        _throttle.Reset();
        // Ein offener Signatur- oder Admin-Dialog darf nicht über dem Sperrbildschirm bedienbar bleiben
        if (_prompt is { Kind: not PromptKind.Unlock } other) other.Close();

        // Zuerst blockieren und abdecken – alles Weitere darf scheitern, ohne dass die Sperre unvollständig bleibt.
        _blocker.Mode = BlockMode.Locked;
        LockState.Set(true);
        Watchdog.Signal(true);
        ServiceLink.Signal(true);
        try { RebuildOverlays(); }
        catch (Exception ex) { Log(AuditEventType.Error, detail: $"Overlay: {ex.Message}"); }
        _topmostTimer.Start();
        // Sofort den Vordergrund übernehmen – war vorher z. B. ein als Administrator gestartetes Fenster aktiv, gingen
        // Tastatureingaben sonst weiter dorthin (UIPI, LockShield)
        HoldShield();

        if (Cfg.Security.RestrictCtrlAltDel)
        {
            try { _sas.Apply(); }
            catch (Exception ex) { Log(AuditEventType.Error, detail: $"Ctrl+Alt+Del restrictions: {ex.Message}"); }
            // Win+L und „Sperren“ im Strg+Alt+Entf-Menü: führten zum Windows-Sperrbildschirm, der den Arbeitsplatz verdeckt
            try { ReportWinLock(_winLock.Hold(WinLockReason.Lock)); }
            catch (Exception ex) { Log(AuditEventType.Error, detail: $"{ErrorCodes.WinLNotDisabled} {ex.Message}"); }
        }
        if (Cfg.Lock.KeepAwake)
            Native.SetThreadExecutionState(Native.ES_CONTINUOUS | Native.ES_DISPLAY_REQUIRED | Native.ES_SYSTEM_REQUIRED);
        if (Cfg.Appearance.HideCursor) CursorHider.Hide();

        // Eigener Desktop zuletzt: Abdeckungen, Hooks und Strg+Alt+Entf-Sicherung stehen schon (Rückfall, zweite Linie)
        EngageDesktop();

        if (Cfg.Audit.LogLockState) Log(AuditEventType.Locked, detail: $"Trigger: {trigger}");
        ScriptRunner.Run(Cfg.Scripts.OnLock, "lock", Cfg.Scripts.TimeoutSeconds, new Dictionary<string, string?> { ["trigger"] = trigger });
        StatusChanged?.Invoke(Status);
    }

    private void Unlock(AuthOutcome who, string method)
    {
        // Zuerst zurück auf den Windows-Desktop – dort liegen noch Abdeckungen und Hooks, bis sie unten wegfallen
        DisengageDesktop();
        _blocker.Mode = BlockMode.Off;
        _topmostTimer.Stop();
        foreach (var o in _overlays) o.Close();
        _overlays.Clear();

        CursorHider.Show();
        _sas.Restore();
        // Mit Lock.ReplaceWinL bleibt der Wert, sonst sperrt Win+L wieder Windows
        _winLock.Release(WinLockReason.Lock);
        Native.SetThreadExecutionState(Native.ES_CONTINUOUS);
        LockState.Set(false);
        Watchdog.Signal(false);
        ServiceLink.Signal(false);

        Status = LockStatus.Unlocked;
        var since = LockedSince;
        LockedSince = null;
        LastUnlockedBy = who.DisplayName ?? who.UserName;
        _throttle.Reset();

        var lockedFor = since is null ? null : AuditDetails.LockedFor(DateTimeOffset.Now - since.Value);
        if (EmergencyAccess.IsEmergency(who))
        {
            // Notfall-Anmeldung: eigener Eintrag mit Begründung und immer als Warnung ins Ereignisprotokoll (auch ohne Audit.EventLog)
            var entry = Log(AuditEventType.UnlockBypass, who.UserName, method, lockedFor, Data(who));
            if (!Cfg.Audit.EventLog)
                try { new EventLogSink().Write(entry); } catch { /* Ereignisprotokoll ist ein Zusatz */ }
        }
        else Log(AuditEventType.Unlocked, who.UserName, method, lockedFor, Data(who));
        if (Responsibility.Unlocked(who, method, DateTimeOffset.UtcNow) is { } change)
        {
            Log(AuditEventType.ResponsibilityChanged, who.UserName, method, ResponsibilityTracker.AuditDetail(change),
                ResponsibilityTracker.AuditData(change));
            ResponsibilityChanged?.Invoke();
        }
        ScriptRunner.Run(Cfg.Scripts.OnUnlock, "unlock", Cfg.Scripts.TimeoutSeconds,
            new Dictionary<string, string?> { ["user"] = who.UserName, ["method"] = method });
        StatusChanged?.Invoke(Status);

        if (ExitOnUnlock) System.Windows.Application.Current.Shutdown();
    }

    private DateTime? _foreignSince;
    private DateTime _lastWorkstationLock = DateTime.MinValue;

    private LockPhase Phase => _externalFlow ? LockPhase.ExternalAuth : PromptActive ? LockPhase.Prompt : LockPhase.Locked;

    /// <summary>Ein Dialog ist offen – auf dem Windows-Desktop oder auf dem Sperr-Desktop.</summary>
    private bool PromptActive => _prompt is not null || _desktopPrompt is not null;

    /// <summary>Abdeckungen auf den Abschnitt der Sperre einstellen (durchklickbar und unten nur bei externer Anmeldung).</summary>
    private void ApplyShield()
    {
        var phase = Phase;
        var shield = LockShield.For(phase);
        foreach (var o in _overlays) o.SetShield(shield);
        // Die Abdeckungen liegen jetzt ganz oben – ein offener Dialog muss wieder darüber
        if (phase == LockPhase.Prompt && _prompt is { } prompt)
        {
            prompt.ForceForeground();
            foreach (var o in _overlays) o.PlaceBelow(prompt.Handle);
        }
    }

    /// <summary>
    /// Regelmäßig während der Sperre: Abdeckungen oben halten (nicht über einem offenen Dialog) und den Vordergrund
    /// zurückholen, wenn ein fremdes Fenster ihn hat. Die Hooks sehen keine Eingaben an Fenster mit höherer Integrität
    /// (als Administrator gestartet) – solange Vitrine den Vordergrund hat, gehen Tastatureingaben nicht dorthin.
    /// </summary>
    private void HoldShield()
    {
        if (Status != LockStatus.Locked) return;
        // Auf dem Sperr-Desktop gibt es keine fremden Fenster; der Windows-Desktop ist dann nicht Eingabe-Desktop
        if (_desk.OnLockDesktop) return;
        var phase = Phase;
        if (phase == LockPhase.Locked) foreach (var o in _overlays) o.SetOnTop(true);
        // Mit Dialog: Abdeckungen direkt unter den Dialog, so bleiben beide über Fenstern, die sich „immer oben“ legen
        else if (phase == LockPhase.Prompt && _prompt is { Handle: not 0 } p) foreach (var o in _overlays) o.PlaceBelow(p.Handle);
        // Hält ein Fenster mit höherer Integrität den Vordergrund (Vitrine kann ihn von dort oft nicht zurückholen),
        // nach kurzer Zeit Windows sperren – Tastatureingaben gingen sonst an dieses Fenster
        // Nach einem Rückfall eine Weile nicht erneut: Wer Windows entsperrt hat, kennt das Kennwort, und der erste Klick auf
        // die Abdeckung holt den Vordergrund ohnehin zu Vitrine
        if (phase == LockPhase.Locked && DateTime.UtcNow - _lastWorkstationLock > TimeSpan.FromSeconds(30) && Native.ForegroundIsForeignIntegrity())
        {
            _foreignSince ??= DateTime.UtcNow;
            if (LockShield.MustLockWorkstation(phase, DateTime.UtcNow - _foreignSince.Value))
            {
                _foreignSince = null;
                _lastWorkstationLock = DateTime.UtcNow;
                FallbackLock("Elevated window kept the foreground while locked", always: true);
                return;
            }
        }
        else _foreignSince = null;
        if (!LockShield.MustTakeForeground(phase, Native.ForegroundIsOwn())) return;
        if (phase == LockPhase.Prompt) _prompt?.ForceForeground();
        else (_overlays.FirstOrDefault(o => o.IsPrimary) ?? _overlays.FirstOrDefault())?.TakeForeground();
    }

    private void RebuildOverlays()
    {
        foreach (var o in _overlays) o.Close();
        _overlays.Clear();

        var look = Cfg.Appearance.Clone();
        if (_visualOverride is { } v) look.Visual = v;
        var (title, hint) = OverlayTexts();
        var monitors = Native.GetMonitors();
        var numbers = ScreenMasks.NumberMonitors(monitors.Select(m => (ToPixel(m.Bounds), m.IsPrimary)).ToList());
        for (int i = 0; i < monitors.Count; i++)
        {
            var w = new OverlayWindow(monitors[i], numbers[i], look, title, hint, RevealedOn);
            w.Show();
            _overlays.Add(w);
        }
        // Neu aufgebaut (z. B. Bildschirme geändert) mitten in einer externen Anmeldung: dort bleiben sie durchlässig
        ApplyShield();
    }

    private static PixelRect ToPixel(Native.RECT r) => new(r.Left, r.Top, r.Right, r.Bottom);

    /// <summary>
    /// Sichtbare Teile der Fenster freigegebener Programme (Appearance.RevealProcesses) auf einem Monitor. Eigene Fenster
    /// (Abdeckungen, Dialog) zählen nicht, sonst läge über allem ein „fremdes“ Fenster.
    /// </summary>
    private List<PixelRect> RevealedOn(PixelRect monitor)
    {
        var processes = Cfg.Appearance.RevealProcesses;
        if (processes.Count == 0) return [];
        var own = (uint)Environment.ProcessId;
        var known = new Dictionary<uint, bool>();
        var windows = Native.WindowsTopToBottom()
            .Where(w => w.Pid != own)
            .Select(w =>
            {
                if (!known.TryGetValue(w.Pid, out var reveal))
                    known[w.Pid] = reveal = ScreenMasks.IsRevealed(Native.GetProcessImageName(w.Pid), processes);
                return (ToPixel(w.Rect), reveal);
            });
        return ScreenMasks.RevealedAreas(windows, monitor);
    }

    private (string title, string hint) OverlayTexts()
    {
        var u = Cfg.Unlock;
        string how = u.Trigger switch
        {
            UnlockTrigger.KeyOnly => Loc.T("Overlay_HowKey"),
            UnlockTrigger.HotkeyOnly => Loc.F("Overlay_HowHotkey", Hotkey.Display(Cfg.Lock.Hotkey)),
            _ => Loc.T("Overlay_HowAny"),
        };
        var since = (LockedSince ?? DateTimeOffset.Now).ToString("t", CultureInfo.CurrentCulture);
        var msg = Cfg.Appearance.Message;
        return string.IsNullOrWhiteSpace(msg)
            ? (Loc.F("Overlay_Title", _session.DisplayName), Loc.F("Overlay_Hint", since, how))
            : (msg, Loc.F("Overlay_HintWithMessage", _session.DisplayName, since, how));
    }

    // ================= Eigener Sperr-Desktop (Lock.Mode = Desktop) und Fluchterkennung =================

    /// <summary>Abdeckung des Hauptbildschirms: Besitzer der Fenster externer Anmeldungen, wenn der Dialog auf dem Sperr-Desktop liegt.</summary>
    private nint PrimaryOverlayHandle =>
        (_overlays.FirstOrDefault(o => o.IsPrimary) ?? _overlays.FirstOrDefault()) is { } o ? new System.Windows.Interop.WindowInteropHelper(o).Handle : 0;

    private void LogDesktop(IReadOnlyList<DesktopAudit> audit)
    {
        foreach (var a in audit) Log(a.Event, detail: a.Detail);
    }

    private AppearanceSettings CurrentLook()
    {
        var look = Cfg.Appearance.Clone();
        if (_visualOverride is { } v) look.Visual = v;
        return look;
    }

    /// <summary>
    /// Beim Sperren mit <c>Lock.Mode = Desktop</c>: Sperr-Desktop anlegen, Oberfläche dort zeigen, wechseln. Jeder Fehler
    /// lässt die Sperre bei den Abdeckungen (VIT-0450, VIT-0451, VIT-0453); Entscheidungen in <see cref="DesktopLockSession"/>.
    /// </summary>
    private void EngageDesktop()
    {
        try { LogDesktop(_desk.Lock(Cfg.Lock.Mode, ShowDesktopUi, HideDesktopUi)); }
        catch (Exception ex) { Log(AuditEventType.Error, detail: $"{ErrorCodes.LockDesktopUiFailed} {ex.Message}; this lock uses overlays"); }
        if (_desk.OnLockDesktop) StartPreview();
    }

    /// <summary>Abdeckungen auf dem Sperr-Desktop aufbauen (auch nach geänderten Bildschirmen). false = gescheitert.</summary>
    private bool ShowDesktopUi()
    {
        if (_host is null)
        {
            _host = new LockDesktopHost();
            _host.Activity += kind => _ui.BeginInvoke(() => OnActivity(kind));
            _host.Failed += ex => _ui.BeginInvoke(() => OnDesktopUiFailed(ex));
        }
        if (!_host.Start(_desktop.Handle)) return false;
        var (title, hint) = OverlayTexts();
        var look = CurrentLook();
        var preview = DesktopPreview.ContentFor(Cfg.Lock, look) != PreviewContent.None;
        return _host.ShowCurtains(Native.GetMonitors(), title, hint, preview ? look.DimPercent : 0, Hotkey.Parse(Cfg.Lock.Hotkey), preview);
    }

    private void HideDesktopUi()
    {
        StopPreview();
        _host?.HideAll();
    }

    /// <summary>Fehler auf dem Thread des Sperr-Desktops: zurück zu den Abdeckungen für den Rest dieser Sperre.</summary>
    private void OnDesktopUiFailed(Exception ex)
    {
        Log(AuditEventType.Error, detail: $"{ErrorCodes.LockDesktopUiFailed} {ex.GetType().Name}: {ex.Message}; the rest of this lock uses overlays");
        if (!_desk.Engaged) return;
        LogDesktop(_desk.Abandon());
        HideDesktopUi();
        if (Status != LockStatus.Locked) return;
        _blocker.Mode = PromptActive ? BlockMode.Prompt : BlockMode.Locked;
        ApplyShield();
        HoldShield();
    }

    /// <summary>Entsperrt bzw. Programmende: zurück auf den Windows-Desktop, Oberfläche des Sperr-Desktops schließen.</summary>
    private void DisengageDesktop()
    {
        StopPreview();
        _desktopPrompt = null;
        LogDesktop(_desk.Unlock());
        _host?.HideAll();
    }

    private void StartPreview()
    {
        StopPreview();
        var look = CurrentLook();
        var content = DesktopPreview.ContentFor(Cfg.Lock, look);
        if (content == PreviewContent.None || _host is not { } host) return;
        // Text und Sprache hier festlegen: Der Thread der Vorschau hat nicht die Sprache der Oberfläche
        var culture = CultureInfo.CurrentCulture;
        var format = Loc.T("Desktop_PreviewAt");
        _preview = new DesktopPreviewCapture(content, look, DesktopPreview.Interval(Cfg.Lock.DesktopPreviewSeconds),
            (frames, at) => host.SetPreview(frames, string.Format(culture, format, at.ToString("T", culture))),
            why => _ui.BeginInvoke(() =>
            {
                if (_previewFailureLogged) return;
                _previewFailureLogged = true;
                Log(AuditEventType.Error, detail: $"{ErrorCodes.LockDesktopPreviewFailed} Preview of the Windows desktop not available: {why}");
            }));
        _preview.Start();
    }

    private void StopPreview()
    {
        _preview?.Dispose();
        _preview = null;
    }

    /// <summary>
    /// Entsperr-Dialog auf dem Sperr-Desktop. Lässt er sich dort nicht öffnen (VIT-0456), erscheint er diesmal auf dem
    /// Windows-Desktop über den Abdeckungen, danach geht es zurück auf den Sperr-Desktop.
    /// </summary>
    private async Task<AuthOutcome?> RunDesktopPrompt(LockDesktopHost host, object token, PromptRequest remote, PromptRequest fallback)
    {
        _desktopPrompt = token;
        _blocker.Mode = BlockMode.Prompt;
        AuthOutcome? who = null;
        nint hwnd = 0;
        try
        {
            // Hooks gelten nur auf dem Desktop, auf dem sie gesetzt wurden (dem Windows-Desktop) und sehen die Eingaben auf
            // dem Sperr-Desktop nicht. Den Dialog trotzdem freigeben, falls das auf einer Windows-Version anders sein sollte
            who = await host.RunPromptAsync(remote, h => { hwnd = h; _blocker.AllowWindow(h); });
            return who;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            Log(AuditEventType.Error, detail: $"{ErrorCodes.LockDesktopPromptFailed} {ex.GetType().Name}: {ex.Message}; showing the dialog on the Windows desktop");
            if (!ReferenceEquals(_desktopPrompt, token) || Status != LockStatus.Locked) return null;
            _desktopPrompt = null;
            _externalFlow = false;
            LogDesktop(_desk.HandOff("unlock dialog"));
            who = await RunPrompt(fallback);
            return who;
        }
        finally
        {
            _blocker.DisallowWindow(hwnd);
            if (ReferenceEquals(_desktopPrompt, token))
            {
                _desktopPrompt = null;
                _externalFlow = false;
            }
            if (Status == LockStatus.Locked && !PromptActive)
            {
                // Ohne Erfolg (abgebrochen, Zeitlimit, Fehler) zurück auf den Sperr-Desktop. Mit Erfolg nicht: Gleich wird
                // entsperrt, ein Zwischenwechsel ließe den Sperr-Desktop nur kurz aufblitzen.
                if (who is null && _desk.HandedOff) LogDesktop(_desk.Resume(HideDesktopUi));
                _blocker.Mode = BlockMode.Locked;
                ApplyShield();
                HoldShield();
                if (_desk.OnLockDesktop) host.Focus();
            }
        }
    }

    /// <summary>
    /// Externe Anmeldung aus dem Dialog auf dem Sperr-Desktop: vorübergehend auf den Windows-Desktop (dort erscheinen
    /// Windows Hello, der Windows-Sicherheitsdialog und das Microsoft-Anmeldefenster), danach zurück.
    /// </summary>
    private void SetDesktopExternalFlow(object token, bool active)
    {
        if (!ReferenceEquals(token, _desktopPrompt) || Status != LockStatus.Locked) return;
        _externalFlow = active;
        if (active) LogDesktop(_desk.HandOff("external sign-in"));
        _blocker.Mode = active ? BlockMode.ExternalAuth : BlockMode.Prompt;
        ApplyShield();
        if (active) return;
        LogDesktop(_desk.Resume(HideDesktopUi));
        if (_desk.OnLockDesktop) _host?.Focus();
    }

    /// <summary>
    /// Prüfung des Eingabe-Desktops (gesperrt alle 250 ms, sonst jede Sekunde): Flucht vom Sperr-Desktop bzw. auf einen
    /// fremden Desktop melden und zurückschalten; geht das nicht, Windows sperren.
    /// </summary>
    private void GuardDesktop()
    {
        if (Status != LockStatus.Locked && ++_guardTicks % 4 != 0) return;
        GuardResult r;
        try { r = _desk.Poll(); }
        catch { return; }
        LogDesktop(r.Audit);
        switch (r.Action)
        {
            case GuardAction.Restored when Status == LockStatus.Locked:
                if (_desk.OnLockDesktop) _host?.Focus();
                else HoldShield();
                break;
            case GuardAction.FallbackLock when DateTime.UtcNow - _lastWorkstationLock > TimeSpan.FromSeconds(30):
                _lastWorkstationLock = DateTime.UtcNow;
                FallbackLock("Desktop switch could not be undone while locked", always: true);
                break;
        }
    }

    // ================= Eingaben während der Sperre =================

    private void OnActivity(ActivityKind kind)
    {
        if (Status != LockStatus.Locked) return;

        if (PromptActive)
        {
            if (!_externalFlow)
            {
                _prompt?.ForceForeground();
                if (_desktopPrompt is not null) _host?.Focus();
            }
            return;
        }

        bool open = kind switch
        {
            ActivityKind.Hotkey => true,
            ActivityKind.Key => Cfg.Unlock.Trigger is UnlockTrigger.AnyInput or UnlockTrigger.KeyOnly,
            ActivityKind.Mouse => Cfg.Unlock.Trigger == UnlockTrigger.AnyInput,
            _ => false,
        };

        if (open) _ = ShowUnlockPromptAsync();
        else if (DateTime.Now - _lastNudge > TimeSpan.FromSeconds(1))
        {
            _lastNudge = DateTime.Now;
            foreach (var o in _overlays) o.Nudge();
            if (_desk.OnLockDesktop) _host?.Nudge();
        }
    }

    // ================= Dialoge =================

    public async Task ShowUnlockPromptAsync()
    {
        if (Status != LockStatus.Locked || PromptActive) return;

        // Microsoft am Sperrbildschirm im eigenen Anmeldefenster oder mit Broker; ohne WebView2-Laufzeit und ohne Broker
        // nicht (VIT-0190). Bleibt nichts übrig, das Windows-Kennwort – das melden Protokoll und Einstellungen (VIT-0016)
        var methods = await _auth.GetActiveAsync(LockScreenMethods.Filter(Cfg.Unlock.Methods, EntraIdProvider.OnLockScreen(Cfg.Entra)));
        if (Status != LockStatus.Locked || PromptActive) return;
        PromptRequest Request(Func<IAuthProvider, AuthRequest, PromptInput, Task<(AuthOutcome? ok, string? error, TimeSpan delay)>> verify,
            Action<UnlockWindow, bool> externalFlowChanged) => new()
        {
            Kind = PromptKind.Unlock,
            Heading = _session.DisplayName,
            SubHeading = Loc.F("Prompt_LockedSince", (LockedSince ?? DateTimeOffset.Now).ToString("t", CultureInfo.CurrentCulture), _session.MachineName),
            Reason = Loc.T("Prompt_ReasonUnlock"),
            Initials = _session.Initials,
            Methods = methods,
            PreferredMethod = methods.FirstOrDefault()?.Id,
            DefaultUser = Cfg.Unlock.PrefillUserName ? (_session.Upn ?? _session.UserName) : null,
            TimeoutSeconds = Cfg.Unlock.PromptTimeoutSeconds,
            LogoPath = Cfg.Appearance.LogoPath,
            Verify = verify,
            ExternalFlowChanged = externalFlowChanged,
            // Notfall-Anmeldung (Unlock.BypassGroups): immer mit dem Windows-Kennwort, auch wenn es kein Entsperr-Verfahren ist.
            // Das Windows-Kennwort wird im Dialog eingegeben – mit Lock.Mode = Desktop also auf dem Sperr-Desktop
            EmergencyMethod = EmergencyAccess.Enabled(Cfg.Unlock) ? _auth.Get(EmergencyAccess.Method) : null,
            EmergencyReasonMinLength = Reasons.EffectiveMinLength(Cfg.Unlock.BypassReasonMinLength),
        };
        var req = Request((p, r, i) => VerifyAsync(p, r, i, PromptKind.Unlock), SetExternalFlow);

        Log(AuditEventType.PromptShown);
        ScriptRunner.Run(Cfg.Scripts.OnPromptShown, "prompt", Cfg.Scripts.TimeoutSeconds);

        AuthOutcome? who;
        if (_desk.OnLockDesktop && _host is { Running: true } host)
        {
            // Dialog auf dem Sperr-Desktop: Rückrufe kommen vom Thread des Sperr-Desktops und werden hierher geholt.
            // Externe Verfahren (Hello, Microsoft, Windows-Anmeldung) zeigen ihre Fenster auf dem Windows-Desktop – Besitzer
            // ist dann die Abdeckung des Hauptbildschirms, nicht der Dialog auf dem anderen Desktop.
            var token = new object();
            var remote = Request(
                (p, r, i) => _ui.InvokeAsync(() => VerifyAsync(p, r, i, PromptKind.Unlock,
                    owner: DesktopSignIn.NeedsWindowsDesktop(p.Id, p.Input) ? PrimaryOverlayHandle : null)).Task.Unwrap(),
                (_, active) => _ui.BeginInvoke(() => SetDesktopExternalFlow(token, active)));
            who = await RunDesktopPrompt(host, token, remote, req);
        }
        else who = await RunPrompt(req);
        if (who is not null) Unlock(who, who.Details.TryGetValue("method", out var m) ? m : "?");
    }

    /// <summary>Elektronische Signatur für Fachanwendungen (über die Integrations-Schnittstelle).</summary>
    /// <param name="client">Prozess der Gegenstelle („lims.exe (PID 1234)“), ermittelt vom Pipe-Server.</param>
    /// <param name="scopes">Zugriffstoken für diese (vom Pipe-Server geprüften) Scopes: dann nur Microsoft Entra ID.</param>
    public async Task<AuthOutcome?> RequestSignatureAsync(string reason, string? meaning, string? requester, string? client = null,
        IReadOnlyList<string>? scopes = null)
    {
        // Nie über dem Sperrbildschirm: der Dialog würde den gesperrten Arbeitsplatz für eine Anmeldung öffnen
        if (PromptActive || Status == LockStatus.Locked) return null;
        // Schreibt der Dienst das Protokoll, ist er aber nicht erreichbar: keine Signatur, die niemand prüft und einträgt
        if (SignatureService is { Connected: false })
        {
            Log(AuditEventType.SignatureFailed, detail: ErrorCodes.AuditServiceUnavailable,
                data: new() { ["code"] = ErrorCodes.AuditServiceUnavailable, ["reason"] = reason });
            return AuthOutcome.Fail(CoreText.Error(ErrorCodes.AuditServiceUnavailable), ErrorCodes.AuditServiceUnavailable);
        }
        var methods = (await _auth.GetActiveAsync(Cfg.Unlock.Methods)).Where(m => m.Id != "pin").ToList();
        if (scopes is { Count: > 0 })
        {
            // Ein Token gibt es nur von Microsoft; auch wenn Entra nicht unter den Entsperr-Verfahren steht
            methods = _auth.Get("entra") is { } entra && await entra.IsAvailableAsync(CancellationToken.None) ? [entra] : [];
            if (methods.Count == 0) return null;
        }
        else if (methods.Count == 0 && _auth.Get("windows") is { } w) methods.Add(w);

        var req = new PromptRequest
        {
            Kind = PromptKind.Signature,
            Heading = _session.DisplayName,
            SubHeading = (requester, client) switch
            {
                (null, null) => null,
                ({ } r, null) => Loc.F("Prompt_RequestedBy", r),
                (null, { } c) => Loc.F("Prompt_RequestedBy", c),
                ({ } r, { } c) => Loc.F("Prompt_RequestedByProcess", r, c),
            },
            Reason = reason,
            Initials = _session.Initials,
            SignReason = reason,
            SignMeaning = meaning,
            Methods = methods,
            DefaultUser = _session.Upn ?? _session.UserName,
            TimeoutSeconds = Math.Max(60, Cfg.Unlock.PromptTimeoutSeconds),
            LogoPath = Cfg.Appearance.LogoPath,
            Verify = (p, r, i) => VerifyAsync(p, r, i, PromptKind.Signature, scopes: scopes),
            ExternalFlowChanged = SetExternalFlow,
        };
        AuthOutcome? who;
        // Sicherheitsschlüssel für eine Signatur nur aus diesem Dialog (der Windows-Sicherheitsdialog zeigt den Zweck nicht)
        using (FidoGate?.Open(FidoPurpose.Signature))
            who = await RunPrompt(req);
        if (who is not null && SignatureService is { } service)
        {
            // Der Dienst trägt die Signatur ein; Person und Verfahren kommen aus seinem Ticket, nicht aus der App
            var ticket = who.Tokens.GetValueOrDefault(AuthResults.Ticket) ?? "";
            var signed = await service.SignAsync(ticket, reason, meaning, requester, client);
            if (!signed.Ok)
            {
                var code = signed.Code ?? ErrorCodes.AuditServiceUnavailable;
                Log(AuditEventType.SignatureFailed, who.UserName, who.Details.GetValueOrDefault("method"), code, new() { ["code"] = code, ["reason"] = reason });
                return AuthOutcome.Fail(signed.Error ?? CoreText.Error(code), code);
            }
            // Für die Abonnenten der Schnittstelle wie ein eigener Eintrag
            Audited?.Invoke(new AuditEntry
            {
                V = AuditFormat.Signed, Seq = signed.Seq, Hash = signed.Hash, Time = DateTimeOffset.UtcNow, SessionUser = _session.UserName,
                Event = AuditEventType.SignatureGranted, Actor = who.UserName, Method = who.Details.GetValueOrDefault("method"),
                Detail = $"{reason}{(meaning is null ? "" : $" – {meaning}")}", Assurance = signed.Assurance,
            });
            return AuthResults.Signed(who, signed.Hash, signed.Seq, signed.Assurance);
        }
        if (who is not null)
        {
            var data = Data(who);
            data["reason"] = reason;
            if (meaning is not null) data["meaning"] = meaning;
            if (requester is not null) data["requester"] = requester;
            if (client is not null) data["clientProcess"] = client;
            var entry = Log(AuditEventType.SignatureGranted, who.UserName, who.Details.GetValueOrDefault("method"),
                $"{reason}{(meaning is null ? "" : $" – {meaning}")}", data);
            // Token des Anbieters bleiben erhalten (Antwort an die Anwendung), kommen aber nie ins Protokoll (Data oben).
            // Ohne Dienst: Format 2, nicht Part-11-fähig („local“)
            return AuthResults.Signed(who, entry.Hash, entry.Seq, AuditAssurance.Local);
        }
        Log(AuditEventType.SignatureFailed, detail: $"Cancelled: {reason}");
        return null;
    }

    /// <summary>Administrator-Bestätigung (Beenden, Einstellungen): Rolle „Einstellungs-Administrator“.</summary>
    /// <param name="why">Was freigegeben werden soll, in der Sprache der Oberfläche (Anzeige).</param>
    /// <param name="action">Dasselbe als feste englische Kennung fürs Protokoll.</param>
    public async Task<bool> RequireAdminAsync(string why, string action) =>
        await RequireRoleAsync(why, action, [VitrineRole.ConfigAdmin]) is not null;

    /// <summary>
    /// Bestätigung durch eine Person mit einer der Rollen (Roles.*). Mit Security.ReasonRequiredForAdminActions verlangt
    /// der Dialog eine Begründung; sie steht im Protokoll (Data „reason“). Liefert die angemeldete Person oder null.
    /// </summary>
    public async Task<AuthOutcome?> RequireRoleAsync(string why, string action, IReadOnlyCollection<VitrineRole> roles)
    {
        if (PromptActive) return null;
        var methods = (await _auth.GetActiveAsync(Cfg.Unlock.Methods)).Where(m => m.Id != "pin").ToList();
        if (methods.Count == 0 && _auth.Get("windows") is { } w) methods.Add(w);
        var req = new PromptRequest
        {
            Kind = PromptKind.Admin,
            Heading = Loc.T("Prompt_AdminHeading"),
            SubHeading = why,
            Reason = why,
            Initials = "••",
            Methods = methods,
            PreferredMethod = methods.FirstOrDefault(m => m.Id == "windows")?.Id,
            DefaultUser = "",
            TimeoutSeconds = 60,
            Verify = (p, r, i) => VerifyAsync(p, r, i, PromptKind.Admin, roles),
            ExternalFlowChanged = SetExternalFlow,
            ReasonRequired = Cfg.Security.ReasonRequiredForAdminActions,
            ReasonMinLength = Reasons.EffectiveMinLength(Cfg.Security.ReasonMinLength),
        };
        var who = await RunPrompt(req);
        if (who is not null)
        {
            var data = new Dictionary<string, string> { ["roles"] = string.Join(",", Roles.RolesOf(who)) };
            if (who.Details.TryGetValue(EmergencyAccess.ReasonDetail, out var reason) && reason.Length > 0) data["reason"] = reason;
            Log(AuditEventType.ConfigChanged, who.UserName, who.Details.GetValueOrDefault("method"), $"Administrator approval: {action}", data);
        }
        return who;
    }

    /// <summary>
    /// Anmeldung einer Person, die Sicherheitsschlüssel registrieren oder widerrufen will. Nur Verfahren, die der Dienst
    /// selbst prüft (Windows-Kennwort, Microsoft, Sicherheitsschlüssel); der Dienst prüft auch die Rolle
    /// (<see cref="IRoleCheck"/>) und gibt ein Ticket nur für Registrieren und Widerrufen. Ergebnis mit Ticket
    /// (<see cref="AuthResults.Ticket"/>) oder null (abgebrochen, Dienst nicht erreichbar).
    /// </summary>
    /// <param name="why">Was freigegeben werden soll, in der Sprache der Oberfläche (Anzeige).</param>
    public async Task<AuthOutcome?> RequireRegistrarAsync(string why)
    {
        if (PromptActive || AuditLink is not { Connected: true } link) return null;
        var ids = new List<string> { "windows" };
        ids.AddRange(Cfg.Unlock.Methods.Where(m => m is "entra" or FidoProtocol.MethodId));
        var methods = (await _auth.GetActiveAsync(ids)).Where(m => m.Id is "windows" or "entra" or FidoProtocol.MethodId).ToList();
        var req = new PromptRequest
        {
            Kind = PromptKind.Admin,
            Heading = Loc.T("Prompt_RegistrarHeading"),
            SubHeading = why,
            Reason = why,
            Initials = "••",
            Methods = methods,
            PreferredMethod = methods.FirstOrDefault(m => m.Id == "windows")?.Id,
            DefaultUser = "",
            TimeoutSeconds = 60,
            Verify = (p, r, _) => VerifyRegistrarAsync(p, r, link),
            ExternalFlowChanged = SetExternalFlow,
        };
        // Sicherheitsschlüssel für Registrar nur aus diesem Dialog (der Windows-Sicherheitsdialog zeigt den Zweck nicht)
        using (FidoGate?.Open(FidoPurpose.Registrar))
            return await RunPrompt(req);
    }

    /// <summary>Anmeldung der registrierenden Person: immer durch den Dienst geprüft (Zweck „registrar“).</summary>
    private async Task<(AuthOutcome?, string?, TimeSpan)> VerifyRegistrarAsync(IAuthProvider p, AuthRequest r, AuditLink link)
    {
        if (_throttle.Remaining(DateTimeOffset.UtcNow) is { } wait)
            return (null, CoreText.Error(ErrorCodes.PleaseWait, Math.Ceiling(wait.TotalSeconds)), wait);
        var request = new AuthRequest
        {
            UserName = r.UserName, Secret = r.Secret, OwnerWindow = r.OwnerWindow, Reason = r.Reason, SessionUser = _session.UserName,
            SessionUpn = _session.Upn, Purpose = AuthPurpose.Signature,
        };
        AuthOutcome outcome;
        using var limit = p.Input == AuthInputKind.External ? new CancellationTokenSource(LockShield.ExternalAuthTimeout) : null;
        try
        {
            switch (p)
            {
                case WindowsPasswordProvider windows:
                {
                    var target = windows.ResolveTarget(r.UserName);
                    outcome = string.IsNullOrEmpty(r.Secret) ? AuthOutcome.Fail(CoreText.Error(ErrorCodes.SecretMissing), ErrorCodes.SecretMissing)
                        : target.IsRefused ? AuthOutcome.Fail(CoreText.Error(ErrorCodes.UseUpnForEntra), ErrorCodes.UseUpnForEntra)
                        : await link.VerifyWindowsAsync(target, r.Secret, Core.Service.AuditBroker.PurposeRegistrar);
                    break;
                }
                case EntraIdProvider entra:
                {
                    var nonce = await link.ChallengeAsync();
                    if (nonce is null) { outcome = AuthOutcome.Fail(CoreText.Error(ErrorCodes.AuditServiceUnavailable), ErrorCodes.AuditServiceUnavailable); break; }
                    var local = await entra.AuthenticateAsync(request, limit?.Token ?? CancellationToken.None, nonce);
                    outcome = !local.Success ? local
                        : local.Tokens.TryGetValue(AuthResults.ProofIdToken, out var idToken)
                            ? await link.VerifyEntraAsync(idToken, Core.Service.AuditBroker.PurposeRegistrar)
                            : AuthOutcome.Fail(CoreText.Error(ErrorCodes.ServiceEntraTokenRejected, "no ID token"), ErrorCodes.ServiceEntraTokenRejected);
                    break;
                }
                case FidoProvider fido:
                    outcome = await fido.AuthenticateAsync(request, FidoPurpose.Registrar, limit?.Token ?? CancellationToken.None);
                    break;
                default:
                    outcome = AuthOutcome.Fail(CoreText.Error(ErrorCodes.ServiceMethodNotAllowed), ErrorCodes.ServiceMethodNotAllowed);
                    break;
            }
        }
        catch (OperationCanceledException) when (limit?.IsCancellationRequested == true)
        {
            outcome = AuthOutcome.Fail(CoreText.Error(ErrorCodes.SignInCancelled), ErrorCodes.SignInCancelled);
        }
        catch (Exception ex) { outcome = AuthOutcome.Fail(ErrorCodes.WithCode(ex.Message, ErrorCodes.SignInFailed), ErrorCodes.SignInFailed); }

        if (!outcome.Success)
            return Failed(PromptKind.Admin, p, r.UserName, ErrorCodes.WithCode(outcome.Error ?? CoreText.Error(ErrorCodes.SignInFailed), outcome.ErrorCode),
                outcome.ErrorCode ?? ErrorCodes.SignInFailed, AuditEventType.UnlockFailed, audited: outcome.Details.GetValueOrDefault("audited") == "true");
        return (AuthResults.Verified(outcome, p.Id), null, TimeSpan.Zero);
    }

    private async Task<AuthOutcome?> RunPrompt(PromptRequest req)
    {
        var prompt = _prompt = new UnlockWindow(req);
        nint hwnd = 0;
        try
        {
            prompt.Show();
            hwnd = new System.Windows.Interop.WindowInteropHelper(prompt).Handle;
            _blocker.AllowWindow(hwnd);
            if (Status == LockStatus.Locked) _blocker.Mode = BlockMode.Prompt;
            return await prompt.Result;
        }
        finally
        {
            _blocker.DisallowWindow(hwnd);
            // Nur den eigenen Dialog austragen – ein inzwischen geöffneter neuer Dialog bleibt
            if (ReferenceEquals(_prompt, prompt))
            {
                _prompt = null;
                _externalFlow = false;
            }
            if (Status == LockStatus.Locked && _prompt is null)
            {
                _blocker.Mode = BlockMode.Locked;
                ApplyShield();
                HoldShield();
            }
        }
    }

    private void SetExternalFlow(UnlockWindow sender, bool active)
    {
        // Meldung eines Dialogs, der schon geschlossen ist (z. B. von der Sperre während einer Signatur): ignorieren
        if (!ReferenceEquals(sender, _prompt)) return;
        _externalFlow = active;
        if (Status != LockStatus.Locked) return;
        _blocker.Mode = active ? BlockMode.ExternalAuth : BlockMode.Prompt;
        ApplyShield();
    }

    // ================= Prüfung =================

    /// <param name="input">Begründung und Notfall-Anmeldung aus dem Dialog.</param>
    /// <param name="roles">Bestätigung (Admin): eine dieser Rollen genügt.</param>
    /// <param name="owner">Anderer Besitzer für Fenster der Anmeldung (Dialog auf dem Sperr-Desktop, externe Anmeldung).</param>
    private async Task<(AuthOutcome?, string?, TimeSpan)> VerifyAsync(IAuthProvider p, AuthRequest r, PromptInput input, PromptKind kind,
        IReadOnlyCollection<VitrineRole>? roles = null, IReadOnlyList<string>? scopes = null, nint? owner = null)
    {
        // Wartezeit nach Fehlversuchen gilt über Dialoge hinweg; währenddessen wird gar nicht erst angemeldet
        if (_throttle.Remaining(DateTimeOffset.UtcNow) is { } wait)
            return (null, CoreText.Error(ErrorCodes.PleaseWait, Math.Ceiling(wait.TotalSeconds)), wait);

        // Begründung vor der Anmeldung prüfen: Fehlt nur sie, ist es kein Fehlversuch
        bool emergency = input.Emergency && kind == PromptKind.Unlock;
        if (input.Emergency && (kind != PromptKind.Unlock || p.Id != EmergencyAccess.Method))
            return (null, CoreText.Error(ErrorCodes.EmergencyNeedsWindowsPassword), TimeSpan.Zero);
        if (emergency && EmergencyAccess.CheckReason(input.Reason, Cfg.Unlock) is { Allowed: false } noReason)
            return (null, noReason.Reason, TimeSpan.Zero);
        if (kind == PromptKind.Admin && Cfg.Security.ReasonRequiredForAdminActions && !Reasons.IsSufficient(input.Reason, Cfg.Security.ReasonMinLength))
            return (null, CoreText.Error(ErrorCodes.ReasonTooShort, Reasons.EffectiveMinLength(Cfg.Security.ReasonMinLength)), TimeSpan.Zero);

        var request = new AuthRequest
        {
            UserName = r.UserName,
            Secret = r.Secret,
            OwnerWindow = owner ?? r.OwnerWindow,
            Reason = r.Reason,
            SessionUser = _session.UserName,
            SessionUpn = _session.Upn,
            Purpose = kind switch { PromptKind.Signature => AuthPurpose.Signature, PromptKind.Admin => AuthPurpose.Admin, _ => AuthPurpose.Unlock },
            Scopes = scopes ?? [],
        };

        AuthOutcome outcome;
        // Signatur, und der Dienst schreibt das Protokoll: Er prüft die Anmeldung selbst (#15)
        var service = kind == PromptKind.Signature ? SignatureService : null;
        if (service is not null && p is WindowsPasswordProvider windows)
        {
            // Windows-Kennwort: LogonUser im Dienst statt hier; Benutzer und Domäne bestimmt die App wie sonst auch
            var target = windows.ResolveTarget(r.UserName);
            outcome = string.IsNullOrEmpty(r.Secret) ? AuthOutcome.Fail(CoreText.Error(ErrorCodes.SecretMissing), ErrorCodes.SecretMissing)
                : target.IsRefused ? AuthOutcome.Fail(CoreText.Error(ErrorCodes.UseUpnForEntra), ErrorCodes.UseUpnForEntra)
                : await service.VerifyWindowsAsync(target, r.Secret);
        }
        else
        {
            // Externe Anmeldung (Hello, Microsoft) zeitlich begrenzt: Währenddessen sind die Abdeckungen nicht „immer oben“
            using var limit = p.Input == AuthInputKind.External ? new CancellationTokenSource(LockShield.ExternalAuthTimeout) : null;
            try
            {
                if (p is FidoProvider fido)
                {
                    // Sicherheitsschlüssel: Der Dienst prüft immer (auch beim Entsperren) und liefert Person und Gruppen;
                    // bei einer Signatur dazu das Ticket (Stufe „verified“)
                    outcome = await fido.AuthenticateAsync(request, kind == PromptKind.Signature ? FidoPurpose.Signature
                        : kind == PromptKind.Admin ? FidoPurpose.Admin : FidoPurpose.Unlock, limit?.Token ?? CancellationToken.None);
                }
                else if (service is not null && p is EntraIdProvider entra)
                {
                    // Microsoft für eine Signatur: Nonce vom Dienst holen und an Entra geben; ohne sie erkennt der Dienst das
                    // Token nicht an (bindet es an diese Anfrage, keine wiederverwendete Browser-Sitzung)
                    var nonce = await service.ChallengeAsync();
                    outcome = nonce is null
                        ? AuthOutcome.Fail(CoreText.Error(ErrorCodes.AuditServiceUnavailable), ErrorCodes.AuditServiceUnavailable)
                        : await entra.AuthenticateAsync(request, limit?.Token ?? CancellationToken.None, nonce);
                }
                else outcome = await p.AuthenticateAsync(request, limit?.Token ?? CancellationToken.None);
            }
            catch (OperationCanceledException) when (limit?.IsCancellationRequested == true)
            {
                outcome = AuthOutcome.Fail(CoreText.Error(ErrorCodes.SignInCancelled), ErrorCodes.SignInCancelled);
            }
            catch (Exception ex) { outcome = AuthOutcome.Fail(ErrorCodes.WithCode(ex.Message, ErrorCodes.SignInFailed), ErrorCodes.SignInFailed); }

            if (service is not null && outcome.Success && p is not FidoProvider)
            {
                // Microsoft: Der Dienst prüft das ID-Token. Hello und Plugins kann er nicht prüfen: von der App bezeugt („client“)
                var local = outcome;
                outcome = p.Id == "entra"
                    ? local.Tokens.TryGetValue(AuthResults.ProofIdToken, out var idToken)
                        ? await service.VerifyEntraAsync(idToken)
                        : AuthOutcome.Fail(CoreText.Error(ErrorCodes.ServiceEntraTokenRejected, "no ID token"), ErrorCodes.ServiceEntraTokenRejected)
                    : await service.AttestAsync(p.Id, local);
                // Token des Anbieters (Zugriffstoken für die Anwendung) behalten, dazu das Ticket des Dienstes
                if (outcome.Success)
                    outcome = outcome.WithTokens(AuthResults.WithoutInternal(local).Tokens.Concat(outcome.Tokens).ToDictionary(t => t.Key, t => t.Value));
            }
        }

        if (!outcome.Success)
            return Failed(kind, p, r.UserName, ErrorCodes.WithCode(outcome.Error ?? CoreText.Error(ErrorCodes.SignInFailed), outcome.ErrorCode),
                outcome.ErrorCode ?? ErrorCodes.SignInFailed, AuditEventType.UnlockFailed,
                audited: outcome.Details.GetValueOrDefault("audited") == "true");

        if (kind == PromptKind.Signature && UnlockPolicy.IsShared(outcome))
            return Failed(kind, p, outcome.UserName, CoreText.Error(ErrorCodes.PersonalSignatureRequired), ErrorCodes.PersonalSignatureRequired,
                AuditEventType.UnlockDenied);

        var rules = Cfg.Unlock;
        if (kind == PromptKind.Signature)
            rules = new UnlockSettings { Allowed = UnlockAllowed.AnyAuthenticated, AllowedDomains = Cfg.Unlock.AllowedDomains };

        // Microsoft: lokale Gruppen (Unlock.AllowedGroups, Rollen, Notfall-Gruppen) und Administratoren über die SIDs, die
        // Windows für Entra-Konten und -Gruppen bildet; Windows-Anmeldungen bringen sie schon im Token mit. Mitglieder je
        // Versuch neu gelesen.
        if (p.Id == "entra" && kind != PromptKind.Signature)
            outcome = EntraLocalGroups.Expand(outcome, RoleCheck.AllGroups(Cfg), WindowsAccounts.ToSid, new LocalGroupDirectory());

        var decision = emergency
            ? EmergencyAccess.Evaluate(outcome, p.Id, Cfg, input.Reason, WindowsAccounts.ToSid)
            : kind == PromptKind.Admin
                ? Roles.Decide(outcome, roles ?? [VitrineRole.ConfigAdmin])
                : UnlockPolicy.Evaluate(outcome, rules, resolveSid: WindowsAccounts.ToSid);
        if (!decision.Allowed)
        {
            var who = emergency ? outcome.WithDetails(new Dictionary<string, string>(outcome.Details) { [EmergencyAccess.Detail] = "true" }) : outcome;
            return Failed(kind, p, outcome.UserName, decision.Reason ?? CoreText.Error(ErrorCodes.NotAllowedToUnlock, outcome.UserName),
                decision.Code ?? ErrorCodes.NotAllowedToUnlock, AuditEventType.UnlockDenied, who);
        }

        if (kind == PromptKind.Unlock) _throttle.Reset();
        if (emergency) return (EmergencyAccess.Mark(outcome, input.Reason), null, TimeSpan.Zero);
        // Begründung einer Bestätigung fürs Protokoll mitgeben
        if (kind == PromptKind.Admin && Reasons.Normalize(input.Reason) is { } why)
            outcome = outcome.WithDetails(new Dictionary<string, string>(outcome.Details) { [EmergencyAccess.ReasonDetail] = why });
        // Mit den Token des Anbieters (vorher gingen sie hier verloren und kamen nie bei der Anwendung an)
        return (AuthResults.Verified(outcome, p.Id), null, TimeSpan.Zero);
    }

    /// <param name="audited">Der Dienst hat den Fehlversuch schon eingetragen (Prüfung einer Signatur durch den Dienst).</param>
    private (AuthOutcome?, string?, TimeSpan) Failed(PromptKind kind, IAuthProvider p, string? user, string error, string code,
        AuditEventType type, AuthOutcome? who = null, bool audited = false)
    {
        if (kind == PromptKind.Signature) type = AuditEventType.SignatureFailed;
        var delay = _throttle.RecordFailure(DateTimeOffset.UtcNow, Cfg.Security);
        var failed = _throttle.Failed;
        // Protokoll sprachunabhängig: Code statt übersetztem Text
        var data = who is null ? new Dictionary<string, string>() : Data(who);
        data["code"] = code;
        if (!audited) Log(type, user, p.Id, code, data);
        ScriptRunner.Run(Cfg.Scripts.OnFailedAttempt, "failed", Cfg.Scripts.TimeoutSeconds,
            new Dictionary<string, string?> { ["user"] = user, ["method"] = p.Id, ["attempt"] = failed.ToString(CultureInfo.InvariantCulture), ["code"] = code });

        var sec = Cfg.Security;
        if (kind == PromptKind.Unlock && FailurePolicy.TriggersAction(failed, sec))
        {
            Log(AuditEventType.FailureActionTriggered, detail: $"{failed} failed attempts -> {sec.FailureAction}");
            _ui.BeginInvoke(() => ExecuteFailureAction(sec.FailureAction), DispatcherPriority.Background);
        }

        var remaining = kind == PromptKind.Unlock ? FailurePolicy.Remaining(failed, sec) : null;
        if (FailurePolicy.ShouldWarn(remaining)) error += " " + Loc.F("Prompt_AttemptsLeft", remaining);
        return (null, error, delay);
    }

    private void ExecuteFailureAction(FailureAction a)
    {
        switch (a)
        {
            case FailureAction.LockWorkstation: FallbackLock("FailureAction LockWorkstation", always: false); break;
            // Erzwungen: Sonst fragte Windows bei Vitrine an, und Vitrine lehnt gesperrt ab (SessionEnd) – die Maßnahme liefe ins Leere
            case FailureAction.LogOff: Native.ExitWindowsEx(Native.EWX_LOGOFF | Native.EWX_FORCE, 0); break;
            case FailureAction.Shutdown: ShutdownHelper.Shutdown(); break;
        }
    }

    // ================= Protokoll =================

    public AuditEntry Log(AuditEventType type, string? actor = null, string? method = null, string? detail = null,
        Dictionary<string, string>? data = null)
    {
        // Schreibt der Dienst, kommt der Eintrag mit Nummer und Hash später (anderer Thread) – erst dann an die Abonnenten
        if (_audit.Forwarding && _audit.Enabled) return _audit.Write(type, actor, method, detail, data, committed: c => Audited?.Invoke(c));
        var e = _audit.Write(type, actor, method, detail, data);
        Audited?.Invoke(e);
        return e;
    }

    private static Dictionary<string, string> Data(AuthOutcome o)
    {
        var d = new Dictionary<string, string>();
        if (o.UserId is not null) d["userId"] = o.UserId;
        if (o.DisplayName is not null) d["displayName"] = o.DisplayName;
        if (o.TenantId is not null) d["tenant"] = o.TenantId;
        foreach (var (k, v) in o.Details) d.TryAdd(k, v);
        return d;
    }

    /// <summary>Beim Programmende: nie eine halbe Sperre zurücklassen.</summary>
    public void Dispose()
    {
        _guardTimer.Stop();
        // Nie auf dem Sperr-Desktop zurücklassen, wenn die App endet
        DisengageDesktop();
        _host?.Dispose();
        _desktop.Dispose();
        _blocker.Dispose();
        CursorHider.Show();
        _sas.Restore();
        // Auch mit Lock.ReplaceWinL: Ohne laufende Vitrine soll Win+L wieder Windows sperren
        _winLock.ReleaseAll();
        Native.SetThreadExecutionState(Native.ES_CONTINUOUS);
        if (Status == LockStatus.Unlocked) LockState.Set(false);
    }
}
