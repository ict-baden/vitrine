// SPDX-License-Identifier: MIT
using System.Globalization;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Threading;
using Vitrine.Core.About;
using Vitrine.Core.Audit;
using Vitrine.Core.Auth;
using Vitrine.Abstractions;
using Vitrine.Core.Config;
using Vitrine.Core.Localization;
using Vitrine.Core.Lock;
using Vitrine.Platform;
using Vitrine.Services.Auth;
using Vitrine.Services.Integration;
using Vitrine.Services.Lock;
using Vitrine.Services.Supervisor;
using Vitrine.UI;
using Vitrine.UI.Theme;

namespace Vitrine;

public partial class App : Application
{
    private Mutex? _mutex;
    private ConfigStore _store = null!;
    private SessionInfo _session = null!;
    private AuditLog _audit = null!;
    private AuditLink? _auditLink;
    private AuthRegistry _auth = null!;
    private LockController _lock = null!;
    private TriggerService _triggers = null!;
    private PipeServer? _pipe;
    private TrayIcon? _tray;
    private SettingsWindow? _settings;
    private AboutWindow? _about;
    private bool _exiting;
    private DispatcherTimer? _serviceRetry;
    private readonly HashSet<string> _unlockSetupReported = new(StringComparer.Ordinal);
    private bool _cleanedUp;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        var args = e.Args.Select(a => a.Trim()).ToArray();
        string? Arg(string name) => Array.FindIndex(args, a => a.Equals(name, StringComparison.OrdinalIgnoreCase)) is var i and >= 0 && i + 1 < args.Length ? args[i + 1] : null;
        bool Has(string name) => args.Any(a => a.Equals(name, StringComparison.OrdinalIgnoreCase));

        // Sprache vor dem ersten Text: Richtlinie und Gerätekonfiguration kommen aus dem ConfigStore
        _store = new ConfigStore(ConfigFiles.Default, RegistryPolicySource.All(), new AdminOnlyFiles());
        _store.Load();
        ApplyLanguage();

        // ---------- Hilfsmodi ohne Oberfläche ----------
        // Dienst (--service) und Wächter (--watchdog) startet Program.Main ohne WPF (Issue #18)
        if (Has("--register-eventlog")) { RunAdminTask(EventLogSink.Register, Loc.F("Admin_EventSourceRegistered", AppPaths.EventSource)); return; }
        if (Has("--apply-config") && Arg("--apply-config") is { } src) { RunAdminTask(() => ApplyConfig(src, Arg("--sha256")), null); return; }
        if (Has("--export-audit-key")) { ExportAuditKey(Arg("--export-audit-key")); return; }
        if (Has("--rotate-audit-key")) { RunAdminTask(RotateAuditKey, null); return; }
        if (Has("--verify-log") && Arg("--verify-log") is { } log)
        {
            // Datei oder Ordner; Schlüssel aus audit-keys.json daneben oder --keys, Anker des Dienstes aus der Registry (#15)
            var result = AuditTools.Verify(log, Arg("--keys"));
            var (ok, msg) = (result.Ok, result.Message);
            // --quiet: nur Exitcode (geplante Aufgaben, Monitoring) – 0 vollständig, 2 verändert oder unlesbar
            if (!Has("--quiet")) MessageBox.Show(msg, ok ? Loc.T("VerifyLog_OkTitle") : Loc.T("VerifyLog_BrokenTitle"), MessageBoxButton.OK,
                ok ? MessageBoxImage.Information : MessageBoxImage.Warning);
            Shutdown(ok ? 0 : 2);
            return;
        }
        if (Has("--authorization-report"))
        {
            // Datei fehlt: wie jeder andere Fehler mit Meldung bzw. Exitcode 1
            AuthorizationReport(Arg("--authorization-report"), Has("--quiet"));
            return;
        }
        if (Has("--screenshots") && Arg("--screenshots") is { } shots) { _ = Screenshots.RunAsync(this, shots); return; }

        // ---------- Bildschirmschoner: /s starten, /c konfigurieren, /p Vorschau ----------
        var saver = args.FirstOrDefault(a => a.StartsWith("/", StringComparison.Ordinal))?.ToLowerInvariant();
        if (saver is not null && saver.StartsWith("/p", StringComparison.Ordinal)) { Shutdown(); return; }
        bool screensaver = saver is not null && saver.StartsWith("/s", StringComparison.Ordinal);
        bool wantSettings = Has("--settings") || (saver is not null && saver.StartsWith("/c", StringComparison.Ordinal));
        bool wantLock = Has("--lock") || screensaver;
        // Vom Dienst gestartet: läuft schon eine Vitrine in der Sitzung, meldet sie sich selbst beim Dienst
        bool agent = Has("--agent");
        // Aus dem Autostart (HKCU/HKLM Run): läuft schon eine Vitrine (z. B. vom Dienst gestartet), still beenden –
        // sonst öffnete jede Anmeldung die Einstellungen bzw. die Administrator-Abfrage
        bool autostart = Has("--autostart");

        _session = new SessionInfo();

        // ---------- Einzelinstanz pro Sitzung ----------
        _mutex = new Mutex(true, AppPaths.SingleInstanceMutex, out bool first);
        if (!first && (agent || autostart) && !wantLock) { Shutdown(); return; }
        if (!first)
        {
            // Übergabe an die laufende Instanz. Klappt sie nicht (Name belegt, fremder Server), wenigstens Windows sperren,
            // wenn gesperrt werden sollte – nie still nichts tun.
            // Über WorkstationLocker: Ein von der laufenden Instanz gesetztes DisableLockWorkstation verhinderte sonst die Sperre
            if (!PipeServer.TrySend(_session.SessionId, wantLock ? "lock" : "settings") && wantLock)
            {
                var (outcome, detail) = WorkstationLocker.Lock(WorkstationLocker.CreatePolicy(), "second instance without hand-over");
                if (outcome != FallbackLockOutcome.Locked) WriteAudit(AuditEventType.Error, detail);
            }
            Shutdown();
            return;
        }

        var sas = new SasRestrictions(new RegistryUserPolicyStore());
        // Nach einem Absturz: Reste aufräumen (auch den eigenen Win+L-Wert; der LockController setzt ihn bei Bedarf neu)
        sas.Restore();
        try { WorkstationLocker.CreatePolicy().Revert(); } catch { }
        CursorHider.RestoreSystemCursors();
        LockState.Set(false);
        // Nach einem Absturz auf dem eigenen Sperr-Desktop (Lock.Mode = Desktop): zurück auf den Windows-Desktop (VIT-0455)
        string? stranded = null;
        try { stranded = DesktopSwitcher.LeaveStrandedLockDesktop(); } catch { }

        var cfg = _store.Current;

        ThemeManager.Initialize(cfg.Appearance.Accent);
        _store.Changed += c => Dispatcher.BeginInvoke(() => ThemeManager.SetAccent(c.Appearance.Accent));

        _audit = new AuditLog(cfg.Audit, _session.UserName, new EventLogSink());
        // Schreibt der Dienst das Protokoll (#15), gehen alle Einträge an ihn – auch wenn er gerade nicht erreichbar ist
        // (dann warten sie im Speicher). Sonst schreibt die App selbst, nicht Part-11-fähig, und sagt das im Protokoll.
        if (AuditLink.ServiceExpected())
        {
            _auditLink = new AuditLink();
            _audit.UseForwarder(_auditLink);
            _auditLink.Delivery += ReportAuditDelivery;
            _auditLink.Start();
        }
        else _audit.Write(AuditEventType.AuditLocalMode, detail: "Written by the session app without the service – not Part 11 capable");
        if (stranded is not null) _audit.Write(AuditEventType.Error, detail: stranded);
        _auth = new AuthRegistry(_session, _store, _auditLink);
        _lock = new LockController(_store, _session, _auth, _audit, Dispatcher) { ExitOnUnlock = screensaver, AuditLink = _auditLink };
        // Überwachung vor allem, was sperren kann (Auslöser, Schnittstelle), damit sie jede Sperre mitbekommt: der Dienst,
        // sonst der Wächterprozess. Fällt der Dienst weg, übernimmt der Wächter; startet er später, meldet sich die App.
        // Der gewünschte Zustand gilt schon vor dem Verbinden: Nach einem Absturz startet der Dienst die App gesperrt neu,
        // und ihre erste Meldung darf dann nicht „entsperrt“ sein.
        ServiceLink.Initialize(Dispatcher);
        ServiceLink.Signal(wantLock || cfg.Lock.LockOnStartup);
        var link = ServiceLink.TryConnect();
        if (link != ServiceLinkResult.Connected) Watchdog.Start(cfg.Security);
        ReportServiceLink(link);
        ServiceLink.Lost += () => Dispatcher.BeginInvoke(() =>
        {
            Watchdog.Start(_store.Current.Security);
            Watchdog.Signal(_lock.Status == LockStatus.Locked);
        });
        // Erneut verbinden ohne den UI-Thread zu blockieren (Connect wartet bis zu 500 ms auf die Pipe)
        _serviceRetry = new DispatcherTimer(TimeSpan.FromSeconds(30), DispatcherPriority.Background, (_, _) =>
        {
            if (ServiceLink.Connected || _serviceConnecting) return;
            _serviceConnecting = true;
            Task.Run(ServiceLink.TryConnect).ContinueWith(t => Dispatcher.BeginInvoke(() =>
            {
                _serviceConnecting = false;
                if (t.IsCompletedSuccessfully) ReportServiceLink(t.Result);
            }), TaskScheduler.Default);
        }, Dispatcher);
        _serviceRetry.Start();
        _triggers = new TriggerService(_lock, _store);
        _pipe = new PipeServer(_lock, _store, Dispatcher, _session.SessionId, () => _ = OpenSettingsAsync());

        if (!screensaver)
        {
            _tray = CreateTray();
            _lock.StatusChanged += _ => UpdateTrayTooltip();
        }

        _audit.Write(AuditEventType.AppStarted, detail: $"Version {AppInfo.Version}{(AppInfo.Commit is null ? "" : $" ({AppInfo.Commit})")}, language {CultureInfo.CurrentUICulture.Name}");
        ReportUnlockSetup(cfg);
        _store.Changed += c => Dispatcher.BeginInvoke(() => ReportUnlockSetup(c));
        // Profilordner früherer Microsoft-Anmeldungen, die nicht gelöscht werden konnten (Absturz, gesperrte Dateien)
        _ = Task.Run(() => EphemeralProfiles.CleanUp(AppPaths.WebViewProfilesDir, DateTime.UtcNow, EphemeralProfiles.StaleAfter));

        DispatcherUnhandledException += OnUnhandled;
        SessionEnding += (_, e) =>
        {
            _sessionEndQueried = true;
            // Gesperrt: WM_QUERYENDSESSION ist nur eine Anfrage. Ohne Cancel beendete WPF die App sofort und gäbe die Sperre
            // frei – bricht der Benutzer das Ende danach ab (Strg+Alt+Entf → Neu starten → ein Programm blockiert →
            // Abbrechen), wäre der Arbeitsplatz offen. Also ablehnen; endet die Sitzung doch (erzwungen oder „Trotzdem neu
            // starten“), räumt OnSessionEndMessage bei WM_ENDSESSION auf (SessionEnd in Vitrine.Core).
            if (SessionEnd.OnQuery(_lock.Status == LockStatus.Locked) == SessionEndAction.KeepLock)
            {
                e.Cancel = true;
                if (_sessionEndWindow is { } w && !_sessionEndBlocked)
                    _sessionEndBlocked = Services.Interop.Native.ShutdownBlockReasonCreate(w.Handle, Loc.T("Lock_ShutdownBlockReason"));
                _lock.Log(AuditEventType.SessionEndRefused, detail: e.ReasonSessionEnding.ToString());
                return;
            }
            // Abmelden/Herunterfahren angekündigt: dem Dienst sagen, dass das Ende der App wohl erwartet ist. Nur eine
            // Ankündigung – wird die Abmeldung abgebrochen (oder kam die Nachricht von einem anderen Prozess), gilt das
            // Ende nach SessionSupervisor.LogoffWindow doch als Verlust (gesperrt: Trennen und gesperrter Neustart).
            ServiceLink.Logoff();
            Cleanup();
        };
        // Unsichtbares Fenster nur für WM_ENDSESSION (und als Fenster für den Grund in der Liste „Diese Apps verhindern …“)
        _sessionEndWindow = new HwndSource(new HwndSourceParameters("Vitrine.SessionEnd") { WindowStyle = 0, Width = 0, Height = 0 });
        _sessionEndWindow.AddHook(OnSessionEndMessage);
        _lock.StatusChanged += s =>
        {
            if (s != LockStatus.Unlocked || !_sessionEndBlocked || _sessionEndWindow is null) return;
            Services.Interop.Native.ShutdownBlockReasonDestroy(_sessionEndWindow.Handle);
            _sessionEndBlocked = false;
        };

        if (wantLock || cfg.Lock.LockOnStartup) _lock.Lock(screensaver ? LockTriggers.Screensaver : LockTriggers.Startup);
        if (wantSettings) _ = OpenSettingsAsync();
        else if (!wantLock && !agent && !autostart && !cfg.Lock.LockOnStartup && !Autostart.IsEnabled)
            _tray?.ShowBalloon(Loc.T("Tray_RunningTitle"), Loc.F("Tray_RunningText", Hotkey.Display(cfg.Lock.Hotkey)));
    }

    // ================= Sprache =================

    /// <summary>
    /// Sprache nach richtlinien/13: VITRINE_LANGUAGE → Richtlinie → Wahl des Benutzers (Info-Fenster) → Gerätekonfiguration
    /// → Windows → Englisch.
    /// </summary>
    private void ApplyLanguage()
    {
        var policy = _store.IsManaged("Appearance.Language") ? _store.Current.Appearance.Language : null;
        UiLanguage.Apply(policy, UserPreferences.Load().Language, _store.Editable.Appearance.Language);
        // Texte in Vorlagen (Controls.xaml) über DynamicResource
        Resources["Text_Off"] = Loc.T("Common_Off");
        Resources["Text_On"] = Loc.T("Common_On");
        Resources["Text_Managed"] = Loc.T("Common_ManagedByPolicy");
    }

    /// <summary>Sprache des Benutzers wechseln: speichern, anwenden, offene Fenster neu öffnen.</summary>
    public void ChangeLanguage(string code)
    {
        var prefs = UserPreferences.Load();
        prefs.Language = UiLanguage.Normalize(code);
        prefs.Save();
        ApplyLanguage();
        RefreshLanguage();
    }

    /// <summary>Alles mit Text neu aufbauen (nach einem Sprachwechsel oder neu geladener Richtlinie).</summary>
    private void RefreshLanguage()
    {
        _tray?.Dispose();
        _tray = CreateTray();
        UpdateTrayTooltip();
        if (_settings is { } s) { s.Close(); _ = OpenSettingsAsync(); }
        if (_about is { } a) { a.Close(); OpenAbout(); }
    }

    public bool LanguageIsManaged => _store.IsManaged("Appearance.Language");

    // ================= Aktionen =================

    private TrayIcon CreateTray() =>
        new(CreateFlyout, () => _lock.Lock(LockTriggers.Tray), () => _ = OpenSettingsAsync(), OpenAbout, () => _ = ExitAsync());

    private void UpdateTrayTooltip() =>
        _tray?.SetTooltip(_lock.Status == LockStatus.Locked ? Loc.T("Tray_TooltipLocked") : Loc.T("Tray_TooltipReady"));

    private TrayFlyout CreateFlyout()
    {
        var locked = _lock.Status == LockStatus.Locked;
        var cfg = _store.Current;
        string title = locked ? Loc.T("Status_Locked") : Loc.T("Status_Ready");
        string text = locked
            ? Loc.F("Tray_LockedSince", _lock.LockedSince?.ToString("t", CultureInfo.CurrentCulture))
            : Loc.F("Tray_HotkeyHint", Hotkey.Display(cfg.Lock.Hotkey)) +
              (cfg.Lock.IdleMinutes > 0 ? " " + Loc.F("Tray_IdleHint", cfg.Lock.IdleMinutes) : "");
        if (_triggers.HotkeyError is { } err) { title = Loc.T("Tray_HotkeyTaken"); text = err; }

        var f = new TrayFlyout($"{_session.DisplayName} · {_session.MachineName}", title, text, _triggers.HotkeyError is null, ResponsibleText());
        f.LockRequested += () => _lock.Lock(LockTriggers.Tray);
        f.LockBlankRequested += () => _lock.Lock(LockTriggers.TrayBlank, LockVisual.Blank);
        f.SettingsRequested += () => _ = OpenSettingsAsync();
        f.LogRequested += () => _ = OpenSettingsAsync("audit");
        f.AboutRequested += OpenAbout;
        f.ExitRequested += () => _ = ExitAsync();
        return f;
    }

    /// <summary>„Verantwortlich: Name seit Uhrzeit“ für Infobereich und Übersicht; null, wenn niemand bekannt ist.</summary>
    public string? ResponsibleText() => _lock?.Responsibility.Current is { } p
        ? Loc.F("Responsible_Since", p.Name, p.Since.ToLocalTime().ToString(p.Since.ToLocalTime().Date == DateTime.Today ? "t" : "g", CultureInfo.CurrentCulture))
        : null;

    /// <summary>Info-Fenster: für jeden, ohne Adminrechte (richtlinien/07).</summary>
    public void OpenAbout()
    {
        if (_lock?.Status == LockStatus.Locked) return;
        if (_about is not null) { _about.Activate(); return; }
        _about = new AboutWindow(this, _store);
        _about.Closed += (_, _) => _about = null;
        _about.Show();
        _about.Activate();
    }

    private async Task OpenSettingsAsync(string? page = null)
    {
        if (_lock.Status == LockStatus.Locked) return;
        if (_settings is not null)
        {
            _settings.Activate();
            if (page is not null) _settings.ShowPage(page);
            return;
        }

        // Rollen (Roles.*): Einstellungs-Administratoren öffnen alles, Prüfer nur das Protokoll (ohne Ändern). Der Benutzer
        // der Sitzung braucht keinen Dialog, wenn er Einstellungs-Administrator ist (wie früher als Administrator).
        var sec = _store.Current.Security;
        var access = SettingsAccess.Full;
        AuthOutcome? who = null;
        if (sec.SettingsAdminOnly)
        {
            var session = _session.AsOutcome();
            if (_lock.Roles.IsConfigAdmin(session)) who = session;
            else
            {
                who = await _lock.RequireRoleAsync(Loc.T("Admin_OpenSettings"), "open settings", [VitrineRole.ConfigAdmin, VitrineRole.Auditor]);
                if (who is null) return;
                if (!_lock.Roles.IsConfigAdmin(who)) access = SettingsAccess.AuditOnly;
            }
        }
        if (_lock.Status == LockStatus.Locked) return; // während des Dialogs gesperrt (Zeitplan, Schnittstelle)
        if (_settings is not null) { _settings.Activate(); return; }

        _settings = new SettingsWindow(_store, _session, _lock, _auth, _audit, _triggers, OpenAbout, ReloadAll, access, who);
        if (access == SettingsAccess.AuditOnly) page = "audit";
        _settings.Closed += (_, _) => _settings = null;
        if (page is not null) _settings.ShowPage(page);
        _settings.Show();
        _settings.Activate();
    }

    /// <summary>Nach „Richtlinien neu laden“: Sprache kann sich geändert haben.</summary>
    private void ReloadAll()
    {
        var before = CultureInfo.CurrentUICulture.Name;
        ApplyLanguage();
        if (CultureInfo.CurrentUICulture.Name != before) RefreshLanguage();
    }

    private async Task ExitAsync()
    {
        if (_lock.Status == LockStatus.Locked) return;
        if (_store.Current.Security.ExitRequiresAdmin && !await _lock.RequireAdminAsync(Loc.T("Admin_Exit"), "exit Vitrine"))
            return;
        if (_lock.Status == LockStatus.Locked) return; // nie aus einer Sperre heraus beenden
        _exiting = true;
        ServiceLink.Exit();
        Cleanup();
        Shutdown();
    }

    private bool _serviceConnecting;
    private ServiceLinkResult? _serviceLinkReported;

    /// <summary>
    /// Ergebnis der Verbindung zum Dienst: Fehler, die nicht von selbst vergehen (Zugriff verweigert, fremder Server),
    /// einmal protokollieren. Läuft die App unter dem Dienst, ist ein Autostart-Eintrag pro Benutzer überflüssig – er
    /// würde bei jeder Anmeldung eine zweite Instanz starten – und wird entfernt.
    /// </summary>
    private void ReportServiceLink(ServiceLinkResult result)
    {
        if (result == ServiceLinkResult.Connected)
        {
            if (Autostart.IsEnabled) Autostart.Set(false);
        }
        else if (result is ServiceLinkResult.Denied or ServiceLinkResult.WrongServer && _serviceLinkReported != result)
        {
            _audit?.Write(AuditEventType.Error, detail: $"Service pipe: {result}");
        }
        _serviceLinkReported = result;
    }

    /// <summary>
    /// Einstellungen, mit denen am Sperrbildschirm nicht wie eingestellt entsperrt wird (nur Microsoft ohne Broker, Regeln
    /// ohne passende Windows-Anmeldung): je einmal ins Protokoll und damit als Warnung ins Ereignisprotokoll – auch auf
    /// Geräten, auf denen niemand die Einstellungen öffnet (GPO, Intune). Die Übersicht der Einstellungen zeigt sie auch.
    /// </summary>
    private void ReportUnlockSetup(VitrineConfig cfg)
    {
        // Dazu Microsoft: Broker eingeschaltet (merkt sich Konten, VIT-0191), WebView2-Laufzeit fehlt (VIT-0190)
        // Sicherheitsschlüssel: Windows-Sicherheitsdialog nicht in Security.AuthUiProcesses (VIT-0423)
        foreach (var w in LockScreenMethods.Warnings(cfg.Unlock, EntraIdProvider.OnLockScreen(cfg.Entra)).Concat(EntraIdProvider.Warnings(cfg.Entra))
                     .Concat(Core.Fido.FidoWarnings.For(cfg)))
            if (_unlockSetupReported.Add(w.AuditDetail)) _audit?.Write(AuditEventType.Error, detail: w.AuditDetail);
        // Niemand darf die Einstellungen ändern (VIT-0430)
        foreach (var code in RoleCheck.Warnings(cfg))
        {
            var detail = $"{code} Security.LocalAdministratorsArePrivileged is off and Roles.ConfigAdmins is empty";
            if (_unlockSetupReported.Add(detail)) _audit?.Write(AuditEventType.Error, detail: detail);
        }
    }

    private HwndSource? _sessionEndWindow;
    private bool _sessionEndBlocked;
    private bool _sessionEndQueried;

    /// <summary>
    /// WM_ENDSESSION: Endet die Sitzung wirklich (SessionEnd.CleanUpOnEnd), jetzt aufräumen und beenden – auch nach einem
    /// abgelehnten WM_QUERYENDSESSION während der Sperre. Abgebrochen, vom Restart Manager (ENDSESSION_CLOSEAPP) oder von
    /// einem anderen Programm geschickt: Die Sperre bleibt, wie sie ist.
    /// </summary>
    private nint OnSessionEndMessage(nint hwnd, int msg, nint wParam, nint lParam, ref bool handled)
    {
        if (msg != Services.Interop.Native.WM_ENDSESSION) return 0;
        bool ending = wParam != 0;
        bool closeApp = (lParam & Services.Interop.Native.ENDSESSION_CLOSEAPP) != 0;
        bool shuttingDown = Services.Interop.Native.GetSystemMetrics(Services.Interop.Native.SM_SHUTTINGDOWN) != 0;
        if (SessionEnd.CleanUpOnEnd(ending, _sessionEndQueried, closeApp, shuttingDown))
        {
            ServiceLink.Logoff();
            Cleanup();
            // Nie mit aufgeräumter (also offener) Sperre weiterlaufen
            Environment.Exit(0);
        }
        if (!ending) _sessionEndQueried = false; // abgebrochen: nächster Durchgang beginnt neu
        return 0;
    }

    private void OnUnhandled(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        // Niemals wegen eines Fehlers abstürzen – schon gar nicht während der Sperre.
        try { _audit?.Write(AuditEventType.Error, detail: $"{ErrorCodes.Unexpected} {e.Exception}"); } catch { }
        e.Handled = true;
    }

    /// <summary>
    /// Einträge kommen nicht beim Dienst an (VIT-0330): ins Ereignisprotokoll – auch ohne Audit.EventLog, sonst bliebe es
    /// unbemerkt – und als Fehler-Eintrag in die Warteschlange, damit das signierte Protokoll die Lücke später zeigt.
    /// Die Einstellungen zeigen es unter „Protokoll“ (<see cref="AuditLink.Problem"/>).
    /// </summary>
    private void ReportAuditDelivery(AuditDeliveryReport report)
    {
        if (report.Recovered) return;
        var entry = new AuditEntry
        {
            Time = DateTimeOffset.UtcNow, SessionUser = _session?.UserName ?? "", Event = AuditEventType.Error, Detail = report.LogText,
        };
        try { new EventLogSink().Write(entry); } catch { /* Ereignisprotokoll ist ein Zusatz */ }
        try { _audit?.Write(AuditEventType.Error, detail: report.LogText, data: new() { ["code"] = ErrorCodes.AuditNotDelivered }); } catch { }
    }

    /// <summary>Eintrag ins Protokoll, bevor (oder ohne dass) die App ihr eigenes Protokoll geöffnet hat (zweite Instanz).</summary>
    private void WriteAudit(AuditEventType type, string detail) =>
        FallbackAudit.Write(_store.Current.Audit, (_session ?? new SessionInfo()).UserName, type, detail);

    private void Cleanup()
    {
        // Nach SessionEnding ruft OnExit noch einmal auf: nur einmal protokollieren und aufräumen
        if (_audit is null || _cleanedUp) return;
        _cleanedUp = true;
        // Abmelden: niemand mehr verantwortlich (nur im Speicher; die nächste Sitzung beginnt mit ihrem Benutzer)
        _lock?.Responsibility.Reset();
        try { _audit.Write(AuditEventType.AppStopped, detail: _exiting ? "Exit" : "Windows sign-out"); } catch { }
        if (_auditLink is { } link)
        {
            // Dem Dienst alles übergeben; was er nicht mehr bekommt, lieber ungeschützt pro Benutzer als verloren
            link.Flush(TimeSpan.FromSeconds(2));
            _audit.WriteUnsent(link.TakeUnsent());
            link.Dispose();
        }
        // Netzkopie des Protokolls kurz nachschreiben lassen (läuft im Hintergrund)
        AuditLog.FlushNetworkCopies(TimeSpan.FromSeconds(2));
        _pipe?.Dispose();
        _triggers?.Dispose();
        _lock?.Dispose();
        _tray?.Dispose();
        _tray = null;
    }

    protected override void OnExit(ExitEventArgs e)
    {
        if (!_exiting) Cleanup();
        try { _mutex?.ReleaseMutex(); } catch { }
        base.OnExit(e);
    }

    // ================= Admin-Hilfsmodi =================

    /// <summary>
    /// --export-audit-key [datei]: öffentliche Schlüssel und Anker des Protokolls für einen Prüfer (ohne Geheimnis, ohne
    /// Adminrechte). Ohne Datei nur der Fingerabdruck. Exitcode 0, 1 ohne Schlüssel (kein Dienst) oder bei Fehler.
    /// </summary>
    private void ExportAuditKey(string? file)
    {
        var json = AuditTools.ExportKeys();
        if (json is null)
        {
            MessageBox.Show(CoreText.Error(ErrorCodes.LogNoPublicKey, Environment.MachineName), AppInfo.Name, MessageBoxButton.OK, MessageBoxImage.Warning);
            Shutdown(1);
            return;
        }
        var fingerprints = string.Join("\n", AuditState.PublicKeys().Select(k => k.Fingerprint));
        try
        {
            if (file is not null) File.WriteAllText(file, json);
            MessageBox.Show(file is null ? Loc.F("AuditKey_Fingerprint", fingerprints) : Loc.F("AuditKey_Exported", file, fingerprints),
                AppInfo.Name, MessageBoxButton.OK, MessageBoxImage.Information);
            Shutdown(0);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            MessageBox.Show(Loc.Error(ErrorCodes.AdminTaskFailed, ex.Message), AppInfo.Name, MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown(1);
        }
    }

    /// <summary>
    /// --authorization-report &lt;datei&gt; [--quiet]: Berechtigungsbericht als HTML (und CSV daneben) bzw. nur CSV bei
    /// .csv. Mit Security.SettingsAdminOnly nur für Einstellungs-Administratoren und Prüfer (Konto, unter dem der Aufruf
    /// läuft). Exitcode 0 geschrieben, 1 Fehler oder keine Berechtigung.
    /// </summary>
    private void AuthorizationReport(string? file, bool quiet)
    {
        void Fail(string message)
        {
            if (!quiet) MessageBox.Show(message, AppInfo.Name, MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown(1);
        }
        if (string.IsNullOrWhiteSpace(file) || file.StartsWith("--", StringComparison.Ordinal)) { Fail(Loc.Error(ErrorCodes.ReportFailed, "--authorization-report <file>")); return; }
        var session = new SessionInfo();
        var roles = new RoleCheck(() => _store.Current, WindowsAccounts.ToSid);
        if (_store.Current.Security.SettingsAdminOnly && !roles.IsAuditor(session.AsOutcome()))
        {
            Fail(CoreText.Error(ErrorCodes.RoleRequired, $"{RoleCheck.Name(VitrineRole.ConfigAdmin)}, {RoleCheck.Name(VitrineRole.Auditor)}"));
            return;
        }
        try
        {
            var written = AuthorizationReports.Write(file, _store, session.UserName);
            if (!quiet) MessageBox.Show(Loc.F("Report_Written", string.Join("\n", written)), AppInfo.Name, MessageBoxButton.OK, MessageBoxImage.Information);
            Shutdown(0);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            Fail(Loc.Error(ErrorCodes.ReportFailed, ex.Message));
        }
    }

    /// <summary>--rotate-audit-key (als Administrator): Der Dienst legt einen neuen Schlüssel an und trägt den Wechsel ein.</summary>
    private static void RotateAuditKey()
    {
        using var link = new AuditLink();
        link.Start();
        var until = DateTime.UtcNow + TimeSpan.FromSeconds(10);
        while (!link.Connected && DateTime.UtcNow < until) Thread.Sleep(100);
        var answer = link.Connected ? link.RotateAsync().GetAwaiter().GetResult() : null;
        if (answer is null) throw new InvalidOperationException(CoreText.Error(ErrorCodes.AuditServiceUnavailable));
        if (answer["ok"]?.GetValue<bool>() != true)
            throw new InvalidOperationException(ErrorCodes.WithCode(answer["error"]?.GetValue<string>() ?? "", answer["code"]?.GetValue<string>()));
        MessageBox.Show(Loc.F("AuditKey_Rotated", answer["fingerprint"]?.GetValue<string>()), AppInfo.Name, MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void RunAdminTask(Action action, string? success)
    {
        try
        {
            action();
            if (success is not null) MessageBox.Show(success, AppInfo.Name, MessageBoxButton.OK, MessageBoxImage.Information);
            Shutdown(0);
        }
        catch (Exception ex)
        {
            // Meldungen mit eigenem Code (z. B. ungültige Konfiguration) unverändert zeigen
            var message = ex.Message.Contains("VIT-", StringComparison.Ordinal) ? ex.Message : Loc.Error(ErrorCodes.AdminTaskFailed, ex.Message);
            MessageBox.Show(message, AppInfo.Name, MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown(1);
        }
    }

    /// <summary>
    /// Übernimmt eine Konfigurationsdatei nach %ProgramData%\ICT-Baden\Vitrine (läuft mit Adminrechten). Die Einstellungen
    /// geben die SHA-256 des Inhalts mit: Die Datei liegt im Temp-Ordner des Benutzers und könnte sonst nach der
    /// UAC-Bestätigung ausgetauscht werden. Ohne passende Prüfsumme wird nichts geschrieben.
    /// </summary>
    private void ApplyConfig(string source, string? sha256)
    {
        var bytes = File.ReadAllBytes(source);
        var actual = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes));
        if (sha256 is null || !string.Equals(actual, sha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException(Loc.Error(ErrorCodes.ApplyConfigRefused));
        var json = System.Text.Encoding.UTF8.GetString(bytes);
        try { _ = ConfigStore.Validate(json); }
        catch (Exception ex) when (ex is System.Text.Json.JsonException or InvalidDataException or InvalidOperationException or NotSupportedException)
        {
            throw new InvalidDataException(Loc.Error(ErrorCodes.ApplyConfigInvalid, ex.Message), ex);
        }
        _store.WriteMachineFile(json);
    }
}
