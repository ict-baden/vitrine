// SPDX-License-Identifier: MIT
using System.Globalization;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using Vitrine.Abstractions;
using Vitrine.Core.About;
using Vitrine.Core.Audit;
using Vitrine.Core.Config;
using Vitrine.Core.Localization;
using Vitrine.Core.Lock;
using Vitrine.Services.Auth;
using Vitrine.Services.Interop;
using Vitrine.Services.Lock;
using Vitrine.UI.Theme;

namespace Vitrine.UI;

/// <summary>
/// <c>Vitrine.exe --screenshots &lt;Ordner&gt; [--theme light|dark]</c> (Sprache über VITRINE_LANGUAGE): zeichnet alle
/// Fenster der echten App mit Beispieldaten als PNG (richtlinien/08, Vorbild Lupe/Riegel). Englisch nach
/// <c>&lt;Ordner&gt;</c> (für docs/assets/screenshots), jede weitere Sprache nach <c>&lt;Ordner&gt;/&lt;Sprache&gt;</c> zur
/// Prüfung von Übersetzung und Layout. Sperrt nie, installiert keine Hooks, liest und schreibt keine echte Konfiguration.
/// </summary>
internal static class Screenshots
{
    private const string DemoClientId = "11111111-2222-3333-4444-555555555555";
    private static bool _mica;

    public static async Task RunAsync(App app, string folder)
    {
        int exit = 0;
        Directory.CreateDirectory(folder);
        var errorFile = Path.Combine(folder, "error.txt");
        void Report(object? e) { try { File.AppendAllText(errorFile, $"{DateTime.UtcNow:O} {e}\n\n"); } catch { } }
        AppDomain.CurrentDomain.UnhandledException += (_, e) => Report(e.ExceptionObject);
        app.DispatcherUnhandledException += (_, e) => { Report(e.Exception); e.Handled = true; exit = 1; };
        TaskScheduler.UnobservedTaskException += (_, e) => Report(e.Exception);
        try
        {
            // Eine Sprache und ein Farbschema pro Prozess, so wie die App startet: Sprache aus VITRINE_LANGUAGE (App.ApplyLanguage),
            // Schema aus --theme light|dark. Ein Wechsel im laufenden Prozess hinterließ gemischte Farben und Texte.
            var args = Environment.GetCommandLineArgs();
            var i = Array.FindIndex(args, a => a.Equals("--theme", StringComparison.OrdinalIgnoreCase));
            bool dark = i >= 0 && i + 1 < args.Length && args[i + 1].Equals("dark", StringComparison.OrdinalIgnoreCase);
            var language = UiLanguage.Normalize(CultureInfo.CurrentUICulture.Name);

            // --mica: Fenster sichtbar auf dem Bildschirm mit echtem Mica-Hintergrund zeigen und vom Bildschirm abfotografieren
            // (zur Prüfung des echten Startpfads; RenderTargetBitmap sieht Mica nicht). Nicht für docs/assets gedacht.
            _mica = args.Any(a => a.Equals("--mica", StringComparison.OrdinalIgnoreCase));
            ThemeManager.NoMica = !_mica;
            if (!_mica) AppIcon.MinScale = 2; // RenderTargetBitmap mit 192 dpi
            ThemeManager.Initialize("", dark);
            var temp = Directory.CreateTempSubdirectory("vitrine-shots-").FullName;
            var dir = language == UiLanguage.Fallback ? folder : Path.Combine(folder, language);
            Directory.CreateDirectory(dir);
            await RenderAllAsync(dir, dark ? "dark" : "light", temp);
            try { Directory.Delete(temp, recursive: true); } catch { }
        }
        catch (Exception ex)
        {
            Report(ex);
            exit = 1;
        }
        app.Shutdown(exit);
    }

    private static async Task RenderAllAsync(string dir, string theme, string temp)
    {
        // Beispieldaten: eigene Konfiguration im Temp-Ordner, keine Richtlinien, Beispielsitzung ohne echte Namen
        var files = new ConfigFiles(Path.Combine(temp, "config.json"), Path.Combine(temp, "none.json"),
            Path.Combine(temp, "user.json"), Path.Combine(temp, "none-user.json"));
        var store = new ConfigStore(files, []);
        var demo = new VitrineConfig();
        demo.Entra.ClientId = DemoClientId;
        demo.Entra.TenantId = "contoso.onmicrosoft.com";
        demo.Lock.IdleMinutes = 10;
        demo.Lock.Schedule = [new ScheduleEntry { Time = "18:00", Days = [DayOfWeek.Monday, DayOfWeek.Tuesday, DayOfWeek.Wednesday, DayOfWeek.Thursday, DayOfWeek.Friday] }];
        demo.Audit.Directory = Path.Combine(temp, "logs");
        demo.Audit.EventLog = false;
        demo.Unlock.AllowedGroups = ["LAB\\QA-Supervisors"];
        store.Save(demo);

        var session = SessionInfo.Demo(Loc.T("Shots_DemoUser"));
        var audit = new AuditLog(store.Current.Audit, session.UserName);
        if (audit.CurrentFile() is null) WriteDemoLog(audit);

        var auth = new AuthRegistry(session, store);
        using var lockController = new LockController(store, session, auth, audit, Dispatcher.CurrentDispatcher);
        using var triggers = new TriggerService(lockController, store, active: false); // nie sperren

        // ---- Einstellungen, jede Seite ----
        // Pfade wie auf einem Gerät mit Standardinstallation, nicht die des Build-Rechners (Temp-Ordner, D:\a\…)
        var programDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Vitrine") + Path.DirectorySeparatorChar;
        SettingsWindow.DisplayPath = p => p
            .Replace(temp, AppPaths.MachineDir, StringComparison.OrdinalIgnoreCase)
            .Replace(AppContext.BaseDirectory, programDir, StringComparison.OrdinalIgnoreCase);
        var settings = new SettingsWindow(store, session, lockController, auth, audit, triggers, () => { }, () => { });
        settings.ShowDefaultAuditFolder();
        await ShowOffscreenAsync(settings);
        foreach (var page in SettingsWindow.Pages)
        {
            settings.ShowPage(page);
            await IdleAsync(250);
            Save(settings, Path.Combine(dir, $"settings-{page}-{theme}.png"), Background());
        }
        settings.Close();

        // ---- Info ----
        var about = new AboutWindow((App)Application.Current, store);
        await ShowOffscreenAsync(about);
        Save(about, Path.Combine(dir, $"about-{theme}.png"), Background());
        about.Close();

        // ---- Infobereich ----
        var flyout = new TrayFlyout($"{session.DisplayName} · {session.MachineName}", Loc.T("Status_Ready"),
            Loc.F("Tray_HotkeyHint", Hotkey.Display(store.Current.Lock.Hotkey)) + " " + Loc.F("Tray_IdleHint", 10), true);
        await ShowOffscreenAsync(flyout);
        Save(flyout, Path.Combine(dir, $"tray-{theme}.png"), null);
        flyout.Close();

        // ---- Entsperr-Dialog, Fehler, Signatur ----
        // Wie die echte App: Am Sperrbildschirm bietet sie Microsoft mit dem eigenen Anmeldefenster oder dem Broker an,
        // ohne WebView2-Laufzeit und ohne Broker nicht (EntraIdProvider.OnLockScreen); Signaturen gehen immer mit Microsoft
        var signMethods = new List<IAuthProvider> { auth.Get("entra")!, auth.Get("windows")!, auth.Get("hello")! };
        var unlockMethods = signMethods.Where(m => m.Id != "entra" || EntraIdProvider.OnLockScreen(store.Current.Entra)).ToList();
        foreach (var (name, kind, method, error) in new (string, PromptKind, string, string?)[]
                 {
                     ("unlock", PromptKind.Unlock, "windows", (string?)null),
                     ("unlock-error", PromptKind.Unlock, "windows", CoreText.Error(ErrorCodes.WrongCredentials) + " " + Loc.F("Prompt_AttemptsLeft", 2)),
                     ("sign", PromptKind.Signature, "windows", null),
                     ("sign-entra", PromptKind.Signature, "entra", null),
                 })
        {
            var methods = kind == PromptKind.Unlock ? unlockMethods : signMethods;
            var prompt = new UnlockWindow(new PromptRequest
            {
                Kind = kind,
                Heading = session.DisplayName,
                SubHeading = kind == PromptKind.Signature ? Loc.F("Prompt_RequestedBy", "LIMS")
                    : Loc.F("Prompt_LockedSince", new DateTime(2026, 10, 19, 10, 42, 0).ToString("t", CultureInfo.CurrentCulture), session.MachineName),
                Reason = Loc.T("Prompt_ReasonUnlock"),
                Initials = session.Initials,
                SignReason = Loc.T("Shots_SignReason"),
                SignMeaning = Loc.T("Shots_SignMeaning"),
                Methods = methods,
                PreferredMethod = method,
                DefaultUser = session.Upn,
                TimeoutSeconds = 3600,
                Verify = (_, _, _) => Task.FromResult<(AuthOutcome?, string?, TimeSpan)>((null, null, TimeSpan.Zero)),
            });
            await ShowOffscreenAsync(prompt);
            if (error is not null) prompt.ShowErrorForScreenshot(error);
            await IdleAsync(400);
            Save(prompt, Path.Combine(dir, $"{name}-{theme}.png"), null);
            prompt.Close();
        }

        // ---- Reiter der Verfahren mit 2–5 Verfahren (nur zur Prüfung des Layouts, Unterordner „layout“, nicht für docs/assets) ----
        var layoutDir = Path.Combine(dir, "layout");
        Directory.CreateDirectory(layoutDir);
        string[][] layouts =
        [
            ["entra", "windows"],
            ["entra", "windows", "windowslogon"],
            ["entra", "windows", "hello", "windowslogon"],
            ["entra", "windows", "hello", "windowslogon", "pin"],
        ];
        foreach (var ids in layouts)
        {
            var prompt = new UnlockWindow(new PromptRequest
            {
                Kind = PromptKind.Unlock,
                Heading = session.DisplayName,
                SubHeading = Loc.F("Prompt_LockedSince", new DateTime(2026, 10, 19, 10, 42, 0).ToString("t", CultureInfo.CurrentCulture), session.MachineName),
                Reason = Loc.T("Prompt_ReasonUnlock"),
                Initials = session.Initials,
                Methods = ids.Select(id => auth.Get(id)!).ToList(),
                PreferredMethod = "windows",
                DefaultUser = session.Upn,
                TimeoutSeconds = 3600,
                Verify = (_, _, _) => Task.FromResult<(AuthOutcome?, string?, TimeSpan)>((null, null, TimeSpan.Zero)),
            });
            await ShowOffscreenAsync(prompt);
            await IdleAsync(300);
            Save(prompt, Path.Combine(layoutDir, $"unlock-{ids.Length}-{theme}.png"), null);
            prompt.Close();
        }

        // ---- Sperre: Hinweisleiste über dem Desktop, verdeckter Bildschirm ----
        var monitor = new Native.MonitorInfo(new Native.RECT { Left = 0, Top = 0, Right = 1280, Bottom = 720 },
            new Native.RECT { Left = 0, Top = 0, Right = 1280, Bottom = 680 }, true, "DEMO");
        MaskRegion[] masks = [MaskRegion.Parse("1:4,8,26,40")!, MaskRegion.Parse("1:62,8,34,18")!];
        foreach (var (name, visual, mask) in new[] { ("lock", LockVisual.Transparent, false), ("blank", LockVisual.Blank, false), ("lock-masked", LockVisual.Transparent, true) })
        {
            var look = new AppearanceSettings { Visual = visual, DimPercent = 8, Masks = mask ? [.. masks] : [] };
            var since = new DateTime(2026, 10, 19, 10, 42, 0).ToString("t", CultureInfo.CurrentCulture);
            var overlay = new OverlayWindow(monitor, 1, look, Loc.F("Overlay_Title", session.DisplayName),
                Loc.F("Overlay_Hint", since, Loc.T("Overlay_HowAny")));
            await ShowOffscreenAsync(overlay, place: false);
            await IdleAsync(500);
            Save(overlay, Path.Combine(dir, $"{name}-{theme}.png"), DesktopBrush());
            overlay.Close();
        }
    }

    private static void WriteDemoLog(AuditLog audit)
    {
        audit.Write(AuditEventType.AppStarted, detail: "Version 0.1.0");
        audit.Write(AuditEventType.Locked, detail: $"Trigger: {LockTriggers.Hotkey}");
        audit.Write(AuditEventType.UnlockFailed, "LAB\\operator", "windows", ErrorCodes.WrongCredentials);
        audit.Write(AuditEventType.Unlocked, "LAB\\operator", "windows", "Locked for 00:12:31");
        audit.Write(AuditEventType.SignatureGranted, "operator@contoso.com", "entra", "Release batch 4711 – Approved");
    }

    private static async Task ShowOffscreenAsync(Window w, bool place = true)
    {
        w.ShowActivated = false;
        w.ShowInTaskbar = false;
        if (place && _mica && w is IThemedWindow)
        {
            // Sichtbar und vorn, sonst zeichnet DWM kein Mica (inaktive Fenster bekommen die Ersatzfarbe)
            w.WindowStartupLocation = WindowStartupLocation.Manual;
            w.Left = 40;
            w.Top = 40;
            w.Topmost = true;
            w.ShowActivated = true;
        }
        else if (place)
        {
            w.WindowStartupLocation = WindowStartupLocation.Manual;
            w.Left = -32000;
            w.Top = -32000;
        }
        w.Show();
        await IdleAsync(700); // Einblend-Animationen abwarten
    }

    private static async Task IdleAsync(int ms)
    {
        await Task.Delay(ms);
        await Dispatcher.Yield(DispatcherPriority.ApplicationIdle);
    }

    private static Brush Background() =>
        (Application.Current.TryFindResource("ApplicationBackgroundBrush") as Brush) ?? Brushes.White;

    /// <summary>Neutraler Hintergrund statt eines echten Desktops (keine fremden Programme auf den Bildern).</summary>
    private static Brush DesktopBrush() => new LinearGradientBrush(Color.FromRgb(0x2D, 0x5B, 0xD7), Color.FromRgb(0x7A, 0x3F, 0xD1), 45);

    /// <summary>Client-Bereich des Fensters (erstes Kind im visuellen Baum), samt Rändern des Inhalts.</summary>
    private static void Save(Window w, string file, Brush? background)
    {
        if (_mica && w is IThemedWindow) { SaveFromScreen(w, file); return; }
        Save((FrameworkElement)VisualTreeHelper.GetChild(w, 0), file, background);
    }

    /// <summary>Fenster so, wie DWM es zusammensetzt (mit Mica), vom Bildschirm kopieren.</summary>
    private static void SaveFromScreen(Window w, string file)
    {
        var hwnd = new System.Windows.Interop.WindowInteropHelper(w).Handle;
        w.Activate();
        if (Native.DwmGetWindowAttribute(hwnd, Native.DWMWA_EXTENDED_FRAME_BOUNDS, out Native.RECT r, System.Runtime.InteropServices.Marshal.SizeOf<Native.RECT>()) != 0)
            Native.GetWindowRect(hwnd, out r);
        int width = r.Right - r.Left, height = r.Bottom - r.Top;
        if (width < 1 || height < 1) throw new InvalidOperationException($"{file}: empty window");
        using var bmp = new System.Drawing.Bitmap(width, height);
        using (var g = System.Drawing.Graphics.FromImage(bmp))
            g.CopyFromScreen(r.Left, r.Top, 0, 0, new System.Drawing.Size(width, height));
        bmp.Save(file, System.Drawing.Imaging.ImageFormat.Png);
    }

    private static void Save(FrameworkElement root, string file, Brush? background)
    {
        root.UpdateLayout();
        double w = Math.Ceiling(root.ActualWidth), h = Math.Ceiling(root.ActualHeight);
        if (w < 1 || h < 1) throw new InvalidOperationException($"{file}: empty layout");
        var visual = new DrawingVisual();
        using (var dc = visual.RenderOpen())
        {
            if (background is not null) dc.DrawRectangle(background, null, new Rect(0, 0, w, h));
            dc.DrawRectangle(new VisualBrush(root) { Stretch = Stretch.None, AlignmentX = AlignmentX.Left, AlignmentY = AlignmentY.Top },
                null, new Rect(0, 0, w, h));
        }
        var bitmap = new RenderTargetBitmap((int)(w * 2), (int)(h * 2), 192, 192, PixelFormats.Pbgra32);
        bitmap.Render(visual);
        var png = new PngBitmapEncoder();
        png.Frames.Add(BitmapFrame.Create(bitmap));
        using var fs = File.Create(file);
        png.Save(fs);
    }
}
