// SPDX-License-Identifier: MIT
using System.Globalization;
using System.Windows;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using Vitrine.Abstractions;
using Vitrine.Services.Interop;
using Vitrine.UI;
using Vitrine.UI.Theme;

namespace Vitrine.Services.Lock;

/// <summary>
/// Eigener UI-Thread auf Vitrines Sperr-Desktop (<c>Lock.Mode = Desktop</c>). Ein Thread kann nur Fenster auf dem Desktop
/// anlegen, an dem er hängt, und SetThreadDesktop geht nur, solange er noch keine Fenster hat – der UI-Thread der App hat
/// längst welche. Deshalb ein zweiter STA-Thread mit eigenem Dispatcher, der vor allem anderen SetThreadDesktop aufruft.
/// Er trägt die Abdeckungen des Sperr-Desktops (<see cref="DesktopCurtainWindow"/>) und den Entsperr-Dialog mit eigenen
/// Theme-Ressourcen. Aufrufe vom UI-Thread der App kommen nur über Invoke mit Zeitlimit oder BeginInvoke; dieser Thread
/// ruft die App nie synchron auf (keine gegenseitige Blockade).
/// </summary>
public sealed class LockDesktopHost : IDisposable
{
    private Thread? _thread;
    private Dispatcher? _dispatcher;
    private ResourceDictionary? _resources;
    private readonly List<DesktopCurtainWindow> _curtains = [];
    private UnlockWindow? _prompt;

    /// <summary>Eingabe auf dem Sperr-Desktop (auf diesem Thread ausgelöst).</summary>
    public event Action<ActivityKind>? Activity;

    /// <summary>Unbehandelter Fehler auf diesem Thread (auf diesem Thread ausgelöst); die Sperre fällt dann auf die Abdeckungen zurück.</summary>
    public event Action<Exception>? Failed;

    public bool Running => _dispatcher is { HasShutdownStarted: false };

    /// <summary>Thread starten und an den Desktop hängen (einmal; danach wiederverwendet).</summary>
    public bool Start(nint desktop)
    {
        if (Running) return true;
        if (desktop == 0) return false;
        var uiCulture = CultureInfo.CurrentUICulture;
        var culture = CultureInfo.CurrentCulture;
        using var ready = new ManualResetEventSlim();
        Dispatcher? started = null;
        _thread = new Thread(() =>
        {
            // Vor jedem Fenster, auch vor dem versteckten Fenster des Dispatchers
            if (!Native.SetThreadDesktop(desktop)) { ready.Set(); return; }
            Thread.CurrentThread.CurrentUICulture = uiCulture;
            Thread.CurrentThread.CurrentCulture = culture;
            var d = Dispatcher.CurrentDispatcher;
            d.UnhandledException += (_, e) =>
            {
                e.Handled = true;
                try { Failed?.Invoke(e.Exception); } catch { }
            };
            SynchronizationContext.SetSynchronizationContext(new DispatcherSynchronizationContext(d));
            started = d;
            ready.Set();
            Dispatcher.Run();
        })
        { IsBackground = true, Name = "Vitrine.LockDesktop" };
        _thread.SetApartmentState(ApartmentState.STA);
        _thread.Start();
        if (!ready.Wait(TimeSpan.FromSeconds(5)) || started is null) return false;
        _dispatcher = started;
        return true;
    }

    private bool Invoke(Action a)
    {
        if (!Running) return false;
        try
        {
            _dispatcher!.Invoke(a, DispatcherPriority.Send, CancellationToken.None, TimeSpan.FromSeconds(5));
            return true;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException) { return false; }
    }

    private void Post(Action a)
    {
        if (!Running) return;
        try { _dispatcher!.BeginInvoke(a); } catch { }
    }

    private ResourceDictionary Resources => _resources ??= ThemeManager.CreateThreadResources();

    /// <summary>Abdeckungen je Monitor aufbauen (ersetzt vorhandene). false = gescheitert.</summary>
    public bool ShowCurtains(IReadOnlyList<Native.MonitorInfo> monitors, string title, string hint, int dimPercent, Hotkey hotkey, bool previewExpected)
    {
        bool ok = false;
        var done = Invoke(() =>
        {
            CloseCurtains();
            foreach (var m in monitors)
            {
                var w = new DesktopCurtainWindow(m, title, hint, dimPercent, hotkey, previewExpected, Resources);
                w.Activity += kind => Activity?.Invoke(kind);
                w.Show();
                _curtains.Add(w);
            }
            (_curtains.FirstOrDefault(c => c.IsPrimary) ?? _curtains.FirstOrDefault())?.TakeForeground();
            ok = _curtains.Count > 0;
        });
        return done && ok;
    }

    /// <summary>Neue Bilder der Vorschau, je Monitor (Gerätename) eines; eingefroren, also über Threads hinweg nutzbar.</summary>
    public void SetPreview(IReadOnlyDictionary<string, BitmapSource> frames, string stamp) => Post(() =>
    {
        foreach (var c in _curtains) c.SetPreview(frames.GetValueOrDefault(c.Device), stamp);
    });

    public void Nudge() => Post(() => { foreach (var c in _curtains) c.Nudge(); });

    /// <summary>Dialog bzw. Abdeckung nach vorn (nach dem Zurückschalten).</summary>
    public void Focus() => Post(() =>
    {
        if (_prompt is { } p) p.ForceForeground();
        else (_curtains.FirstOrDefault(c => c.IsPrimary) ?? _curtains.FirstOrDefault())?.TakeForeground();
    });

    /// <summary>
    /// Entsperr-Dialog auf dem Sperr-Desktop. Wirft, wenn er sich nicht öffnen lässt (der Aufrufer zeigt ihn dann auf dem
    /// Windows-Desktop). Die Rückrufe von <paramref name="request"/> kommen auf diesem Thread.
    /// </summary>
    /// <param name="shown">Der Dialog ist offen, mit seinem Fensterhandle (auf diesem Thread).</param>
    public async Task<AuthOutcome?> RunPromptAsync(PromptRequest request, Action<nint>? shown = null)
    {
        if (!Running) throw new InvalidOperationException("lock desktop thread not running");
        var window = await _dispatcher!.InvokeAsync(() =>
        {
            var w = new UnlockWindow(request, Resources);
            w.Show();
            _prompt = w;
            shown?.Invoke(w.Handle);
            return w;
        });
        try { return await window.Result; }
        finally { Post(() => { if (ReferenceEquals(_prompt, window)) _prompt = null; }); }
    }

    /// <summary>Dialog und Abdeckungen schließen; der Thread bleibt für die nächste Sperre.</summary>
    public void HideAll() => Invoke(() =>
    {
        _prompt?.Close();
        _prompt = null;
        CloseCurtains();
    });

    private void CloseCurtains()
    {
        foreach (var c in _curtains)
        {
            try { c.CloseForGood(); } catch { }
        }
        _curtains.Clear();
    }

    public void Dispose()
    {
        HideAll();
        try { _dispatcher?.InvokeShutdown(); } catch { }
        _thread?.Join(TimeSpan.FromSeconds(2));
        _dispatcher = null;
    }
}
