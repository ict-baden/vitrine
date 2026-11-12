// SPDX-License-Identifier: MIT
using System.Windows.Interop;
using System.Windows.Threading;
using Vitrine.Core.Config;
using Vitrine.Core.Localization;
using Vitrine.Core.Lock;
using Vitrine.Services.Interop;

namespace Vitrine.Services.Lock;

/// <summary>Löst die Sperre aus: Tastenkürzel, Win+L (<c>Lock.ReplaceWinL</c>), Leerlauf und Zeitplan.</summary>
public sealed class TriggerService : IDisposable
{
    private const int HotkeyId = 0x5649; // "VI"
    private readonly LockController _lock;
    private readonly ConfigStore _store;
    private readonly DispatcherTimer _timer;
    private readonly HwndSource _msgWindow;
    private readonly HashSet<string> _firedToday = new();
    private DateOnly _today = DateOnly.FromDateTime(DateTime.Now);
    private bool _hotkeyRegistered;
    private readonly WinLWatcher _winL = new();

    public string? HotkeyError { get; private set; }

    /// <param name="active">false nur für die Screenshots: kein Tastenkürzel, kein Leerlauf, kein Zeitplan – nie sperren.</param>
    public TriggerService(LockController lockController, ConfigStore store, bool active = true)
    {
        _lock = lockController;
        _store = store;

        // Unsichtbares Nachrichtenfenster für RegisterHotKey
        _msgWindow = new HwndSource(new HwndSourceParameters("Vitrine.Hotkeys") { Width = 0, Height = 0, WindowStyle = 0 });
        _msgWindow.AddHook(WndProc);
        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        if (!active) return;
        RegisterHotkey(store.Current.Lock.Hotkey);
        var ui = Dispatcher.CurrentDispatcher;
        store.Changed += cfg => ui.BeginInvoke(() => RegisterHotkey(cfg.Lock.Hotkey));

        // Win+L: Hook nur, solange die Einstellung an ist (DisableLockWorkstation setzt der LockController)
        _winL.Pressed += () => ui.BeginInvoke(() =>
        {
            if (_lock.Status == LockStatus.Unlocked && _store.Current.Lock.ReplaceWinL) _lock.Lock(LockTriggers.WinL);
        });
        WatchWinL(store.Current.Lock.ReplaceWinL);
        store.Changed += cfg => ui.BeginInvoke(() => WatchWinL(cfg.Lock.ReplaceWinL));

        _timer.Tick += (_, _) => Tick();
        _timer.Start();
    }

    private void RegisterHotkey(string? text)
    {
        if (_hotkeyRegistered) { Native.UnregisterHotKey(_msgWindow.Handle, HotkeyId); _hotkeyRegistered = false; }
        HotkeyError = null;
        var hk = Hotkey.Parse(text);
        if (hk.IsEmpty) return;
        _hotkeyRegistered = Native.RegisterHotKey(_msgWindow.Handle, HotkeyId, hk.Modifiers | Native.MOD_NOREPEAT, hk.VirtualKey);
        if (!_hotkeyRegistered) HotkeyError = UI.Loc.Error(ErrorCodes.HotkeyInUse, Hotkey.Display(text));
    }

    private void WatchWinL(bool on)
    {
        if (on) _winL.Start();
        else _winL.Stop();
    }

    private nint WndProc(nint hwnd, int msg, nint wParam, nint lParam, ref bool handled)
    {
        if (msg == Native.WM_HOTKEY && wParam == HotkeyId)
        {
            handled = true;
            if (_lock.Status == LockStatus.Unlocked) _lock.Lock(LockTriggers.Hotkey);
        }
        return 0;
    }

    private void Tick()
    {
        if (_lock.Status == LockStatus.Locked) return;
        var cfg = _store.Current.Lock;

        // Leerlauf
        if (cfg.IdleMinutes > 0 && Native.GetIdleTime() >= TimeSpan.FromMinutes(cfg.IdleMinutes))
        {
            _lock.Lock(LockTriggers.Idle(cfg.IdleMinutes));
            return;
        }

        // Zeitplan
        var now = DateTime.Now;
        var today = DateOnly.FromDateTime(now);
        if (today != _today) { _today = today; _firedToday.Clear(); }
        if (Schedule.Due(now, cfg.Schedule, _firedToday) is { } due)
            _lock.Lock(LockTriggers.Scheduled(due.Time));
    }

    public void Dispose()
    {
        _timer.Stop();
        _winL.Dispose();
        if (_hotkeyRegistered) Native.UnregisterHotKey(_msgWindow.Handle, HotkeyId);
        _msgWindow.Dispose();
    }
}
