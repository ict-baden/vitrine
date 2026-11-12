// SPDX-License-Identifier: MIT
using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using Vitrine.Services.Interop;

namespace Vitrine.Services.Lock;

public enum BlockMode
{
    /// <summary>Keine Sperre.</summary>
    Off,
    /// <summary>Alles blockieren.</summary>
    Locked,
    /// <summary>Nur Eingaben in ausdrücklich freigegebene Fenster (Entsperr-Dialog) zulassen.</summary>
    Prompt,
    /// <summary>Zusätzlich Fenster der Anmelde-Prozesse zulassen (Entra/WAM, Windows Hello).</summary>
    ExternalAuth,
}

public enum ActivityKind { Key, Mouse, Hotkey }

/// <summary>
/// Blockiert Tastatur und Maus systemweit über Low-Level-Hooks. Die Hooks laufen auf einem
/// eigenen Thread mit eigener Nachrichtenschleife: Hängt die Oberfläche, entfernt Windows die
/// Hooks sonst nach Ablauf von LowLevelHooksTimeout stillschweigend – und die Sperre wäre weg.
/// Strg+Alt+Entf lässt sich technisch nicht abfangen (siehe SasRestrictions).
/// </summary>
public sealed class InputBlocker : IDisposable
{
    private const uint WM_APP_REHOOK = 0x8001, WM_APP_HOOK = 0x8002, WM_APP_UNHOOK = 0x8003;
    private const uint VK_TAB = 0x09, VK_ESCAPE = 0x1B, VK_F4 = 0x73, VK_LWIN = 0x5B, VK_RWIN = 0x5C, VK_APPS = 0x5D;
    private const uint VK_SHIFT = 0x10, VK_CONTROL = 0x11, VK_MENU = 0x12;
    private const uint VK_LSHIFT = 0xA0, VK_RSHIFT = 0xA1, VK_LCONTROL = 0xA2, VK_RCONTROL = 0xA3, VK_LMENU = 0xA4, VK_RMENU = 0xA5;
    private const uint WM_KEYUP = 0x0101, WM_SYSKEYUP = 0x0105;

    private readonly ConcurrentDictionary<uint, string?> _procPaths = new();
    private readonly ConcurrentDictionary<uint, uint> _parents = new();
    private readonly Core.Lock.TrustedRoots _roots = Core.Lock.TrustedRoots.FromEnvironment();
    private volatile uint _webViewBrowserPid;
    private readonly ConcurrentDictionary<nint, byte> _interactive = new();
    private readonly Native.LowLevelProc _kbProc;
    private readonly Native.LowLevelProc _msProc;
    private Thread? _thread;
    private uint _threadId;
    private nint _kbHook, _msHook;
    private System.Threading.Timer? _rehookTimer;
    private ManualResetEventSlim? _hookDone;
    // Nur UI-Thread: Hooks sind gesetzt (bzw. angefordert)
    private bool _hooked;
    private volatile BlockMode _mode = BlockMode.Off;
    private volatile HashSet<string> _allowedProcs = new(StringComparer.OrdinalIgnoreCase);

    // Sichtbare Fenster, die es schon gab, als die externe Anmeldung begann. Sie bleiben gesperrt, auch wenn ihr Prozess erlaubt ist:
    // msedgewebview2.exe gehört auch zu Teams, Outlook, Widgets … – nur das neu geöffnete Anmeldefenster darf Eingaben bekommen.
    private volatile HashSet<nint> _preExisting = new();


    // Modifikatoren selbst mitzählen – GetAsyncKeyState sieht verschluckte Tasten nicht.
    private volatile bool _ctrl, _alt, _shift, _win;
    private uint _hotMods, _hotVk;

    public InputBlocker()
    {
        _kbProc = KeyboardProc;
        _msProc = MouseProc;
    }

    /// <summary>Wird auf dem Hook-Thread ausgelöst, wenn während der Sperre Eingaben verworfen werden.</summary>
    public event Action<ActivityKind>? Activity;

    public bool BlockMouseMove { get; set; } = true;

    public BlockMode Mode
    {
        get => _mode;
        set
        {
            // Beim Wechsel in die externe Anmeldung festhalten, welche Fenster schon offen sind
            if (value == BlockMode.ExternalAuth && _mode != BlockMode.ExternalAuth) _preExisting = Native.VisibleTopLevelWindows();
            _mode = value;
            _procPaths.Clear();
            _parents.Clear();
            // Nach Strg+Alt+Entf kommen keine KeyUp-Ereignisse an – Zustand zurücksetzen
            _ctrl = _alt = _shift = _win = false;
            if (value != BlockMode.Off) EnsureHooked();
            else ReleaseHooks();
        }
    }

    public void SetAllowedProcesses(IEnumerable<string> names) =>
        _allowedProcs = new HashSet<string>(names, StringComparer.OrdinalIgnoreCase);

    public void SetHotkey(uint mods, uint vk) { _hotMods = mods; _hotVk = vk; }

    /// <summary>
    /// Gibt genau dieses Fenster für Eingaben frei. Bewusst per Handle und nicht per Prozess:
    /// Die Overlays gehören auch zu Vitrine, sind aber durchklickbar – ein Klick „auf“ sie
    /// würde in Wahrheit in der Anwendung darunter landen.
    /// </summary>
    public void AllowWindow(nint hwnd) { if (hwnd != 0) _interactive[hwnd] = 0; }

    public void DisallowWindow(nint hwnd) => _interactive.TryRemove(hwnd, out _);

    /// <summary>
    /// Browser-Prozess (msedgewebview2.exe) des Anmeldefensters von Vitrine, 0 = keiner. Nur er und seine Kindprozesse
    /// (Renderer, GPU) fallen unter die Besitzer-Regel – nicht die WebView2-Prozesse von Teams, Outlook usw.
    /// </summary>
    public void SetWebViewBrowser(uint pid)
    {
        _webViewBrowserPid = pid;
        _parents.Clear();
    }

    /// <summary>
    /// Hooks setzen, bevor die Sperre weitergeht: beim ersten Mal mit eigenem Thread, danach über dessen Nachrichtenschleife.
    /// Wartet wie bisher höchstens 2 s auf den Hook-Thread.
    /// </summary>
    private void EnsureHooked()
    {
        if (_hooked) return;
        _hooked = true;
        if (_thread is null)
        {
            using var ready = new ManualResetEventSlim();
            _thread = new Thread(() =>
            {
                _threadId = Native.GetCurrentThreadId();
                Install();
                bool wanted = true;
                ready.Set();
                while (Native.GetMessage(out var msg, 0, 0, 0) > 0)
                {
                    switch (msg.message)
                    {
                        // Ein verspätetes Neu-Setzen nach dem Entsperren darf die Hooks nicht zurückbringen
                        case WM_APP_REHOOK when wanted: Rehook(); break;
                        case WM_APP_HOOK:
                            wanted = true;
                            if (_kbHook != 0 || _msHook != 0) Rehook(); else Install();
                            try { Volatile.Read(ref _hookDone)?.Set(); }
                            catch (ObjectDisposedException) { } // Warten schon abgelaufen
                            break;
                        // Inzwischen wieder gesperrt (UNHOOK und HOOK kurz nacheinander): Hooks bleiben
                        case WM_APP_UNHOOK when _mode == BlockMode.Off:
                            wanted = false;
                            Uninstall();
                            break;
                    }
                }
                Uninstall();
            })
            { IsBackground = true, Name = "Vitrine.InputBlocker", Priority = ThreadPriority.Highest };
            _thread.Start();
            ready.Wait(2000);

            // Hooks regelmäßig neu setzen – falls Windows sie entfernt hat, sind sie danach wieder da.
            _rehookTimer = new System.Threading.Timer(_ =>
            {
                if (_mode != BlockMode.Off) Native.PostThreadMessage(_threadId, WM_APP_REHOOK, 0, 0);
            }, null, 5000, 5000);
            return;
        }

        using var done = new ManualResetEventSlim();
        Volatile.Write(ref _hookDone, done);
        if (Native.PostThreadMessage(_threadId, WM_APP_HOOK, 0, 0)) done.Wait(2000);
        Volatile.Write(ref _hookDone, null);
        _rehookTimer?.Change(5000, 5000);
    }

    /// <summary>
    /// Entsperrt: Hooks entfernen und das Neu-Setzen anhalten. Vorher blieben sie nach der ersten Sperre für immer gesetzt
    /// – jede Taste und jede Mausbewegung im ganzen System lief dann auch entsperrt durch Vitrine (Issue #18).
    /// </summary>
    private void ReleaseHooks()
    {
        if (!_hooked) return;
        _hooked = false;
        _rehookTimer?.Change(Timeout.Infinite, Timeout.Infinite);
        if (_threadId != 0) Native.PostThreadMessage(_threadId, WM_APP_UNHOOK, 0, 0);
    }

    private void Install()
    {
        var hMod = Native.GetModuleHandle(null);
        _kbHook = Native.SetWindowsHookEx(Native.WH_KEYBOARD_LL, _kbProc, hMod, 0);
        _msHook = Native.SetWindowsHookEx(Native.WH_MOUSE_LL, _msProc, hMod, 0);
    }

    /// <summary>
    /// Erst die neuen Hooks setzen, dann die alten entfernen – so gibt es keinen Moment ohne Hook. Scheitert das Setzen,
    /// bleibt der alte Hook (falls Windows ihn nicht schon entfernt hat).
    /// </summary>
    private void Rehook()
    {
        var hMod = Native.GetModuleHandle(null);
        var oldKb = _kbHook;
        var oldMs = _msHook;
        var kb = Native.SetWindowsHookEx(Native.WH_KEYBOARD_LL, _kbProc, hMod, 0);
        var ms = Native.SetWindowsHookEx(Native.WH_MOUSE_LL, _msProc, hMod, 0);
        if (kb != 0) { _kbHook = kb; if (oldKb != 0) Native.UnhookWindowsHookEx(oldKb); }
        if (ms != 0) { _msHook = ms; if (oldMs != 0) Native.UnhookWindowsHookEx(oldMs); }
    }

    private void Uninstall()
    {
        if (_kbHook != 0) { Native.UnhookWindowsHookEx(_kbHook); _kbHook = 0; }
        if (_msHook != 0) { Native.UnhookWindowsHookEx(_msHook); _msHook = 0; }
    }

    private nint KeyboardProc(int nCode, nint wParam, nint lParam)
    {
        if (nCode != Native.HC_ACTION) return Native.CallNextHookEx(_kbHook, nCode, wParam, lParam);

        var k = Marshal.PtrToStructure<Native.KBDLLHOOKSTRUCT>(lParam);
        int msg = (int)wParam;
        bool down = msg is Native.WM_KEYDOWN or Native.WM_SYSKEYDOWN;
        TrackModifier(k.vkCode, down);

        var mode = _mode;
        if (mode == BlockMode.Off) return Native.CallNextHookEx(_kbHook, nCode, wParam, lParam);

        // Hotkey während der Sperre erkennen (RegisterHotKey greift nicht, weil wir die Taste verschlucken)
        if (down && _hotVk != 0 && k.vkCode == _hotVk && ModsMatch())
        {
            Raise(ActivityKind.Hotkey);
            return 1;
        }

        // Systemkürzel immer blockieren: Win, Alt+Tab, Alt+Esc, Strg+Esc, Alt+F4, Kontextmenü-Taste
        if (k.vkCode is VK_LWIN or VK_RWIN or VK_APPS) return 1;
        if (_alt && k.vkCode is VK_TAB or VK_ESCAPE or VK_F4) return 1;
        if (_ctrl && k.vkCode == VK_ESCAPE) return 1;

        switch (mode)
        {
            case BlockMode.Locked:
                if (down && !IsModifier(k.vkCode)) Raise(ActivityKind.Key);
                return 1;

            case BlockMode.Prompt:
            case BlockMode.ExternalAuth:
                if (IsAllowedWindow(Native.GetForegroundWindow(), mode))
                    return Native.CallNextHookEx(_kbHook, nCode, wParam, lParam);
                if (down && !IsModifier(k.vkCode)) Raise(ActivityKind.Key);
                return 1;
        }
        return 1;
    }

    private nint MouseProc(int nCode, nint wParam, nint lParam)
    {
        if (nCode != Native.HC_ACTION) return Native.CallNextHookEx(_msHook, nCode, wParam, lParam);

        var mode = _mode;
        if (mode == BlockMode.Off) return Native.CallNextHookEx(_msHook, nCode, wParam, lParam);

        int msg = (int)wParam;
        bool isMove = msg == Native.WM_MOUSEMOVE;
        bool isClick = msg is Native.WM_LBUTTONDOWN or Native.WM_RBUTTONDOWN or Native.WM_MBUTTONDOWN or Native.WM_XBUTTONDOWN;

        if (mode == BlockMode.Locked)
        {
            if (isMove) return BlockMouseMove ? 1 : Native.CallNextHookEx(_msHook, nCode, wParam, lParam);
            if (isClick) Raise(ActivityKind.Mouse);
            return 1;
        }

        // Prompt/ExternalAuth: Zeiger darf sich bewegen, Klicks/Rad nur auf erlaubten Fenstern
        if (isMove) return Native.CallNextHookEx(_msHook, nCode, wParam, lParam);
        var m = Marshal.PtrToStructure<Native.MSLLHOOKSTRUCT>(lParam);
        var hwnd = Native.GetAncestor(Native.WindowFromPoint(m.pt), Native.GA_ROOT);
        if (IsAllowedWindow(hwnd, mode)) return Native.CallNextHookEx(_msHook, nCode, wParam, lParam);
        if (isClick) Raise(ActivityKind.Mouse);
        return 1;
    }

    private bool IsAllowedWindow(nint hwnd, BlockMode mode)
    {
        if (hwnd == 0) return false;
        var root = Native.GetAncestor(hwnd, Native.GA_ROOT);
        if (root == 0) root = hwnd;
        if (_interactive.ContainsKey(root)) return true;
        if (mode != BlockMode.ExternalAuth) return false;

        // Entscheidung in Vitrine.Core (ExternalAuthWindows): keine Standarddialoge (Datei, Drucken), Besitzer-Regel nur
        // für Vitrine und die WebView2-Prozesse des eigenen Anmeldefensters, Prozesse nur von geschützten Orten
        Native.GetWindowThreadProcessId(root, out var pid);
        var contentPid = pid;
        var path = _procPaths.GetOrAdd(pid, p => Native.ProcessPath(p));
        if (path is null) return false;

        // UWP-Fenster (z. B. der Microsoft-Anmeldedialog) hängen in einem ApplicationFrameHost-Rahmen.
        // Dann zählt der Prozess des eigentlichen Inhalts, sonst wären alle UWP-Apps freigegeben.
        if (Path.GetFileName(path).Equals("ApplicationFrameHost.exe", StringComparison.OrdinalIgnoreCase))
        {
            var core = Native.FindWindowEx(root, 0, "Windows.UI.Core.CoreWindow", null);
            if (core == 0) return false;
            Native.GetWindowThreadProcessId(core, out contentPid);
            path = _procPaths.GetOrAdd(contentPid, p => Native.ProcessPath(p));
            if (path is null) return false;
        }

        bool own = contentPid == (uint)Environment.ProcessId;
        var browser = _webViewBrowserPid;
        bool ourWebView = browser != 0 && (contentPid == browser || _parents.GetOrAdd(contentPid, p => Native.ParentProcessId(p)) == browser);
        bool owned = (own || ourWebView) && Core.Lock.WindowOwnership.OwnedByAllowed(root, w => Native.GetWindow(w, Native.GW_OWNER),
            w => _interactive.ContainsKey(w) || _interactive.ContainsKey(Native.GetAncestor(w, Native.GA_ROOT)));

        var facts = new Core.Lock.AuthWindowFacts(Native.ClassName(root), path, own, ourWebView, owned, _preExisting.Contains(root));
        return Core.Lock.ExternalAuthWindows.Allow(facts, _allowedProcs, _roots);
    }

    private void Raise(ActivityKind kind)
    {
        var h = Activity;
        if (h is null) return;
        // Nicht auf dem Hook-Thread arbeiten – sofort zurückkehren
        ThreadPool.UnsafeQueueUserWorkItem(_ => h(kind), null);
    }

    private void TrackModifier(uint vk, bool down)
    {
        switch (vk)
        {
            case VK_CONTROL or VK_LCONTROL or VK_RCONTROL: _ctrl = down; break;
            case VK_MENU or VK_LMENU or VK_RMENU: _alt = down; break;
            case VK_SHIFT or VK_LSHIFT or VK_RSHIFT: _shift = down; break;
            case VK_LWIN or VK_RWIN: _win = down; break;
        }
    }

    private bool ModsMatch()
    {
        uint m = 0;
        if (_ctrl) m |= Native.MOD_CONTROL;
        if (_alt) m |= Native.MOD_ALT;
        if (_shift) m |= Native.MOD_SHIFT;
        if (_win) m |= Native.MOD_WIN;
        return m == (_hotMods & 0xF);
    }

    private static bool IsModifier(uint vk) => vk is VK_SHIFT or VK_CONTROL or VK_MENU or VK_LSHIFT or VK_RSHIFT
        or VK_LCONTROL or VK_RCONTROL or VK_LMENU or VK_RMENU or VK_LWIN or VK_RWIN;

    public void Dispose()
    {
        _mode = BlockMode.Off;
        _rehookTimer?.Dispose();
        if (_threadId != 0) Native.PostThreadMessage(_threadId, Native.WM_QUIT, 0, 0);
        _thread?.Join(1000);
        _thread = null;
    }
}
