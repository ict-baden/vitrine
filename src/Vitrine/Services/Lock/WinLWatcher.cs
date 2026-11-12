// SPDX-License-Identifier: MIT
using System.Runtime.InteropServices;
using Vitrine.Services.Interop;

namespace Vitrine.Services.Lock;

/// <summary>
/// Erkennt Win+L für <c>Lock.ReplaceWinL</c>, auch im entsperrten Zustand. Bewusst klein: nur ein Tastatur-Hook (keine
/// Maus), nur wenn die Einstellung an ist, und er lässt jede Taste durch – er schaut nur zu. Win+L kann ein Hook nicht
/// abfangen; Windows ignoriert es erst, wenn DisableLockWorkstation gesetzt ist (<see cref="Core.Lock.LockWorkstationPolicy"/>).
/// Dann kommt das L bei den Hooks an, und dieser meldet es. Eigener Thread mit Nachrichtenschleife (wie
/// <see cref="InputBlocker"/>), alle 5 s neu gesetzt, falls Windows ihn nach LowLevelHooksTimeout entfernt hat.
/// Während der Vitrine-Sperre liegt der Hook des Eingabeblockers davor und verschluckt die Tasten; dieser sieht dann nichts.
/// </summary>
public sealed class WinLWatcher : IDisposable
{
    private const uint WM_APP_REHOOK = 0x8001;
    private const int VK_L = 0x4C, VK_LWIN = 0x5B, VK_RWIN = 0x5C, VK_CONTROL = 0x11, VK_MENU = 0x12;

    private readonly Native.LowLevelProc _proc;
    private Thread? _thread;
    private uint _threadId;
    private nint _hook;
    private System.Threading.Timer? _rehookTimer;

    public WinLWatcher() => _proc = KeyboardProc;

    /// <summary>Win+L gedrückt (auf einem Thread des Pools – nicht dem UI-Thread).</summary>
    public event Action? Pressed;

    public bool Enabled => _thread is not null;

    public void Start()
    {
        if (_thread is not null) return;
        using var ready = new ManualResetEventSlim();
        _thread = new Thread(() =>
        {
            _threadId = Native.GetCurrentThreadId();
            _hook = Native.SetWindowsHookEx(Native.WH_KEYBOARD_LL, _proc, Native.GetModuleHandle(null), 0);
            ready.Set();
            while (Native.GetMessage(out var msg, 0, 0, 0) > 0)
                if (msg.message == WM_APP_REHOOK) Rehook();
            if (_hook != 0) { Native.UnhookWindowsHookEx(_hook); _hook = 0; }
        })
        { IsBackground = true, Name = "Vitrine.WinLWatcher" };
        _thread.Start();
        ready.Wait(2000);
        _rehookTimer = new System.Threading.Timer(_ => Native.PostThreadMessage(_threadId, WM_APP_REHOOK, 0, 0), null, 5000, 5000);
    }

    public void Stop()
    {
        _rehookTimer?.Dispose();
        _rehookTimer = null;
        if (_threadId != 0) Native.PostThreadMessage(_threadId, Native.WM_QUIT, 0, 0);
        _thread?.Join(1000);
        _thread = null;
        _threadId = 0;
    }

    /// <summary>Erst den neuen Hook setzen, dann den alten entfernen – keine Lücke.</summary>
    private void Rehook()
    {
        var old = _hook;
        var hook = Native.SetWindowsHookEx(Native.WH_KEYBOARD_LL, _proc, Native.GetModuleHandle(null), 0);
        if (hook == 0) return;
        _hook = hook;
        if (old != 0) Native.UnhookWindowsHookEx(old);
    }

    private nint KeyboardProc(int nCode, nint wParam, nint lParam)
    {
        if (nCode == Native.HC_ACTION && (int)wParam is Native.WM_KEYDOWN or Native.WM_SYSKEYDOWN)
        {
            var k = Marshal.PtrToStructure<Native.KBDLLHOOKSTRUCT>(lParam);
            // Im entsperrten Zustand verschluckt niemand Tasten, GetAsyncKeyState kennt die Windows-Taste also
            if (k.vkCode == VK_L && (Down(VK_LWIN) || Down(VK_RWIN)) && !Down(VK_CONTROL) && !Down(VK_MENU) && Pressed is { } h)
                ThreadPool.UnsafeQueueUserWorkItem(_ => h(), null);
        }
        // Immer durchreichen: Mit DisableLockWorkstation tut Win+L in Windows nichts, und das Startmenü öffnet sich nicht,
        // weil zwischen Drücken und Loslassen der Windows-Taste eine andere Taste kam
        return Native.CallNextHookEx(_hook, nCode, wParam, lParam);
    }

    private static bool Down(int vk) => (Native.GetAsyncKeyState(vk) & 0x8000) != 0;

    public void Dispose() => Stop();
}
