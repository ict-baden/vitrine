// SPDX-License-Identifier: MIT
using System.Runtime.InteropServices;
using System.Text;

namespace Vitrine.Services.Interop;

public static partial class Native
{
    // ---------- Hooks ----------
    public const int WH_KEYBOARD_LL = 13;
    public const int WH_MOUSE_LL = 14;
    public const int HC_ACTION = 0;

    public const int WM_KEYDOWN = 0x0100;
    public const int WM_SYSKEYDOWN = 0x0104;
    public const int WM_MOUSEMOVE = 0x0200;
    public const int WM_LBUTTONDOWN = 0x0201;
    public const int WM_RBUTTONDOWN = 0x0204;
    public const int WM_MBUTTONDOWN = 0x0207;
    public const int WM_MOUSEWHEEL = 0x020A;
    public const int WM_XBUTTONDOWN = 0x020B;
    public const int WM_MOUSEHWHEEL = 0x020E;
    public const int WM_QUIT = 0x0012;
    public const int WM_HOTKEY = 0x0312;

    public const uint LLKHF_INJECTED = 0x10;
    public const uint LLMHF_INJECTED = 0x01;

    public delegate nint LowLevelProc(int nCode, nint wParam, nint lParam);

    [StructLayout(LayoutKind.Sequential)]
    public struct KBDLLHOOKSTRUCT
    {
        public uint vkCode;
        public uint scanCode;
        public uint flags;
        public uint time;
        public nint dwExtraInfo;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct POINT { public int X; public int Y; }

    [StructLayout(LayoutKind.Sequential)]
    public struct MSLLHOOKSTRUCT
    {
        public POINT pt;
        public uint mouseData;
        public uint flags;
        public uint time;
        public nint dwExtraInfo;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MSG
    {
        public nint hwnd;
        public uint message;
        public nint wParam;
        public nint lParam;
        public uint time;
        public POINT pt;
    }

    [DllImport("user32.dll", SetLastError = true)]
    public static extern nint SetWindowsHookEx(int idHook, LowLevelProc lpfn, nint hMod, uint dwThreadId);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool UnhookWindowsHookEx(nint hhk);

    [DllImport("user32.dll")]
    public static extern nint CallNextHookEx(nint hhk, int nCode, nint wParam, nint lParam);

    [DllImport("user32.dll")]
    public static extern int GetMessage(out MSG lpMsg, nint hWnd, uint wMsgFilterMin, uint wMsgFilterMax);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool PostThreadMessage(uint idThread, uint msg, nint wParam, nint lParam);

    [DllImport("kernel32.dll")]
    public static extern uint GetCurrentThreadId();

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    public static extern nint GetModuleHandle(string? lpModuleName);

    // ---------- Fenster ----------
    public const int GWL_EXSTYLE = -20;
    public const int WS_EX_TRANSPARENT = 0x00000020;
    public const int WS_EX_TOOLWINDOW = 0x00000080;
    public const int WS_EX_LAYERED = 0x00080000;
    public const int WS_EX_NOACTIVATE = 0x08000000;
    public const int WS_EX_TOPMOST = 0x00000008;

    public static readonly nint HWND_TOPMOST = new(-1);
    public static readonly nint HWND_NOTOPMOST = new(-2);
    public const uint SWP_NOSIZE = 0x0001;
    public const uint SWP_NOMOVE = 0x0002;
    public const uint SWP_NOZORDER = 0x0004;
    public const uint SWP_NOACTIVATE = 0x0010;
    public const uint SWP_SHOWWINDOW = 0x0040;

    [DllImport("user32.dll", EntryPoint = "GetWindowLongPtrW")]
    public static extern nint GetWindowLongPtr(nint hWnd, int nIndex);

    [DllImport("user32.dll", EntryPoint = "SetWindowLongPtrW")]
    public static extern nint SetWindowLongPtr(nint hWnd, int nIndex, nint dwNewLong);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SetWindowPos(nint hWnd, nint hWndInsertAfter, int X, int Y, int cx, int cy, uint uFlags);

    [DllImport("user32.dll")]
    public static extern nint GetForegroundWindow();

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SetForegroundWindow(nint hWnd);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool BringWindowToTop(nint hWnd);

    [DllImport("user32.dll")]
    public static extern uint GetWindowThreadProcessId(nint hWnd, out uint lpdwProcessId);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool AttachThreadInput(uint idAttach, uint idAttachTo, [MarshalAs(UnmanagedType.Bool)] bool fAttach);

    /// <summary>Gehört das Vordergrundfenster zu diesem Prozess?</summary>
    public static bool ForegroundIsOwn()
    {
        var fg = GetForegroundWindow();
        if (fg == 0) return false;
        GetWindowThreadProcessId(fg, out var pid);
        return pid == (uint)Environment.ProcessId;
    }

    /// <summary>
    /// Holt ein eigenes Fenster nach vorn, auch wenn gerade ein anderer Prozess den Vordergrund hat (über
    /// AttachThreadInput). Gegenüber Fenstern mit höherer Integrität (als Administrator gestartet) kann das scheitern –
    /// dann bleibt es beim Versuch; der Aufrufer wiederholt ihn regelmäßig.
    /// </summary>
    public static void ForceForeground(nint hwnd)
    {
        if (hwnd == 0) return;
        var fg = GetForegroundWindow();
        // An ein hängendes Fenster nicht anhängen – der eigene UI-Thread hinge sonst mit (und der Dienst trennte die Sitzung)
        if (fg != 0 && IsHungAppWindow(fg)) fg = 0;
        uint fgThread = fg == 0 ? 0 : GetWindowThreadProcessId(fg, out _);
        uint myThread = GetCurrentThreadId();
        bool attached = fg != 0 && fgThread != myThread && AttachThreadInput(fgThread, myThread, true);
        try
        {
            SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
            BringWindowToTop(hwnd);
            SetForegroundWindow(hwnd);
        }
        finally
        {
            if (attached) AttachThreadInput(fgThread, myThread, false);
        }
    }

    // Grund in der Liste „Diese Apps verhindern das Neustarten“ (Windows zeigt ihn statt „Diese App verhindert …“)
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ShutdownBlockReasonCreate(nint hWnd, string pwszReason);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ShutdownBlockReasonDestroy(nint hWnd);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool IsHungAppWindow(nint hWnd);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(nint process, uint access, out nint token);
    private const uint TOKEN_QUERY = 0x0008;

    /// <summary>
    /// Gehört das Vordergrundfenster einem Prozess, dessen Token dieser Prozess nicht lesen darf – als Administrator
    /// gestartet, SYSTEM oder ein anderer Benutzer? Für solche Fenster sehen die Hooks keine Eingaben (UIPI).
    /// </summary>
    public static bool ForegroundIsForeignIntegrity()
    {
        var fg = GetForegroundWindow();
        if (fg == 0) return false;
        GetWindowThreadProcessId(fg, out var pid);
        if (pid == 0 || pid == (uint)Environment.ProcessId) return false;
        var h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h == 0) return true;
        try
        {
            if (!OpenProcessToken(h, TOKEN_QUERY, out var token)) return true;
            CloseHandle(token);
            return false;
        }
        finally { CloseHandle(h); }
    }

    [DllImport("user32.dll")]
    public static extern int GetSystemMetrics(int nIndex);
    public const int SM_SHUTTINGDOWN = 0x2000;
    public const int SM_CXSMICON = 49;

    /// <summary>Systemmaß für ein bestimmtes DPI (Windows 10 1607+); GetSystemMetrics liefert bei PerMonitorV2 nur das System-DPI.</summary>
    [DllImport("user32.dll")]
    public static extern int GetSystemMetricsForDpi(int nIndex, uint dpi);

    [DllImport("user32.dll")]
    public static extern uint GetDpiForWindow(nint hwnd);

    public static readonly nint ENDSESSION_CLOSEAPP = 0x1;

    public const int WM_QUERYENDSESSION = 0x0011;
    public const int WM_ENDSESSION = 0x0016;

    [DllImport("user32.dll")]
    public static extern nint WindowFromPoint(POINT point);

    [DllImport("user32.dll")]
    public static extern nint GetAncestor(nint hwnd, uint gaFlags);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern nint FindWindowEx(nint parent, nint childAfter, string? className, string? windowName);
    public const uint GA_ROOT = 2;

    [DllImport("user32.dll")]
    public static extern nint GetWindow(nint hwnd, uint cmd);
    public const uint GW_OWNER = 4;

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetClassName(nint hwnd, StringBuilder name, int max);

    /// <summary>Fensterklasse, null wenn nicht lesbar.</summary>
    public static string? ClassName(nint hwnd)
    {
        var sb = new StringBuilder(256);
        return GetClassName(hwnd, sb, sb.Capacity) > 0 ? sb.ToString() : null;
    }

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool EnableWindow(nint hwnd, [MarshalAs(UnmanagedType.Bool)] bool enable);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool IsWindowEnabled(nint hwnd);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool PostMessage(nint hwnd, uint msg, nint wParam, nint lParam);
    public const uint WM_CLOSE = 0x0010;

    // ---------- Elternprozess (Toolhelp) ----------
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct PROCESSENTRY32
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public nint th32DefaultHeapID;
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szExeFile;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint CreateToolhelp32Snapshot(uint flags, uint pid);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Process32FirstW(nint snapshot, ref PROCESSENTRY32 entry);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Process32NextW(nint snapshot, ref PROCESSENTRY32 entry);

    /// <summary>Elternprozess (PID), 0 wenn unbekannt. Ein Schnappschuss aller Prozesse – nur zwischengespeichert aufrufen.</summary>
    public static uint ParentProcessId(uint pid)
    {
        var snap = CreateToolhelp32Snapshot(0x2 /* TH32CS_SNAPPROCESS */, 0);
        if (snap == 0 || snap == -1) return 0;
        try
        {
            var e = new PROCESSENTRY32 { dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32>() };
            if (!Process32FirstW(snap, ref e)) return 0;
            do { if (e.th32ProcessID == pid) return e.th32ParentProcessID; } while (Process32NextW(snap, ref e));
            return 0;
        }
        finally { CloseHandle(snap); }
    }

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetCursorPos(out POINT lpPoint);

    // ---------- Monitore ----------
    [StructLayout(LayoutKind.Sequential)]
    public struct RECT { public int Left, Top, Right, Bottom; }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct MONITORINFOEX
    {
        public int cbSize;
        public RECT rcMonitor;
        public RECT rcWork;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
        public string szDevice;
    }

    public delegate bool MonitorEnumProc(nint hMonitor, nint hdcMonitor, ref RECT lprcMonitor, nint dwData);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool EnumDisplayMonitors(nint hdc, nint lprcClip, MonitorEnumProc lpfnEnum, nint dwData);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetMonitorInfo(nint hMonitor, ref MONITORINFOEX lpmi);

    [DllImport("user32.dll")]
    public static extern nint MonitorFromPoint(POINT pt, uint dwFlags);
    public const uint MONITOR_DEFAULTTONEAREST = 2;

    public sealed record MonitorInfo(RECT Bounds, RECT Work, bool IsPrimary, string Device);

    public static List<MonitorInfo> GetMonitors()
    {
        var list = new List<MonitorInfo>();
        EnumDisplayMonitors(0, 0, (nint h, nint _, ref RECT _, nint _) =>
        {
            var mi = new MONITORINFOEX { cbSize = Marshal.SizeOf<MONITORINFOEX>() };
            if (GetMonitorInfo(h, ref mi))
                list.Add(new MonitorInfo(mi.rcMonitor, mi.rcWork, (mi.dwFlags & 1) != 0, mi.szDevice));
            return true;
        }, 0);
        return list;
    }

    public static MonitorInfo? GetMonitorAtCursor()
    {
        GetCursorPos(out var pt);
        var h = MonitorFromPoint(pt, MONITOR_DEFAULTTONEAREST);
        var mi = new MONITORINFOEX { cbSize = Marshal.SizeOf<MONITORINFOEX>() };
        return GetMonitorInfo(h, ref mi) ? new MonitorInfo(mi.rcMonitor, mi.rcWork, (mi.dwFlags & 1) != 0, mi.szDevice) : null;
    }

    // ---------- Leerlauf, Hotkeys, Sitzung ----------
    [StructLayout(LayoutKind.Sequential)]
    public struct LASTINPUTINFO { public uint cbSize; public uint dwTime; }

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);

    public static TimeSpan GetIdleTime()
    {
        var info = new LASTINPUTINFO { cbSize = (uint)Marshal.SizeOf<LASTINPUTINFO>() };
        if (!GetLastInputInfo(ref info)) return TimeSpan.Zero;
        return TimeSpan.FromMilliseconds(unchecked((uint)Environment.TickCount - info.dwTime));
    }

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool RegisterHotKey(nint hWnd, int id, uint fsModifiers, uint vk);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool UnregisterHotKey(nint hWnd, int id);

    public const uint MOD_ALT = 0x1, MOD_CONTROL = 0x2, MOD_SHIFT = 0x4, MOD_WIN = 0x8, MOD_NOREPEAT = 0x4000;

    /// <summary>
    /// Nur über <see cref="Vitrine.Services.Lock.WorkstationLocker"/> aufrufen: Solange DisableLockWorkstation gesetzt ist, sperrt der Aufruf
    /// nicht (und meldet das nicht immer als Fehler, er läuft asynchron).
    /// </summary>
    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool LockWorkStation();

    public const int WTS_CURRENT_SESSION = -1;

    /// <summary>Sitzung trennen (wie tsdiscon): Anmeldebildschirm, Programme laufen weiter. Die eigene Sitzung geht ohne Adminrechte.</summary>
    [DllImport("wtsapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WTSDisconnectSession(nint hServer, int sessionId, [MarshalAs(UnmanagedType.Bool)] bool wait);

    [DllImport("wtsapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WTSQuerySessionInformation(nint hServer, int sessionId, int infoClass, out nint buffer, out int bytes);

    [DllImport("wtsapi32.dll")]
    private static extern void WTSFreeMemory(nint memory);

    private const int WTSSessionInfoEx = 25;

    /// <summary>
    /// Ist die eigene Sitzung gesperrt (Windows-Sperrbildschirm)? null = unbekannt. WTSINFOEX_LEVEL1.SessionFlags:
    /// 0 = WTS_SESSIONSTATE_LOCK, 1 = UNLOCK (ab Windows 8 so herum).
    /// </summary>
    public static bool? IsSessionLocked()
    {
        if (!WTSQuerySessionInformation(0, WTS_CURRENT_SESSION, WTSSessionInfoEx, out var buffer, out var bytes) || buffer == 0) return null;
        try
        {
            // WTSINFOEX: DWORD Level, dann die Union (auf 8 Byte ausgerichtet): SessionId, SessionState, SessionFlags
            if (bytes < 20 || Marshal.ReadInt32(buffer) != 1) return null;
            return Marshal.ReadInt32(buffer, 16) switch { 0 => true, 1 => false, _ => null };
        }
        finally { WTSFreeMemory(buffer); }
    }

    /// <summary>
    /// Verbindungszustand der eigenen Sitzung (WTSINFOEX_LEVEL1.SessionState, WTS_CONNECTSTATE_CLASS): 0 = aktiv,
    /// sonst verbunden, getrennt usw. null = unbekannt.
    /// </summary>
    public static int? SessionConnectState()
    {
        if (!WTSQuerySessionInformation(0, WTS_CURRENT_SESSION, WTSSessionInfoEx, out var buffer, out var bytes) || buffer == 0) return null;
        try
        {
            if (bytes < 20 || Marshal.ReadInt32(buffer) != 1) return null;
            return Marshal.ReadInt32(buffer, 12);
        }
        finally { WTSFreeMemory(buffer); }
    }

    [DllImport("user32.dll")]
    public static extern short GetAsyncKeyState(int vKey);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ExitWindowsEx(uint uFlags, uint dwReason);
    public const uint EWX_LOGOFF = 0x0, EWX_SHUTDOWN = 0x1, EWX_FORCE = 0x4, EWX_FORCEIFHUNG = 0x10, EWX_POWEROFF = 0x8;

    [DllImport("kernel32.dll")]
    public static extern uint SetThreadExecutionState(uint esFlags);
    public const uint ES_CONTINUOUS = 0x80000000, ES_DISPLAY_REQUIRED = 0x2, ES_SYSTEM_REQUIRED = 0x1;

    // ---------- Prozesse ----------
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern nint OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint pid);
    public const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool QueryFullProcessImageName(nint hProcess, int flags, StringBuilder name, ref int size);

    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(nint h);

    public static string? GetProcessImageName(uint pid)
    {
        var h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h == 0) return null;
        try
        {
            var sb = new StringBuilder(1024);
            int size = sb.Capacity;
            return QueryFullProcessImageName(h, 0, sb, ref size) ? Path.GetFileName(sb.ToString()) : null;
        }
        finally { CloseHandle(h); }
    }

    // ---------- Anmeldung ----------
    public const int LOGON32_LOGON_INTERACTIVE = 2;
    public const int LOGON32_LOGON_NETWORK = 3;
    public const int LOGON32_PROVIDER_DEFAULT = 0;

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool LogonUser(string lpszUsername, string? lpszDomain, string lpszPassword,
        int dwLogonType, int dwLogonProvider, out nint phToken);

    // ---------- Geräte-Anbindung (Entra, Active Directory) ----------
    /// <summary>DSREG_JOIN_TYPE: DSREG_DEVICE_JOIN = Gerät in Entra eingebunden (Entra-joined oder Hybrid).</summary>
    public const int DSREG_DEVICE_JOIN = 1;
    /// <summary>NETSETUP_JOIN_STATUS: NetSetupDomainName = Mitglied einer AD-Domäne.</summary>
    public const int NetSetupDomainName = 3;

    /// <summary>Liefert HRESULT; <paramref name="ppJoinInfo"/> = 0, wenn das Gerät nicht eingebunden ist. Ab Windows 10.</summary>
    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    public static extern int NetGetAadJoinInformation(string? pcszTenantId, out nint ppJoinInfo);

    [DllImport("netapi32.dll")]
    public static extern void NetFreeAadJoinInformation(nint pJoinInfo);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    public static extern int NetGetJoinInformation(string? lpServer, out nint lpNameBuffer, out int bufferType);

    [DllImport("netapi32.dll")]
    public static extern int NetApiBufferFree(nint buffer);

    public const int TokenElevationType = 18;
    public const int TokenLinkedToken = 19;
    public const int TokenElevationTypeLimited = 3;

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetTokenInformation(nint tokenHandle, int tokenInformationClass, out int tokenInformation, int length, out int returnLength);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetTokenInformation(nint tokenHandle, int tokenInformationClass, out nint tokenInformation, int length, out int returnLength);

    public enum EXTENDED_NAME_FORMAT { NameSamCompatible = 2, NameDisplay = 3, NameUserPrincipal = 8 }

    [DllImport("secur32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.U1)]
    public static extern bool GetUserNameEx(EXTENDED_NAME_FORMAT nameFormat, StringBuilder lpNameBuffer, ref uint lpnSize);

    public static string? GetCurrentUserName(EXTENDED_NAME_FORMAT format)
    {
        uint size = 512;
        var sb = new StringBuilder((int)size);
        return GetUserNameEx(format, sb, ref size) ? sb.ToString() : null;
    }

    // ---------- DWM ----------
    public const int DWMWA_USE_IMMERSIVE_DARK_MODE = 20;
    public const int DWMWA_WINDOW_CORNER_PREFERENCE = 33;
    public const int DWMWA_SYSTEMBACKDROP_TYPE = 38;

    [DllImport("dwmapi.dll")]
    public static extern int DwmSetWindowAttribute(nint hwnd, int attr, ref int attrValue, int attrSize);

    [StructLayout(LayoutKind.Sequential)]
    public struct MARGINS { public int Left, Right, Top, Bottom; }

    [DllImport("dwmapi.dll")]
    public static extern int DwmExtendFrameIntoClientArea(nint hwnd, ref MARGINS margins);

    // ---------- Named Pipes: Gegenstelle feststellen ----------
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetNamedPipeClientProcessId(Microsoft.Win32.SafeHandles.SafePipeHandle pipe, out uint clientProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetNamedPipeServerProcessId(Microsoft.Win32.SafeHandles.SafePipeHandle pipe, out uint serverProcessId);

    /// <summary>„name.exe (PID 1234)“ der Gegenstelle, null wenn unbekannt.</summary>
    public static string? DescribeProcess(uint pid)
    {
        try
        {
            using var p = System.Diagnostics.Process.GetProcessById((int)pid);
            return $"{p.ProcessName}.exe (PID {pid})";
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException) { return $"PID {pid}"; }
    }

    /// <summary>
    /// Vollständiger Pfad der Exe eines Prozesses, null wenn nicht lesbar. Mit PROCESS_QUERY_LIMITED_INFORMATION und
    /// QueryFullProcessImageName – geht auch über Sitzungen und Integritätsstufen hinweg (vorher Process.MainModule:
    /// braucht PROCESS_VM_READ und liest die Modulliste des fremden Prozesses).
    /// </summary>
    public static string? ProcessPath(uint pid)
    {
        var h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h == 0) return null;
        try
        {
            var sb = new StringBuilder(1024);
            int size = sb.Capacity;
            return QueryFullProcessImageName(h, 0, sb, ref size) ? sb.ToString(0, size) : null;
        }
        finally { CloseHandle(h); }
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern Microsoft.Win32.SafeHandles.SafeFileHandle CreateFileW(string name, uint access, uint share, nint security,
        uint disposition, uint flags, nint template);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(Microsoft.Win32.SafeHandles.SafeFileHandle file, StringBuilder path, uint size, uint flags);

    /// <summary>
    /// Pfad einer Datei so, wie Windows ihn auflöst (GetFinalPathNameByHandle, FILE_NAME_NORMALIZED, Laufwerksbuchstabe):
    /// lange statt 8.3-Namen, Verknüpfungen aufgelöst, Schreibweise der Platte. null, wenn die Datei nicht zu öffnen ist.
    /// </summary>
    public static string? FinalPath(string path)
    {
        const uint FILE_READ_ATTRIBUTES = 0x80, SHARE_ALL = 0x7, OPEN_EXISTING = 3, FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
        try
        {
            using var h = CreateFileW(path, FILE_READ_ATTRIBUTES, SHARE_ALL, 0, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, 0);
            if (h.IsInvalid) return null;
            var sb = new StringBuilder(1024);
            var n = GetFinalPathNameByHandleW(h, sb, (uint)sb.Capacity, 0);
            if (n == 0) return null;
            if (n >= sb.Capacity)
            {
                sb = new StringBuilder((int)n + 1);
                n = GetFinalPathNameByHandleW(h, sb, (uint)sb.Capacity, 0);
                if (n == 0 || n >= sb.Capacity) return null;
            }
            return sb.ToString(0, (int)n);
        }
        catch (Exception ex) when (ex is ArgumentException or IOException) { return null; }
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenThreadToken(nint thread, uint access, [MarshalAs(UnmanagedType.Bool)] bool openAsSelf, out nint token);

    [DllImport("kernel32.dll")]
    private static extern nint GetCurrentThread();

    /// <summary>
    /// Token des aktuellen Threads öffnen (TOKEN_QUERY, mit den Rechten des Prozesses). Nur P/Invoke, kein verwalteter Code,
    /// der Dateien braucht: Unter einer Identifikations-Identität (ImpersonateNamedPipeClient) scheitert jedes Laden einer
    /// Assembly mit FileNotFoundException – so lehnte der Dienst seit 0.2.0 jede Sitzungs-App auf der Protokoll-Pipe ab.
    /// 0 = kein Token (Fehler in Marshal.GetLastPInvokeError).
    /// </summary>
    public static nint OpenCurrentThreadToken()
    {
        const uint TOKEN_QUERY = 0x8;
        return OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, out var token) ? token : 0;
    }

    // ---------- Fenster aufzählen ----------
    public delegate bool EnumWindowsProc(nint hWnd, nint lParam);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, nint lParam);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool IsWindowVisible(nint hWnd);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool IsIconic(nint hWnd);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetWindowRect(nint hWnd, out RECT rect);

    public const int DWMWA_CLOAKED = 14;
    public const int DWMWA_EXTENDED_FRAME_BOUNDS = 9;

    [DllImport("dwmapi.dll")]
    public static extern int DwmGetWindowAttribute(nint hwnd, int attr, out RECT value, int size);

    [DllImport("dwmapi.dll")]
    public static extern int DwmGetWindowAttribute(nint hwnd, int attr, out int value, int size);

    /// <summary>
    /// Sichtbare Fenster der obersten Ebene in Z-Reihenfolge (oberstes zuerst) mit Rahmen in Pixeln und Prozess. Ohne
    /// minimierte und von Windows ausgeblendete (andere virtuelle Desktops, angehaltene Apps).
    /// </summary>
    public static List<(RECT Rect, uint Pid)> WindowsTopToBottom()
    {
        var list = new List<(RECT, uint)>();
        EnumWindows((h, _) =>
        {
            if (!IsWindowVisible(h) || IsIconic(h)) return true;
            if (DwmGetWindowAttribute(h, DWMWA_CLOAKED, out int cloaked, sizeof(int)) == 0 && cloaked != 0) return true;
            // Sichtbarer Rahmen ohne den unsichtbaren Rand für die Größenänderung
            if (DwmGetWindowAttribute(h, DWMWA_EXTENDED_FRAME_BOUNDS, out RECT r, Marshal.SizeOf<RECT>()) != 0 && !GetWindowRect(h, out r))
                return true;
            GetWindowThreadProcessId(h, out var pid);
            list.Add((r, pid));
            return true;
        }, 0);
        return list;
    }

    /// <summary>
    /// Sichtbare Fenster der obersten Ebene, die es gerade gibt. Unsichtbare zählen nicht: Der Anmeldebroker kann ein schon
    /// vorhandenes, verstecktes Fenster für den Dialog einblenden.
    /// </summary>
    public static HashSet<nint> VisibleTopLevelWindows()
    {
        var set = new HashSet<nint>();
        EnumWindows((h, _) => { if (IsWindowVisible(h)) set.Add(h); return true; }, 0);
        return set;
    }
}
