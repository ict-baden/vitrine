// SPDX-License-Identifier: MIT
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Vitrine.Services.Supervisor;

/// <summary>Windows-Aufrufe für den Dienst: Sitzungen aufzählen und trennen, Sitzungs-App als angemeldeter Benutzer starten.</summary>
internal static class SessionApi
{
    private const int WTSActive = 0, WTSDisconnected = 4;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WTS_SESSION_INFO { public int SessionId; public string pWinStationName; public int State; }

    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSEnumerateSessions(nint server, int reserved, int version, out nint info, out int count);

    [DllImport("wtsapi32.dll")]
    private static extern void WTSFreeMemory(nint memory);

    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSQueryUserToken(int sessionId, out nint token);

    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSDisconnectSession(nint server, int sessionId, bool wait);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetNamedPipeServerSessionId(SafePipeHandle pipe, out int sessionId);

    [DllImport("kernel32.dll")]
    private static extern bool QueryUnbiasedInterruptTime(out ulong time);

    /// <summary>
    /// Monotone Zeit seit dem Systemstart ohne Energiesparmodus und Ruhezustand (100-ns-Schritte). Für die Fristen des
    /// Dienstes: Ein Schlaf des Rechners oder eine Uhrumstellung zählt so nie als Schweigen der Sitzungs-App.
    /// </summary>
    public static TimeSpan MonotonicNow() =>
        QueryUnbiasedInterruptTime(out var t) ? TimeSpan.FromTicks((long)t) : TimeSpan.FromMilliseconds(Environment.TickCount64);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetNamedPipeClientSessionId(SafePipeHandle pipe, out int sessionId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint pid);

    [DllImport("userenv.dll", SetLastError = true)]
    private static extern bool CreateEnvironmentBlock(out nint env, nint token, bool inherit);

    [DllImport("userenv.dll")]
    private static extern bool DestroyEnvironmentBlock(nint env);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(nint h);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
    {
        public int cb; public string? lpReserved; public string? lpDesktop; public string? lpTitle;
        public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow, cbReserved2; public nint lpReserved2, hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION { public nint hProcess, hThread; public int dwProcessId, dwThreadId; }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateProcessAsUser(nint token, string? app, System.Text.StringBuilder cmd, nint procAttr, nint threadAttr,
        bool inherit, uint flags, nint env, string? dir, ref STARTUPINFO si, out PROCESS_INFORMATION pi);

    private const uint CREATE_UNICODE_ENVIRONMENT = 0x400;

    /// <summary>Sitzungen mit angemeldetem Benutzer (aktiv oder getrennt), ohne Sitzung 0.</summary>
    public static List<int> UserSessions()
    {
        var list = new List<int>();
        if (!WTSEnumerateSessions(0, 0, 1, out var info, out var count)) return list;
        try
        {
            int size = Marshal.SizeOf<WTS_SESSION_INFO>();
            for (int i = 0; i < count; i++)
            {
                var s = Marshal.PtrToStructure<WTS_SESSION_INFO>(info + i * size);
                if (s.SessionId == 0 || s.State is not (WTSActive or WTSDisconnected)) continue;
                if (WTSQueryUserToken(s.SessionId, out var t)) { CloseHandle(t); list.Add(s.SessionId); }
            }
        }
        finally { WTSFreeMemory(info); }
        return list;
    }

    /// <summary>Alle Sitzungen, die Windows gerade kennt (jeder Zustand), ohne Sitzung 0; null, wenn die Abfrage scheitert.</summary>
    public static HashSet<int>? ExistingSessions()
    {
        if (!WTSEnumerateSessions(0, 0, 1, out var info, out var count)) return null;
        var set = new HashSet<int>();
        try
        {
            int size = Marshal.SizeOf<WTS_SESSION_INFO>();
            for (int i = 0; i < count; i++)
            {
                var s = Marshal.PtrToStructure<WTS_SESSION_INFO>(info + i * size);
                if (s.SessionId != 0) set.Add(s.SessionId);
            }
        }
        finally { WTSFreeMemory(info); }
        return set;
    }

    /// <summary>SID des angemeldeten Benutzers der Sitzung (für HKU\&lt;SID&gt;), null ohne Benutzer.</summary>
    public static string? UserSid(int sessionId)
    {
        if (!WTSQueryUserToken(sessionId, out var token)) return null;
        try
        {
            using var id = new System.Security.Principal.WindowsIdentity(token);
            return id.User?.Value;
        }
        finally { CloseHandle(token); }
    }

    /// <summary>Sitzung trennen: Windows zeigt den Anmeldebildschirm, Programme laufen weiter.</summary>
    public static bool Disconnect(int sessionId) => WTSDisconnectSession(0, sessionId, false);

    /// <summary>Startet <paramref name="exe"/> als angemeldeter Benutzer auf dessen Desktop. Prozess-ID oder Win32-Fehler.</summary>
    public static (int Pid, int Error) StartAsUser(int sessionId, string exe, string args)
    {
        if (!WTSQueryUserToken(sessionId, out var token)) return (0, Marshal.GetLastWin32Error());
        nint env = 0;
        try
        {
            CreateEnvironmentBlock(out env, token, false);
            var si = new STARTUPINFO { cb = Marshal.SizeOf<STARTUPINFO>(), lpDesktop = @"winsta0\default" };
            var cmd = new System.Text.StringBuilder($"\"{exe}\" {args}");
            if (!CreateProcessAsUser(token, exe, cmd, 0, 0, false, CREATE_UNICODE_ENVIRONMENT, env, Path.GetDirectoryName(exe), ref si, out var pi))
                return (0, Marshal.GetLastWin32Error());
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            return (pi.dwProcessId, 0);
        }
        finally
        {
            if (env != 0) DestroyEnvironmentBlock(env);
            CloseHandle(token);
        }
    }
}
