// SPDX-License-Identifier: MIT
using System.Runtime.InteropServices;
using System.Text;

namespace Vitrine.Services.Interop;

/// <summary>Desktops (CreateDesktop, SwitchDesktop …) und GDI für die Sperre mit eigenem Desktop (<c>Lock.Mode = Desktop</c>).</summary>
public static partial class Native
{
    // ---------- Desktops ----------
    public const uint DESKTOP_READOBJECTS = 0x0001, DESKTOP_CREATEWINDOW = 0x0002, DESKTOP_SWITCHDESKTOP = 0x0100;
    /// <summary>Alle Rechte an einem Desktop (STANDARD_RIGHTS_REQUIRED | 0x1FF).</summary>
    public const uint DESKTOP_ALL_ACCESS = 0x000F01FF;
    public const int UOI_NAME = 2;

    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public nint lpSecurityDescriptor;
        [MarshalAs(UnmanagedType.Bool)] public bool bInheritHandle;
    }

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "CreateDesktopW")]
    public static extern nint CreateDesktop(string name, nint device, nint devmode, uint flags, uint access, ref SECURITY_ATTRIBUTES sa);

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "OpenDesktopW")]
    public static extern nint OpenDesktop(string name, uint flags, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint access);

    [DllImport("user32.dll", SetLastError = true)]
    public static extern nint OpenInputDesktop(uint flags, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint access);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SwitchDesktop(nint desktop);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SetThreadDesktop(nint desktop);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseDesktop(nint desktop);

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "GetUserObjectInformationW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetUserObjectInformation(nint obj, int index, StringBuilder? info, int length, out int needed);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "ConvertStringSecurityDescriptorToSecurityDescriptorW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string sddl, uint revision, out nint descriptor, out uint size);

    [DllImport("kernel32.dll")]
    public static extern nint LocalFree(nint mem);

    /// <summary>Name eines Desktops (UOI_NAME), null bei Fehler.</summary>
    public static string? DesktopName(nint desktop)
    {
        if (desktop == 0) return null;
        var sb = new StringBuilder(256);
        return GetUserObjectInformation(desktop, UOI_NAME, sb, sb.Capacity * 2, out _) ? sb.ToString() : null;
    }

    /// <summary>Name des Eingabe-Desktops; null, wenn er nicht lesbar ist (Winlogon, aber auch jeder Desktop, der den Benutzer aussperrt).</summary>
    public static string? InputDesktopName()
    {
        var h = OpenInputDesktop(0, false, DESKTOP_READOBJECTS);
        if (h == 0) return null;
        try { return DesktopName(h); }
        finally { CloseDesktop(h); }
    }

    private const uint SPI_GETSCREENSAVERRUNNING = 0x0072;

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SystemParametersInfo(uint action, uint param, out int value, uint winIni);

    /// <summary>Läuft gerade ein Bildschirmschoner (auch ein gesicherter auf dem Desktop „Screen-saver“)?</summary>
    public static bool ScreenSaverRunning() => SystemParametersInfo(SPI_GETSCREENSAVERRUNNING, 0, out var running, 0) && running != 0;

    /// <summary>
    /// Läuft in dieser Sitzung ein Prozess mit diesem Namen, der nicht dem eigenen Benutzer gehört (LogonUI.exe und
    /// consent.exe laufen als SYSTEM)? Ein vom Benutzer selbst gestartetes Programm gleichen Namens zählt nicht: Sein Token
    /// lässt sich öffnen und nennt den eigenen Benutzer. Ein Token, das sich nicht öffnen lässt, gilt als fremd.
    /// </summary>
    public static bool SystemProcessInSession(string name)
    {
        var session = System.Diagnostics.Process.GetCurrentProcess().SessionId;
        using var me = System.Security.Principal.WindowsIdentity.GetCurrent();
        foreach (var p in System.Diagnostics.Process.GetProcessesByName(name))
        {
            using (p)
            {
                try
                {
                    if (p.SessionId != session) continue;
                    if (!OwnedBy(p.Id, me.User)) return true;
                }
                catch (InvalidOperationException) { /* inzwischen beendet */ }
            }
        }
        return false;
    }

    private static bool OwnedBy(int pid, System.Security.Principal.SecurityIdentifier? user)
    {
        var h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, (uint)pid);
        if (h == 0) return false;
        try
        {
            if (!OpenProcessToken(h, 0x0008 /* TOKEN_QUERY */, out var token)) return false;
            try
            {
                using var id = new System.Security.Principal.WindowsIdentity(token);
                return user is not null && id.User == user;
            }
            catch { return false; }
            finally { CloseHandle(token); }
        }
        finally { CloseHandle(h); }
    }

    // ---------- GDI (Vorschau) ----------
    public const uint SRCCOPY = 0x00CC0020, BLACKNESS = 0x00000042;
    public const uint PW_RENDERFULLCONTENT = 0x00000002;
    public const int HALFTONE = 4;

    [DllImport("user32.dll")]
    public static extern nint GetDC(nint hwnd);

    [DllImport("user32.dll")]
    public static extern int ReleaseDC(nint hwnd, nint dc);

    [DllImport("gdi32.dll")]
    public static extern nint CreateCompatibleDC(nint dc);

    [DllImport("gdi32.dll")]
    public static extern nint CreateCompatibleBitmap(nint dc, int width, int height);

    [DllImport("gdi32.dll")]
    public static extern nint SelectObject(nint dc, nint obj);

    [DllImport("gdi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool DeleteObject(nint obj);

    [DllImport("gdi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool DeleteDC(nint dc);

    [DllImport("gdi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool BitBlt(nint dest, int x, int y, int width, int height, nint src, int srcX, int srcY, uint rop);

    [DllImport("gdi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool StretchBlt(nint dest, int x, int y, int width, int height, nint src, int srcX, int srcY, int srcWidth, int srcHeight, uint rop);

    [DllImport("gdi32.dll")]
    public static extern int SetStretchBltMode(nint dc, int mode);

    [DllImport("gdi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool PatBlt(nint dc, int x, int y, int width, int height, uint rop);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool PrintWindow(nint hwnd, nint dc, uint flags);
}
