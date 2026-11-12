// SPDX-License-Identifier: MIT
using System.Runtime.InteropServices;
using System.Security.Principal;
using Vitrine.Core.Lock;
using Vitrine.Services.Interop;

namespace Vitrine.Services.Lock;

/// <summary>
/// Vitrines eigener Desktop für <c>Lock.Mode = Desktop</c> (<see cref="ILockDesktop"/>): angelegt beim ersten Sperren,
/// danach bis zum Programmende wiederverwendet. Zugriff nur für SYSTEM und den Benutzer der Sitzung (DACL ohne
/// Vererbung); der Name hat einen zufälligen Teil (<see cref="LockDesktopNames.NewLockDesktopName"/>).
/// </summary>
public sealed class WindowsLockDesktop : ILockDesktop, IDisposable
{
    private nint _handle;

    public string LockDesktopName { get; private set; } = "";

    /// <summary>Handle des Sperr-Desktops (für SetThreadDesktop der Oberfläche), 0 vor <see cref="Create"/>.</summary>
    public nint Handle => _handle;

    public int LastError { get; private set; }

    public bool Create()
    {
        if (_handle != 0) return true;
        var name = LockDesktopNames.NewLockDesktopName();
        string sid;
        using (var id = WindowsIdentity.GetCurrent()) sid = id.User?.Value ?? "";
        // P: keine geerbten Einträge; SYSTEM und der Benutzer der Sitzung, sonst niemand
        var sddl = $"D:P(A;;0x{Native.DESKTOP_ALL_ACCESS:X};;;SY)" + (sid.Length > 0 ? $"(A;;0x{Native.DESKTOP_ALL_ACCESS:X};;;{sid})" : "");
        if (!Native.ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, 1, out var sd, out _))
        {
            LastError = Marshal.GetLastWin32Error();
            return false;
        }
        try
        {
            var sa = new Native.SECURITY_ATTRIBUTES { nLength = Marshal.SizeOf<Native.SECURITY_ATTRIBUTES>(), lpSecurityDescriptor = sd };
            var h = Native.CreateDesktop(name, 0, 0, 0, Native.DESKTOP_ALL_ACCESS, ref sa);
            if (h == 0)
            {
                LastError = Marshal.GetLastWin32Error();
                return false;
            }
            _handle = h;
            LockDesktopName = name;
            return true;
        }
        finally { Native.LocalFree(sd); }
    }

    public bool SwitchToLock()
    {
        if (_handle == 0) { LastError = 6; return false; } // ERROR_INVALID_HANDLE
        var ok = DesktopSwitcher.Switch(_handle, out var error);
        LastError = error;
        return ok;
    }

    public bool SwitchToDefault()
    {
        var ok = DesktopSwitcher.SwitchToDefault(out var error);
        LastError = error;
        return ok;
    }

    public string? InputDesktopName() => Native.InputDesktopName();

    /// <summary>
    /// Belege aus der Sitzung, dass Windows einen sicheren Desktop zeigt: Sitzung gesperrt oder nicht aktiv verbunden,
    /// LogonUI.exe (Sperrbildschirm, Strg+Alt+Entf) oder consent.exe (UAC) als fremder Prozess in der Sitzung, oder ein
    /// laufender Bildschirmschoner. Ein nicht lesbarer Desktop allein beweist das nicht (Befund M2).
    /// </summary>
    public bool SecureDesktopExpected()
    {
        try
        {
            if (Native.IsSessionLocked() == true) return true;
            if (Native.SessionConnectState() is { } state && state != 0) return true;
            if (Native.ScreenSaverRunning()) return true;
            return Native.SystemProcessInSession("LogonUI") || Native.SystemProcessInSession("consent");
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // Im Zweifel nicht als sicher werten: dann greift nach kurzer Frist die Rückkehr bzw. die Windows-Sperre
            return false;
        }
    }

    public void Dispose()
    {
        // Scheitert, solange noch ein Thread daran hängt; dann räumt Windows beim Prozessende auf
        if (_handle != 0 && Native.CloseDesktop(_handle)) _handle = 0;
    }
}

/// <summary>
/// Desktop-Wechsel. SwitchDesktop wird von einem kurzlebigen Thread aus aufgerufen, der am gerade aktiven
/// Eingabe-Desktop hängt: So gelingt der Wechsel auch aus einem Prozess, dessen übrige Threads auf einem anderen Desktop
/// sind (Wächter nach einem Absturz auf dem Sperr-Desktop, Rückkehr vom Sperr-Desktop). Ist der Eingabe-Desktop nicht
/// zu öffnen (sicherer Desktop), wird es ohne diesen Umweg versucht.
/// </summary>
public static class DesktopSwitcher
{
    public static bool Switch(nint target, out int error)
    {
        bool ok = false;
        int err = 0;
        nint input = 0;
        var t = new Thread(() =>
        {
            input = Native.OpenInputDesktop(0, false, Native.DESKTOP_READOBJECTS | Native.DESKTOP_SWITCHDESKTOP | Native.DESKTOP_CREATEWINDOW);
            if (input != 0) Native.SetThreadDesktop(input);
            ok = Native.SwitchDesktop(target);
            if (!ok) err = Marshal.GetLastWin32Error();
        }) { IsBackground = true, Name = "Vitrine.DesktopSwitch" };
        t.Start();
        if (!t.Join(TimeSpan.FromSeconds(3)))
        {
            error = 1460; // ERROR_TIMEOUT
            return false;
        }
        // Erst nach dem Ende des Threads schließen (solange er daran hängt, scheitert CloseDesktop)
        if (input != 0) Native.CloseDesktop(input);
        error = err;
        return ok;
    }

    /// <summary>Den Desktop von Windows („Default“) zum Eingabe-Desktop machen.</summary>
    public static bool SwitchToDefault(out int error)
    {
        var d = Native.OpenDesktop(LockDesktopNames.Default, 0, false, Native.DESKTOP_SWITCHDESKTOP);
        if (d == 0)
        {
            error = Marshal.GetLastWin32Error();
            return false;
        }
        try { return Switch(d, out error); }
        finally { Native.CloseDesktop(d); }
    }

    /// <summary>
    /// Nach einem Absturz (Wächter) oder beim Start: Ist ein Sperr-Desktop von Vitrine noch Eingabe-Desktop, zurück auf den
    /// Windows-Desktop (<see cref="DesktopRecovery"/>). Ergebnis als englischer Protokolltext mit VIT-0455, null = nichts zu tun.
    /// </summary>
    public static string? LeaveStrandedLockDesktop()
    {
        var input = Native.InputDesktopName();
        if (!DesktopRecovery.MustSwitchToDefault(input)) return null;
        var ok = SwitchToDefault(out var error);
        return $"{Core.Localization.ErrorCodes.LockDesktopStranded} Lock desktop {input} was the input desktop; " +
               (ok ? "switched to Default" : $"switching to Default failed (Win32 {error})");
    }
}
