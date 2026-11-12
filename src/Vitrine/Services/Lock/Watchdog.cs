// SPDX-License-Identifier: MIT
using Vitrine.Core.Config;
using Vitrine.Core.Lock;
using Vitrine.Platform;

namespace Vitrine.Services.Lock;

/// <summary>
/// Läuft als zweiter Prozess („Vitrine.exe --watchdog &lt;pid&gt;“). Endet Vitrine, während gesperrt ist (Absturz,
/// Prozess beendet), sperrt der Wächter sofort Windows – der Arbeitsplatz bleibt geschützt. Grenzen (wer den Wächter
/// selbst beenden kann): docs/limitations.md.
/// </summary>
public static class Watchdog
{
    private static StreamWriter? _channel;

    /// <summary>
    /// Läuft im Wächterprozess. Den Sperrzustand meldet Vitrine über die Standardeingabe („1“ gesperrt, „0“ entsperrt);
    /// die Datei %LocalAppData%\Vitrine\locked gilt nur, wenn nie etwas ankam (sie kann der Benutzer selbst löschen).
    /// </summary>
    /// <param name="audit">Eintrag ins Protokoll (Ergebnis des Rückfalls; die App selbst ist dann schon weg).</param>
    public static void Run(int pid, Action<string>? audit = null)
    {
        int state = -1; // unbekannt
        var reader = new Thread(() =>
        {
            try
            {
                string? line;
                while ((line = Console.In.ReadLine()) is not null)
                    if (line == "1" || line == "0") Volatile.Write(ref state, line == "1" ? 1 : 0);
            }
            catch { }
        }) { IsBackground = true };
        reader.Start();

        try
        {
            using var p = System.Diagnostics.Process.GetProcessById(pid);
            p.WaitForExit();
        }
        catch (ArgumentException) { /* schon weg */ }
        reader.Join(500); // letzte Zeile noch lesen

        var s = Volatile.Read(ref state);
        // Lock.Mode = Desktop: Ist Vitrines Sperr-Desktop noch Eingabe-Desktop, zuerst zurück auf den Windows-Desktop.
        // Sonst bliebe nach dem Entsperren von Windows ein leerer Desktop ohne Vitrine stehen (VIT-0455)
        try
        {
            if (DesktopSwitcher.LeaveStrandedLockDesktop() is { } stranded) audit?.Invoke(stranded);
        }
        catch { }
        var winLock = WorkstationLocker.CreatePolicy();
        if (s == 1 || (s == -1 && LockState.WasLocked))
        {
            // Erst Vitrines DisableLockWorkstation entfernen, sonst sperrt LockWorkStation nicht (WorkstationLocker);
            // klappt das Sperren nicht, wird die Sitzung getrennt
            var (_, detail) = WorkstationLocker.Lock(winLock, "watchdog: Vitrine ended while locked");
            try { audit?.Invoke(detail); } catch { }
            new SasRestrictions(new RegistryUserPolicyStore()).Restore();
            CursorHider.RestoreSystemCursors();
            LockState.Set(false);
        }
        else
        {
            // Entsperrt beendet (z. B. abgestürzt mit Lock.ReplaceWinL): Win+L soll wieder Windows sperren
            try { winLock.Revert(); } catch { }
        }
    }

    public static void Start(SecuritySettings s)
    {
        if (!s.Watchdog || Environment.ProcessPath is null || _channel is not null) return; // läuft schon
        try
        {
            var p = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(Environment.ProcessPath,
                $"--watchdog {Environment.ProcessId}") { UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true });
            if (p is not null) _channel = new StreamWriter(p.StandardInput.BaseStream) { AutoFlush = true };
        }
        catch { }
    }

    /// <summary>Sperrzustand an den Wächter melden.</summary>
    public static void Signal(bool locked)
    {
        try { _channel?.WriteLine(locked ? "1" : "0"); }
        catch { _channel = null; } // Wächter beendet
    }
}

internal static class ShutdownHelper
{
    /// <summary>Herunterfahren über shutdown.exe (braucht kein SeShutdownPrivilege-Gefummel), erzwungen.</summary>
    public static void Shutdown()
    {
        try
        {
            var shutdown = Path.Combine(Environment.SystemDirectory, "shutdown.exe");
            // Grund, den Windows anzeigt, in der Sprache der Oberfläche (ohne Anführungszeichen, er steht in der Befehlszeile)
            var args = Core.Lock.FailurePolicy.ShutdownArguments(UI.Loc.T("Shutdown_Reason"));
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(shutdown, args)
            { UseShellExecute = false, CreateNoWindow = true });
        }
        catch { }
    }
}
