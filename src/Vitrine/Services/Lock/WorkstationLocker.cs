// SPDX-License-Identifier: MIT
using System.Runtime.InteropServices;
using Vitrine.Core.Lock;
using Vitrine.Platform;
using Vitrine.Services.Interop;

namespace Vitrine.Services.Lock;

/// <summary>
/// Rückfall „Windows sperren“ – der einzige Weg zu <c>LockWorkStation()</c> (Wächter, Fehlversuche, Vordergrund eines
/// Administrator-Fensters, zweite Instanz). Solange DisableLockWorkstation gesetzt ist, sperrt <c>LockWorkStation()</c>
/// nicht; deshalb zuerst Vitrines eigenen Wert entfernen (<see cref="LockWorkstationPolicy.BeforeFallbackLock"/>), dann
/// sperren und prüfen, ob Windows wirklich gesperrt ist. Klappt das nicht (fremde Richtlinie, keine Sperre nach 3 s),
/// wird die Sitzung getrennt. Nie still eine offene Sitzung zurücklassen.
/// </summary>
public static class WorkstationLocker
{
    /// <summary>So lange auf den Windows-Sperrbildschirm warten, dann trennen.</summary>
    private static readonly TimeSpan LockTimeout = TimeSpan.FromSeconds(3);

    /// <summary>Win+L-Wert des angemeldeten Benutzers (HKCU) mit Computerrichtlinie (HKLM).</summary>
    public static LockWorkstationPolicy CreatePolicy() => new(new RegistryUserPolicyStore(), new RegistryMachinePolicyReader());

    /// <summary>
    /// Windows sperren bzw. Sitzung trennen. Blockiert bis zu <see cref="LockTimeout"/> – nicht auf dem UI-Thread aufrufen.
    /// </summary>
    /// <param name="cause">Englische Kennung fürs Protokoll („watchdog“, „failed attempts“ …).</param>
    /// <returns>Ergebnis und Protokolltext (Englisch, mit VIT-Code bei Problemen).</returns>
    public static (FallbackLockOutcome Outcome, string Detail) Lock(LockWorkstationPolicy policy, string cause)
    {
        FallbackLockPlan plan;
        // Scheitert schon das Aufräumen, trotzdem sperren – notfalls trennt die Prüfung unten
        try { plan = policy.BeforeFallbackLock(); }
        catch { plan = new FallbackLockPlan(FallbackLockMethod.LockWorkstation, false, null); }

        int lockError = 0;
        if (plan.Method == FallbackLockMethod.LockWorkstation)
        {
            // LockWorkStation läuft asynchron: true heißt nur „angestoßen“. Deshalb nachsehen, ob die Sitzung gesperrt ist.
            if (Native.LockWorkStation())
            {
                if (WaitUntilLocked()) return (FallbackLockOutcome.Locked, plan.AuditDetail(cause, FallbackLockOutcome.Locked));
            }
            else lockError = Marshal.GetLastWin32Error();
        }

        if (Native.WTSDisconnectSession(0, Native.WTS_CURRENT_SESSION, false))
            return (FallbackLockOutcome.Disconnected, plan.AuditDetail(cause, FallbackLockOutcome.Disconnected, lockError));
        int disconnectError = Marshal.GetLastWin32Error();
        return (FallbackLockOutcome.Failed, plan.AuditDetail(cause, FallbackLockOutcome.Failed, lockError, disconnectError));
    }

    private static bool WaitUntilLocked()
    {
        var until = Environment.TickCount64 + (long)LockTimeout.TotalMilliseconds;
        while (true)
        {
            if (Native.IsSessionLocked() == true) return true;
            if (Environment.TickCount64 >= until) return false;
            Thread.Sleep(100);
        }
    }
}
