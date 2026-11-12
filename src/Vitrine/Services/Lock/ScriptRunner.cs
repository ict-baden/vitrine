// SPDX-License-Identifier: MIT
using System.Diagnostics;

namespace Vitrine.Services.Lock;

/// <summary>Führt die unter „Skripte“ hinterlegten Befehle unsichtbar aus.</summary>
public static class ScriptRunner
{
    public static void Run(string? command, string evt, int timeoutSeconds, IDictionary<string, string?>? vars = null)
    {
        if (string.IsNullOrWhiteSpace(command)) return;
        _ = Task.Run(() =>
        {
            try
            {
                var psi = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "cmd.exe"), $"/d /c {command}")
                {
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden,
                };
                // Werte bereinigt (Vitrine.Core: ScriptEnvironment) – cmd würde Sonderzeichen in %VARIABLEN% sonst ausführen
                foreach (var (k, v) in Core.Lock.ScriptEnvironment.Build(evt, DateTimeOffset.UtcNow, vars)) psi.Environment[k] = v;

                using var p = Process.Start(psi);
                if (p is not null && !p.WaitForExit(TimeSpan.FromSeconds(Math.Max(1, timeoutSeconds))))
                    p.Kill(entireProcessTree: true);
            }
            catch { }
        });
    }
}
