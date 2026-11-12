// SPDX-License-Identifier: MIT
using System.Globalization;
using System.Text;

namespace Vitrine.Core.Lock;

/// <summary>
/// Umgebungsvariablen für die Skripte (Scripts.OnLock …). cmd.exe setzt %VARIABLEN% ein, bevor es die Zeile liest – ein
/// Wert wie <c>x&amp;calc</c> im Benutzernamen (am Sperrbildschirm frei eintippbar) würde sonst als Befehl ausgeführt.
/// Deshalb kommen nur Werte ohne Steuer- und Sonderzeichen von cmd an, höchstens 256 Zeichen.
/// </summary>
public static class ScriptEnvironment
{
    public const int MaxValueLength = 256;

    // Zeichen mit Bedeutung für cmd.exe (Befehlstrenner, Umleitung, Escape, Variablen, verzögerte Erweiterung, Klammern, Anführung)
    private const string Special = "&|<>^%!\"()`";

    public static IReadOnlyDictionary<string, string> Build(string evt, DateTimeOffset now, IDictionary<string, string?>? vars)
    {
        var env = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["VITRINE_EVENT"] = Clean(evt),
            ["VITRINE_TIME"] = now.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture),
        };
        if (vars is not null)
            foreach (var (k, v) in vars)
                env[$"VITRINE_{k.ToUpperInvariant()}"] = Clean(v);
        return env;
    }

    public static string Clean(string? value)
    {
        if (string.IsNullOrEmpty(value)) return "";
        var sb = new StringBuilder(Math.Min(value.Length, MaxValueLength));
        foreach (var c in value)
        {
            if (sb.Length >= MaxValueLength) break;
            sb.Append(char.IsControl(c) || Special.Contains(c) ? '_' : c);
        }
        return sb.ToString();
    }
}
