// SPDX-License-Identifier: MIT
namespace Vitrine.Core.Governance;

/// <summary>
/// Begründungen (Notfall-Anmeldung, Administrator-Bestätigung, Änderung der Einstellungen): Steuerzeichen entfernt,
/// Leerraum zusammengefasst, auf <see cref="MaxLength"/> gekürzt – sie stehen im Protokoll und im Ereignisprotokoll.
/// </summary>
public static class Reasons
{
    /// <summary>Längste Begründung (passt in ein Datenfeld des Dienstes, PipeProtocol.MaxFieldLength).</summary>
    public const int MaxLength = 500;

    /// <summary>Bereinigte Begründung; null, wenn nichts übrig bleibt.</summary>
    public static string? Normalize(string? reason)
    {
        if (reason is null) return null;
        var parts = new string(reason.Select(c => char.IsControl(c) ? ' ' : c).ToArray())
            .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var text = string.Join(' ', parts);
        if (text.Length == 0) return null;
        return text.Length > MaxLength ? text[..MaxLength] : text;
    }

    /// <summary>Mindestlänge aus der Konfiguration, nie unter 1 und nie über <see cref="MaxLength"/>.</summary>
    public static int EffectiveMinLength(int configured) => Math.Clamp(configured, 1, MaxLength);

    /// <summary>Lang genug (nach dem Bereinigen, ohne Leerzeichen am Rand)?</summary>
    public static bool IsSufficient(string? reason, int minLength) =>
        Normalize(reason) is { } r && r.Length >= EffectiveMinLength(minLength);
}
