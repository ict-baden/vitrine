// SPDX-License-Identifier: MIT
using System.Globalization;

namespace Vitrine.Core.Audit;

/// <summary>
/// Feste englische Texte für <see cref="AuditEntry.Detail"/> (das Protokoll ist sprachunabhängig, richtlinien/13) und
/// ihre Erkennung für die übersetzte Anzeige in den Einstellungen.
/// </summary>
public static class AuditDetails
{
    private const string LockedForPrefix = "Locked for ";

    /// <summary>„Locked for 62:00:00“: Dauer der Sperre in Stunden, Minuten, Sekunden – Stunden ohne Obergrenze.</summary>
    public static string LockedFor(TimeSpan duration) => LockedForPrefix + Duration(duration);

    /// <summary>
    /// Dauer als „h:mm:ss“ mit allen Stunden (62:00:00). Vorher „hh:mm:ss“ von TimeSpan, das die Tage wegließ: Eine Sperre
    /// über das Wochenende stand als „14:00:00“ im Audit-Trail (Prüfung vom 2026-10-20).
    /// </summary>
    public static string Duration(TimeSpan d)
    {
        if (d < TimeSpan.Zero) d = TimeSpan.Zero;
        return string.Create(CultureInfo.InvariantCulture, $"{(long)d.TotalHours:00}:{d.Minutes:00}:{d.Seconds:00}");
    }

    /// <summary>Ist das ein „Locked for …“-Detail? Dann die Dauer für die übersetzte Anzeige.</summary>
    public static bool TryLockedFor(string? detail, out string duration)
    {
        duration = "";
        if (detail is null || !detail.StartsWith(LockedForPrefix, StringComparison.Ordinal)) return false;
        duration = detail[LockedForPrefix.Length..];
        return duration.Length > 0;
    }
}
