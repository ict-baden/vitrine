// SPDX-License-Identifier: MIT
using System.Globalization;

namespace Vitrine.Core.Config;

/// <summary>Zeitplan-Einträge „18:00“ bzw. „07:30@Mo,Di,Mi“ oder „07:30@Mo-Fr“ lesen, schreiben und auswerten.</summary>
public static class Schedule
{
    /// <summary>
    /// "HH:mm" (auch "H.mm") oder "HH:mm@Tage". Tage als Kürzel: deutsch (Mo, Di, Mi, Do, Fr, Sa, So), englisch (Mon … Sun),
    /// englischer Name oder Kurz-/Langname in der Sprache der Oberfläche (<paramref name="culture"/>, z. B. „lun.“), auch als
    /// Bereich („Mo-Fr“, „Fr-Mo“ über das Wochenende). null, wenn etwas nicht lesbar ist – auch ein einzelner Tag: Ein
    /// unbekannter Tag galt früher als „jeden Tag“, und die Zeile sperrte dann auch am Wochenende (Prüfung vom 2026-10-20).
    /// </summary>
    public static ScheduleEntry? Parse(string s) => Parse(s, null);

    public static ScheduleEntry? Parse(string s, CultureInfo? culture)
    {
        var parts = s.Split('@', 2);
        if (NormalizeTime(parts[0]) is not { } time) return null;
        var e = new ScheduleEntry { Time = time };
        if (parts.Length == 2)
        {
            var tokens = parts[1].Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (tokens.Length == 0) return null; // „18:00@“: Tage fehlen – nicht stillschweigend jeden Tag
            foreach (var token in tokens)
            {
                if (!TryParseDays(token, culture, out var days)) return null;
                foreach (var d in days)
                    if (!e.Days.Contains(d)) e.Days.Add(d);
            }
        }
        return e;
    }

    /// <summary>Uhrzeit „18:00“, „7:30“ oder „18.00“ in der Form mit Doppelpunkt, sonst null (auch „6:30 PM“).</summary>
    public static string? NormalizeTime(string text)
    {
        var time = text.Trim().Replace('.', ':');
        return TimeOnly.TryParseExact(time, ["H:mm", "HH:mm"], CultureInfo.InvariantCulture, DateTimeStyles.None, out _) ? time : null;
    }

    /// <summary>Ein Tag oder ein Bereich „Mo-Fr“ (in Wochenreihenfolge, „Sa-Mo“ über das Wochenende).</summary>
    private static bool TryParseDays(string token, CultureInfo? culture, out List<DayOfWeek> days)
    {
        days = [];
        var range = token.Split('-', 2, StringSplitOptions.TrimEntries);
        if (range.Length == 1)
        {
            if (!TryParseDay(token, culture, out var day)) return false;
            days.Add(day);
            return true;
        }
        if (!TryParseDay(range[0], culture, out var from) || !TryParseDay(range[1], culture, out var to)) return false;
        for (var d = from; ; d = (DayOfWeek)(((int)d + 1) % 7))
        {
            days.Add(d);
            if (d == to) return true;
        }
    }

    /// <summary>Text der Eingabezeile mit Tageskürzeln in der Sprache <paramref name="culture"/> (null = englisch).</summary>
    public static string Format(ScheduleEntry e, CultureInfo? culture = null) =>
        e.Days.Count == 0 ? e.Time : $"{e.Time}@{string.Join(',', e.Days.Select(d => DayName(d, culture)))}";

    /// <summary>Kurzname ohne Punkt („Mo“, „lun“, „周一“); ohne Kultur englisch („Mon“).</summary>
    public static string DayName(DayOfWeek d, CultureInfo? culture)
    {
        if (culture is null || culture.Equals(CultureInfo.InvariantCulture)) return d.ToString()[..3];
        var name = culture.DateTimeFormat.GetAbbreviatedDayName(d).Trim().TrimEnd('.');
        return name.Length == 0 || name.Contains(',') || name.Contains('@') || name.Contains('-') ? d.ToString()[..3] : name;
    }

    public static bool TryParseDay(string d, out DayOfWeek day) => TryParseDay(d, null, out day);

    public static bool TryParseDay(string d, CultureInfo? culture, out DayOfWeek day)
    {
        if (culture is not null)
        {
            var text = d.Trim().TrimEnd('.');
            foreach (var candidate in Enum.GetValues<DayOfWeek>())
            {
                if (string.Equals(text, DayName(candidate, culture), StringComparison.CurrentCultureIgnoreCase) ||
                    string.Equals(text, culture.DateTimeFormat.GetDayName(candidate), StringComparison.CurrentCultureIgnoreCase))
                {
                    day = candidate;
                    return true;
                }
            }
        }

        var name = d.Trim().ToLowerInvariant() switch
        {
            "mo" or "mon" => "Monday",
            "di" or "tue" => "Tuesday",
            "mi" or "wed" => "Wednesday",
            "do" or "thu" => "Thursday",
            "fr" or "fri" => "Friday",
            "sa" or "sat" => "Saturday",
            "so" or "sun" => "Sunday",
            var other => other,
        };
        // Zahlen („1“) nicht als Wochentag zulassen – Enum.TryParse würde sie annehmen
        if (name.Length > 0 && char.IsDigit(name[0])) { day = default; return false; }
        return Enum.TryParse(name, ignoreCase: true, out day) && Enum.IsDefined(day);
    }

    /// <summary>
    /// Welcher Eintrag ist jetzt fällig? Fällig ist ein Eintrag in der Minute ab seiner Uhrzeit, einmal pro Tag
    /// (<paramref name="firedToday"/> merkt sich die schon ausgelösten).
    /// </summary>
    public static ScheduleEntry? Due(DateTime now, IEnumerable<ScheduleEntry> entries, ISet<string> firedToday)
    {
        var today = DateOnly.FromDateTime(now);
        foreach (var e in entries)
        {
            if (NormalizeTime(e.Time) is not { } time ||
                !TimeOnly.TryParseExact(time, ["H:mm", "HH:mm"], CultureInfo.InvariantCulture, DateTimeStyles.None, out var t)) continue;
            if (e.Days.Count > 0 && !e.Days.Contains(now.DayOfWeek)) continue;
            var key = Key(e);
            if (firedToday.Contains(key)) continue;
            var due = today.ToDateTime(t);
            if (now >= due && now - due < TimeSpan.FromMinutes(1))
            {
                firedToday.Add(key);
                return e;
            }
        }
        return null;
    }

    private static string Key(ScheduleEntry e) => $"{e.Time.Trim()}|{string.Join(',', e.Days)}";
}
