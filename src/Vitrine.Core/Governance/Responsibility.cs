// SPDX-License-Identifier: MIT
using System.Globalization;
using Vitrine.Abstractions;
using Vitrine.Core.Auth;

namespace Vitrine.Core.Governance;

/// <summary>Wer ist gerade für den Rechner verantwortlich (zuletzt entsperrt bzw. an Windows angemeldet)?</summary>
/// <param name="Key">Vergleichsschlüssel (SID, sonst Kontoname klein; Entra-Objekt-IDs als S-1-12-1-SID).</param>
/// <param name="UserName">Konto wie im Protokoll.</param>
/// <param name="Name">Anzeigename (sonst Konto).</param>
/// <param name="Since">Seit wann (UTC).</param>
/// <param name="Method">Verfahren der Anmeldung (<see cref="ResponsibilityTracker.SessionSignIn"/> für die Windows-Anmeldung).</param>
public sealed record ResponsiblePerson(string Key, string UserName, string Name, DateTimeOffset Since, string Method);

/// <summary>Wechsel der Verantwortung: von (null = niemand bekannt) zu.</summary>
public sealed record ResponsibilityChange(ResponsiblePerson? From, ResponsiblePerson To);

/// <summary>
/// Verfolgt die verantwortliche Person (GxP: „wer ist jetzt für den Rechner verantwortlich“). Zu Beginn ist es der an
/// Windows angemeldete Benutzer der Sitzung. Entsperrt eine andere Person, wechselt die Verantwortung – das meldet
/// <see cref="Unlocked"/>, damit es als ResponsibilityChanged ins Protokoll kommt. Entsperrt dieselbe Person erneut, bleibt
/// „seit“ unverändert. Das gemeinsame Entsperr-Kennwort identifiziert niemanden: Die Verantwortung geht dann auf
/// „gemeinsames Entsperr-Kennwort“ über (Schlüssel <see cref="SharedKey"/>), damit sichtbar ist, dass keine Person bekannt ist.
/// Mit dem Abmelden der Sitzung endet alles (<see cref="Reset"/>); der Zustand liegt nur im Speicher der Sitzungs-App.
/// </summary>
public sealed class ResponsibilityTracker
{
    /// <summary>Verfahren für die Windows-Anmeldung der Sitzung.</summary>
    public const string SessionSignIn = "session";

    /// <summary>Schlüssel für Entsperren mit dem gemeinsamen Entsperr-Kennwort.</summary>
    public const string SharedKey = "shared";

    private readonly object _gate = new();
    private ResponsiblePerson? _current;

    public ResponsiblePerson? Current { get { lock (_gate) return _current; } }

    /// <summary>Beginn der Sitzung: Benutzer der Windows-Anmeldung ist verantwortlich (kein Wechsel, kein Eintrag).</summary>
    public void Begin(string userName, string? sid, string? displayName, DateTimeOffset since)
    {
        var key = Key(sid, userName);
        lock (_gate) _current = new ResponsiblePerson(key, userName, string.IsNullOrWhiteSpace(displayName) ? userName : displayName!, since, SessionSignIn);
    }

    /// <summary>Nach erfolgreichem Entsperren. Liefert den Wechsel, wenn eine andere Person entsperrt hat, sonst null.</summary>
    public ResponsibilityChange? Unlocked(AuthOutcome who, string method, DateTimeOffset now)
    {
        if (!who.Success) return null;
        var key = KeyOf(who);
        var user = who.UserName ?? who.DisplayName ?? "?";
        var person = new ResponsiblePerson(key, user, who.DisplayName ?? user, now, method);
        lock (_gate)
        {
            if (_current is { } cur && string.Equals(cur.Key, key, StringComparison.OrdinalIgnoreCase)) return null;
            var change = new ResponsibilityChange(_current, person);
            _current = person;
            return change;
        }
    }

    /// <summary>Abmelden der Sitzung: niemand mehr verantwortlich.</summary>
    public void Reset()
    {
        lock (_gate) _current = null;
    }

    /// <summary>Vergleichsschlüssel einer Anmeldung.</summary>
    public static string KeyOf(AuthOutcome o) => UnlockPolicy.IsShared(o) ? SharedKey : Key(o.UserId, o.UserName);

    private static string Key(string? id, string? userName)
    {
        // Entra-Anmeldung liefert die Objekt-ID, Windows-Anmeldung desselben Kontos (Entra-gebunden) die SID S-1-12-1-…
        if (EntraClaims.SidFromObjectId(id) is { } sid) return sid;
        if (!string.IsNullOrWhiteSpace(id)) return id.Trim();
        return (userName ?? "").Trim().ToLowerInvariant();
    }

    /// <summary>Detail des Protokolleintrags (sprachunabhängig): „von -> zu“.</summary>
    public static string AuditDetail(ResponsibilityChange c) => $"{c.From?.UserName ?? "(none)"} -> {c.To.UserName}";

    /// <summary>Data des Protokolleintrags.</summary>
    public static Dictionary<string, string> AuditData(ResponsibilityChange c)
    {
        var d = new Dictionary<string, string>
        {
            ["toUser"] = c.To.UserName,
            ["toName"] = c.To.Name,
            ["method"] = c.To.Method,
        };
        if (c.From is { } f)
        {
            d["fromUser"] = f.UserName;
            d["fromName"] = f.Name;
            d["fromMethod"] = f.Method;
            d["fromSince"] = f.Since.UtcDateTime.ToString("O", CultureInfo.InvariantCulture);
        }
        return d;
    }
}
