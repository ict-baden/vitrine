// SPDX-License-Identifier: MIT
using Vitrine.Abstractions;

namespace Vitrine.Core.Auth;

/// <summary>Lokale Gruppen des Rechners (Windows: NetLocalGroupGetMembers); Schnittstelle, damit Tests ohne Windows auskommen.</summary>
public interface ILocalGroupDirectory
{
    /// <summary>SID der Kontendomäne des Rechners (S-1-5-21-a-b-c), null = unbekannt.</summary>
    string? MachineSid { get; }

    /// <summary>Direkte Mitglieder der lokalen Gruppe als SIDs; null = Gruppe unbekannt oder Abfrage fehlgeschlagen.</summary>
    IReadOnlyCollection<string>? MemberSids(string groupSid);
}

/// <summary>
/// Lokale Gruppen für Anmeldungen mit Microsoft Entra ID. Windows-Anmeldungen (Kennwort, Hello, Anmeldedialog) liefern die
/// Gruppen des Tokens als SIDs, darunter lokale Gruppen wie „Vitrine-Entsperrer“. Eine Entra-Anmeldung liefert nur die
/// Claims (Objekt-IDs im groups-Claim, App-Rollen) – eine lokale Gruppe in Unlock.AllowedGroups passte daher nie.
/// Hier bildet Vitrine die SIDs, unter denen Windows das Konto und seine Entra-Gruppen auf einem Entra-gebundenen Gerät
/// führt (S-1-12-1-… aus der Objekt-ID, <see cref="EntraClaims.SidFromObjectId"/>), und schaut in den Mitgliedern der
/// lokalen Gruppen nach. Treffer kommen als SID in <see cref="AuthOutcome.Groups"/> (dann greift die normale Regelprüfung)
/// und in <see cref="AuthOutcome.Details"/> („localGroups“, fürs Protokoll). Mitglied der Administratoren
/// (S-1-5-32-544) → <see cref="AuthOutcome.IsAdministrator"/>.
/// Grenzen: nur direkte Mitglieder (lokale Gruppen enthalten keine lokalen Gruppen); Entra-Gruppen nur, wenn sie im
/// groups-Claim stehen – bei mehr als 200 Gruppen ersetzt Entra den Claim durch _claim_names (Überlauf), dann zählt nur
/// das Benutzerkonto selbst. Vitrine fragt Microsoft Graph bewusst nicht ab.
/// </summary>
public static class EntraLocalGroups
{
    /// <summary>VORDEFINIERT\Administratoren.</summary>
    public const string AdministratorsSid = "S-1-5-32-544";

    /// <summary>Eintrag in <see cref="AuthOutcome.Details"/>: passende lokale Gruppen als SIDs, durch Leerzeichen getrennt.</summary>
    public const string Detail = "localGroups";

    /// <summary>
    /// Lokale Gruppe dieses Rechners? Vordefinierte (S-1-5-32-…) oder eine der Kontendomäne des Rechners
    /// (<paramref name="machineSid"/>-RID). Domänen- und Entra-Gruppen nicht.
    /// </summary>
    public static bool IsLocalGroupSid(string? sid, string? machineSid)
    {
        if (string.IsNullOrWhiteSpace(sid)) return false;
        sid = sid.Trim();
        if (HasRidAfter(sid, "S-1-5-32")) return true;
        return !string.IsNullOrWhiteSpace(machineSid) && machineSid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase)
            && HasRidAfter(sid, machineSid.Trim());
    }

    /// <summary><paramref name="sid"/> = <paramref name="prefix"/>-Zahl.</summary>
    private static bool HasRidAfter(string sid, string prefix) =>
        sid.Length > prefix.Length + 1 && sid.StartsWith(prefix + "-", StringComparison.OrdinalIgnoreCase)
        && sid[(prefix.Length + 1)..].All(char.IsAsciiDigit);

    /// <summary>
    /// SIDs der angemeldeten Person, wie Windows sie auf einem Entra-gebundenen Gerät kennt: das Konto (aus der oid in
    /// <see cref="AuthOutcome.UserId"/>) und jede Entra-Gruppe aus dem groups-Claim (Objekt-IDs). App-Rollen
    /// (<see cref="EntraClaims.RolesDetail"/>) zählen nie, auch nicht, wenn ihr Wert eine GUID ist: Sonst würde eine Rolle
    /// mit dem Wert der Objekt-ID einer Gruppe zur Mitgliedschaft in deren lokalen Gruppen.
    /// </summary>
    public static HashSet<string> PersonSids(AuthOutcome o)
    {
        var sids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (EntraClaims.SidFromObjectId(o.UserId) is { } user) sids.Add(user);
        var roles = o.Details.TryGetValue(EntraClaims.RolesDetail, out var r)
            ? r.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToHashSet(StringComparer.OrdinalIgnoreCase)
            : [];
        foreach (var g in o.Groups.Where(g => !roles.Contains(g)))
            if (EntraClaims.SidFromObjectId(g) is { } group) sids.Add(group);
        return sids;
    }

    /// <summary>
    /// Ergänzt ein erfolgreiches Entra-Ergebnis um die lokalen Gruppen aus <paramref name="allowedGroups"/> und die
    /// Administratoren, in denen die Person (Konto oder eine ihrer Entra-Gruppen) direktes Mitglied ist. Mitglieder werden
    /// nur für diesen Aufruf zwischengespeichert (je Entsperr-Versuch neu gelesen).
    /// </summary>
    /// <param name="resolveSid">„Gruppe“, „.\Gruppe“, „RECHNER\Gruppe“ → SID (Windows); SIDs werden direkt genommen.</param>
    public static AuthOutcome Expand(AuthOutcome o, IEnumerable<string> allowedGroups, Func<string, string?>? resolveSid, ILocalGroupDirectory directory)
    {
        if (!o.Success) return o;
        var person = PersonSids(o);
        if (person.Count == 0) return o;

        var cache = new Dictionary<string, IReadOnlyCollection<string>?>(StringComparer.OrdinalIgnoreCase);
        bool IsMember(string groupSid)
        {
            if (!cache.TryGetValue(groupSid, out var members))
            {
                try { members = directory.MemberSids(groupSid); }
                catch { members = null; } // unbekannte Gruppe, keine Rechte: zählt als „kein Mitglied“
                cache[groupSid] = members;
            }
            return members is not null && members.Any(m => person.Contains(m.Trim()));
        }

        string? machine;
        try { machine = directory.MachineSid; } catch { machine = null; }

        var matched = new List<string>();
        foreach (var entry in allowedGroups.Where(e => !string.IsNullOrWhiteSpace(e)).Select(e => e.Trim()))
        {
            string? sid = entry.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase) ? entry : resolveSid?.Invoke(entry);
            if (sid is null || !IsLocalGroupSid(sid, machine)) continue;
            if (!matched.Contains(sid, StringComparer.OrdinalIgnoreCase) && IsMember(sid)) matched.Add(sid);
        }

        bool admin = IsMember(AdministratorsSid);
        if (admin && !matched.Contains(AdministratorsSid, StringComparer.OrdinalIgnoreCase)) matched.Add(AdministratorsSid);
        return matched.Count == 0 ? o : o.WithLocalGroups(matched, admin);
    }
}
