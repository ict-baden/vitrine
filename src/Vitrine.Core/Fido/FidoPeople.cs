// SPDX-License-Identifier: MIT
using Vitrine.Abstractions;
using Vitrine.Core.Auth;
using Vitrine.Core.Localization;

namespace Vitrine.Core.Fido;

/// <summary>Woher die Gruppen einer Anmeldung mit Sicherheitsschlüssel stammen (steht im Protokoll als <c>groupsSource</c>).</summary>
public static class FidoGroupsSource
{
    /// <summary>Gerade gelesen: S4U-Anmeldung des Dienstes (Domänencontroller bzw. lokales Konto).</summary>
    public const string Live = "live";
    /// <summary>Konto nur in Microsoft Entra ID: lokale Gruppen dieses Rechners, gerade gelesen; Entra-Gruppen und Kontostatus unbekannt.</summary>
    public const string Local = "local";
    /// <summary>Zwischengespeichert von einer früheren Auflösung (ohne Domänencontroller, höchstens Fido.OfflineMaxHours alt).</summary>
    public const string Cached = "cached";
}

/// <summary>Zustand eines Kontos laut Windows.</summary>
public enum FidoAccountState
{
    Ok,
    Disabled,
    LockedOut,
    /// <summary>Konto oder Kennwort abgelaufen.</summary>
    Expired,
    /// <summary>Sonstige Kontoeinschränkung (Anmeldezeiten, Arbeitsstationen …).</summary>
    Restricted,
    /// <summary>Konto gibt es nicht (mehr) oder es hat eine andere SID.</summary>
    NotFound,
    /// <summary>Kein Domänencontroller erreichbar: Zustand und Gruppen unbekannt.</summary>
    Offline,
}

/// <summary>Konto, für das registriert wird.</summary>
public sealed record FidoAccount(string Sid, string Name, string? Upn);

/// <summary>Ergebnis der Auflösung einer Person durch Windows.</summary>
/// <param name="Groups">Gruppen-SIDs (bei <see cref="FidoAccountState.Ok"/>).</param>
/// <param name="Source"><see cref="FidoGroupsSource.Live"/> oder <see cref="FidoGroupsSource.Local"/>.</param>
/// <param name="Detail">Windows-Fehler o. Ä. fürs Protokoll (englisch).</param>
public sealed record FidoResolution(FidoAccountState State, string? Name, IReadOnlyCollection<string> Groups, string Source, string? Detail = null)
{
    public static FidoResolution Failed(FidoAccountState state, string? detail) => new(state, null, Array.Empty<string>(), FidoGroupsSource.Live, detail);
}

/// <summary>
/// Konten für Sicherheitsschlüssel (im Dienst: LookupAccountName, S4U-Anmeldung mit LsaLogonUser, lokale Gruppen).
/// Hinter einer Schnittstelle, damit Tests ohne Windows und ohne Domäne auskommen.
/// </summary>
public interface IFidoAccounts
{
    /// <summary>„DOMÄNE\name“, „AzureAD\upn“, „.\name“, UPN oder SID → Konto; null, wenn unbekannt.</summary>
    FidoAccount? Lookup(string input);

    /// <summary>Kontostatus und aktuelle Gruppen der Person.</summary>
    Task<FidoResolution> ResolveAsync(string sid, string name, string? upn, CancellationToken ct = default);
}

/// <summary>Gruppen, mit denen eine Person angemeldet wird, oder warum nicht.</summary>
public sealed record FidoPersonDecision(bool Allowed, IReadOnlyCollection<string> Groups, string Source, DateTimeOffset? ResolvedAt, string? Code, string? Problem)
{
    public static FidoPersonDecision Refuse(string code, string problem) => new(false, Array.Empty<string>(), "", null, code, problem);
}

/// <summary>Entscheidungen zu Personen beim Anmelden mit Sicherheitsschlüssel.</summary>
public static class FidoPeople
{
    /// <summary>Konto nur in Microsoft Entra ID (SID S-1-12-1-…): Windows kann dafür keine S4U-Anmeldung bilden.</summary>
    public static bool IsEntraOnly(string? sid) => sid?.StartsWith("S-1-12-1-", StringComparison.OrdinalIgnoreCase) == true;

    /// <summary>
    /// Gruppen aus der Auflösung oder, ohne Domänencontroller, aus dem Zwischenspeicher, wenn er höchstens
    /// <paramref name="offlineMaxHours"/> alt ist. Gesperrte, deaktivierte, abgelaufene oder unbekannte Konten: abgelehnt.
    /// </summary>
    public static FidoPersonDecision Decide(FidoResolution r, FidoGroupSnapshot? cached, DateTimeOffset now, int offlineMaxHours)
    {
        switch (r.State)
        {
            case FidoAccountState.Ok:
                return new FidoPersonDecision(true, r.Groups, r.Source, now, null, null);
            case FidoAccountState.Offline:
                if (cached is null)
                    return FidoPersonDecision.Refuse(ErrorCodes.FidoOfflineTooLong, $"no domain controller and no cached groups ({r.Detail})");
                var age = now - cached.ResolvedAt;
                if (offlineMaxHours <= 0 || age > TimeSpan.FromHours(offlineMaxHours) || age < -TimeSpan.FromHours(1))
                    return FidoPersonDecision.Refuse(ErrorCodes.FidoOfflineTooLong,
                        $"no domain controller, cached groups from {cached.ResolvedAt:u} older than {offlineMaxHours} h ({r.Detail})");
                return new FidoPersonDecision(true, cached.Groups, FidoGroupsSource.Cached, cached.ResolvedAt, null, null);
            default:
                return FidoPersonDecision.Refuse(ErrorCodes.FidoAccountUnusable, $"account {r.State.ToString().ToLowerInvariant()}{(r.Detail is null ? "" : $" ({r.Detail})")}");
        }
    }

    /// <summary>
    /// Windows-Fehler einer S4U-Anmeldung → Zustand. Netzwerk- und Domänencontroller-Fehler zählen als „offline“
    /// (dann gilt der Zwischenspeicher), Kontofehler als Ablehnung.
    /// </summary>
    public static FidoAccountState StateForWin32Error(int error) => error switch
    {
        0 => FidoAccountState.Ok,
        1331 => FidoAccountState.Disabled,               // ERROR_ACCOUNT_DISABLED
        1909 => FidoAccountState.LockedOut,              // ERROR_ACCOUNT_LOCKED_OUT
        1793 or 1330 or 1907 => FidoAccountState.Expired, // Konto abgelaufen, Kennwort abgelaufen, muss geändert werden
        1327 or 1328 or 1329 or 1384 or 1385 => FidoAccountState.Restricted,
        1317 or 1332 or 1326 or 1788 => FidoAccountState.NotFound, // kein solcher Benutzer, keine Zuordnung, Anmeldung abgelehnt
        // ERROR_NO_LOGON_SERVERS, NO_SUCH_DOMAIN, DOMAIN_CONTROLLER_NOT_FOUND, RPC nicht verfügbar, Netzwerkpfad, Zeitüberschreitung,
        // Netz nicht erreichbar, Vertrauensstellung, Uhrzeit (KRB_AP_ERR_SKEW über 1398)
        1311 or 1355 or 1908 or 1722 or 1727 or 53 or 1231 or 1232 or 1460 or 121 or 1786 or 1787 or 1789 or 1398 or 59 or 64 or 1219
            => FidoAccountState.Offline,
        // Unbekannt: ablehnen statt auf den Zwischenspeicher auszuweichen (lieber einmal zu streng)
        _ => FidoAccountState.Restricted,
    };

    /// <summary>
    /// Kennungen der registrierenden Person: SIDs (Windows-Anmeldung: <see cref="AuthOutcome.UserId"/>; Microsoft-Anmeldung:
    /// die aus der Objekt-ID gebildete SID S-1-12-1-… und <c>onprem_sid</c> bei hybriden Konten) und Namen (UPN, Kontoname).
    /// </summary>
    public static (HashSet<string> Sids, HashSet<string> Names) Identities(AuthOutcome who)
    {
        var sids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        void Sid(string? s)
        {
            if (!string.IsNullOrWhiteSpace(s) && s.Trim().StartsWith("S-1-", StringComparison.OrdinalIgnoreCase)) sids.Add(s.Trim());
        }
        void Name(string? n)
        {
            if (!string.IsNullOrWhiteSpace(n)) names.Add(n.Trim());
        }
        Sid(who.UserId);
        Sid(EntraClaims.SidFromObjectId(who.UserId));
        Sid(EntraClaims.SidFromObjectId(who.Details.GetValueOrDefault("oid")));
        Sid(who.Details.GetValueOrDefault(EntraClaims.OnPremSidDetail));
        Name(who.UserName);
        Name(who.Details.GetValueOrDefault("upn"));
        return (sids, names);
    }

    /// <summary>
    /// Registriert die Person für sich selbst? Grund (englisch) oder null. Ohne SID der registrierenden Person ist der
    /// Vergleich nicht sicher – dann ebenfalls abgelehnt (Prüfung vom 2026-10-30: Microsoft-Anmeldungen liefern eine
    /// Objekt-ID, die nie gleich einer SID ist).
    /// </summary>
    public static string? SelfRegistration(FidoAccount person, AuthOutcome registrar)
    {
        var (sids, names) = Identities(registrar);
        if (sids.Count == 0) return "the registrar's identity cannot be expressed as a Windows SID";
        if (sids.Contains(person.Sid)) return "registering a key for oneself is not allowed";
        if (person.Upn is { } upn && names.Contains(upn)) return "registering a key for oneself is not allowed (same UPN)";
        if (names.Contains(person.Name)) return "registering a key for oneself is not allowed (same account name)";
        return null;
    }

    /// <summary>Anzeigename aus „DOMÄNE\name“ (Teil nach dem Backslash).</summary>
    public static string DisplayName(string name)
    {
        int i = name.IndexOf('\\');
        return i >= 0 ? name[(i + 1)..] : name;
    }
}

/// <summary>
/// Vorübergehende Sperre nach Fehlversuchen (Fido.MaxFailedAttempts, Fido.BlockMinutes), je Schlüssel und je Person
/// getrennt gezählt. Nur im Speicher des Dienstes (ein Neustart des Dienstes setzt die Zähler zurück).
/// </summary>
public sealed class FidoAttempts
{
    private sealed class Entry
    {
        public int Failures;
        public DateTimeOffset? BlockedUntil;
    }

    private readonly Dictionary<string, Entry> _entries = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();

    public static string ForCredential(string idHash) => "key:" + idHash;
    public static string ForPerson(string sid) => "sid:" + sid;

    /// <summary>Anfragende Sitzung: Fehlversuche ohne gültige Signatur (jedes Programm kann sie erzeugen).</summary>
    public static string ForSession(int session, string sid) => $"session:{session}:{sid}";

    /// <summary>Restzeit der Sperre, null wenn nicht gesperrt.</summary>
    public TimeSpan? Blocked(string key, DateTimeOffset now)
    {
        lock (_gate)
        {
            if (!_entries.TryGetValue(key, out var e) || e.BlockedUntil is not { } until) return null;
            if (until > now) return until - now;
            _entries.Remove(key); // Sperre abgelaufen: Zählung beginnt neu
            return null;
        }
    }

    /// <summary>Fehlversuch zählen. true, wenn der Schlüssel bzw. die Person jetzt gesperrt ist.</summary>
    public bool RecordFailure(string key, DateTimeOffset now, int maxFailed, int blockMinutes)
    {
        if (maxFailed <= 0) return false;
        lock (_gate)
        {
            if (!_entries.TryGetValue(key, out var e)) _entries[key] = e = new Entry();
            if (e.BlockedUntil is { } until && until <= now) { e.BlockedUntil = null; e.Failures = 0; }
            e.Failures++;
            if (e.Failures < maxFailed) return false;
            e.BlockedUntil = now + TimeSpan.FromMinutes(Math.Max(1, blockMinutes));
            return true;
        }
    }

    /// <summary>Nach einer gelungenen Anmeldung: Zählung zurücksetzen.</summary>
    public void Reset(string key)
    {
        lock (_gate) _entries.Remove(key);
    }
}
