// SPDX-License-Identifier: MIT
using Vitrine.Abstractions;
using Vitrine.Core.Config;
using Vitrine.Core.Localization;

namespace Vitrine.Core.Auth;

/// <summary>Was MSAL nach einer erfolgreichen Anmeldung liefert (ID-Token-Claims und Kontodaten).</summary>
public sealed record EntraSignIn(
    IReadOnlyList<KeyValuePair<string, string>> Claims,
    string? TenantId,
    string? UniqueId,
    string? AccountUserName);

/// <summary>
/// Prüft eine Entra-Anmeldung gegen die Einstellungen und macht daraus ein <see cref="AuthOutcome"/>: zugelassene
/// Mandanten, Alter der Anmeldung (auth_time), Admin-Rolle, Zuordnung zum Sitzungsbenutzer. Ohne Netzwerk und ohne
/// MSAL, damit testbar.
/// Seit 2026-10-21 nur mit festgelegtem Mandanten (GUID in TenantId oder AllowedTenants): Mit „organizations“ allein
/// nahm Vitrine jedes Arbeitskonto jeder Organisation an (VIT-0117). Der Sitzungsbenutzer wird über unveränderliche
/// Kennungen erkannt (onprem_sid bzw. aus der oid abgeleitete SID), nicht mehr über den änderbaren preferred_username.
/// </summary>
public static class EntraClaims
{
    /// <summary>Eintrag in <see cref="AuthOutcome.Details"/>: App-Rollen (roles-Claim), durch Leerzeichen getrennt.</summary>
    public const string RolesDetail = "roles";

    /// <summary>Eintrag in <see cref="AuthOutcome.Details"/>: onprem_sid (hybride Konten), wenn das Token ihn enthält.</summary>
    public const string OnPremSidDetail = "onpremSid";

    /// <summary>App-Rolle, die Administratorrechte für Vitrine verleiht.</summary>
    public const string AdminRole = "Vitrine.Admin";

    /// <summary>Rollenvorlage „Globaler Administrator“ (wids-Claim).</summary>
    public const string GlobalAdminRoleTemplate = "62e90394-69f5-4237-9190-012177145e10";

    /// <param name="sessionSid">SID des angemeldeten Windows-Benutzers (für <see cref="AuthOutcome.IsSessionUser"/>).</param>
    /// <summary>Toleranz zwischen der Uhr von Microsoft (auth_time) und der des Rechners beim Entsperren.</summary>
    public static readonly TimeSpan FreshSignInSkew = TimeSpan.FromSeconds(120);

    /// <param name="authContext">Angeforderter Authentifizierungskontext (z. B. „c1“), null = keiner.</param>
    /// <param name="signInStartedAt">
    /// Entsperren und Administrator-Bestätigung: Beginn des Versuchs. Dann muss das ID-Token eine Anmeldung danach belegen
    /// (auth_time ≥ Beginn − <see cref="FreshSignInSkew"/>); ohne auth_time abgelehnt. Sonst entsperrte der Windows-
    /// Kontobroker mit einem Klick über das Primary Refresh Token des angemeldeten (technischen) Kontos, ganz ohne
    /// Anmeldedaten (0.3.0). null = keine Prüfung (Signaturen prüft der Dienst mit Nonce und auth_time).
    /// </param>
    public static AuthOutcome Evaluate(EntraSignIn signIn, EntraSettings s, string? sessionSid, DateTimeOffset now, string? authContext = null,
        DateTimeOffset? signInStartedAt = null)
    {
        string? Claim(string type) => signIn.Claims.FirstOrDefault(c => c.Key == type).Value;

        var tid = Claim("tid") ?? signIn.TenantId;
        var oid = Claim("oid") ?? signIn.UniqueId;
        var upn = Claim("preferred_username") ?? signIn.AccountUserName;
        var name = Claim("name") ?? upn;

        // Mandant prüfen: ohne festgelegten Mandanten gar nicht (sonst jedes Konto jeder Organisation)
        var allowedTenants = AllowedTenants(s);
        if (allowedTenants.Count == 0)
            return AuthOutcome.Fail(CoreText.Error(ErrorCodes.EntraTenantNotPinned), ErrorCodes.EntraTenantNotPinned);
        if (tid is null || !Guid.TryParse(tid, out var tenant) || !allowedTenants.Contains(tenant.ToString("D")))
            return AuthOutcome.Fail(CoreText.Error(ErrorCodes.TenantNotAllowed), ErrorCodes.TenantNotAllowed);

        // Entsperren: Anmeldung muss nach Beginn des Versuchs stattgefunden haben (keine Einmal-Klick-Anmeldung per SSO)
        // In der Zeit von Entra vergleichen: Abstand der Rechneruhr zu Microsoft aus iat (Ausstellung) gegen den Empfang.
        // Vorher ging eine um mehr als 2 Minuten vorgehende Uhr als „nicht frisch“ (VIT-0181) durch.
        var clockOffset = ClockOffset(Claim("iat"), now);
        if (signInStartedAt is { } started && FreshSignInRefusal(Claim("auth_time"), started + clockOffset) is { } refusal)
            return AuthOutcome.Fail(CoreText.Error(refusal), refusal);

        // Frische der Anmeldung prüfen (falls auth_time geliefert wird)
        if (s.MaxAuthAgeSeconds > 0 && long.TryParse(Claim("auth_time"), out var authTime))
        {
            var age = now + clockOffset - DateTimeOffset.FromUnixTimeSeconds(authTime);
            if (age > TimeSpan.FromSeconds(s.MaxAuthAgeSeconds))
                return AuthOutcome.Fail(CoreText.Error(ErrorCodes.SignInTooOld), ErrorCodes.SignInTooOld);
        }

        // Liefert Entra die erfüllten Kontexte (acrs), muss der angeforderte dabei sein. Durchgesetzt wird er von Entra
        // selbst (bedingter Zugriff); fehlt der Claim, bleibt es bei dieser Durchsetzung.
        var acrs = signIn.Claims.Where(c => c.Key == "acrs").Select(c => c.Value).ToList();
        if (authContext is not null && acrs.Count > 0 && !acrs.Contains(authContext, StringComparer.OrdinalIgnoreCase))
            return AuthOutcome.Fail(CoreText.Error(ErrorCodes.AuthContextNotMet), ErrorCodes.AuthContextNotMet);

        var groups = signIn.Claims.Where(c => c.Key is "groups" or "roles")
            .Select(c => c.Value)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var roles = signIn.Claims.Where(c => c.Key == "roles").Select(c => c.Value);
        var wids = signIn.Claims.Where(c => c.Key == "wids").Select(c => c.Value);
        // Administrator nur aus App-Rollen (roles) oder der Rollenvorlage (wids), nie aus Gruppennamen im groups-Claim.
        // Der Mandant ist oben schon auf die festgelegten beschränkt. Dazu kommt beim Entsperren die Mitgliedschaft in den
        // lokalen Administratoren (Konto oder Entra-Gruppe, EntraLocalGroups.Expand, nur in der App mit Windows-Zugriff).
        bool isAdmin = roles.Contains(AdminRole, StringComparer.OrdinalIgnoreCase) || wids.Contains(GlobalAdminRoleTemplate, StringComparer.OrdinalIgnoreCase);

        var details = new Dictionary<string, string> { ["tid"] = tid ?? "", ["oid"] = oid ?? "" };
        var amr = signIn.Claims.Where(c => c.Key == "amr").Select(c => c.Value).ToList();
        if (amr.Count > 0) details["amr"] = string.Join(' ', amr);
        if (acrs.Count > 0) details["acrs"] = string.Join(' ', acrs);
        if (Claim("onprem_sid") is { Length: > 0 } onPremSid) details[OnPremSidDetail] = onPremSid;
        // App-Rollen getrennt festhalten: Groups enthält groups und roles; lokale Gruppen (EntraLocalGroups) dürfen nur aus
        // dem groups-Claim abgeleitet werden – eine App-Rolle mit GUID als Wert ist keine Entra-Gruppe
        var roleList = roles.ToList();
        if (roleList.Count > 0) details[RolesDetail] = string.Join(' ', roleList);

        return new AuthOutcome
        {
            Success = true,
            UserName = upn,
            DisplayName = name,
            UserId = oid,
            TenantId = tid,
            Groups = groups,
            IsAdministrator = isAdmin,
            IsSessionUser = IsSessionUser(Claim("onprem_sid"), oid, sessionSid),
            Details = details,
        };
    }

    /// <summary>
    /// Abstand der Uhr von Entra zur Rechneruhr: iat (Ausstellung des Tokens, Uhr von Entra) minus Empfang (Rechneruhr).
    /// Positiv = Rechneruhr geht nach. Ohne gültiges iat 0. Ein Rechnerzeitpunkt plus dieser Abstand ist die Zeit von
    /// Entra (bis auf die Laufzeit des Tokens, wenige Sekunden – darin liegt die Toleranz <see cref="FreshSignInSkew"/>).
    /// </summary>
    public static TimeSpan ClockOffset(string? iatClaim, DateTimeOffset receivedAt) =>
        long.TryParse(iatClaim, System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out var iat)
            ? DateTimeOffset.FromUnixTimeSeconds(iat) - receivedAt
            : TimeSpan.Zero;

    /// <summary>
    /// Belegt auth_time eine Anmeldung nach <paramref name="started"/> (mit <see cref="FreshSignInSkew"/> Toleranz)?
    /// null = ja; sonst der Fehlercode (VIT-0180 ohne auth_time, VIT-0181 zu alt). <paramref name="started"/> in der Zeit
    /// von Entra (<see cref="ClockOffset"/>).
    /// </summary>
    public static string? FreshSignInRefusal(string? authTimeClaim, DateTimeOffset started)
    {
        if (!long.TryParse(authTimeClaim, System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out var seconds))
            return ErrorCodes.EntraAuthTimeMissing;
        return DateTimeOffset.FromUnixTimeSeconds(seconds) < started - FreshSignInSkew ? ErrorCodes.EntraSignInNotFresh : null;
    }

    /// <summary>
    /// Authentifizierungskontext für diese Anmeldung: bei Signaturen der eigene, sonst der allgemeine; null = keiner oder
    /// ungültig. Ob ein eingetragener Wert ungültig ist, sagt <see cref="InvalidAuthContext"/> – dann darf nicht ohne
    /// Kontext angemeldet werden (sonst schaltete ein Tippfehler die Anforderung still ab).
    /// </summary>
    public static string? AuthContextFor(EntraSettings s, bool signature) =>
        Configured(s, signature) is { } c && IsValidAuthContext(c) ? c.ToLowerInvariant() : null;

    /// <summary>Eingetragener, aber ungültiger Kontext für diese Anmeldung (nicht c1 … c99), sonst null.</summary>
    public static string? InvalidAuthContext(EntraSettings s, bool signature) =>
        Configured(s, signature) is { } c && !IsValidAuthContext(c) ? c : null;

    /// <summary>Ungültige Werte in beiden Einstellungen (für die Meldungen beim Laden der Konfiguration).</summary>
    public static IEnumerable<string> InvalidAuthContexts(EntraSettings s) =>
        new[] { s.AuthenticationContext, s.SignatureAuthenticationContext }
            .Select(c => c?.Trim()).Where(c => !string.IsNullOrEmpty(c) && !IsValidAuthContext(c)).Select(c => c!);

    /// <summary>Kennungen der Kontexte sind c1 … c99 (Microsoft Entra ID); alles andere kommt nie in die Anfrage.</summary>
    public static bool IsValidAuthContext(string c) =>
        c.Length is 2 or 3 && c[0] is 'c' or 'C' && c[1] is >= '1' and <= '9' && c[1..].All(char.IsAsciiDigit);

    private static string? Configured(EntraSettings s, bool signature)
    {
        var c = signature && !string.IsNullOrWhiteSpace(s.SignatureAuthenticationContext) ? s.SignatureAuthenticationContext : s.AuthenticationContext;
        c = c?.Trim();
        return string.IsNullOrEmpty(c) ? null : c;
    }

    /// <summary>Claims-Anfrage für einen Authentifizierungskontext (Parameter „claims“ von OpenID Connect).</summary>
    public static string AuthContextClaims(string context) =>
        new System.Text.Json.Nodes.JsonObject
        {
            ["access_token"] = new System.Text.Json.Nodes.JsonObject
            {
                ["acrs"] = new System.Text.Json.Nodes.JsonObject { ["essential"] = true, ["value"] = context },
            },
        }.ToJsonString();

    /// <summary>
    /// Konfigurierter Mandant (wenn GUID) plus die weiteren zugelassenen, als GUID („D“, Kleinbuchstaben). Einträge, die
    /// keine GUID sind (Domänen, „organizations“), zählen nicht – der tid-Claim ist immer eine GUID. Leer = kein Mandant
    /// festgelegt: Entra ist dann gesperrt (VIT-0117).
    /// </summary>
    public static HashSet<string> AllowedTenants(EntraSettings s)
    {
        var allowed = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var t in s.AllowedTenants.Append(s.TenantId))
            if (Guid.TryParse(t?.Trim(), out var g)) allowed.Add(g.ToString("D"));
        return allowed;
    }

    /// <summary>Ist ein Mandant festgelegt? Sonst lehnt Vitrine jede Entra-Anmeldung ab, ohne den Browser zu öffnen.</summary>
    public static bool TenantPinned(EntraSettings s) => AllowedTenants(s).Count > 0;

    /// <summary>
    /// Gehört die Anmeldung zum Windows-Benutzer der Sitzung? Nur über unveränderliche Kennungen: onprem_sid (Hybrid,
    /// optionaler Claim der App-Registrierung) oder – bei Entra-gebundenen Konten – die SID, die Windows aus der
    /// Objekt-ID bildet (S-1-12-1-…). Der preferred_username taugt nicht: Er ist änderbar und nicht eindeutig.
    /// </summary>
    public static bool IsSessionUser(string? onPremSid, string? oid, string? sessionSid)
    {
        if (string.IsNullOrWhiteSpace(sessionSid)) return false;
        if (!string.IsNullOrWhiteSpace(onPremSid) && string.Equals(onPremSid.Trim(), sessionSid, StringComparison.OrdinalIgnoreCase))
            return true;
        return SidFromObjectId(oid) is { } sid && string.Equals(sid, sessionSid, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// SID eines Entra-Kontos auf einem Entra-gebundenen Gerät („AzureAD\name“): S-1-12-1- und die 16 Bytes der Objekt-ID
    /// als vier 32-Bit-Zahlen (Bytes in der Reihenfolge von <see cref="Guid.ToByteArray()"/>). null, wenn keine GUID.
    /// </summary>
    public static string? SidFromObjectId(string? oid)
    {
        if (!Guid.TryParse(oid?.Trim(), out var g)) return null;
        var b = g.ToByteArray();
        var parts = Enumerable.Range(0, 4).Select(i => System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(i * 4, 4)).ToString(System.Globalization.CultureInfo.InvariantCulture));
        return "S-1-12-1-" + string.Join('-', parts);
    }
}

public static class AuthOutcomeExtensions
{
    /// <summary>Dasselbe Ergebnis mit Token für die anfragende Anwendung (<see cref="AuthOutcome.Tokens"/>).</summary>
    public static AuthOutcome WithTokens(this AuthOutcome o, IReadOnlyDictionary<string, string> tokens) => Copy(o, o.Details, tokens);

    /// <summary>Dasselbe Ergebnis mit anderen Angaben fürs Protokoll; Token bleiben erhalten.</summary>
    public static AuthOutcome WithDetails(this AuthOutcome o, IReadOnlyDictionary<string, string> details) => Copy(o, details, o.Tokens);

    /// <summary>
    /// Dasselbe Ergebnis mit den passenden lokalen Gruppen (SIDs) zusätzlich in <see cref="AuthOutcome.Groups"/> und im
    /// Protokoll („localGroups“); <paramref name="administrator"/> = Mitglied der Administratoren (setzt nie zurück).
    /// </summary>
    public static AuthOutcome WithLocalGroups(this AuthOutcome o, IReadOnlyCollection<string> localGroupSids, bool administrator)
    {
        var groups = new HashSet<string>(o.Groups, StringComparer.OrdinalIgnoreCase);
        groups.UnionWith(localGroupSids);
        var details = new Dictionary<string, string>(o.Details) { [EntraLocalGroups.Detail] = string.Join(' ', localGroupSids) };
        return Copy(o, details, o.Tokens, groups, o.IsAdministrator || administrator);
    }

    /// <summary>Vollständige Kopie – neue Eigenschaften von <see cref="AuthOutcome"/> hier ergänzen, sonst gehen sie verloren.</summary>
    private static AuthOutcome Copy(AuthOutcome o, IReadOnlyDictionary<string, string> details, IReadOnlyDictionary<string, string> tokens,
        IReadOnlyCollection<string>? groups = null, bool? isAdministrator = null) => new()
    {
        Success = o.Success, Error = o.Error, ErrorCode = o.ErrorCode, UserName = o.UserName, DisplayName = o.DisplayName,
        UserId = o.UserId, Groups = groups ?? o.Groups, IsAdministrator = isAdministrator ?? o.IsAdministrator, TenantId = o.TenantId,
        IsSessionUser = o.IsSessionUser, Details = details, Tokens = tokens,
    };
}

/// <summary>
/// Ergebnis einer erfolgreichen Anmeldung auf dem Weg vom Anbieter über Entsperren oder Signatur bis zur Antwort der
/// Schnittstelle. Jeder Schritt ergänzt nur Angaben fürs Protokoll; die Token des Anbieters (ID-Token, Zugriffstoken)
/// bleiben bis zur Antwort an die anfragende Anwendung erhalten (vor 2026-10-20 gingen sie beim Prüfen verloren).
/// </summary>
public static class AuthResults
{
    /// <summary>Nach der Prüfung der Entsperr-Regeln: Verfahren (<c>method</c>) dazu.</summary>
    public static AuthOutcome Verified(AuthOutcome outcome, string method) =>
        outcome.WithDetails(new Dictionary<string, string>(outcome.Details) { ["method"] = method });

    /// <summary>
    /// Nach dem Protokolleintrag der Signatur: Nummer, Hash und Vertrauensstufe des Eintrags dazu (<c>assurance</c>:
    /// „verified“/„client“ vom Dienst, „local“ ohne Dienst). Interne Token (<see cref="ProofIdToken"/>, <see cref="Ticket"/>)
    /// werden entfernt.
    /// </summary>
    public static AuthOutcome Signed(AuthOutcome who, string? auditHash, long auditSeq, string? assurance = null)
    {
        var details = new Dictionary<string, string>(who.Details)
        {
            ["auditHash"] = auditHash ?? "",
            ["auditSeq"] = auditSeq.ToString(System.Globalization.CultureInfo.InvariantCulture),
        };
        if (assurance is not null) details["assurance"] = assurance;
        return WithoutInternal(who).WithDetails(details);
    }

    /// <summary>
    /// Rohes ID-Token für die Prüfung durch den Dienst (#15), nur bei Signaturen. Bleibt intern: geht nie in die Antwort
    /// der Schnittstelle (dort nur <c>id_token</c> mit Entra.ShareIdToken) und nie ins Protokoll.
    /// </summary>
    public const string ProofIdToken = "vitrine:proof_id_token";

    /// <summary>Einmal-Ticket des Dienstes zwischen geprüfter Anmeldung und Signatur (intern).</summary>
    public const string Ticket = "vitrine:ticket";

    /// <summary>Ohne die internen Token.</summary>
    public static AuthOutcome WithoutInternal(AuthOutcome o) =>
        o.Tokens.ContainsKey(ProofIdToken) || o.Tokens.ContainsKey(Ticket)
            ? o.WithTokens(o.Tokens.Where(t => t.Key is not (ProofIdToken or Ticket)).ToDictionary(t => t.Key, t => t.Value))
            : o;
}
