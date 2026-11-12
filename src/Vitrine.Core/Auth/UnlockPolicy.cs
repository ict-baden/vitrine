// SPDX-License-Identifier: MIT
using Vitrine.Abstractions;
using Vitrine.Core.Config;
using Vitrine.Core.Localization;

namespace Vitrine.Core.Auth;

/// <summary>Ergebnis der Regelprüfung: erlaubt, sonst Meldung (mit Code) und Code allein.</summary>
public readonly record struct PolicyDecision(bool Allowed, string? Reason, string? Code)
{
    public static PolicyDecision Allow => new(true, null, null);

    public static PolicyDecision Deny(string code, params object?[] args) => new(false, CoreText.Error(code, args), code);
}

/// <summary>Entscheidet, ob eine erfolgreich angemeldete Person entsperren darf.</summary>
public static class UnlockPolicy
{
    /// <summary>Markierung in <see cref="AuthOutcome.Details"/> für das gemeinsame Entsperr-Kennwort.</summary>
    public const string SharedSecretDetail = "shared";

    public static bool IsShared(AuthOutcome o) => o.Details.TryGetValue(SharedSecretDetail, out var v) && v == "true";

    /// <param name="o">Ergebnis der Anmeldung.</param>
    /// <param name="s">Entsperr-Regeln.</param>
    /// <param name="requireAdmin">Nur Administratoren (Beenden, Einstellungen).</param>
    /// <param name="resolveSid">Löst „DOMÄNE\Gruppe“ zu einer SID auf (Windows); null = nur wörtlicher Vergleich.</param>
    public static PolicyDecision Evaluate(AuthOutcome o, UnlockSettings s, bool requireAdmin = false, Func<string, string?>? resolveSid = null)
    {
        if (!o.Success)
            return new(false, o.Error ?? CoreText.Error(ErrorCodes.SignInFailed), o.ErrorCode ?? ErrorCodes.SignInFailed);

        // Gemeinsames Entsperr-Kennwort: Besitz des Kennworts genügt (aber nie für Admin-Aktionen).
        if (IsShared(o))
            return requireAdmin ? PolicyDecision.Deny(ErrorCodes.PersonalAdminRequired) : PolicyDecision.Allow;

        if (s.AllowedDomains.Count > 0 && !DomainAllowed(o.UserName, s.AllowedDomains))
            return PolicyDecision.Deny(ErrorCodes.DomainNotAllowed);

        if (requireAdmin)
            return o.IsAdministrator ? PolicyDecision.Allow : PolicyDecision.Deny(ErrorCodes.AdminRequired);

        var a = s.Allowed;
        if (a.HasFlag(UnlockAllowed.AnyAuthenticated)) return PolicyDecision.Allow;
        if (a.HasFlag(UnlockAllowed.SessionUser) && o.IsSessionUser) return PolicyDecision.Allow;
        if (a.HasFlag(UnlockAllowed.Administrators) && o.IsAdministrator) return PolicyDecision.Allow;

        if (a.HasFlag(UnlockAllowed.Users) && MatchesAny(o, s.AllowedUsers, isGroup: false, resolveSid)) return PolicyDecision.Allow;
        if (a.HasFlag(UnlockAllowed.Groups) && MatchesAny(o, s.AllowedGroups, isGroup: true, resolveSid)) return PolicyDecision.Allow;

        return PolicyDecision.Deny(ErrorCodes.NotAllowedToUnlock, o.DisplayName ?? o.UserName);
    }

    /// <summary>Ist die Person Mitglied einer der Gruppen (Schreibweise wie Unlock.AllowedGroups)?</summary>
    public static bool InGroups(AuthOutcome o, IEnumerable<string> groups, Func<string, string?>? resolveSid = null) =>
        MatchesAny(o, groups, isGroup: true, resolveSid);

    /// <summary>Unlock.AllowedDomains erlaubt das Konto (leere Liste = alle).</summary>
    public static bool DomainAllowed(AuthOutcome o, UnlockSettings s) => s.AllowedDomains.Count == 0 || DomainAllowed(o.UserName, s.AllowedDomains);

    private static bool MatchesAny(AuthOutcome o, IEnumerable<string> entries, bool isGroup, Func<string, string?>? resolveSid)
    {
        foreach (var entry in entries.Where(e => !string.IsNullOrWhiteSpace(e)))
        {
            var e = entry.Trim();
            var sid = resolveSid?.Invoke(e);
            if (isGroup)
            {
                if (o.Groups.Contains(e, StringComparer.OrdinalIgnoreCase)) return true;
                if (sid is not null && o.Groups.Contains(sid, StringComparer.OrdinalIgnoreCase)) return true;
            }
            else
            {
                if (string.Equals(e, o.UserName, StringComparison.OrdinalIgnoreCase)) return true;
                if (o.UserId is not null && string.Equals(e, o.UserId, StringComparison.OrdinalIgnoreCase)) return true;
                if (sid is not null && string.Equals(sid, o.UserId, StringComparison.OrdinalIgnoreCase)) return true;
            }
        }
        return false;
    }

    /// <summary>Domäne aus „DOMÄNE\name“ oder UPN-Suffix aus „name@contoso.com“.</summary>
    internal static string? DomainOf(string? user)
    {
        if (string.IsNullOrEmpty(user)) return null;
        int bs = user.IndexOf('\\');
        if (bs > 0) return user[..bs];
        int at = user.LastIndexOf('@');
        return at >= 0 && at < user.Length - 1 ? user[(at + 1)..] : null;
    }

    private static bool DomainAllowed(string? user, List<string> domains)
    {
        var dom = DomainOf(user);
        return dom is not null && domains.Any(d => string.Equals(d.Trim(), dom, StringComparison.OrdinalIgnoreCase));
    }
}
