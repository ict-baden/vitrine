// SPDX-License-Identifier: MIT
using Vitrine.Core.Config;
using Vitrine.Core.Localization;

namespace Vitrine.Core.Auth;

/// <summary>Hinweis auf eine Einstellung, mit der das Entsperren nicht wie eingestellt funktioniert.</summary>
/// <param name="Code">Fehlercode (VIT-0016, VIT-0017).</param>
/// <param name="Setting">Betroffene Einstellung, z. B. „Unlock.AllowedDomains“ (sprachunabhängig, fürs Protokoll).</param>
/// <param name="Entries">Betroffene Einträge, durch Komma getrennt (leer, wenn keine).</param>
public sealed record UnlockSetupWarning(string Code, string Setting, string Entries)
{
    /// <summary>Übersetzte Meldung mit Code.</summary>
    public string Message => Code == ErrorCodes.UnlockRulesNeverMatch ? CoreText.Error(Code, Setting, Entries)
        : Code == ErrorCodes.FidoDialogBlocked ? CoreText.Error(Code, Entries)
        : CoreText.Error(Code);

    /// <summary>Fürs Protokoll und Ereignisprotokoll: sprachunabhängig.</summary>
    public string AuditDetail => Entries.Length == 0 ? $"{Code} {Setting}" : $"{Code} {Setting}: {Entries}";
}

/// <summary>
/// Welche Verfahren am Sperrbildschirm angeboten werden. Microsoft Entra ID dort mit dem eigenen Anmeldefenster
/// (Standard seit 2026-10-27) oder dem Windows-Kontobroker; nicht, wenn keins von beiden geht (WebView2-Laufzeit fehlt,
/// kein Broker – <see cref="EntraSignInMode.OnLockScreen"/>). Einen System-Browser über der Sperre gibt es nie.
/// Bleibt so kein Verfahren übrig, entsperrt Vitrine mit dem Windows-Kennwort (<c>AuthRegistry.GetActiveAsync</c>) –
/// das meldet <see cref="Warnings"/>, ebenso Entsperr-Regeln, die zu keiner Windows-Anmeldung passen können.
/// </summary>
public static class LockScreenMethods
{
    /// <summary>Verfahren mit Windows-Konto: Name „DOMÄNE\Name“, Gruppen als SIDs (auch Sicherheitsschlüssel – die Person ist ein Windows-Konto).</summary>
    private static readonly HashSet<string> WindowsIdentity = new(StringComparer.OrdinalIgnoreCase) { "windows", "hello", WindowsLogonDialog.MethodId, Fido.FidoProtocol.MethodId };

    /// <summary>Eingestellte Verfahren ohne Microsoft, wenn es am Sperrbildschirm nicht geht (Groß-/Kleinschreibung egal).</summary>
    public static List<string> Filter(IEnumerable<string> methods, bool entraOnLockScreen) =>
        methods.Where(m => entraOnLockScreen || !string.Equals(m?.Trim(), "entra", StringComparison.OrdinalIgnoreCase)).ToList();

    /// <summary>
    /// Einstellungen, mit denen am Sperrbildschirm nicht wie eingestellt entsperrt wird: nur Microsoft eingestellt (Rückfall
    /// auf das Windows-Kennwort, VIT-0016), oder Domänen- bzw. Gruppenregeln, die keine Windows-Anmeldung erfüllen kann
    /// (VIT-0017; dann kann womöglich niemand entsperren, auch kein Administrator).
    /// </summary>
    public static List<UnlockSetupWarning> Warnings(UnlockSettings unlock, bool entraOnLockScreen)
    {
        var warnings = new List<UnlockSetupWarning>();
        var methods = Filter(unlock.Methods, entraOnLockScreen);
        if (methods.Count == 0)
        {
            if (!entraOnLockScreen && unlock.Methods.Any(m => string.Equals(m?.Trim(), "entra", StringComparison.OrdinalIgnoreCase)))
                warnings.Add(new(ErrorCodes.UnlockFallsBackToWindows, "Unlock.Methods", ""));
            methods = ["windows"]; // Rückfall wie AuthRegistry.GetActiveAsync
        }
        // Nur Windows-Konten am Sperrbildschirm (kein gemeinsames Kennwort, kein Plugin): passen die Regeln dazu?
        if (!methods.All(m => WindowsIdentity.Contains(m.Trim()))) return warnings;

        var domains = NonBlank(unlock.AllowedDomains);
        // „contoso.com“ ist ein UPN-Suffix; Windows liefert „CONTOSO\name“ (NetBIOS-Name, ohne Punkt)
        if (domains.Count > 0 && domains.All(d => d.Contains('.')))
            warnings.Add(new(ErrorCodes.UnlockRulesNeverMatch, "Unlock.AllowedDomains", string.Join(", ", domains)));

        // Gruppen-IDs von Microsoft Entra (GUID) passen nie zu Windows-Gruppen (SIDs, „DOMÄNE\Gruppe“). Nur ein Problem, wenn
        // keine andere Regel jemanden zulässt.
        var groups = NonBlank(unlock.AllowedGroups);
        var others = UnlockAllowed.AnyAuthenticated | UnlockAllowed.SessionUser | UnlockAllowed.Administrators;
        bool usersMayMatch = unlock.Allowed.HasFlag(UnlockAllowed.Users) && NonBlank(unlock.AllowedUsers).Count > 0;
        if (unlock.Allowed.HasFlag(UnlockAllowed.Groups) && (unlock.Allowed & others) == 0 && !usersMayMatch &&
            groups.Count > 0 && groups.All(g => Guid.TryParse(g, out _)))
            warnings.Add(new(ErrorCodes.UnlockRulesNeverMatch, "Unlock.AllowedGroups", string.Join(", ", groups)));
        return warnings;
    }

    private static List<string> NonBlank(IEnumerable<string> values) =>
        values.Where(v => !string.IsNullOrWhiteSpace(v)).Select(v => v.Trim()).ToList();
}
