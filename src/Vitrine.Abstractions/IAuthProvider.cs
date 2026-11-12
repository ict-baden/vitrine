// SPDX-License-Identifier: MIT
namespace Vitrine.Abstractions;

/// <summary>Welche Eingaben ein Anbieter im Entsperr-Dialog braucht.</summary>
public enum AuthInputKind
{
    /// <summary>Benutzername und Kennwort.</summary>
    UsernamePassword,
    /// <summary>Nur ein Kennwort bzw. eine PIN.</summary>
    Secret,
    /// <summary>Kein Eingabefeld; der Anbieter zeigt eigene Oberfläche (Browser, Windows Hello, Kartenleser …).</summary>
    External,
}

/// <summary>
/// Ein Anmeldeverfahren für den Entsperr-Dialog. Eigene Adapter (z. B. für ein LIMS oder
/// eine GxP-Benutzerverwaltung) implementieren diese Schnittstelle und werden als DLL in den
/// Ordner „Plugins“ neben Vitrine.exe gelegt.
/// </summary>
public interface IAuthProvider
{
    /// <summary>Eindeutige, stabile Kennung, z. B. "windows" oder "acme-lims".</summary>
    string Id { get; }

    /// <summary>Anzeigename im Dialog.</summary>
    string DisplayName { get; }

    /// <summary>Glyph aus „Segoe Fluent Icons“, z. B. "".</summary>
    string Glyph { get; }

    AuthInputKind Input { get; }

    /// <summary>Ob das Verfahren auf diesem Gerät gerade nutzbar ist.</summary>
    Task<bool> IsAvailableAsync(CancellationToken ct);

    Task<AuthOutcome> AuthenticateAsync(AuthRequest request, CancellationToken ct);
}

public sealed class AuthRequest
{
    public string? UserName { get; init; }
    public string? Secret { get; init; }

    /// <summary>Fenster-Handle des Dialogs, für Anbieter mit eigener Oberfläche.</summary>
    public nint OwnerWindow { get; init; }

    /// <summary>
    /// Warum angemeldet wird, in der Sprache der Oberfläche, z. B. „Arbeitsplatz entsperren“ oder „Freigabe Charge 4711“.
    /// Vitrine setzt den Text immer; der Standardwert gilt nur für Anbieter, die eine eigene Anfrage bauen.
    /// </summary>
    public string Reason { get; init; } = "Unlock";

    /// <summary>Angemeldeter Windows-Benutzer der Sitzung (DOMAIN\name).</summary>
    public string SessionUser { get; init; } = "";

    /// <summary>UPN der Sitzung, falls bekannt (name@contoso.com).</summary>
    public string? SessionUpn { get; init; }

    /// <summary>Wofür angemeldet wird: Entsperren, Signatur oder Administrator-Bestätigung.</summary>
    public AuthPurpose Purpose { get; init; } = AuthPurpose.Unlock;

    /// <summary>
    /// Berechtigungen, für die eine Fachanwendung über die Schnittstelle ein Zugriffstoken möchte (nur Microsoft Entra ID,
    /// vom Administrator freigegeben). Leer = keins. Andere Anbieter ignorieren das.
    /// </summary>
    public IReadOnlyList<string> Scopes { get; init; } = Array.Empty<string>();
}

public enum AuthPurpose
{
    Unlock,
    Signature,
    Admin,
}

public sealed class AuthOutcome
{
    public bool Success { get; init; }

    /// <summary>Fehlermeldung für den Dialog, in der Sprache der Oberfläche (<see cref="System.Globalization.CultureInfo.CurrentUICulture"/>).</summary>
    public string? Error { get; init; }

    /// <summary>
    /// Sprachunabhängiger Fehlercode, z. B. "VIT-0101" oder ein eigener wie "ACME-0007" (richtlinien/13 Punkt 9).
    /// Der Dialog zeigt ihn neben der Meldung; der Support ordnet Meldungen darüber zu.
    /// </summary>
    public string? ErrorCode { get; init; }

    /// <summary>Kanonischer Name, z. B. "CONTOSO\jdoe" oder "jdoe@contoso.com".</summary>
    public string? UserName { get; init; }
    public string? DisplayName { get; init; }

    /// <summary>Windows-SID oder Entra-Objekt-ID.</summary>
    public string? UserId { get; init; }

    /// <summary>Gruppen/Rollen (SIDs, Namen, Objekt-IDs oder App-Rollen), gegen die die Richtlinie prüft.</summary>
    public IReadOnlyCollection<string> Groups { get; init; } = Array.Empty<string>();

    public bool IsAdministrator { get; init; }

    /// <summary>Entra-Mandant (tid), falls zutreffend.</summary>
    public string? TenantId { get; init; }

    /// <summary>Gehört die Identität zum Benutzer der gesperrten Sitzung?</summary>
    public bool IsSessionUser { get; init; }

    /// <summary>Zusätzliche Angaben fürs Protokoll.</summary>
    public IReadOnlyDictionary<string, string> Details { get; init; } = new Dictionary<string, string>();

    /// <summary>
    /// Token für die anfragende Fachanwendung (z. B. "id_token", "access_token", "expires_on"). Vitrine gibt sie nur über
    /// die Schnittstelle an den Anfragenden weiter und schreibt sie nie ins Protokoll.
    /// </summary>
    public IReadOnlyDictionary<string, string> Tokens { get; init; } = new Dictionary<string, string>();

    public static AuthOutcome Fail(string error) => new() { Success = false, Error = error };

    public static AuthOutcome Fail(string error, string errorCode) => new() { Success = false, Error = error, ErrorCode = errorCode };
}
