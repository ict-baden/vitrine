// SPDX-License-Identifier: MIT
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Vitrine.Abstractions;
using Vitrine.Core.Localization;

namespace Vitrine.Core.Integration;

/// <summary>Eine gelesene Anfrage oder der Fehler, warum sie nicht gilt.</summary>
public sealed record PipeRequest(string? Command, string? Reason, string? Meaning, string? Requester, string? Trigger)
{
    /// <summary>Berechtigungen für ein Zugriffstoken (authenticate/sign mit Microsoft Entra ID), leer = keins.</summary>
    public IReadOnlyList<string> Scopes { get; init; } = [];

    public string? ErrorCode { get; init; }
    public string? Error { get; init; }
    public bool IsValid => ErrorCode is null;
}

/// <summary>
/// Protokoll der lokalen Schnittstelle (docs/interface.md): eine JSON-Zeile pro Anfrage, eine JSON-Zeile pro Antwort.
/// Antworten sind Teil der Programmierschnittstelle und deshalb auf Englisch, mit sprachunabhängigem Code
/// (<c>{"ok":false,"code":"VIT-0203","error":"'reason' is missing"}</c>).
/// </summary>
public static class PipeProtocol
{
    /// <summary>Längste Anfragezeile in Zeichen; längere werden verworfen (Schutz vor Speicherfressern).</summary>
    public const int MaxLineLength = 16 * 1024;

    /// <summary>Längste Felder (Grund, Bedeutung, Anforderer, Auslöser) – sie stehen im Dialog und im Protokoll.</summary>
    public const int MaxFieldLength = 500;

    /// <summary>Höchstens so viele Scopes je Anfrage.</summary>
    public const int MaxScopes = 10;

    /// <summary>Standard-Scopes von OpenID Connect; sie gehören zu keiner Ressource und sind immer erlaubt.</summary>
    public static readonly IReadOnlySet<string> OidcScopes =
        new HashSet<string>(["openid", "profile", "email", "offline_access"], StringComparer.OrdinalIgnoreCase);

    public static readonly IReadOnlySet<string> Commands =
        new HashSet<string>(["status", "lock", "settings", "authenticate", "sign", "subscribe"], StringComparer.Ordinal);

    public static PipeRequest Parse(string line)
    {
        JsonNode? node;
        try { node = JsonNode.Parse(line); }
        catch (JsonException) { return Invalid(ErrorCodes.PipeInvalidJson, "Invalid JSON"); }
        if (node is not JsonObject req) return Invalid(ErrorCodes.PipeObjectExpected, "JSON object expected");

        string? Text(string name) => req[name] is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;

        var cmd = Text("cmd")?.Trim().ToLowerInvariant();
        var request = new PipeRequest(cmd, Clean(Text("reason")), Clean(Text("meaning")), Clean(Text("requester")), Clean(Text("trigger")));
        foreach (var (name, value) in new[] { ("reason", request.Reason), ("meaning", request.Meaning), ("requester", request.Requester), ("trigger", request.Trigger) })
            if (value is { Length: > MaxFieldLength })
                return request with { ErrorCode = ErrorCodes.PipeFieldTooLong, Error = $"'{name}' is longer than {MaxFieldLength} characters" };

        if (cmd is null || !Commands.Contains(cmd))
            return request with { ErrorCode = ErrorCodes.PipeUnknownCommand, Error = $"Unknown command '{cmd}'" };
        if (cmd is "authenticate" or "sign" && string.IsNullOrWhiteSpace(request.Reason))
            return request with { ErrorCode = ErrorCodes.PipeReasonMissing, Error = "'reason' is missing" };

        // "scopes": ["api://lims/Sign"] oder "api://lims/Sign api://lims/Read"
        var scopes = req["scopes"] switch
        {
            JsonArray a => a.Select(n => n is JsonValue v && v.TryGetValue<string>(out var t) ? t : null).ToList(),
            JsonValue v when v.TryGetValue<string>(out var t) => t.Split(' ', StringSplitOptions.RemoveEmptyEntries).Select(x => (string?)x).ToList(),
            null => [],
            _ => [null],
        };
        if (scopes.Any(x => x is null || x.Length > MaxFieldLength || x.Any(char.IsControl) || x.Any(char.IsWhiteSpace)) || scopes.Count > MaxScopes)
            return request with { ErrorCode = ErrorCodes.PipeScopeNotAllowed, Error = "'scopes' must be up to 10 strings without spaces" };
        return request with { Scopes = scopes.Select(x => x!).Distinct(StringComparer.Ordinal).ToList() };
    }

    /// <summary>
    /// Prüft angefragte Scopes gegen die Liste des Administrators (<c>Entra.AllowedTokenScopes</c>): jeder muss genau so
    /// darin stehen (ohne Groß/Klein), und alle müssen zu einer Ressource gehören (eine Anmeldung, ein Token).
    /// null = in Ordnung, sonst Code und englische Meldung.
    /// </summary>
    public static (string Code, string Error)? CheckScopes(IReadOnlyList<string> requested, IEnumerable<string> allowed)
    {
        if (requested.Count == 0) return null;
        var allow = new HashSet<string>(allowed.Select(a => a.Trim()).Where(a => a.Length > 0), StringComparer.OrdinalIgnoreCase);
        // Leere Liste = keine Zugriffstoken, auch nicht für reine OpenID-Scopes (sonst gäbe es ein Token für Microsoft Graph)
        if (allow.Count == 0) return (ErrorCodes.PipeScopeNotAllowed, "Access tokens are not allowed on this device");
        if (requested.All(OidcScopes.Contains))
            return (ErrorCodes.PipeScopeNotAllowed, "'scopes' must contain a scope of an API, not only OpenID scopes");
        foreach (var s in requested)
            if (!OidcScopes.Contains(s) && !allow.Contains(s))
                return (ErrorCodes.PipeScopeNotAllowed, $"Scope '{s}' is not allowed on this device");
        var resources = requested.Where(s => !OidcScopes.Contains(s)).Select(ResourceOf).Distinct(StringComparer.OrdinalIgnoreCase).Count();
        if (resources > 1) return (ErrorCodes.PipeScopesMixed, "Scopes of more than one resource");
        return null;
    }

    /// <summary>Ressource eines Scopes: „api://lims/Sign“ → „api://lims“, „User.Read“ → Microsoft Graph.</summary>
    public static string ResourceOf(string scope)
    {
        var i = scope.LastIndexOf('/');
        return i > 0 ? scope[..i] : "https://graph.microsoft.com";
    }

    /// <summary>Steuerzeichen (Zeilenumbrüche, Escape-Sequenzen) entfernen – die Felder landen im Dialog und im Protokoll.</summary>
    internal static string? Clean(string? s)
    {
        if (s is null) return null;
        var sb = new StringBuilder(s.Length);
        foreach (var c in s) sb.Append(char.IsControl(c) ? ' ' : c);
        return sb.ToString().Trim();
    }

    public static JsonObject Error(string code, string message) => new() { ["ok"] = false, ["code"] = code, ["error"] = message };

    /// <summary>
    /// Englische Meldung zu einem Code für die Antwort der Schnittstelle (die Schnittstelle antwortet immer auf Englisch,
    /// unabhängig von der Sprache der Oberfläche).
    /// </summary>
    public static string EnglishError(string? code)
    {
        if (code is null) return "Cancelled or failed";
        var text = CoreText.Strings.GetString(ErrorCodes.Key(code), System.Globalization.CultureInfo.InvariantCulture);
        return text is null ? "Cancelled or failed" : System.Text.RegularExpressions.Regex.Replace(text, @"\{\d+\}", "…");
    }

    /// <summary>Token aus <see cref="AuthOutcome.Tokens"/> und ihr Feld in der Antwort (docs/interface.md).</summary>
    public static readonly IReadOnlyList<(string Name, string Field)> TokenFields =
        [("id_token", "idToken"), ("access_token", "accessToken"), ("expires_on", "expiresOn"), ("scopes", "scopes")];

    /// <summary>
    /// Antwort auf authenticate/sign nach erfolgreicher Anmeldung (docs/interface.md). Token gehen nur in diese Antwort,
    /// nie ins Protokoll (ID-Token mit Entra.ShareIdToken, Zugriffstoken mit scopes).
    /// </summary>
    public static JsonObject SignatureAnswer(AuthOutcome who, string reason, string? meaning, DateTimeOffset time)
    {
        var answer = new JsonObject
        {
            ["ok"] = true,
            ["user"] = who.UserName,
            ["displayName"] = who.DisplayName,
            ["userId"] = who.UserId,
            ["tenantId"] = who.TenantId,
            ["method"] = who.Details.GetValueOrDefault("method"),
            ["time"] = time.ToUniversalTime().ToString("O", System.Globalization.CultureInfo.InvariantCulture),
            ["reason"] = reason,
            ["meaning"] = meaning,
            ["auditSeq"] = who.Details.GetValueOrDefault("auditSeq"),
            ["auditHash"] = who.Details.GetValueOrDefault("auditHash"),
            // Wofür der Protokolleintrag bürgt: „verified“ (Dienst hat die Anmeldung geprüft), „client“ (von der App bezeugt),
            // „local“ (ohne Dienst, nicht Part-11-fähig) – docs/interface.md
            ["assurance"] = who.Details.GetValueOrDefault("assurance"),
            // Anmeldeverfahren laut Microsoft (z. B. „fido“, „mfa“), falls im Token
            ["amr"] = who.Details.GetValueOrDefault("amr"),
        };
        foreach (var (name, field) in TokenFields)
            if (who.Tokens.TryGetValue(name, out var value)) answer[field] = value;
        return answer;
    }

    private static PipeRequest Invalid(string code, string message) =>
        new(null, null, null, null, null) { ErrorCode = code, Error = message };
}

/// <summary>Liest Zeilen mit Längengrenze (StreamReader.ReadLine würde beliebig lange Zeilen in den Speicher holen).</summary>
public sealed class BoundedLineReader
{
    private readonly TextReader _reader;
    private readonly int _max;
    private readonly char[] _one = new char[1];

    public BoundedLineReader(TextReader reader, int maxLength)
    {
        _reader = reader;
        _max = maxLength;
    }

    /// <summary>Nächste Zeile ohne Zeilenende; null am Ende des Datenstroms. Zu lange Zeilen: <see cref="LineTooLongException"/>.</summary>
    public async Task<string?> ReadLineAsync(CancellationToken ct)
    {
        var sb = new StringBuilder();
        while (true)
        {
            int n = await _reader.ReadAsync(_one.AsMemory(), ct).ConfigureAwait(false);
            if (n == 0) return sb.Length == 0 ? null : sb.ToString();
            char c = _one[0];
            if (c == '\n') return sb.ToString().TrimEnd('\r');
            if (sb.Length >= _max) throw new LineTooLongException();
            sb.Append(c);
        }
    }
}

public sealed class LineTooLongException : IOException
{
    public LineTooLongException() : base("Line too long") { }
}
