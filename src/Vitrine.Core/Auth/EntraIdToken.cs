// SPDX-License-Identifier: MIT
using System.Buffers.Text;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Vitrine.Core.Config;

namespace Vitrine.Core.Auth;

/// <summary>Ergebnis der Prüfung eines ID-Tokens: die Claims oder der Grund (englisch, fürs Protokoll).</summary>
public sealed record EntraTokenCheck(IReadOnlyList<KeyValuePair<string, string>>? Claims, string? Problem)
{
    public bool Valid => Claims is not null;
}

/// <summary>
/// Prüft ein ID-Token von Microsoft Entra ID selbst – im Dienst, für Signaturen (#15): Die App meldet sich mit MSAL an und
/// reicht das Token weiter; MSAL prüft die Signatur des ID-Tokens nicht (es kommt über TLS direkt von Microsoft), der
/// Dienst muss es, weil er der App nicht traut. Geprüft werden: RS256-Signatur mit einem Schlüssel aus den JWKS des
/// Mandanten, Aussteller (v2.0-Endpunkt des Mandanten im Token), Zielgruppe (Entra.ClientId), Gültigkeit (exp/nbf, 5 min
/// Toleranz) und Frische (iat höchstens <see cref="MaxTokenAge"/> alt). Mandant, auth_time, Kontext und Rollen prüft danach
/// wie in der App <see cref="EntraClaims.Evaluate"/>. Wiederverwendung erkennt der Aufrufer (Hash des Tokens).
/// Den Nonce kennt nur MSAL in der App; er wird nicht geprüft.
/// </summary>
public static class EntraIdToken
{
    /// <summary>Höchstalter des Tokens (iat): Es muss eben für diese Signatur ausgestellt worden sein.</summary>
    public static readonly TimeSpan MaxTokenAge = TimeSpan.FromMinutes(10);

    private static readonly TimeSpan Skew = TimeSpan.FromMinutes(5);

    /// <summary>Kopf und Inhalt ohne Prüfung lesen (um die Schlüssel des richtigen Mandanten zu holen). null = kein JWT.</summary>
    public static (string? Kid, string? Tenant)? Peek(string jwt)
    {
        var parts = jwt.Split('.');
        if (parts.Length != 3) return null;
        try
        {
            var header = JsonNode.Parse(Base64Url.DecodeFromChars(parts[0])) as JsonObject;
            var payload = JsonNode.Parse(Base64Url.DecodeFromChars(parts[1])) as JsonObject;
            if (header is null || payload is null) return null;
            return (Str(header["kid"]), Str(payload["tid"]));
        }
        catch (Exception ex) when (ex is FormatException or JsonException or InvalidOperationException) { return null; }
    }

    /// <summary>Adresse der Signaturschlüssel des Mandanten (mit appid, falls die App eigene Schlüssel hat).</summary>
    public static Uri KeysUri(string tenant, string clientId) =>
        new($"https://login.microsoftonline.com/{Uri.EscapeDataString(tenant)}/discovery/v2.0/keys?appid={Uri.EscapeDataString(clientId)}");

    /// <param name="jwks">JSON Web Key Set des Mandanten, wie von <see cref="KeysUri"/> geliefert.</param>
    public static EntraTokenCheck Validate(string jwt, string jwks, EntraSettings s, DateTimeOffset now)
    {
        var parts = jwt.Split('.');
        if (parts.Length != 3) return Bad("not a JWT");
        JsonObject header, payload;
        byte[] signature;
        try
        {
            header = JsonNode.Parse(Base64Url.DecodeFromChars(parts[0])) as JsonObject ?? throw new FormatException();
            payload = JsonNode.Parse(Base64Url.DecodeFromChars(parts[1])) as JsonObject ?? throw new FormatException();
            signature = Base64Url.DecodeFromChars(parts[2]);
        }
        catch (Exception ex) when (ex is FormatException or JsonException or InvalidOperationException) { return Bad("not a JWT"); }

        if (Str(header["alg"]) != "RS256") return Bad("algorithm is not RS256");
        if (Str(header["kid"]) is not { } kid) return Bad("no key ID");
        if (FindKey(jwks, kid) is not { } rsa) return Bad($"unknown signing key {kid}");
        using (rsa)
        {
            var signed = Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]);
            if (!rsa.VerifyData(signed, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)) return Bad("signature invalid");
        }

        var tid = Str(payload["tid"]);
        if (tid is null || !Guid.TryParse(tid, out _)) return Bad("no tenant");
        if (Str(payload["iss"]) != $"https://login.microsoftonline.com/{tid}/v2.0") return Bad("issuer");
        var clientId = s.ClientId?.Trim();
        if (string.IsNullOrEmpty(clientId) || !Audiences(payload["aud"]).Contains(clientId, StringComparer.OrdinalIgnoreCase)) return Bad("audience");
        if (Seconds(payload["exp"]) is not { } exp || now > DateTimeOffset.FromUnixTimeSeconds(exp) + Skew) return Bad("expired");
        if (Seconds(payload["nbf"]) is { } nbf && now + Skew < DateTimeOffset.FromUnixTimeSeconds(nbf)) return Bad("not yet valid");
        if (Seconds(payload["iat"]) is not { } iat) return Bad("no issue time");
        var issued = DateTimeOffset.FromUnixTimeSeconds(iat);
        if (now - issued > MaxTokenAge || issued - now > Skew) return Bad("not issued just now");

        return new EntraTokenCheck(Claims(payload), null);
    }

    /// <summary>Claims wie im ClaimsPrincipal von MSAL: Listen als mehrere Einträge, Zahlen als Text.</summary>
    public static List<KeyValuePair<string, string>> Claims(JsonObject payload)
    {
        var list = new List<KeyValuePair<string, string>>();
        foreach (var (name, value) in payload)
        {
            if (value is JsonArray a)
                foreach (var item in a) { if (Text(item) is { } t) list.Add(new(name, t)); }
            else if (Text(value) is { } t) list.Add(new(name, t));
        }
        return list;
    }

    private static string? Text(JsonNode? n) => n switch
    {
        null => null,
        JsonValue v when v.TryGetValue<string>(out var s) => s,
        JsonValue v => v.ToJsonString(),
        _ => n.ToJsonString(),
    };

    private static IEnumerable<string> Audiences(JsonNode? aud) => aud switch
    {
        JsonArray a => a.Select(Str).OfType<string>(),
        _ => Str(aud) is { } one ? [one] : [],
    };

    private static long? Seconds(JsonNode? n)
    {
        if (n is not JsonValue v) return null;
        if (v.TryGetValue<long>(out var l)) return l;
        if (v.TryGetValue<double>(out var d)) return (long)d;
        return v.TryGetValue<string>(out var s) && long.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var p) ? p : null;
    }

    private static string? Str(JsonNode? n) => n is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;

    /// <summary>RSA-Schlüssel mit dieser ID aus dem JWKS; null, wenn keiner passt.</summary>
    private static RSA? FindKey(string jwks, string kid)
    {
        try
        {
            if (JsonNode.Parse(jwks)?["keys"] is not JsonArray keys) return null;
            foreach (var k in keys)
            {
                if (k is not JsonObject o || Str(o["kid"]) != kid || Str(o["kty"]) != "RSA") continue;
                if (Str(o["n"]) is not { } n || Str(o["e"]) is not { } e) continue;
                var rsa = RSA.Create();
                rsa.ImportParameters(new RSAParameters { Modulus = Base64Url.DecodeFromChars(n), Exponent = Base64Url.DecodeFromChars(e) });
                if (rsa.KeySize < 2048) { rsa.Dispose(); continue; }
                return rsa;
            }
        }
        catch (Exception ex) when (ex is FormatException or JsonException or InvalidOperationException or CryptographicException) { }
        return null;
    }

    private static EntraTokenCheck Bad(string problem) => new(null, problem);
}
