// SPDX-License-Identifier: MIT
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using Vitrine.Core.Localization;

namespace Vitrine.Core.Fido;

/// <summary>
/// Rohdaten eines Schlüssel-Objekts im Active Directory (serviceConnectionPoint unter CN=SecurityKeys): cn, keywords,
/// serviceBindingInformation (mehrwertig, Reihenfolge im AD nicht garantiert) und description.
/// </summary>
public sealed record FidoDirectoryEntry(string Cn, IReadOnlyList<string> Keywords, IReadOnlyList<string> BindingInformation, string? Description);

/// <summary>
/// Zugang zum Container der Schlüssel im AD. Windows: LDAP (System.DirectoryServices.Protocols) als Computerkonto zum
/// Lesen, als registrierende Person zum Schreiben; Tests: Attrappe. Fehler als <see cref="FidoStoreException"/> mit
/// VIT-0471 (nicht erreichbar), VIT-0472 (abgelehnt), VIT-0474 (nicht eingerichtet).
/// </summary>
public interface IFidoDirectory
{
    /// <summary>DN des Containers mit den Schlüsseln (für Anzeige und Protokoll), soweit bekannt.</summary>
    string? Location { get; }

    /// <summary>Alle Objekte mit dem Stichwort <see cref="FidoDirectoryCodec.Marker"/>.</summary>
    Task<IReadOnlyList<FidoDirectoryEntry>> ReadAllAsync(CancellationToken ct = default);

    /// <summary>Ein Objekt nach cn (SHA-256 der Credential-ID, hex), null wenn es keins gibt.</summary>
    Task<FidoDirectoryEntry?> ReadAsync(string cn, CancellationToken ct = default);

    /// <summary>Verbindung mit den Anmeldedaten der registrierenden Person (Kennwort bzw. Token nur für die Anmeldung).</summary>
    Task<IFidoDirectoryWriter> OpenWriterAsync(FidoWriteCredential credential, CancellationToken ct = default);
}

/// <summary>Schreibende Verbindung zum AD, angemeldet als die registrierende Person.</summary>
public interface IFidoDirectoryWriter : IFidoStoreWriter
{
    Task<FidoDirectoryEntry?> ReadAsync(string cn, CancellationToken ct = default);

    /// <summary>Objekt anlegen; gibt es den cn schon, <see cref="FidoStoreException"/> mit VIT-0419.</summary>
    Task CreateAsync(FidoDirectoryEntry entry, CancellationToken ct = default);

    /// <summary>keywords, serviceBindingInformation und description ersetzen.</summary>
    Task ReplaceAsync(FidoDirectoryEntry entry, CancellationToken ct = default);
}

/// <summary>Inhalt von serviceBindingInformation: dieselben Angaben wie ein Eintrag der lokalen Datei, ohne Zähler.</summary>
public sealed class FidoDirectoryPayload
{
    /// <summary>Version des Formats. Ein Dienst liest nur Versionen, die er kennt (<see cref="FidoDirectoryCodec.PayloadVersion"/>).</summary>
    [JsonPropertyName("v")] public int Version { get; set; } = FidoDirectoryCodec.PayloadVersion;
    public string CredentialId { get; set; } = "";
    public string IdHash { get; set; } = "";
    public string RpId { get; set; } = "";
    public string PublicKey { get; set; } = "";
    public int Algorithm { get; set; }
    public string Aaguid { get; set; } = "";
    public string AttestationFormat { get; set; } = "";
    public bool AttestationVerified { get; set; }
    public string? AttestationCertificate { get; set; }
    public string UserHandle { get; set; } = "";
    public string PersonSid { get; set; } = "";
    public string PersonName { get; set; } = "";
    public string? PersonUpn { get; set; }
    public string Label { get; set; } = "";
    public string Reason { get; set; } = "";
    public DateTimeOffset RegisteredAt { get; set; }
    public string RegisteredBySid { get; set; } = "";
    public string RegisteredByName { get; set; } = "";
    public string RegisteredOn { get; set; } = "";
    public string Status { get; set; } = FidoDirectoryCodec.StatusActive;
    public DateTimeOffset? RevokedAt { get; set; }
    public string? RevokedBySid { get; set; }
    public string? RevokedByName { get; set; }
    public string? RevokeReason { get; set; }
}

/// <summary>Ergebnis des Lesens eines Objekts: Schlüssel oder Grund, warum es ignoriert wird.</summary>
public sealed record FidoDecodeResult(FidoCredential? Credential, string? Problem)
{
    public bool Ok => Credential is not null;
}

/// <summary>Stichwörter eines Objekts.</summary>
/// <param name="IsVitrine">Hat das Stichwort <see cref="FidoDirectoryCodec.Marker"/>.</param>
/// <param name="Status">Wert von „status=…“ (klein), null wenn fehlend oder mehrdeutig.</param>
/// <param name="RpId">Wert von „rp=…“, null wenn fehlend oder mehrdeutig.</param>
public sealed record FidoDirectoryKeywords(bool IsVitrine, string? Status, string? RpId);

/// <summary>
/// Abbildung Schlüssel ↔ AD-Objekt (ohne Schemaerweiterung): cn = SHA-256 der Credential-ID (hex, klein);
/// keywords = <c>VitrineFidoCredential</c>, <c>status=active|revoked</c>, <c>rp=&lt;RP ID&gt;</c>; serviceBindingInformation =
/// JSON (<see cref="FidoDirectoryPayload"/>) in Stücken „vitrine-fido:&lt;Version&gt;:&lt;i&gt;/&lt;n&gt;:&lt;Text&gt;“ (mehrwertige
/// Attribute haben im AD keine Reihenfolge); description = Begründung des Widerrufs. Der Signaturzähler steht nicht im AD
/// (Rechner dürfen dort nicht schreiben), er bleibt je Rechner beim Dienst.
/// </summary>
public static class FidoDirectoryCodec
{
    public const string Marker = "VitrineFidoCredential";
    public const int PayloadVersion = 1;
    public const string StatusActive = "active";
    public const string StatusRevoked = "revoked";
    public const string ChunkPrefix = "vitrine-fido:";

    /// <summary>Zeichen je Wert von serviceBindingInformation (klein genug für jede LDAP-Grenze).</summary>
    public const int ChunkLength = 900;

    /// <summary>Höchstens so viele Stücke (≈ 58 000 Zeichen) – mehr ist kein Schlüssel von Vitrine.</summary>
    public const int MaxChunks = 64;

    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public static FidoDirectoryKeywords ParseKeywords(IEnumerable<string>? keywords)
    {
        bool marker = false;
        var status = new HashSet<string>(StringComparer.Ordinal);
        var rp = new HashSet<string>(StringComparer.Ordinal);
        foreach (var raw in keywords ?? [])
        {
            var k = raw?.Trim() ?? "";
            if (string.Equals(k, Marker, StringComparison.OrdinalIgnoreCase)) marker = true;
            else if (k.StartsWith("status=", StringComparison.OrdinalIgnoreCase)) status.Add(k["status=".Length..].Trim().ToLowerInvariant());
            else if (k.StartsWith("rp=", StringComparison.OrdinalIgnoreCase)) rp.Add(k["rp=".Length..].Trim());
        }
        return new FidoDirectoryKeywords(marker, status.Count == 1 ? status.First() : null, rp.Count == 1 ? rp.First() : null);
    }

    public static FidoDirectoryPayload ToPayload(FidoCredential c) => new()
    {
        CredentialId = c.CredentialId, IdHash = c.IdHash.ToLowerInvariant(), RpId = c.RpId, PublicKey = c.PublicKey, Algorithm = c.Algorithm,
        Aaguid = c.Aaguid, AttestationFormat = c.AttestationFormat, AttestationVerified = c.AttestationVerified,
        AttestationCertificate = c.AttestationCertificate, UserHandle = c.UserHandle, PersonSid = c.PersonSid, PersonName = c.PersonName,
        PersonUpn = c.PersonUpn, Label = c.Label, Reason = c.Reason, RegisteredAt = c.RegisteredAt, RegisteredBySid = c.RegisteredBySid,
        RegisteredByName = c.RegisteredByName, RegisteredOn = c.RegisteredOn,
        Status = c.IsActive ? StatusActive : StatusRevoked, RevokedAt = c.RevokedAt, RevokedBySid = c.RevokedBySid,
        RevokedByName = c.RevokedByName, RevokeReason = c.RevokeReason,
    };

    /// <summary>Objekt für einen Schlüssel (ohne Zähler und letzte Nutzung).</summary>
    public static FidoDirectoryEntry Encode(FidoCredential c)
    {
        var json = JsonSerializer.Serialize(ToPayload(c), Json);
        var chunks = new List<string>();
        int n = Math.Max(1, (json.Length + ChunkLength - 1) / ChunkLength);
        for (int i = 0; i < n; i++)
        {
            var part = json.Substring(i * ChunkLength, Math.Min(ChunkLength, json.Length - i * ChunkLength));
            chunks.Add(string.Create(CultureInfo.InvariantCulture, $"{ChunkPrefix}{PayloadVersion}:{i}/{n}:{part}"));
        }
        var keywords = new List<string> { Marker, "status=" + (c.IsActive ? StatusActive : StatusRevoked), "rp=" + c.RpId };
        return new FidoDirectoryEntry(c.IdHash.ToLowerInvariant(), keywords, chunks, c.IsActive ? null : c.RevokeReason);
    }

    /// <summary>
    /// Objekt lesen und prüfen: Stichwort, vollständige Stücke einer bekannten Version, cn = SHA-256 der Credential-ID =
    /// idHash, RP ID in Stichwort und Inhalt gleich, öffentlicher Schlüssel und Person vorhanden. Widerrufen ist der Schlüssel,
    /// sobald Stichwort <b>oder</b> Inhalt es sagen (oder der Status unklar ist) – aktiv nur, wenn beide „active“ sagen.
    /// </summary>
    public static FidoDecodeResult Decode(FidoDirectoryEntry e)
    {
        static FidoDecodeResult Bad(string problem) => new(null, problem);
        var kw = ParseKeywords(e.Keywords);
        if (!kw.IsVitrine) return Bad("no keyword " + Marker);
        if (Assemble(e.BindingInformation, out var json) is { } chunkProblem) return Bad(chunkProblem);

        FidoDirectoryPayload? p;
        try
        {
            using var doc = JsonDocument.Parse(json!);
            if (doc.RootElement.ValueKind != JsonValueKind.Object) return Bad("payload is not a JSON object");
            if (!doc.RootElement.TryGetProperty("v", out var v) || !v.TryGetInt32(out int version)) return Bad("payload without version");
            if (version != PayloadVersion) return Bad($"payload version {version} not supported");
            p = doc.RootElement.Deserialize<FidoDirectoryPayload>(Json);
        }
        catch (JsonException ex) { return Bad("payload not readable: " + ex.Message); }
        if (p is null) return Bad("payload empty");

        var id = FidoProtocol.FromBase64Url(p.CredentialId);
        if (id is null || id.Length == 0) return Bad("credential ID missing");
        var hash = FidoProtocol.IdHash(id);
        if (!string.Equals(hash, e.Cn, StringComparison.OrdinalIgnoreCase)) return Bad("cn is not the SHA-256 of the credential ID");
        if (p.IdHash.Length > 0 && !string.Equals(hash, p.IdHash, StringComparison.OrdinalIgnoreCase)) return Bad("idHash does not match the credential ID");
        if (string.IsNullOrWhiteSpace(p.RpId) || kw.RpId is null || !string.Equals(kw.RpId, p.RpId, StringComparison.Ordinal))
            return Bad("RP ID missing or different in keywords and payload");
        if (FidoProtocol.FromBase64Url(p.PublicKey) is not { Length: > 0 }) return Bad("public key missing");
        if (!p.PersonSid.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase)) return Bad("person SID missing");

        bool active = kw.Status == StatusActive && string.Equals(p.Status, StatusActive, StringComparison.OrdinalIgnoreCase);
        var c = new FidoCredential
        {
            CredentialId = p.CredentialId, IdHash = hash, RpId = p.RpId, PublicKey = p.PublicKey, Algorithm = p.Algorithm, Aaguid = p.Aaguid,
            AttestationFormat = p.AttestationFormat, AttestationVerified = p.AttestationVerified, AttestationCertificate = p.AttestationCertificate,
            UserHandle = p.UserHandle, PersonSid = p.PersonSid, PersonName = p.PersonName, PersonUpn = p.PersonUpn, Label = p.Label,
            Reason = p.Reason, RegisteredAt = p.RegisteredAt, RegisteredBySid = p.RegisteredBySid, RegisteredByName = p.RegisteredByName,
            RegisteredOn = p.RegisteredOn,
            Status = active ? FidoCredentialStatus.Active : FidoCredentialStatus.Revoked,
            RevokedAt = p.RevokedAt, RevokedBySid = p.RevokedBySid, RevokedByName = p.RevokedByName,
            RevokeReason = p.RevokeReason ?? (active ? null : e.Description),
        };
        return new FidoDecodeResult(c, null);
    }

    /// <summary>Stücke zusammensetzen; null = in Ordnung, sonst der Grund.</summary>
    private static string? Assemble(IReadOnlyList<string>? values, out string? json)
    {
        json = null;
        if (values is null || values.Count == 0) return "serviceBindingInformation missing";
        int count = -1;
        var parts = new SortedDictionary<int, string>();
        foreach (var value in values)
        {
            if (value is null || !value.StartsWith(ChunkPrefix, StringComparison.Ordinal)) continue; // fremde Werte stören nicht
            var rest = value[ChunkPrefix.Length..];
            int c1 = rest.IndexOf(':');
            int c2 = c1 < 0 ? -1 : rest.IndexOf(':', c1 + 1);
            if (c2 < 0) return "chunk without header";
            if (!int.TryParse(rest[..c1], NumberStyles.None, CultureInfo.InvariantCulture, out int version)) return "chunk without version";
            if (version != PayloadVersion) return $"payload version {version} not supported";
            var pos = rest[(c1 + 1)..c2].Split('/');
            if (pos.Length != 2 || !int.TryParse(pos[0], NumberStyles.None, CultureInfo.InvariantCulture, out int i) ||
                !int.TryParse(pos[1], NumberStyles.None, CultureInfo.InvariantCulture, out int n) || n < 1 || n > MaxChunks || i >= n)
                return "chunk position invalid";
            if (count >= 0 && n != count) return "chunks of different payloads";
            count = n;
            if (!parts.TryAdd(i, rest[(c2 + 1)..])) return "chunk twice";
        }
        if (count < 0) return "no chunk of a Vitrine payload";
        if (parts.Count != count) return $"{count - parts.Count} of {count} chunks missing";
        json = string.Concat(parts.Values);
        return null;
    }

    /// <summary>LDAP-Ergebniscode → Fehlercode (Windows-Anbindung; hier, damit testbar).</summary>
    public static string CodeForLdapResult(int resultCode) => resultCode switch
    {
        // invalidCredentials, insufficientAccessRights, strongAuthRequired, inappropriateAuthentication, confidentialityRequired
        49 or 50 or 8 or 48 or 13 => ErrorCodes.FidoDirectoryAccessDenied,
        // noSuchObject (Container fehlt), referral (falsche Domäne), namingViolation, objectClassViolation
        32 or 10 or 64 or 65 => ErrorCodes.FidoDirectoryNotConfigured,
        // entryAlreadyExists
        68 => ErrorCodes.FidoKeyAlreadyRegistered,
        // serverDown (81), timeout (85), connectError (91), busy (51), unavailable (52) und alles andere
        _ => ErrorCodes.FidoDirectoryUnavailable,
    };
}
