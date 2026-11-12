// SPDX-License-Identifier: MIT
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Vitrine.Core.Audit;

/// <summary>
/// Öffentlicher Schlüssel des Dienstes für das Protokoll im Format 3 (ECDSA P-256). Die ID sind die ersten 16 Hex-Zeichen
/// des SHA-256 über den SubjectPublicKeyInfo-Bytes; der Fingerabdruck (alle 64 Zeichen) gehört in die Validierungsunterlagen.
/// </summary>
public sealed record AuditPublicKey(string Id, byte[] SubjectPublicKeyInfo, DateTimeOffset? Created = null)
{
    public string Fingerprint => FingerprintOf(SubjectPublicKeyInfo);

    public static string FingerprintOf(byte[] spki) => Convert.ToHexString(SHA256.HashData(spki)).ToLowerInvariant();

    public static string IdOf(byte[] spki) => FingerprintOf(spki)[..16];

    public static AuditPublicKey From(byte[] spki, DateTimeOffset? created = null) => new(IdOf(spki), spki, created);

    /// <summary>Prüft eine Signatur im Format IEEE P1363 (r||s, 64 Bytes) über <paramref name="data"/>.</summary>
    public bool Verify(byte[] data, byte[] signature)
    {
        try
        {
            using var ec = ECDsa.Create();
            ec.ImportSubjectPublicKeyInfo(SubjectPublicKeyInfo, out _);
            if (ec.KeySize != 256) return false;
            return ec.VerifyData(data, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (CryptographicException) { return false; }
    }
}

/// <summary>Signiert Zeilen des Protokolls. Der private Schlüssel bleibt beim Dienst (CNG-Maschinenschlüssel, nur SYSTEM).</summary>
public interface IAuditSigner
{
    AuditPublicKey PublicKey { get; }

    /// <summary>ECDSA P-256 mit SHA-256, Ergebnis im Format IEEE P1363 (64 Bytes).</summary>
    byte[] Sign(byte[] data);
}

/// <summary>Schlüssel des Dienstes: aktueller Signierschlüssel, frühere öffentliche Schlüssel, Rotation.</summary>
public interface IAuditKeyStore
{
    /// <summary>Aktueller Schlüssel; wird beim ersten Aufruf angelegt.</summary>
    IAuditSigner Current();

    /// <summary>Neuen Schlüssel anlegen und zum aktuellen machen (der alte bleibt zum Signieren des Wechsels erreichbar).</summary>
    IAuditSigner CreateNext();

    /// <summary>Alle bekannten öffentlichen Schlüssel, ältester zuerst.</summary>
    IReadOnlyList<AuditPublicKey> PublicKeys();
}

/// <summary>
/// Datei mit den öffentlichen Schlüsseln (<c>audit-keys.json</c> neben den Protokollen, Ausgabe von
/// <c>--export-audit-key</c>). Enthält nur öffentliche Daten; Prüfer vergleichen den Fingerabdruck mit dem in den
/// Validierungsunterlagen festgehaltenen. Optional mit den Ankern (letzte Nummer und Hash je Monat) zum Zeitpunkt des Exports.
/// </summary>
public static class AuditKeyFile
{
    public const int Version = 1;

    public static string Serialize(string machine, IEnumerable<AuditPublicKey> keys, IEnumerable<AuditAnchor>? anchors = null)
    {
        var o = new JsonObject
        {
            ["version"] = Version,
            ["machine"] = machine,
            ["algorithm"] = "ECDSA P-256 SHA-256 (IEEE P1363)",
            ["keys"] = new JsonArray(keys.Select(k => (JsonNode)new JsonObject
            {
                ["id"] = k.Id,
                ["fingerprint"] = k.Fingerprint,
                ["created"] = k.Created?.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture),
                ["publicKey"] = Convert.ToBase64String(k.SubjectPublicKeyInfo),
            }).ToArray()),
        };
        if (anchors is not null)
            o["anchors"] = new JsonArray(anchors.Select(a => (JsonNode)new JsonObject { ["month"] = a.Month, ["seq"] = a.Seq, ["hash"] = a.Hash }).ToArray());
        return o.ToJsonString(new JsonSerializerOptions { WriteIndented = true });
    }

    /// <summary>Liest Schlüssel (und Anker) aus der Datei. Ungültige Einträge werden übergangen; null, wenn nicht lesbar.</summary>
    public static (string? Machine, List<AuditPublicKey> Keys, List<AuditAnchor> Anchors)? Parse(string json)
    {
        try
        {
            if (JsonNode.Parse(json) is not JsonObject o) return null;
            var keys = new List<AuditPublicKey>();
            foreach (var k in o["keys"] as JsonArray ?? [])
            {
                if (k?["publicKey"]?.GetValue<string>() is not { } b64) continue;
                byte[] spki;
                try { spki = Convert.FromBase64String(b64); } catch (FormatException) { continue; }
                DateTimeOffset? created = DateTimeOffset.TryParse(k["created"]?.GetValue<string>(), CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal, out var c) ? c : null;
                keys.Add(AuditPublicKey.From(spki, created));
            }
            var anchors = new List<AuditAnchor>();
            foreach (var a in o["anchors"] as JsonArray ?? [])
                if (a?["month"]?.GetValue<string>() is { } m && a["hash"]?.GetValue<string>() is { } h && a["seq"] is { } s)
                    anchors.Add(new AuditAnchor(m, s.GetValue<long>(), h));
            return (o["machine"]?.GetValue<string>(), keys, anchors);
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or FormatException) { return null; }
    }
}

/// <summary>Letzter vom Dienst geschriebener Eintrag eines Monats (Nummer und Hash), außerhalb der Datei gespeichert.</summary>
public sealed record AuditAnchor(string Month, long Seq, string Hash);

/// <summary>
/// Anker außerhalb der Protokolldateien (Registry HKLM, nur SYSTEM darf schreiben). Damit erkennt die Prüfung ein
/// abgeschnittenes Ende, eine gelöschte oder ausgetauschte Datei.
/// </summary>
public interface IAuditAnchorStore
{
    AuditAnchor? Get(string month);

    void Set(AuditAnchor anchor);

    /// <summary>Alle Anker, nach Monat sortiert.</summary>
    IReadOnlyList<AuditAnchor> All();
}

/// <summary>Anker im Speicher (Tests, Prüfung mit exportierten Ankern).</summary>
public sealed class MemoryAnchorStore : IAuditAnchorStore
{
    private readonly Dictionary<string, AuditAnchor> _anchors = new(StringComparer.Ordinal);

    public MemoryAnchorStore(IEnumerable<AuditAnchor>? anchors = null)
    {
        foreach (var a in anchors ?? []) _anchors[a.Month] = a;
    }

    public AuditAnchor? Get(string month) { lock (_anchors) return _anchors.GetValueOrDefault(month); }

    public void Set(AuditAnchor anchor) { lock (_anchors) _anchors[anchor.Month] = anchor; }

    public IReadOnlyList<AuditAnchor> All() { lock (_anchors) return _anchors.Values.OrderBy(a => a.Month, StringComparer.Ordinal).ToList(); }
}
