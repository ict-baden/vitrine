// SPDX-License-Identifier: MIT
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace Vitrine.Core.Audit;

/// <summary>
/// Schreibweise der Protokollzeilen (Format 1 bis 3) an einer Stelle: Serialisierung, Hash, Signatur, Monat der Datei.
/// Format 3 (#15): Der Dienst signiert jede Zeile. Die signierten Bytes sind die Zeile ohne die beiden letzten Felder
/// <c>,"Hash":"…","Sig":"…"</c>; Hash ist der SHA-256 derselben Bytes (für die Kette und als Verweis), Sig die ECDSA-Signatur (IEEE P1363, Base64url ohne Auffüllung).
/// </summary>
public static partial class AuditFormat
{
    /// <summary>Format der Zeilen, die die App ohne Dienst schreibt (nicht Part-11-fähig).</summary>
    public const int Local = 2;

    /// <summary>Format der Zeilen, die der Dienst schreibt und signiert.</summary>
    public const int Signed = 3;

    public static readonly JsonSerializerOptions Opts = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() },
    };

    public static string Serialize(AuditEntry e) => JsonSerializer.Serialize(e, Opts);

    public static string HashOf(string body) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(body))).ToLowerInvariant();

    /// <summary>Monat einer Zeit als „yyyy-MM“, gregorianisch, UTC.</summary>
    public static string MonthOf(DateTimeOffset t) => t.ToUniversalTime().ToString("yyyy-MM", CultureInfo.InvariantCulture);

    /// <summary>Dateiname des Monats: audit-yyyy-MM.jsonl.</summary>
    public static string FileName(string month) => $"audit-{month}.jsonl";

    /// <summary>Monat aus dem Dateinamen (…audit-2026-10.jsonl, auch die Netzkopie RECHNER-audit-2026-10.jsonl); null, wenn keiner.</summary>
    public static string? FileMonth(string path)
    {
        var m = FileMonthRegex().Match(Path.GetFileName(path));
        return m.Success ? m.Groups[1].Value : null;
    }

    /// <summary>Monat davor („2026-01“ → „2025-12“).</summary>
    public static string PreviousMonth(string month)
    {
        var d = DateTime.ParseExact(month + "-01", "yyyy-MM-dd", CultureInfo.InvariantCulture);
        return d.AddMonths(-1).ToString("yyyy-MM", CultureInfo.InvariantCulture);
    }

    /// <summary>
    /// Zeile im Format 3: Hash und Signatur über die Zeile ohne diese beiden Felder. <paramref name="draft"/> enthält schon
    /// V, Seq, Prev und Key.
    /// </summary>
    public static (string Line, AuditEntry Entry) SignLine(AuditEntry draft, IAuditSigner signer)
    {
        var body = Serialize(draft with { Hash = null, Sig = null });
        var bytes = Encoding.UTF8.GetBytes(body);
        var hash = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        // Base64url: der JSON-Serialisierer schriebe ein Plus als Unicode-Escape, die Zeile sähe beim Prüfen anders aus
        var sig = System.Buffers.Text.Base64Url.EncodeToString(signer.Sign(bytes));
        var entry = draft with { Hash = hash, Sig = sig };
        return (body[..^1] + $",\"Hash\":\"{hash}\",\"Sig\":\"{sig}\"}}", entry);
    }

    /// <summary>Signierte Bytes einer Zeile im Format 3, Hash und Signatur; null, wenn die Zeile nicht so endet.</summary>
    public static (string Body, string Hash, byte[] Sig)? SplitSigned(string line)
    {
        var m = SignedTailRegex().Match(line);
        if (!m.Success) return null;
        byte[] sig;
        try { sig = System.Buffers.Text.Base64Url.DecodeFromChars(m.Groups[2].Value); }
        catch (FormatException) { return null; }
        return (line[..m.Index] + "}", m.Groups[1].Value, sig);
    }

    [GeneratedRegex(@"audit-(\d{4}-\d{2})\.jsonl$", RegexOptions.CultureInvariant)]
    private static partial Regex FileMonthRegex();

    // ,"Hash":"<64 Hex>","Sig":"<Base64url ohne Auffüllung von 64 Bytes = 86 Zeichen>"}
    [GeneratedRegex(@",""Hash"":""([0-9a-f]{64})"",""Sig"":""([A-Za-z0-9_-]{86})""\}$", RegexOptions.CultureInvariant)]
    private static partial Regex SignedTailRegex();
}
