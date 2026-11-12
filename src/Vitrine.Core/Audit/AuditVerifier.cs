// SPDX-License-Identifier: MIT
using System.Text;
using Vitrine.Core.Localization;

namespace Vitrine.Core.Audit;

/// <summary>Womit geprüft wird: vertrauenswürdige öffentliche Schlüssel und – auf dem Rechner selbst – die Anker des Dienstes.</summary>
public sealed class AuditVerifyOptions
{
    /// <summary>Öffentliche Schlüssel, denen der Prüfer vertraut (aus audit-keys.json oder --keys). Weitere kommen nur über einen Schlüsselwechsel dazu, den ein vertrauter Schlüssel signiert hat.</summary>
    public IReadOnlyList<AuditPublicKey> TrustedKeys { get; init; } = [];

    /// <summary>Anker (letzte Nummer und Hash je Monat). null = keine Prüfung des Endes.</summary>
    public IAuditAnchorStore? Anchors { get; init; }

    /// <summary>Rechner, zu dem die Anker gehören; sie gelten nur für Dateien, deren Einträge von diesem Rechner stammen.</summary>
    public string? AnchorMachine { get; init; }

    /// <summary>
    /// Schlüssel aus der Schlüsseldatei neben der geprüften Datei – nur die mit demselben Präfix (audit-keys.json zu
    /// audit-*.jsonl, RECHNER-audit-keys.json zur Netzkopie RECHNER-audit-*.jsonl), nie die anderer Rechner im selben Ordner.
    /// </summary>
    public bool KeysNextToFile { get; init; }

    /// <summary>
    /// Bevorzugte Schlüssel für Dateien eines bestimmten Rechners (auf dem Rechner selbst: die aus der Registry); gelten,
    /// wenn die erste signierte Zeile von <see cref="PreferredKeysMachine"/> stammt.
    /// </summary>
    public IReadOnlyList<AuditPublicKey> PreferredKeys { get; init; } = [];

    public string? PreferredKeysMachine { get; init; }

    /// <summary>
    /// Standard für eine Datei oder einen Ordner: Schlüssel aus der passenden Schlüsseldatei daneben
    /// (<see cref="KeysNextToFile"/>), keine Anker.
    /// </summary>
    public static AuditVerifyOptions ForPath(string fileOrDir, IAuditAnchorStore? anchors = null, string? anchorMachine = null) =>
        new() { KeysNextToFile = true, Anchors = anchors, AnchorMachine = anchorMachine };

    /// <summary>Schlüssel aus der Schlüsseldatei mit demselben Präfix wie <paramref name="logFile"/>.</summary>
    public static List<AuditPublicKey> KeysFileFor(string logFile)
    {
        var name = Path.GetFileName(logFile);
        var i = name.LastIndexOf("audit-", StringComparison.Ordinal);
        var prefix = i > 0 ? name[..i] : "";
        var path = Path.Combine(Path.GetDirectoryName(Path.GetFullPath(logFile)) ?? ".", prefix + KeysFileSuffix);
        try
        {
            if (File.Exists(path) && AuditKeyFile.Parse(File.ReadAllText(path)) is { } parsed) return parsed.Keys;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        return [];
    }

    /// <summary>Endung der Schlüsseldatei (audit-keys.json, RECHNER-audit-keys.json).</summary>
    public const string KeysFileSuffix = "audit-keys.json";
}

/// <summary>Ergebnis der Prüfung einer Datei oder eines Ordners.</summary>
public sealed record AuditVerifyResult(bool Ok, string Message, string? Code = null)
{
    public long Entries { get; init; }
    public long SignedEntries { get; init; }
    public long UnsignedEntries => Entries - SignedEntries;
    public long LastSeq { get; init; }
    public string? LastHash { get; init; }
    public IReadOnlyList<string> Fingerprints { get; init; } = [];
}

/// <summary>
/// Prüft Protokolldateien der Formate 1 bis 3 (<c>--verify-log</c>, Einstellungen). Format 3 (Dienst, #15):
/// <list type="bullet">
/// <item>Signatur jeder Zeile mit einem vertrauten Schlüssel; ein neuer Schlüssel gilt nur nach einem vom alten signierten
/// <see cref="AuditEventType.AuditKeyRotated"/> (VIT-0301, VIT-0302, VIT-0310);</item>
/// <item>lückenlose laufende Nummer über Dateien hinweg und Kette Prev → Hash (VIT-0303, VIT-0021): erkennt gelöschte,
/// eingefügte und vertauschte Zeilen;</item>
/// <item>Zeit jeder Zeile im Monat der Datei (VIT-0307): erkennt eine Datei aus einem anderen Monat;</item>
/// <item>nach der ersten signierten Zeile keine unsignierte mehr (VIT-0308): erkennt angehängte Zeilen im alten Format;</item>
/// <item>erste Zeile setzt die Datei des Vormonats fort (VIT-0309), mit den Ankern des Dienstes: Ende nicht abgeschnitten
/// (VIT-0304), Anker passt (VIT-0305), keine Monatsdatei fehlt (VIT-0306).</item>
/// </list>
/// Formate 1 und 2 werden wie bisher geprüft (Hash-Kette ohne Schlüssel) und als nicht signiert gemeldet.
/// </summary>
public static class AuditVerifier
{
    public static AuditVerifyResult VerifyFile(string file, AuditVerifyOptions o) => VerifyFile(file, o, checkMissingMonths: true);

    /// <summary>Alle Monatsdateien eines Ordners (aufsteigend) und fehlende Monate laut Anker.</summary>
    public static AuditVerifyResult VerifyFolder(string dir, AuditVerifyOptions o)
    {
        List<string> files;
        try { files = Directory.EnumerateFiles(dir, "*audit-*.jsonl").Where(f => AuditFormat.FileMonth(f) is not null).Order(StringComparer.Ordinal).ToList(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return Fail(ErrorCodes.LogFileUnreadable, ex.Message);
        }
        if (MissingMonth(dir, o, files) is { } missing) return missing;
        long entries = 0, signed = 0;
        var fingerprints = new List<string>();
        AuditVerifyResult? last = null;
        foreach (var f in files)
        {
            var r = VerifyFile(f, o, checkMissingMonths: false);
            if (!r.Ok) return r with { Message = $"{Path.GetFileName(f)}: {r.Message}" };
            entries += r.Entries;
            signed += r.SignedEntries;
            fingerprints.AddRange(r.Fingerprints);
            last = r;
        }
        if (last is null) return Fail(ErrorCodes.LogFileUnreadable, dir);
        return Success(entries, signed, fingerprints.Distinct().ToList(), last.LastSeq, last.LastHash, files.Count);
    }

    private static AuditVerifyResult VerifyFile(string file, AuditVerifyOptions o, bool checkMissingMonths)
    {
        var month = AuditFormat.FileMonth(file);
        var trusted = new Dictionary<string, AuditPublicKey>(StringComparer.Ordinal);
        bool keysChosen = false;
        // Schlüssel, der gerade signiert: Ein anderer gilt erst nach einem von ihm signierten AuditKeyRotated
        string? currentKey = null;
        var used = new List<string>();

        string? prev = null;
        long n = 0, signed = 0, prevSeq = 0;
        bool inSigned = false;
        string? machine = null;
        bool foreignMachine = false;
        var seen = new Dictionary<long, string>();
        try
        {
            foreach (var raw in File.ReadLines(file))
            {
                if (string.IsNullOrWhiteSpace(raw)) continue;
                n++;
                var line = raw.TrimEnd('\r');
                var e = AuditLog.Parse(line);
                if (e is null) return Fail(ErrorCodes.LogLineUnreadable, n);

                if (e.V != AuditFormat.Signed)
                {
                    // Unsigniert nach signiert: angehängt, nicht vom Dienst
                    if (inSigned) return Fail(ErrorCodes.LogUnsignedAfterSigned, n, e.Seq);
                    if (e.Prev != prev) return Fail(ErrorCodes.LogChainBroken, n, e.Seq);
                    if (CheckUnsigned(line, e) is { } code) return Fail(code, n, e.Seq);
                    prev = e.Hash;
                    prevSeq = e.Seq;
                    continue;
                }

                // ---- Format 3 ----
                if (!string.Equals(AuditFormat.Serialize(e), line, StringComparison.Ordinal)) return Fail(ErrorCodes.LogEntryModified, n, e.Seq);
                if (AuditFormat.SplitSigned(line) is not { } parts || e.Key is null) return Fail(ErrorCodes.LogEntryModified, n, e.Seq);
                var bytes = Encoding.UTF8.GetBytes(parts.Body);
                if (AuditFormat.HashOf(parts.Body) != e.Hash) return Fail(ErrorCodes.LogEntryModified, n, e.Seq);
                if (!keysChosen)
                {
                    keysChosen = true;
                    IReadOnlyList<AuditPublicKey> keys =
                        o.PreferredKeys.Count > 0 && string.Equals(e.Machine, o.PreferredKeysMachine, StringComparison.OrdinalIgnoreCase) ? o.PreferredKeys
                        : o.KeysNextToFile ? KeysFor(file, o)
                        : o.TrustedKeys;
                    foreach (var k in keys) trusted[k.Id] = k;
                    // Setzt die Datei den Vormonat fort, gilt dessen letzter Schlüssel weiter
                    currentKey = PreviousSibling(file) is { } prior && AuditLog.LastLine(prior) is { } priorLine &&
                                 AuditLog.Parse(priorLine) is { V: AuditFormat.Signed } priorTail
                        ? priorTail.Event == AuditEventType.AuditKeyRotated ? priorTail.Data?.GetValueOrDefault("key") : priorTail.Key
                        : null;
                    if (currentKey is not null && !trusted.ContainsKey(currentKey)) currentKey = null;
                }
                if (trusted.Count == 0) return Fail(ErrorCodes.LogNoPublicKey, Path.GetFileName(file));
                if (!trusted.TryGetValue(e.Key, out var key)) return Fail(ErrorCodes.LogUnknownKey, n, e.Seq, e.Key);
                if (!key.Verify(bytes, parts.Sig)) return Fail(ErrorCodes.LogSignatureInvalid, n, e.Seq);
                // Jeder vertraute Schlüssel darf nicht jede Zeile signieren: nur der aktuelle (z. B. kein alter, ausgemusterter)
                if (currentKey is not null && e.Key != currentKey) return Fail(ErrorCodes.LogKeyNotCurrent, n, e.Seq, e.Key, currentKey);
                currentKey = e.Key;
                if (!used.Contains(key.Fingerprint)) used.Add(key.Fingerprint);

                if (month is not null && AuditFormat.MonthOf(e.Time) != month)
                    return Fail(ErrorCodes.LogWrongMonth, n, e.Seq, AuditFormat.MonthOf(e.Time));

                if (!inSigned && n == 1)
                {
                    // Erste Zeile der Datei: setzt sie den Vormonat fort?
                    if (e.Prev is not null && PreviousSibling(file) is { } before)
                    {
                        var tail = AuditLog.LastLine(before) is { } t ? AuditLog.Parse(t) : null;
                        if (tail is null || tail.Hash != e.Prev || tail.Seq != e.Seq - 1)
                            return Fail(ErrorCodes.LogPreviousFileMismatch, AuditFormat.FileMonth(before));
                    }
                    // Auf dem Rechner selbst: Ohne früheren Monat beginnt die erste signierte Datei ohne Vorgänger – sonst
                    // fehlt ihr Anfang
                    else if (e.Prev is not null && month is not null && o.Anchors is not null &&
                             string.Equals(e.Machine, o.AnchorMachine, StringComparison.OrdinalIgnoreCase) &&
                             !o.Anchors.All().Any(a => string.CompareOrdinal(a.Month, month) < 0))
                        return Fail(ErrorCodes.LogPreviousFileMismatch, AuditFormat.PreviousMonth(month));
                }
                else if (e.Prev != prev) return Fail(ErrorCodes.LogChainBroken, n, e.Seq);
                else if (inSigned ? e.Seq != prevSeq + 1 : e.Seq <= prevSeq) return Fail(ErrorCodes.LogSequenceGap, n, e.Seq, prevSeq);

                // Schlüsselwechsel: Der neue Schlüssel gilt, weil ein vertrauter ihn hier signiert hat
                if (e.Event == AuditEventType.AuditKeyRotated && e.Data?.GetValueOrDefault("publicKey") is { } pk)
                {
                    try
                    {
                        var next = AuditPublicKey.From(Convert.FromBase64String(pk));
                        if (next.Id == e.Data.GetValueOrDefault("key"))
                        {
                            trusted.TryAdd(next.Id, next);
                            currentKey = next.Id;
                        }
                    }
                    catch (FormatException) { }
                }

                machine ??= e.Machine;
                if (!string.Equals(machine, e.Machine, StringComparison.OrdinalIgnoreCase)) foreignMachine = true;
                seen[e.Seq] = e.Hash!;
                inSigned = true;
                signed++;
                prev = e.Hash;
                prevSeq = e.Seq;
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Fail(ErrorCodes.LogFileUnreadable, ex.Message);
        }

        // Anker des Dienstes: nur auf dem Rechner, der die Einträge geschrieben hat
        bool anchorsApply = o.Anchors is not null && month is not null && !foreignMachine &&
                            (machine is null || string.Equals(machine, o.AnchorMachine, StringComparison.OrdinalIgnoreCase));
        if (anchorsApply && o.Anchors!.Get(month!) is { } anchor)
        {
            if (prevSeq < anchor.Seq || !inSigned) return Fail(ErrorCodes.LogTruncated, inSigned ? prevSeq : 0, anchor.Seq, month);
            if (!seen.TryGetValue(anchor.Seq, out var h) || h != anchor.Hash) return Fail(ErrorCodes.LogAnchorMismatch, anchor.Seq);
        }
        if (checkMissingMonths && anchorsApply && Path.GetDirectoryName(Path.GetFullPath(file)) is { } dir &&
            MissingMonth(dir, o, null, Prefix(file)) is { } missing)
            return missing;

        return Success(n, signed, used, prevSeq, prev, 1);
    }

    private static IReadOnlyList<AuditPublicKey> KeysFor(string file, AuditVerifyOptions o)
    {
        var keys = AuditVerifyOptions.KeysFileFor(file);
        return keys.Count > 0 ? keys : o.TrustedKeys;
    }

    /// <summary>Format 1 und 2: genau Vitrines Schreibweise und passender Hash. null = in Ordnung, sonst der Fehlercode.</summary>
    private static string? CheckUnsigned(string line, AuditEntry e)
    {
        if (!string.Equals(AuditFormat.Serialize(e), line, StringComparison.Ordinal)) return ErrorCodes.LogEntryModified;
        // Felder des Formats 3 gehören nicht in eine unsignierte Zeile
        if (e.Key is not null || e.Sig is not null || e.Assurance is not null || e.Session is not null || e.ClientTime is not null)
            return ErrorCodes.LogEntryModified;
        if (e.V is null) return AuditLog.ComputeHash(e) == e.Hash ? null : ErrorCodes.LogEntryModified;
        if (e.V != AuditFormat.Local) return ErrorCodes.LogEntryModified; // unbekanntes Format
        return BodyWithoutHash(line) is { } body && AuditFormat.HashOf(body) == e.Hash ? null : ErrorCodes.LogEntryModified;
    }

    private const string HashFieldStart = ",\"Hash\":\"";

    /// <summary>Format 2: die Zeile ohne ihr abschließendes Hash-Feld; null, wenn sie nicht so endet.</summary>
    internal static string? BodyWithoutHash(string line)
    {
        const int hexLength = 64;
        int start = line.Length - (HashFieldStart.Length + hexLength + 2);
        if (start < 1 || !line.EndsWith("\"}", StringComparison.Ordinal) ||
            string.CompareOrdinal(line, start, HashFieldStart, 0, HashFieldStart.Length) != 0)
            return null;
        return line[..start] + "}";
    }

    /// <summary>Teil des Dateinamens vor „audit-“ (leer, bei der Netzkopie „RECHNER-“).</summary>
    private static string Prefix(string file)
    {
        var name = Path.GetFileName(file);
        var i = name.LastIndexOf("audit-", StringComparison.Ordinal);
        return i > 0 ? name[..i] : "";
    }

    /// <summary>Neueste Datei desselben Ordners und Präfixes aus einem früheren Monat.</summary>
    private static string? PreviousSibling(string file)
    {
        var dir = Path.GetDirectoryName(Path.GetFullPath(file));
        var month = AuditFormat.FileMonth(file);
        if (dir is null || month is null) return null;
        var prefix = Prefix(file);
        try
        {
            return Directory.EnumerateFiles(dir, prefix + "audit-*.jsonl")
                .Where(f => Prefix(f) == prefix && AuditFormat.FileMonth(f) is { } m && string.CompareOrdinal(m, month) < 0)
                .OrderDescending(StringComparer.Ordinal).FirstOrDefault();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }
    }

    /// <summary>Monat mit Anker, aber ohne Datei im Ordner: VIT-0306.</summary>
    private static AuditVerifyResult? MissingMonth(string dir, AuditVerifyOptions o, List<string>? files, string prefix = "")
    {
        if (o.Anchors is null) return null;
        try
        {
            var present = (files ?? Directory.EnumerateFiles(dir, prefix + "audit-*.jsonl").ToList())
                .Select(AuditFormat.FileMonth).OfType<string>().ToHashSet(StringComparer.Ordinal);
            foreach (var a in o.Anchors.All())
                if (!present.Contains(a.Month)) return Fail(ErrorCodes.LogFileMissing, a.Month, a.Seq);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        return null;
    }

    private static AuditVerifyResult Fail(string code, params object?[] args) => new(false, CoreText.Error(code, args), code);

    private static AuditVerifyResult Success(long n, long signed, IReadOnlyList<string> fingerprints, long lastSeq, string? lastHash, int files)
    {
        var msg = CoreText.F("Audit_ChainComplete", n);
        if (signed > 0) msg += " · " + CoreText.F("Audit_Signed", signed, string.Join(", ", fingerprints.Select(f => f[..16])));
        if (n - signed > 0) msg += " · " + CoreText.F("Audit_Unsigned", n - signed);
        return new(true, msg) { Entries = n, SignedEntries = signed, Fingerprints = fingerprints, LastSeq = lastSeq, LastHash = lastHash };
    }
}
