// SPDX-License-Identifier: MIT
using System.Text;
using Vitrine.Core.About;
using Vitrine.Core.Config;
using Vitrine.Core.Localization;

namespace Vitrine.Core.Audit;

/// <summary>Ein Eintrag, wie ihn der Dienst schreibt: Ereignis und Inhalt; Zeit, Nummer, Kette und Signatur kommen dazu.</summary>
public sealed record AuditRecord(AuditEventType Event, string SessionUser, string Assurance)
{
    public int? Session { get; init; }
    public string? Actor { get; init; }
    public string? Method { get; init; }
    public string? Detail { get; init; }
    public Dictionary<string, string>? Data { get; init; }
    public DateTimeOffset? ClientTime { get; init; }
}

/// <summary>
/// Protokoll im Format 3, geschrieben vom Dienst „ICT-Baden Vitrine“ (SYSTEM, #15): Jede Zeile ist mit dem Schlüssel des
/// Dienstes signiert (ECDSA P-256), die laufende Nummer zählt über alle Monatsdateien weiter, und die erste Zeile eines
/// Monats setzt die Kette des Vormonats fort. Nach jeder Zeile hält der Dienst Nummer und Hash als Anker außerhalb der
/// Datei fest (<see cref="IAuditAnchorStore"/>, Registry). Benutzer dürfen den Ordner nur lesen.
///
/// Passt das Dateiende nicht zum Anker (Ende abgeschnitten, Datei ersetzt oder gelöscht – das kann nur ein Administrator),
/// schreibt der Dienst einen Fehler-Eintrag (VIT-0316) und setzt die Kette am Anker fort: Der Bruch bleibt beim Prüfen
/// sichtbar. Steht am Dateiende eine Zeile im Format 1/2 (Übergang von einer älteren Version), setzt er die Kette dort fort
/// und schreibt zuerst <see cref="AuditEventType.AuditFormatSwitched"/>.
/// </summary>
public sealed class SignedAuditLog
{
    private readonly object _gate = new();
    private readonly Func<AuditSettings> _settings;
    private readonly IAuditKeyStore _keys;
    private readonly IAuditAnchorStore _anchors;
    private readonly IAuditSink? _sink;
    private readonly Func<DateTimeOffset> _clock;
    private readonly string _machine;
    private string? _keysWrittenFor;

    public SignedAuditLog(Func<AuditSettings> settings, IAuditKeyStore keys, IAuditAnchorStore anchors, IAuditSink? sink = null,
        Func<DateTimeOffset>? clock = null, string? machine = null)
    {
        _settings = settings;
        _keys = keys;
        _anchors = anchors;
        _sink = sink;
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
        _machine = machine ?? Environment.MachineName;
    }

    public string LogDirectory =>
        string.IsNullOrWhiteSpace(_settings().Directory) ? AppPaths.MachineLogDir : Environment.ExpandEnvironmentVariables(_settings().Directory!);

    public bool Enabled => _settings().Enabled;

    /// <summary>
    /// Ordner oder Datei ist eine Verknüpfung (Junction, symbolischer Link): nicht dorthin schreiben. Der Dienst schreibt als
    /// SYSTEM – ein umgelenkter Pfad wäre ein Weg, beliebige Dateien zu überschreiben.
    /// </summary>
    internal static void RefuseReparsePoint(string path)
    {
        if ((File.Exists(path) || Directory.Exists(path)) && File.GetAttributes(path).HasFlag(FileAttributes.ReparsePoint))
            throw new IOException($"{path} is a reparse point (junction or link) – not written");
    }

    /// <summary>Letzter Fehler beim Schreiben (für das Ereignisprotokoll des Dienstes), null = keiner.</summary>
    public string? LastError { get; private set; }

    /// <summary>Schreibt einen Eintrag. null, wenn das Protokoll aus ist oder das Schreiben scheitert (<see cref="LastError"/>).</summary>
    public AuditEntry? Write(AuditRecord record)
    {
        lock (_gate)
        {
            if (!_settings().Enabled) return null;
            try
            {
                var signer = _keys.Current();
                var now = _clock().ToUniversalTime();
                var (file, prevHash, seq, pending) = Prepare(now, signer);
                AuditEntry? last = null;
                foreach (var r in pending.Append(record))
                    (last, prevHash, seq) = Append(file, r, now, prevHash, seq, signer);
                LastError = null;
                return last;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException or
                                           System.Security.Cryptography.CryptographicException or InvalidOperationException)
            {
                LastError = ex.Message;
                return null;
            }
        }
    }

    /// <summary>
    /// Schlüsselwechsel: neuer Schlüssel, und ein Eintrag <see cref="AuditEventType.AuditKeyRotated"/> mit dessen
    /// öffentlichem Schlüssel, signiert noch mit dem alten. Danach signiert der neue. null bei einem Fehler.
    /// </summary>
    public AuditEntry? RotateKey(string sessionUser, string? actor = null)
    {
        lock (_gate)
        {
            try
            {
                var old = _keys.Current();
                var now = _clock().ToUniversalTime();
                var (file, prevHash, seq, pending) = Prepare(now, old);
                foreach (var r in pending) (_, prevHash, seq) = Append(file, r, now, prevHash, seq, old);
                var next = _keys.CreateNext();
                var record = new AuditRecord(AuditEventType.AuditKeyRotated, sessionUser, AuditAssurance.Service)
                {
                    Actor = actor,
                    Detail = $"Key {old.PublicKey.Id} -> {next.PublicKey.Id}",
                    Data = KeyData(next.PublicKey),
                };
                var (entry, _, _) = Append(file, record, now, prevHash, seq, old);
                _keysWrittenFor = null;
                WriteKeyFile(next);
                return entry;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException or
                                           System.Security.Cryptography.CryptographicException or InvalidOperationException)
            {
                LastError = ex.Message;
                return null;
            }
        }
    }

    private static Dictionary<string, string> KeyData(AuditPublicKey k) => new()
    {
        ["key"] = k.Id,
        ["fingerprint"] = k.Fingerprint,
        ["publicKey"] = Convert.ToBase64String(k.SubjectPublicKeyInfo),
    };

    /// <summary>Datei des Monats, Fortsetzung der Kette und Einträge, die vor dem eigentlichen stehen müssen (Formatwechsel, Bruch).</summary>
    private (string File, string? PrevHash, long Seq, List<AuditRecord> Pending) Prepare(DateTimeOffset now, IAuditSigner signer)
    {
        var month = AuditFormat.MonthOf(now);
        var dir = LogDirectory;
        Directory.CreateDirectory(dir);
        RefuseReparsePoint(dir);
        var file = Path.Combine(dir, AuditFormat.FileName(month));
        RefuseReparsePoint(file);
        WriteKeyFile(signer);

        var pending = new List<AuditRecord>();
        var anchor = _anchors.Get(month);
        var all = _anchors.All();
        var tailLine = File.Exists(file) ? AuditLog.LastLine(file) : null;
        var tail = tailLine is null ? null : AuditLog.Parse(tailLine);

        AuditRecord Problem(string detail) => new(AuditEventType.Error, "SYSTEM", AuditAssurance.Service)
        {
            Detail = $"{ErrorCodes.ServiceAnchorMismatch} {detail}",
            Data = new() { ["code"] = ErrorCodes.ServiceAnchorMismatch },
        };

        if (anchor is not null)
        {
            // Hier hat der Dienst schon geschrieben: Das Dateiende muss der Anker sein oder eine gültige, neuere eigene Zeile
            // (Absturz zwischen Schreiben und Anker)
            if (tail is not null && tail.V == AuditFormat.Signed && IsOwnLine(tailLine!) &&
                (tail.Seq > anchor.Seq || (tail.Seq == anchor.Seq && tail.Hash == anchor.Hash)))
                return (file, tail.Hash, tail.Seq, pending);
            var found = tail is null ? "no entries" : $"sequence {tail.Seq}, format {tail.V ?? 1}";
            pending.Add(Problem($"{Path.GetFileName(file)} ends with {found}, the service wrote up to sequence {anchor.Seq} – continuing from there"));
            return (file, anchor.Hash, anchor.Seq, pending);
        }

        var before = all.Where(a => string.CompareOrdinal(a.Month, month) < 0).OrderBy(a => a.Month, StringComparer.Ordinal).LastOrDefault();
        long maxSeq = all.Count == 0 ? 0 : all.Max(a => a.Seq);
        if (tail is not null && tail.V == AuditFormat.Signed)
        {
            // Signierte Zeile ohne Anker (Anker verloren, z. B. Registry zurückgesetzt): fortsetzen, wenn sie echt ist
            if (IsOwnLine(tailLine!)) return (file, tail.Hash, tail.Seq, pending);
            pending.Add(Problem($"{Path.GetFileName(file)} ends with a signed line that does not verify"));
            return (file, before?.Hash, Math.Max(maxSeq, tail.Seq), pending);
        }
        if (tail is not null)
        {
            // Übergang: Datei endet mit Format 1/2 (ältere Version oder App ohne Dienst) – Kette dort fortsetzen
            pending.Add(new AuditRecord(AuditEventType.AuditFormatSwitched, "SYSTEM", AuditAssurance.Service)
            {
                Detail = $"Format {tail.V ?? 1} -> {AuditFormat.Signed}: entries are now written and signed by the service, key {signer.PublicKey.Id}",
                Data = KeyData(signer.PublicKey),
            });
            return (file, tail.Hash, Math.Max(maxSeq, tail.Seq), pending);
        }
        if (tailLine is not null)
        {
            // Unlesbare letzte Zeile ohne Anker: neue Kette in der Datei, der Bruch bleibt beim Prüfen sichtbar
            pending.Add(Problem($"{Path.GetFileName(file)} ends with an unreadable line"));
        }
        if (all.Count == 0)
        {
            // Allererste signierte Zeile auf diesem Rechner
            pending.Add(new AuditRecord(AuditEventType.AuditFormatSwitched, "SYSTEM", AuditAssurance.Service)
            {
                Detail = $"Format {AuditFormat.Signed}: entries are written and signed by the service, key {signer.PublicKey.Id}",
                Data = KeyData(signer.PublicKey),
            });
            return (file, null, 0, pending);
        }
        // Neuer Monat: Kette und Nummer des letzten Monats fortsetzen
        return (file, before?.Hash, maxSeq, pending);
    }

    /// <summary>Ist die Zeile vom Dienst (Signatur mit einem seiner Schlüssel)?</summary>
    private bool IsOwnLine(string line)
    {
        if (AuditLog.Parse(line) is not { Key: { } keyId } e || AuditFormat.SplitSigned(line) is not { } parts) return false;
        if (!string.Equals(AuditFormat.Serialize(e), line, StringComparison.Ordinal) || AuditFormat.HashOf(parts.Body) != e.Hash) return false;
        var key = _keys.PublicKeys().FirstOrDefault(k => k.Id == keyId);
        return key is not null && key.Verify(Encoding.UTF8.GetBytes(parts.Body), parts.Sig);
    }

    private (AuditEntry Entry, string Hash, long Seq) Append(string file, AuditRecord r, DateTimeOffset now, string? prevHash, long seq,
        IAuditSigner signer)
    {
        var draft = new AuditEntry
        {
            V = AuditFormat.Signed,
            Seq = seq + 1,
            Time = now,
            ClientTime = r.ClientTime,
            Machine = _machine,
            Session = r.Session,
            SessionUser = r.SessionUser,
            Event = r.Event,
            Actor = r.Actor,
            Method = r.Method,
            Detail = r.Detail,
            Data = r.Data is { Count: > 0 } ? r.Data : null,
            Assurance = r.Assurance,
            Prev = prevHash,
            Key = signer.PublicKey.Id,
        };
        var (line, entry) = AuditFormat.SignLine(draft, signer);
        var bytes = Encoding.UTF8.GetBytes(line + "\n");
        for (int attempt = 0; ; attempt++)
        {
            try
            {
                // Nur der Dienst schreibt; ohne Schreibfreigabe, damit eine noch laufende ältere App nicht dazwischen schreibt
                RefuseReparsePoint(file);
                using var fs = new FileStream(file, FileMode.Append, FileAccess.Write, FileShare.Read);
                fs.Write(bytes);
                fs.Flush(true);
                break;
            }
            catch (IOException) when (attempt < 40) { Thread.Sleep(25); }
        }
        // Erst nach dem Schreiben: Ein Absturz dazwischen lässt den Anker eine Zeile zurück (das erkennt Prepare)
        _anchors.Set(new AuditAnchor(AuditFormat.MonthOf(now), entry.Seq, entry.Hash!));

        var settings = _settings();
        if (!string.IsNullOrWhiteSpace(settings.NetworkDirectory))
        {
            var dir = Environment.ExpandEnvironmentVariables(settings.NetworkDirectory);
            AuditLog.NetworkCopies.Enqueue(Path.Combine(dir, $"{_machine}-{Path.GetFileName(file)}"), line + "\n");
        }
        if (settings.EventLog)
        {
            try { _sink?.Write(entry); }
            catch { /* Ereignisprotokoll ist ein Zusatz */ }
        }
        return (entry, entry.Hash!, entry.Seq);
    }

    /// <summary>
    /// Öffentliche Schlüssel als audit-keys.json neben die Protokolle (und als RECHNER-audit-keys.json in die Netzkopie),
    /// damit ein Prüfer ohne das Geheimnis prüfen kann. Einmal je Schlüssel und Ordner.
    /// </summary>
    private void WriteKeyFile(IAuditSigner current)
    {
        var dir = LogDirectory;
        var marker = $"{dir}|{current.PublicKey.Id}|{_settings().NetworkDirectory}";
        if (_keysWrittenFor == marker) return;
        var json = AuditKeyFile.Serialize(_machine, _keys.PublicKeys());
        Directory.CreateDirectory(dir);
        RefuseReparsePoint(dir);
        var keysFile = Path.Combine(dir, AuditVerifyOptions.KeysFileSuffix);
        RefuseReparsePoint(keysFile);
        File.WriteAllText(keysFile, json);
        if (_settings().NetworkDirectory is { Length: > 0 } net)
        {
            try
            {
                var target = Environment.ExpandEnvironmentVariables(net);
                Directory.CreateDirectory(target);
                File.WriteAllText(Path.Combine(target, $"{_machine}-{AuditVerifyOptions.KeysFileSuffix}"), json);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException) { }
        }
        _keysWrittenFor = marker;
    }
}
