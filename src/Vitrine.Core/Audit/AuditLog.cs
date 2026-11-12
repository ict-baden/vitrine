// SPDX-License-Identifier: MIT
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Vitrine.Core.About;
using Vitrine.Core.Config;
using Vitrine.Core.Localization;

namespace Vitrine.Core.Audit;

public enum AuditEventType
{
    AppStarted,
    AppStopped,
    Locked,
    PromptShown,
    PromptClosed,
    Unlocked,
    UnlockFailed,
    UnlockDenied,
    FailureActionTriggered,
    SignatureGranted,
    SignatureFailed,
    ConfigChanged,
    Error,
    // Dienst „ICT-Baden Vitrine“
    ServiceStarted,
    ServiceStopped,
    /// <summary>Sitzungs-App verschwunden oder antwortet nicht (Detail: locked/unlocked).</summary>
    AgentLost,
    /// <summary>Sitzungs-App nach bestätigtem Beenden nicht neu gestartet.</summary>
    AgentStopped,
    AgentStartFailed,
    /// <summary>Sitzung vom Dienst getrennt, weil die Sperre sonst offen gewesen wäre.</summary>
    SessionDisconnected,
    /// <summary>Sitzungs-App hat sich beim Dienst gemeldet; ab jetzt überwacht (neu 2026-10-20, Ereignis-ID 1019).</summary>
    AgentConnected,
    /// <summary>Abmelden oder Neustart während der Sperre abgelehnt (neu 2026-10-21, Ereignis-ID 1020; Detail: Logoff/Shutdown).</summary>
    SessionEndRefused,
    /// <summary>
    /// Der Dienst schreibt ab hier im Format 3 (signiert); erster Eintrag nach Format 1/2 oder in einem neuen Protokoll.
    /// Data: Schlüssel-ID und öffentlicher Schlüssel (Ereignis-ID 1021, neu mit #15).
    /// </summary>
    AuditFormatSwitched,
    /// <summary>Neuer Schlüssel; dieser Eintrag ist noch mit dem alten signiert (Ereignis-ID 1022).</summary>
    AuditKeyRotated,
    /// <summary>
    /// Die App schreibt das Protokoll selbst, ohne Dienst (portable Exe, SERVICE=0): nicht Part-11-fähig (Ereignis-ID 1023).
    /// Steht am Anfang jedes Laufs, der lokal schreibt.
    /// </summary>
    AuditLocalMode,
    /// <summary>
    /// Entsperrt über die Notfall-Anmeldung (Unlock.BypassGroups) – die Person stand nicht in den Entsperr-Regeln oder hat
    /// den Notfall-Weg gewählt. Data: reason (Begründung). Immer auch als Warnung ins Ereignisprotokoll (neu 0.5.0).
    /// </summary>
    UnlockBypass,
    /// <summary>
    /// Eine andere Person als bisher hat entsperrt und ist jetzt für den Rechner verantwortlich (GxP). Detail: „von -> zu“,
    /// Data: fromUser, toUser, method (neu 0.5.0).
    /// </summary>
    ResponsibilityChanged,
    /// <summary>
    /// Während der Sperre war ein anderer Desktop als erwartet der Eingabe-Desktop (Flucht vom Sperr-Desktop, fremder
    /// Desktop eines anderen Programms); Vitrine schaltet zurück (Ereignis-ID 1026). Detail: Desktop, erwarteter Desktop.
    /// </summary>
    DesktopSwitchDetected,
    /// <summary>Windows wurde gesperrt, während Vitrine gesperrt war (Ereignis-ID 1027). Detail: Ursache, Modus.</summary>
    WindowsLockDetected,
    /// <summary>Sicherheitsschlüssel registriert (nur der Dienst; Ereignis-ID 1028).</summary>
    FidoKeyRegistered,
    /// <summary>Sicherheitsschlüssel widerrufen (nur der Dienst; Ereignis-ID 1029).</summary>
    FidoKeyRevoked,
    /// <summary>Anmeldung oder Registrierung mit Sicherheitsschlüssel abgelehnt (nur der Dienst; Ereignis-ID 1030).</summary>
    FidoKeyRejected,
    /// <summary>Signaturzähler eines Schlüssels nicht gestiegen – möglicherweise kopiert (nur der Dienst; Ereignis-ID 1031).</summary>
    FidoCloneSuspected,
}

/// <summary>
/// Vertrauensstufe eines Eintrags im Format 3 (<see cref="AuditEntry.Assurance"/>): Wofür bürgt der Dienst?
/// Zeit, Nummer, Sitzung und Sitzungsbenutzer setzt er immer selbst.
/// </summary>
public static class AuditAssurance
{
    /// <summary>Eigenes Ereignis des Dienstes (Start, Überwachung, Formatwechsel).</summary>
    public const string Service = "service";

    /// <summary>Der Dienst hat die Anmeldung selbst geprüft (Windows-Kennwort mit LogonUser, Entra-ID-Token mit Signatur).</summary>
    public const string Verified = "verified";

    /// <summary>
    /// Von der Sitzungs-App gemeldet; der Dienst bürgt nur für Zeit, Nummer und Sitzung, nicht für Person und Inhalt
    /// (Sperren, Entsperren, Fehlversuche, Signaturen mit Windows Hello oder Plugin).
    /// </summary>
    public const string Client = "client";

    /// <summary>Nur in der Antwort der Schnittstelle, nie im Protokoll: ohne Dienst geschrieben (Format 2, nicht Part-11-fähig).</summary>
    public const string Local = "local";
}

public sealed record AuditEntry
{
    /// <summary>
    /// Format der Zeile: fehlt (null) = 1 (bis 2026-10-21), 2 = Hash über die Bytes der Zeile ohne das Hash-Feld.
    /// Steht als erstes Feld in der Zeile.
    /// </summary>
    public int? V { get; init; }
    public long Seq { get; init; }
    public DateTimeOffset Time { get; init; }
    /// <summary>Format 3: Zeit laut Sitzungs-App, nur wenn der Eintrag gepuffert wurde (Dienst nicht erreichbar) – nicht geprüft.</summary>
    public DateTimeOffset? ClientTime { get; init; }
    public string Machine { get; init; } = Environment.MachineName;
    /// <summary>Format 3: Windows-Sitzung der Gegenstelle, vom Dienst festgestellt.</summary>
    public int? Session { get; init; }
    public string SessionUser { get; init; } = "";
    public AuditEventType Event { get; init; }
    public string? Actor { get; init; }
    public string? Method { get; init; }
    public string? Detail { get; init; }
    public Dictionary<string, string>? Data { get; init; }
    /// <summary>Format 3: <see cref="AuditAssurance"/>.</summary>
    public string? Assurance { get; init; }
    public string? Prev { get; init; }
    /// <summary>Format 3: ID des Schlüssels, mit dem <see cref="Sig"/> erstellt wurde.</summary>
    public string? Key { get; init; }
    public string? Hash { get; set; }
    /// <summary>Format 3: ECDSA-P-256-Signatur (IEEE P1363, Base64url ohne Auffüllung) über dieselben Bytes wie <see cref="Hash"/>.</summary>
    public string? Sig { get; set; }
}

/// <summary>
/// Leitet Einträge der Sitzungs-App an den Dienst weiter, statt sie selbst zu schreiben (Format 3, #15).
/// <paramref name="committed"/> kommt, sobald der Dienst den Eintrag mit Nummer und Hash geschrieben hat (anderer Thread).
/// </summary>
public interface IAuditForwarder
{
    void Forward(AuditEntry draft, Action<AuditEntry>? committed);
}

/// <summary>Zusätzliches Ziel für Einträge, z. B. das Windows-Ereignisprotokoll (in der App).</summary>
public interface IAuditSink
{
    void Write(AuditEntry entry);
}

/// <summary>
/// Manipulationserkennendes Protokoll: JSON-Zeilen, jede Zeile enthält den SHA-256 der vorherigen (Hash-Kette). Wird
/// eine Zeile geändert oder mittendrin gelöscht, bricht die Kette – prüfbar mit <c>Vitrine.exe --verify-log &lt;datei&gt;</c>.
/// Wer Schreibrecht auf die Datei hat, kann sie aber neu berechnen oder am Ende kürzen (docs/limitations.md); dagegen
/// helfen nur Dateirechte (Setup: Benutzer dürfen nur anhängen) und die Kopie auf einer Freigabe.
/// Zeiten in UTC, Texte in <see cref="AuditEntry.Detail"/> sprachunabhängig auf Englisch (richtlinien/13 Punkt 5).
/// Seit 2026-10-21 (Format 2, Feld „V“) gilt der Hash den Bytes der Zeile selbst (ohne das abschließende Hash-Feld);
/// vorher wurde die Zeile zum Prüfen gelesen und neu geschrieben, so dass zusätzliche, unbekannte Felder nicht auffielen.
/// Beim Prüfen muss jede Zeile außerdem genau so aussehen, wie Vitrine sie schreibt (keine fremden Felder, keine doppelten,
/// keine andere Schreibweise) – das gilt auch für Zeilen im alten Format.
/// </summary>
public sealed class AuditLog
{
    /// <summary>Format der Zeilen, die die App selbst schreibt (<see cref="AuditEntry.V"/>); der Dienst schreibt Format 3 (<see cref="SignedAuditLog"/>).</summary>
    public const int FormatVersion = AuditFormat.Local;

    private static JsonSerializerOptions Opts => AuditFormat.Opts;

    private readonly object _gate = new();
    private readonly string _sessionUser;
    private readonly IAuditSink? _sink;
    private readonly Func<DateTimeOffset> _clock;
    private AuditSettings _settings;
    private string? _currentFile;
    private IAuditForwarder? _forwarder;

    public AuditLog(AuditSettings settings, string sessionUser, IAuditSink? sink = null, Func<DateTimeOffset>? clock = null)
    {
        _settings = settings;
        _sessionUser = sessionUser;
        _sink = sink;
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
    }

    public void Update(AuditSettings settings)
    {
        lock (_gate) { _settings = settings; _currentFile = null; }
    }

    /// <summary>
    /// Einträge an den Dienst weiterleiten statt selbst zu schreiben (#15). null = selbst schreiben (Format 2, ohne
    /// Schlüssel – nicht Part-11-fähig; nur ohne Dienst: portable Exe, SERVICE=0).
    /// </summary>
    public void UseForwarder(IAuditForwarder? forwarder)
    {
        lock (_gate) _forwarder = forwarder;
    }

    /// <summary>Schreibt der Dienst (Format 3)? Sonst schreibt diese Instanz selbst.</summary>
    public bool Forwarding { get { lock (_gate) return _forwarder is not null; } }

    public bool Enabled { get { lock (_gate) return _settings.Enabled; } }

    public string LogDirectory =>
        string.IsNullOrWhiteSpace(_settings.Directory)
            ? AppPaths.MachineLogDir
            : Environment.ExpandEnvironmentVariables(_settings.Directory);

    /// <summary>Ordner, in denen Protokolle liegen können (eingestellt, Ersatz pro Benutzer, alter Standard).</summary>
    public IEnumerable<string> SearchDirectories => new[] { LogDirectory, AppPaths.UserLogDir, AppPaths.LegacyMachineLogDir }
        .Distinct(StringComparer.OrdinalIgnoreCase);

    /// <summary>Neueste Protokolldatei, null wenn es noch keine gibt.</summary>
    public string? CurrentFile()
    {
        foreach (var dir in SearchDirectories)
        {
            try
            {
                if (!Directory.Exists(dir)) continue;
                var f = Directory.EnumerateFiles(dir, "audit-*.jsonl").OrderDescending(StringComparer.Ordinal).FirstOrDefault();
                if (f is not null) return f;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
        return null;
    }

    /// <param name="committed">Wenn der Eintrag mit Nummer und Hash geschrieben ist: gleich (selbst geschrieben) oder später
    /// auf einem anderen Thread (Dienst). Nie, wenn das Protokoll aus ist oder das Schreiben scheitert.</param>
    public AuditEntry Write(AuditEventType type, string? actor = null, string? method = null, string? detail = null,
        Dictionary<string, string>? data = null, Action<AuditEntry>? committed = null)
    {
        lock (_gate)
        {
            var now = _clock().ToUniversalTime();
            var entry = new AuditEntry
            {
                Time = now,
                SessionUser = _sessionUser,
                Event = type,
                Actor = actor,
                Method = method,
                Detail = detail,
                Data = data,
            };
            if (!_settings.Enabled) return entry;
            if (_forwarder is { } forwarder)
            {
                // Zeit, Nummer und Sitzungsbenutzer setzt der Dienst; Time hier ist nur die Angabe der App (ClientTime)
                forwarder.Forward(entry, committed);
                return entry;
            }

            // Das Protokoll ist ein Zusatz zur Sperre: ein Fehler hier darf nie Sperren oder Entsperren verhindern
            AuditEntry written;
            try { written = WriteLocked(entry, now); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
            {
                return entry;
            }
            if (written.Hash is not null) committed?.Invoke(written);
            return written;
        }
    }

    /// <summary>
    /// Einträge, die der Dienst nicht mehr bekommen hat (App endet, Dienst nicht erreichbar): in den Ersatzordner pro
    /// Benutzer im Format 2, mit <see cref="AuditEventType.AuditLocalMode"/> davor – lieber ungeschützt als still verloren.
    /// Die Zeiten sind die der App.
    /// </summary>
    /// <param name="directory">Ersatzordner; Standard <see cref="AppPaths.UserLogDir"/> (andere nur in Tests).</param>
    public void WriteUnsent(IReadOnlyList<AuditEntry> drafts, string? directory = null)
    {
        if (drafts.Count == 0) return;
        lock (_gate)
        {
            try
            {
                var now = _clock().ToUniversalTime();
                var file = Path.Combine(directory ?? AppPaths.UserLogDir, AuditFormat.FileName(AuditFormat.MonthOf(now)));
                AppendChained(file, new AuditEntry
                {
                    Time = now, SessionUser = _sessionUser, Event = AuditEventType.AuditLocalMode,
                    Detail = $"{drafts.Count} entries not delivered to the service – not Part 11 capable",
                });
                foreach (var d in drafts) AppendChained(file, d);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException) { }
        }
    }

    private AuditEntry WriteLocked(AuditEntry entry, DateTimeOffset now)
    {
            var file = ResolveFile(now);
            var written = AppendChained(file, entry);
            if (written is null)
            {
                // Kein Schreibrecht: lieber pro Benutzer weiterschreiben als still verlieren
                var fallback = Path.Combine(AppPaths.UserLogDir, Path.GetFileName(file));
                written = string.Equals(fallback, file, StringComparison.OrdinalIgnoreCase) ? null : AppendChained(fallback, entry);
            }
            entry = written ?? entry;

            if (_settings.EventLog)
            {
                try { _sink?.Write(entry); }
                catch { /* Ereignisprotokoll ist ein Zusatz – nie deswegen scheitern */ }
            }
            return entry;
    }

    /// <summary>
    /// Hängt einen Eintrag an und setzt dabei die Kette am aktuellen Dateiende fort. Mehrere Sitzungen (Remotedesktop,
    /// Benutzerwechsel) schreiben in dieselbe Monatsdatei: Die Datei wird dafür ohne Schreibfreigabe für andere geöffnet,
    /// so dass immer nur ein Prozess gleichzeitig liest und anhängt – sonst bräche die Kette bei jedem Wechsel.
    /// Die Netzkopie wird im selben Schritt in die Warteschlange gestellt, damit ihre Reihenfolge stimmt. null bei fehlendem Schreibrecht.
    /// </summary>
    private AuditEntry? AppendChained(string file, AuditEntry draft)
    {
        // Prozessübergreifend sperrt das Betriebssystem über die Freigabe (Windows); im selben Prozess dieses Schloss.
        lock (FileGate)
            return AppendChainedLocked(file, draft);
    }

    private static readonly object FileGate = new();

    private AuditEntry? AppendChainedLocked(string file, AuditEntry draft)
    {
        for (int attempt = 0; ; attempt++)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(file)!);
                using var fs = OpenAppendOnly(file);
                var (prevHash, prevSeq) = Tail(file);
                var entry = draft with { V = FormatVersion, Seq = prevSeq + 1, Prev = prevHash, Hash = null };
                // Hash über genau die Bytes, die in der Datei stehen; das Hash-Feld kommt als letztes dazu
                var body = JsonSerializer.Serialize(entry, Opts);
                entry.Hash = HashOf(body);
                var line = WithHash(body, entry.Hash) + "\n";
                fs.Write(Encoding.UTF8.GetBytes(line));
                fs.Flush(true);

                if (!string.IsNullOrWhiteSpace(_settings.NetworkDirectory))
                {
                    // Im Hintergrund, in derselben Reihenfolge: Eine langsame oder nicht erreichbare Freigabe darf die
                    // Oberfläche nicht anhalten (der Dienst hielt die App sonst für hängend und trennte die Sitzung)
                    var dir = Environment.ExpandEnvironmentVariables(_settings.NetworkDirectory);
                    NetworkCopies.Enqueue(Path.Combine(dir, $"{Environment.MachineName}-{Path.GetFileName(file)}"), line);
                }
                return entry;
            }
            catch (UnauthorizedAccessException) { return null; }
            catch (IOException) when (attempt < 40) { Thread.Sleep(25); } // ein anderer Prozess schreibt gerade
            catch (Exception ex) when (ex is IOException or ArgumentException or NotSupportedException) { return null; }
        }
    }

    private string ResolveFile(DateTimeOffset now)
    {
        // Monat immer gregorianisch und unabhängig von den Regionaleinstellungen (z. B. thailändischer Kalender)
        var name = $"audit-{now.ToString("yyyy-MM", CultureInfo.InvariantCulture)}.jsonl";
        if (_currentFile is not null && Path.GetFileName(_currentFile) == name) return _currentFile;

        string dir = LogDirectory;
        try { Directory.CreateDirectory(dir); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            dir = AppPaths.UserLogDir;
            Directory.CreateDirectory(dir);
        }
        _currentFile = Path.Combine(dir, name);
        return _currentFile;
    }

    /// <summary>Hash und Nummer des letzten Eintrags; (null, 0) für eine leere oder am Ende beschädigte Datei (neue Kette).</summary>
    private static (string? hash, long seq) Tail(string file)
    {
        try
        {
            if (LastLine(file) is { } last && Parse(last) is { } prev) return (prev.Hash, prev.Seq);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        return (null, 0); // beschädigte letzte Zeile: neue Kette, der Bruch bleibt beim Prüfen sichtbar
    }

    /// <summary>Letzte nicht leere Zeile, ohne die ganze Datei zu lesen (rückwärts in Blöcken, höchstens 4 MB).</summary>
    internal static string? LastLine(string file)
    {
        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        const int chunk = 64 * 1024;
        const long maxScan = 4 * 1024 * 1024;
        long end = fs.Length;
        var collected = new List<byte>();
        long pos = end;
        while (pos > 0 && end - pos < maxScan)
        {
            int size = (int)Math.Min(chunk, pos);
            pos -= size;
            fs.Seek(pos, SeekOrigin.Begin);
            var buffer = new byte[size];
            fs.ReadExactly(buffer);
            collected.InsertRange(0, buffer);
            // Ein BOM am Dateianfang (von Hand gespeichert) gehört nicht zur Zeile
            var text = Encoding.UTF8.GetString(collected.ToArray()).TrimStart('\uFEFF').TrimEnd('\r', '\n', ' ');
            int nl = text.LastIndexOf('\n');
            if (nl >= 0) return text[(nl + 1)..].Trim();
            if (pos == 0) return text.Length == 0 ? null : text.Trim();
        }
        return null; // Zeile länger als 4 MB: neue Kette
    }

    internal static readonly NetworkCopyQueue NetworkCopies = new();

    /// <summary>Wartet, bis die Netzkopie alle Einträge geschrieben hat (beim Beenden, in Tests). false nach Ablauf der Zeit.</summary>
    public static bool FlushNetworkCopies(TimeSpan timeout) => NetworkCopies.Flush(timeout);

    /// <summary>
    /// Netzkopie in einem eigenen Thread, Einträge in Schreibreihenfolge. Höchstens 10 000 Zeilen warten; ist die Freigabe so
    /// lange weg, fehlen weitere in der Kopie (nie im lokalen Protokoll, das maßgeblich ist).
    /// </summary>
    internal sealed class NetworkCopyQueue
    {
        private readonly System.Collections.Concurrent.BlockingCollection<(string File, string Line)> _queue = new(10_000);
        private readonly object _start = new();
        private Thread? _thread;
        private int _pending;

        public void Enqueue(string file, string line)
        {
            lock (_start)
            {
                if (_thread is null)
                {
                    _thread = new Thread(Run) { IsBackground = true, Name = "Vitrine audit network copy" };
                    _thread.Start();
                }
            }
            Interlocked.Increment(ref _pending);
            if (!_queue.TryAdd((file, line))) Interlocked.Decrement(ref _pending);
        }

        public bool Flush(TimeSpan timeout)
        {
            var until = DateTime.UtcNow + timeout;
            while (Volatile.Read(ref _pending) > 0)
            {
                if (DateTime.UtcNow >= until) return false;
                Thread.Sleep(10);
            }
            return true;
        }

        private void Run()
        {
            foreach (var (file, line) in _queue.GetConsumingEnumerable())
            {
                try { TryAppendCopy(file, line); }
                finally { Interlocked.Decrement(ref _pending); }
            }
        }
    }

    private static void TryAppendCopy(string file, string line)
    {
        for (int i = 0; i < 3; i++)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(file)!);
                using var fs = OpenAppendOnly(file);
                fs.Write(Encoding.UTF8.GetBytes(line));
                fs.Flush(true);
                return;
            }
            catch (IOException) { Thread.Sleep(50); }
            catch { return; } // Netzkopie ist ein Zusatz
        }
    }

    /// <summary>
    /// Öffnet unter Windows nur mit „Daten anhängen“-Recht. So funktioniert das Protokoll auch, wenn das Setup Benutzern
    /// im Log-Ordner nur Anhängen erlaubt (kein Ändern oder Löschen – siehe Package.wxs und install.ps1).
    /// </summary>
    internal static FileStream OpenAppendOnly(string file)
    {
        if (OperatingSystem.IsWindows())
        {
            try
            {
                return new FileInfo(file).Create(FileMode.Append,
                    System.Security.AccessControl.FileSystemRights.AppendData | System.Security.AccessControl.FileSystemRights.Synchronize,
                    FileShare.Read, 4096, FileOptions.None, null);
            }
            // Kein Rückfall bei IOException (z. B. „Datei in Gebrauch“): Der Aufrufer wiederholt; ein Rückfall auf Schreibzugriff
            // scheiterte im Protokollordner des Setups (nur Anhängen erlaubt) und landete im ungeschützten Ordner pro Benutzer.
            catch (Exception ex) when (ex is PlatformNotSupportedException or NotSupportedException) { }
        }
        return new FileStream(file, FileMode.Append, FileAccess.Write, FileShare.Read);
    }

    /// <summary>Hash eines Eintrags, wie Vitrine ihn schreibt (Format 1 und 2: die Zeile ohne Hash-Feld).</summary>
    internal static string ComputeHash(AuditEntry e) => HashOf(JsonSerializer.Serialize(e with { Hash = null }, Opts));

    private static string HashOf(string body) => AuditFormat.HashOf(body);

    private const string HashFieldStart = ",\"Hash\":\"";

    /// <summary>Hängt das Hash-Feld als letztes Feld an das JSON-Objekt an.</summary>
    private static string WithHash(string body, string hash) => body[..^1] + HashFieldStart + hash + "\"}";

    /// <summary>Liest eine Zeile des Protokolls (für die Anzeige), null wenn sie nicht lesbar ist.</summary>
    public static AuditEntry? Parse(string line)
    {
        try { return JsonSerializer.Deserialize<AuditEntry>(line, Opts); }
        catch (JsonException) { return null; }
    }

    /// <summary>
    /// Prüft eine Protokolldatei (Formate 1 bis 3) mit den Schlüsseln aus audit-keys.json daneben, ohne Anker. Meldung in
    /// der Sprache der Oberfläche, Fehler mit Code. Mit Ankern: <see cref="AuditVerifier"/>.
    /// </summary>
    public static (bool ok, string message) Verify(string file)
    {
        var r = AuditVerifier.VerifyFile(file, AuditVerifyOptions.ForPath(file));
        return (r.Ok, r.Message);
    }
}
