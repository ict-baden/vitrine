// SPDX-License-Identifier: MIT
using System.Globalization;
using System.Text.Json.Nodes;
using Vitrine.Core.Localization;

namespace Vitrine.Core.Audit;

/// <summary>Warum Einträge der Sitzungs-App nicht beim Dienst ankommen (VIT-0330).</summary>
public enum AuditDeliveryProblem
{
    None,
    /// <summary>Protokoll-Pipe nicht erreichbar (Dienst gestoppt, startet gerade).</summary>
    NotReachable,
    /// <summary>Öffnen der Pipe verweigert.</summary>
    AccessDenied,
    /// <summary>Gleichnamiger Pipe-Server außerhalb von Sitzung 0 – nicht der Dienst.</summary>
    WrongServer,
    /// <summary>Der Dienst hat die Verbindung ohne Antwort geschlossen (Gegenstelle abgelehnt, VIT-0331/VIT-0332 beim Dienst).</summary>
    ClosedWithoutAnswer,
    /// <summary>Verbunden, aber der Dienst bestätigt keine Einträge.</summary>
    NoAnswer,
    /// <summary>Der Dienst konnte nicht schreiben (VIT-0322).</summary>
    WriteFailed,
}

/// <summary>Meldung über die Zustellung: Einträge warten zu lange (<see cref="Problem"/> ≠ None) oder kommen wieder an.</summary>
public sealed record AuditDeliveryReport(bool Recovered, int Pending, DateTimeOffset? Since, AuditDeliveryProblem Problem, string? Detail)
{
    /// <summary>Englischer Text für Protokoll und Ereignisprotokoll (sprachunabhängig).</summary>
    public string LogText => Recovered
        ? $"{ErrorCodes.AuditNotDelivered} resolved: audit entries reach the service again"
        : $"{ErrorCodes.AuditNotDelivered} {Pending} audit entries not delivered to the service since " +
          $"{Since?.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture)}: {Problem}{(Detail is null ? "" : $" ({Detail})")}";

    /// <summary>Text für die Einstellungen in der Sprache der Oberfläche (VIT-0330 mit Zahl und Grund).</summary>
    public string UserText() => CoreText.Error(ErrorCodes.AuditNotDelivered, Pending, CoreText.T(Problem switch
    {
        AuditDeliveryProblem.NotReachable => "AuditDelivery_NotReachable",
        AuditDeliveryProblem.AccessDenied => "AuditDelivery_AccessDenied",
        AuditDeliveryProblem.WrongServer => "AuditDelivery_WrongServer",
        AuditDeliveryProblem.ClosedWithoutAnswer => "AuditDelivery_ClosedWithoutAnswer",
        AuditDeliveryProblem.WriteFailed => "AuditDelivery_WriteFailed",
        _ => "AuditDelivery_NoAnswer",
    }));
}

/// <summary>
/// Warteschlange der Sitzungs-App für Einträge an den Dienst (#15), ohne Pipe: Reihenfolge, Höchstzahl, Bestätigungen,
/// Wiederholen nach VIT-0322, Herausnehmen beim Beenden – und wann ein Zustellproblem zu melden ist (VIT-0330), statt
/// still zu puffern. Die Pipe selbst führt AuditLink in der App.
/// </summary>
public sealed class AuditOutbox
{
    public const int MaxBuffered = 10_000;

    /// <summary>So lange darf der älteste Eintrag warten, bevor die App das meldet (Ereignisprotokoll, Einstellungen).</summary>
    public static readonly TimeSpan ReportAfter = TimeSpan.FromSeconds(60);

    private sealed record Pending(long Id, AuditEntry Draft, Action<AuditEntry>? Committed, DateTimeOffset Queued);

    /// <summary>Was eine Antwort des Dienstes für einen Eintrag bedeutet.</summary>
    public enum AckKind
    {
        /// <summary>Keine Antwort auf einen Eintrag (andere Anfrage oder unbekannte Nummer).</summary>
        Unknown,
        /// <summary>Geschrieben; <see cref="Ack.Entry"/> mit Nummer und Hash (sofern geliefert).</summary>
        Committed,
        /// <summary>Abgelehnt (z. B. Ereignis nur für den Dienst): nicht wiederholen.</summary>
        Rejected,
        /// <summary>Dienst konnte nicht schreiben (VIT-0322): behalten, Verbindung neu aufbauen, alles erneut senden.</summary>
        Retry,
    }

    public sealed record Ack(AckKind Kind, AuditEntry? Entry = null, Action<AuditEntry>? Committed = null);

    private readonly object _gate = new();
    private readonly LinkedList<Pending> _writes = new();
    private readonly Func<DateTimeOffset> _clock;
    private long _nextId;
    private long _dropped;
    private AuditDeliveryProblem _problem;
    private string? _problemDetail;
    private bool _reported;

    public AuditOutbox(Func<DateTimeOffset>? clock = null) => _clock = clock ?? (() => DateTimeOffset.UtcNow);

    /// <summary>Nummer für eine Anfrage (Einträge und andere Anfragen teilen sich die Nummern einer Verbindung).</summary>
    public long NextId()
    {
        lock (_gate) return ++_nextId;
    }

    public int Count { get { lock (_gate) return _writes.Count; } }

    public long Dropped { get { lock (_gate) return _dropped; } }

    /// <summary>Wartet seit (ältester unbestätigter Eintrag), null = nichts offen.</summary>
    public DateTimeOffset? OldestPending { get { lock (_gate) return _writes.First?.Value.Queued; } }

    public AuditDeliveryProblem Problem { get { lock (_gate) return _problem; } }

    public string? ProblemDetail { get { lock (_gate) return _problemDetail; } }

    /// <summary>Eintrag einreihen. Anfragezeile zum sofortigen Senden, null wenn die Warteschlange voll ist (VIT-0318).</summary>
    public string? Add(AuditEntry draft, Action<AuditEntry>? committed)
    {
        lock (_gate)
        {
            if (_writes.Count >= MaxBuffered)
            {
                _dropped++;
                return null;
            }
            var w = new Pending(++_nextId, draft, committed, _clock());
            _writes.AddLast(w);
            return WriteRequest(w.Id, draft);
        }
    }

    /// <summary>
    /// Neue Verbindung: alle wartenden Einträge in Reihenfolge, danach – wenn Einträge verworfen wurden – ein Fehler-Eintrag
    /// VIT-0318 (wird selbst ein wartender Eintrag).
    /// </summary>
    public List<string> ConnectionUp()
    {
        lock (_gate)
        {
            var lines = _writes.Select(w => WriteRequest(w.Id, w.Draft)).ToList();
            if (_dropped > 0)
            {
                var lost = new Pending(++_nextId, new AuditEntry
                {
                    Time = _clock(), Event = AuditEventType.Error,
                    Detail = $"{ErrorCodes.AuditBufferOverflow} {_dropped} entries lost while the service was not reachable",
                    Data = new() { ["code"] = ErrorCodes.AuditBufferOverflow },
                }, null, _clock());
                _writes.AddLast(lost);
                lines.Add(WriteRequest(lost.Id, lost.Draft));
                _dropped = 0;
            }
            return lines;
        }
    }

    /// <summary>Antwort des Dienstes zuordnen.</summary>
    public Ack Acknowledge(JsonObject answer)
    {
        if (answer["id"] is not JsonValue idv || !idv.TryGetValue<long>(out var id)) return new(AckKind.Unknown);
        bool ok = answer["ok"] is JsonValue okv && okv.TryGetValue<bool>(out var b) && b;
        string? code = answer["code"] is JsonValue cv && cv.TryGetValue<string>(out var c) ? c : null;
        lock (_gate)
        {
            Pending? write = null;
            for (var node = _writes.First; node is not null; node = node.Next)
                if (node.Value.Id == id) { write = node.Value; break; }
            if (write is null) return new(AckKind.Unknown);
            if (!ok && code == ErrorCodes.AuditWriteFailed)
            {
                SetProblemLocked(AuditDeliveryProblem.WriteFailed, answer["error"] is JsonValue ev && ev.TryGetValue<string>(out var err) ? err : null);
                return new(AckKind.Retry);
            }
            _writes.Remove(write);
            // Der Dienst antwortet: Ein früheres Problem der Verbindung ist vorbei
            _problem = AuditDeliveryProblem.None;
            _problemDetail = null;
            if (!ok) return new(AckKind.Rejected);
            long seq = answer["seq"] is JsonValue sv && sv.TryGetValue<long>(out var s) ? s : 0;
            string? hash = answer["hash"] is JsonValue hv && hv.TryGetValue<string>(out var h) ? h : null;
            var entry = string.IsNullOrEmpty(hash) ? null : write.Draft with { V = AuditFormat.Signed, Seq = seq, Hash = hash };
            return new(AckKind.Committed, entry, write.Committed);
        }
    }

    /// <summary>Unbestätigte Einträge herausnehmen (beim Beenden, für den Ersatzordner pro Benutzer).</summary>
    public List<AuditEntry> TakeUnsent()
    {
        lock (_gate)
        {
            var list = _writes.Select(w => w.Draft).ToList();
            _writes.Clear();
            return list;
        }
    }

    /// <summary>Letztes Problem der Verbindung festhalten (für die Meldung und die Einstellungen).</summary>
    public void SetProblem(AuditDeliveryProblem problem, string? detail = null)
    {
        lock (_gate) SetProblemLocked(problem, detail);
    }

    private void SetProblemLocked(AuditDeliveryProblem problem, string? detail)
    {
        _problem = problem;
        _problemDetail = detail;
    }

    /// <summary>
    /// Regelmäßig aufrufen: Meldung, sobald der älteste Eintrag länger als <see cref="ReportAfter"/> wartet (einmal je
    /// Ausfall), und eine Entwarnung, wenn danach alles zugestellt ist. Sonst null.
    /// </summary>
    public AuditDeliveryReport? Check()
    {
        lock (_gate)
        {
            if (_writes.Count == 0)
            {
                if (!_reported) return null;
                _reported = false;
                return new AuditDeliveryReport(true, 0, null, AuditDeliveryProblem.None, null);
            }
            var since = _writes.First!.Value.Queued;
            if (_reported || _clock() - since < ReportAfter) return null;
            _reported = true;
            var problem = _problem == AuditDeliveryProblem.None ? AuditDeliveryProblem.NoAnswer : _problem;
            return new AuditDeliveryReport(false, _writes.Count, since, problem, _problemDetail);
        }
    }

    /// <summary>Ist gerade ein Zustellproblem gemeldet (Einstellungen)?</summary>
    public bool Reported { get { lock (_gate) return _reported; } }

    /// <summary>Anfragezeile „write“ für einen Eintrag (Format der Protokoll-Pipe, <see cref="Service.AuditBroker"/>).</summary>
    public static string WriteRequest(long id, AuditEntry e)
    {
        var req = new JsonObject
        {
            ["op"] = "write", ["id"] = id, ["event"] = e.Event.ToString(), ["actor"] = e.Actor, ["method"] = e.Method,
            ["detail"] = e.Detail, ["time"] = e.Time.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture),
        };
        if (e.Data is { Count: > 0 })
        {
            var d = new JsonObject();
            foreach (var (k, v) in e.Data) d[k] = v;
            req["data"] = d;
        }
        return req.ToJsonString();
    }
}
