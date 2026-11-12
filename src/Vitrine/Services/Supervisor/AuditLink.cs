// SPDX-License-Identifier: MIT
using System.Collections.Concurrent;
using System.Globalization;
using System.IO.Pipes;
using System.ServiceProcess;
using System.Text;
using System.Text.Json.Nodes;
using Vitrine.Abstractions;
using Vitrine.Core.About;
using Vitrine.Core.Audit;
using Vitrine.Core.Auth;
using Vitrine.Core.Fido;
using Vitrine.Core.Service;
using Vitrine.Core.Localization;
using Vitrine.Platform;

namespace Vitrine.Services.Supervisor;

/// <summary>
/// Sitzungs-App → Dienst über die Protokoll-Pipe (#15): Einträge weiterleiten statt selbst schreiben, Anmeldungen für
/// Signaturen vom Dienst prüfen lassen, Signaturen vom Dienst eintragen lassen.
///
/// Ist der Dienst nicht erreichbar, obwohl er das Protokoll schreibt: Sperren und Entsperren gehen weiter, Einträge warten
/// im Speicher (<see cref="AuditOutbox"/>, höchstens <see cref="AuditOutbox.MaxBuffered"/>, danach VIT-0318) und gehen in
/// derselben Reihenfolge an den Dienst, sobald er wieder da ist (mit der Zeit der App als ClientTime). Signaturen lehnt
/// die App dann ab (VIT-0300). Wartet ein Eintrag länger als <see cref="AuditOutbox.ReportAfter"/>, meldet
/// <see cref="Delivery"/> das mit Grund (VIT-0330) – vorher puffert die App still, auch wenn der Dienst sie ablehnte.
/// Endet die App vorher, kommen die wartenden Einträge in den Ersatzordner pro Benutzer (<see cref="AuditLog.WriteUnsent"/>).
/// Bricht die Verbindung zwischen Senden und Antwort ab, wird der Eintrag erneut gesendet; er kann dann doppelt stehen.
/// </summary>
public sealed class AuditLink : IAuditForwarder, IDisposable
{
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan RetryDelay = TimeSpan.FromSeconds(3);
    private static readonly TimeSpan MaxRetryDelay = TimeSpan.FromSeconds(30);

    private sealed class Connection(NamedPipeClientStream pipe)
    {
        public readonly NamedPipeClientStream Pipe = pipe;
        public readonly BlockingCollection<string> Outgoing = new(AuditOutbox.MaxBuffered + 64);
        /// <summary>Antworten auf dieser Verbindung (0 = der Dienst hat noch nie geantwortet).</summary>
        public int Answers;
    }

    private readonly object _gate = new();
    private readonly AuditOutbox _outbox;
    private readonly Dictionary<long, TaskCompletionSource<JsonObject?>> _requests = new();
    private readonly CancellationTokenSource _stop = new();
    private readonly string _pipeName;
    private readonly Func<int?, bool> _serverAccepted;
    private Connection? _connection;
    private Thread? _loop;
    private Timer? _check;

    /// <param name="pipeName">Name der Pipe (Standard <see cref="AppPaths.AuditPipe"/>, andere nur in Tests).</param>
    /// <param name="serverAccepted">Sitzung des Pipe-Servers prüfen (Standard: nur Sitzung 0 – der Dienst).</param>
    /// <param name="clock">Uhr für Wartezeiten (Tests).</param>
    public AuditLink(string? pipeName = null, Func<int?, bool>? serverAccepted = null, Func<DateTimeOffset>? clock = null)
    {
        _pipeName = pipeName ?? AppPaths.AuditPipe;
        _serverAccepted = serverAccepted ?? (session => session == 0);
        _outbox = new AuditOutbox(clock);
    }

    /// <summary>Verbindung zum Dienst hergestellt oder verloren (Hintergrund-Thread).</summary>
    public event Action<bool>? StateChanged;

    /// <summary>
    /// Zustellproblem (Einträge warten länger als <see cref="AuditOutbox.ReportAfter"/>) bzw. Entwarnung danach
    /// (Hintergrund-Thread). Die App schreibt das ins Ereignisprotokoll und zeigt es in den Einstellungen.
    /// </summary>
    public event Action<AuditDeliveryReport>? Delivery;

    /// <summary>Pipe zum Dienst verbunden (sagt nicht, dass er Einträge annimmt – dafür <see cref="Problem"/>).</summary>
    public bool Connected { get { lock (_gate) return _connection is not null; } }

    /// <summary>Wartende (noch nicht bestätigte) Einträge.</summary>
    public int Pending => _outbox.Count;

    /// <summary>Gemeldetes Zustellproblem (für die Einstellungen), null = keins.</summary>
    public AuditDeliveryReport? Problem =>
        _outbox.Reported ? new AuditDeliveryReport(false, _outbox.Count, _outbox.OldestPending, _outbox.Problem, _outbox.ProblemDetail) : null;

    /// <summary>
    /// Schreibt auf diesem Rechner der Dienst das Protokoll? Dann darf die App nicht selbst schreiben (der Ordner ist für
    /// Benutzer nur lesbar), sondern muss warten. Nein bei portabler Exe, ohne installierten Dienst und mit SERVICE=0.
    /// Entscheidung in <see cref="AuditServiceDecision"/> (Vitrine.Core); der Wert „Service“ ist derselbe, den der Dienst
    /// schreibt (<see cref="AuditState.ServiceValue"/>).
    /// </summary>
    public static bool ServiceExpected() => AuditServiceDecision.Expected(new MachineAuditServiceState());

    private sealed class MachineAuditServiceState : IAuditServiceState
    {
        public object? ServiceValue => AuditState.ServiceValueRaw();

        public bool ServiceInstalled
        {
            get
            {
                try
                {
                    using var sc = new ServiceController(AppPaths.ServiceName);
                    _ = sc.Status; // wirft, wenn der Dienst nicht installiert ist (deinstalliert, Wert aber noch da)
                    return true;
                }
                catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception) { return false; }
            }
        }
    }

    public void Start()
    {
        lock (_gate)
        {
            if (_loop is not null) return;
            _loop = new Thread(Loop) { IsBackground = true, Name = "Vitrine audit link" };
            _loop.Start();
            _check = new Timer(_ => CheckDelivery(), null, TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5));
        }
    }

    /// <summary>Meldung fällig? (Timer; in Tests direkt.)</summary>
    internal void CheckDelivery()
    {
        if (_outbox.Check() is not { } report) return;
        try { Delivery?.Invoke(report); }
        catch (Exception ex) when (ex is InvalidOperationException or IOException or ObjectDisposedException) { }
    }

    // ================= Einträge =================

    public void Forward(AuditEntry draft, Action<AuditEntry>? committed)
    {
        lock (_gate)
        {
            if (_outbox.Add(draft, committed) is not { } line) return;
            try { _connection?.Outgoing.TryAdd(line); }
            catch (InvalidOperationException) { } // Verbindung gerade beendet: geht beim nächsten Verbinden mit
        }
    }

    /// <summary>Noch nicht bestätigte Einträge herausnehmen (beim Beenden, für den Ersatzordner).</summary>
    public List<AuditEntry> TakeUnsent() => _outbox.TakeUnsent();

    /// <summary>Wartet, bis der Dienst alle Einträge bestätigt hat. false nach Ablauf der Zeit oder ohne Verbindung.</summary>
    public bool Flush(TimeSpan timeout)
    {
        var until = DateTime.UtcNow + timeout;
        while (true)
        {
            if (_outbox.Count == 0) return true;
            lock (_gate) if (_connection is null) return false;
            if (DateTime.UtcNow >= until) return false;
            Thread.Sleep(20);
        }
    }

    // ================= Signaturen =================

    /// <summary>Windows-Kennwort durch den Dienst prüfen lassen (LogonUser im Dienst statt in der App).</summary>
    /// <param name="purpose">null = Signatur; <see cref="AuditBroker.PurposeRegistrar"/> = Ticket zum Registrieren von Sicherheitsschlüsseln.</param>
    public Task<AuthOutcome> VerifyWindowsAsync(LogonTarget target, string secret, string? purpose = null) =>
        VerifyAsync(new JsonObject { ["op"] = "verify", ["method"] = "windows", ["user"] = target.User, ["domain"] = target.Domain, ["secret"] = secret, ["purpose"] = purpose });

    /// <summary>ID-Token von Microsoft Entra ID durch den Dienst prüfen lassen.</summary>
    public Task<AuthOutcome> VerifyEntraAsync(string idToken, string? purpose = null) =>
        VerifyAsync(new JsonObject { ["op"] = "verify", ["method"] = "entra", ["idToken"] = idToken, ["purpose"] = purpose });

    // ================= Sicherheitsschlüssel =================

    /// <summary>Anfrage „fido-…“ an den Dienst; null, wenn er nicht antwortet.</summary>
    public Task<JsonObject?> FidoAsync(JsonObject req) => RequestAsync(req);

    private static JsonObject AssertionRequest(string op, FidoAssertion a) => new()
    {
        ["op"] = op, ["challenge"] = a.Challenge, ["credentialId"] = a.CredentialId, ["authenticatorData"] = a.AuthenticatorData,
        ["clientDataJSON"] = a.ClientDataJson, ["signature"] = a.Signature,
    };

    /// <summary>Signatur oder Anmeldung einer registrierenden Person: Assertion prüft der Dienst, Antwort mit Ticket.</summary>
    public Task<AuthOutcome> VerifyFidoAsync(FidoAssertion a, string? purpose)
    {
        var req = AssertionRequest("verify", a);
        req["method"] = FidoProtocol.MethodId;
        req["purpose"] = purpose;
        return VerifyAsync(req);
    }

    /// <summary>Entsperren und Administrator-Bestätigung: geprüfte Person mit Gruppen (ohne Ticket).</summary>
    public async Task<AuthOutcome> FidoAssertAsync(FidoAssertion a, bool admin)
    {
        var req = AssertionRequest("fido-assert", a);
        req["purpose"] = admin ? "admin" : "unlock";
        var r = await RequestAsync(req).ConfigureAwait(false);
        if (r is null) return AuthOutcome.Fail(CoreText.Error(ErrorCodes.FidoServiceRequired), ErrorCodes.FidoServiceRequired);
        var outcome = ToOutcome(r);
        if (!outcome.Success) return outcome;
        var groups = r["groups"] is JsonArray arr
            ? arr.Select(g => g is JsonValue v && v.TryGetValue<string>(out var s) ? s : null).Where(s => s is not null).Select(s => s!).ToHashSet(StringComparer.OrdinalIgnoreCase)
            : new HashSet<string>();
        return new AuthOutcome
        {
            Success = true, UserName = outcome.UserName, DisplayName = outcome.DisplayName, UserId = outcome.UserId,
            IsSessionUser = outcome.IsSessionUser, IsAdministrator = outcome.IsAdministrator, Details = outcome.Details, Groups = groups,
        };
    }

    /// <summary>Anmeldung, die nur die App prüfen kann (Windows Hello, Plugin): vom Dienst als „client“ eingetragen.</summary>
    public Task<AuthOutcome> AttestAsync(string method, AuthOutcome who) =>
        VerifyAsync(new JsonObject
        {
            ["op"] = "verify", ["method"] = method, ["actor"] = who.UserName, ["displayName"] = who.DisplayName, ["userId"] = who.UserId,
            ["tenant"] = who.TenantId, ["shared"] = UnlockPolicy.IsShared(who) ? "true" : null,
        });

    private async Task<AuthOutcome> VerifyAsync(JsonObject req)
    {
        var r = await RequestAsync(req).ConfigureAwait(false);
        if (r is null) return Unavailable();
        return ToOutcome(r);
    }

    /// <summary>Antwort des Dienstes auf eine Prüfung → Ergebnis (Fehler mit „audited“, Erfolg mit Ticket und Stufe).</summary>
    private static AuthOutcome ToOutcome(JsonObject r)
    {
        if (r["ok"]?.GetValue<bool>() != true)
        {
            var code = Str(r, "code") ?? ErrorCodes.SignInFailed;
            var fail = AuthOutcome.Fail(Str(r, "error") ?? CoreText.Error(code), code);
            // Der Dienst hat den Fehlversuch selbst eingetragen: die App nicht noch einmal
            return r["audited"]?.GetValue<bool>() == true ? fail.WithDetails(new Dictionary<string, string> { ["audited"] = "true" }) : fail;
        }
        var details = new Dictionary<string, string>();
        if (r["details"] is JsonObject d)
            foreach (var (k, v) in d) if (v is JsonValue jv && jv.TryGetValue<string>(out var s)) details[k] = s;
        details["assurance"] = Str(r, "assurance") ?? AuditAssurance.Client;
        return new AuthOutcome
        {
            Success = true,
            UserName = Str(r, "user"),
            DisplayName = Str(r, "displayName"),
            UserId = Str(r, "userId"),
            TenantId = Str(r, "tenant"),
            IsSessionUser = r["sessionUser"]?.GetValue<bool>() == true,
            IsAdministrator = r["admin"]?.GetValue<bool>() == true,
            Details = details,
            Tokens = new Dictionary<string, string> { [AuthResults.Ticket] = Str(r, "ticket") ?? "" },
        };
    }

    /// <summary>Signatur vom Dienst eintragen lassen. Erfolg: Nummer, Hash, Stufe; sonst Code und Meldung.</summary>
    public async Task<(bool Ok, long Seq, string? Hash, string? Assurance, string? Code, string? Error)> SignAsync(string ticket, string reason,
        string? meaning, string? requester, string? clientProcess)
    {
        var r = await RequestAsync(new JsonObject
        {
            ["op"] = "sign", ["ticket"] = ticket, ["reason"] = reason, ["meaning"] = meaning, ["requester"] = requester, ["clientProcess"] = clientProcess,
        }).ConfigureAwait(false);
        if (r is null) return (false, 0, null, null, ErrorCodes.AuditServiceUnavailable, CoreText.Error(ErrorCodes.AuditServiceUnavailable));
        if (r["ok"]?.GetValue<bool>() != true) return (false, 0, null, null, Str(r, "code"), Str(r, "error"));
        return (true, r["seq"]?.GetValue<long>() ?? 0, Str(r, "hash"), Str(r, "assurance"), null, null);
    }

    /// <summary>Einmal-Nonce des Dienstes für eine Microsoft-Signatur; null, wenn der Dienst nicht antwortet.</summary>
    public async Task<string?> ChallengeAsync()
    {
        var r = await RequestAsync(new JsonObject { ["op"] = "challenge" }).ConfigureAwait(false);
        return r is not null && r["ok"]?.GetValue<bool>() == true ? Str(r, "nonce") : null;
    }

    /// <summary>Neuer Schlüssel (nur als Administrator gestartet; --rotate-audit-key). Antwort des Dienstes oder null.</summary>
    public Task<JsonObject?> RotateAsync() => RequestAsync(new JsonObject { ["op"] = "rotate" });

    private static AuthOutcome Unavailable() =>
        AuthOutcome.Fail(CoreText.Error(ErrorCodes.AuditServiceUnavailable), ErrorCodes.AuditServiceUnavailable);

    private async Task<JsonObject?> RequestAsync(JsonObject req)
    {
        var tcs = new TaskCompletionSource<JsonObject?>(TaskCreationOptions.RunContinuationsAsynchronously);
        long id;
        lock (_gate)
        {
            if (_connection is not { } c) return null;
            id = _outbox.NextId();
            req["id"] = id;
            _requests[id] = tcs;
            try
            {
                if (!c.Outgoing.TryAdd(req.ToJsonString())) { _requests.Remove(id); return null; }
            }
            catch (InvalidOperationException) { _requests.Remove(id); return null; } // Verbindung gerade beendet
        }
        var done = await Task.WhenAny(tcs.Task, Task.Delay(RequestTimeout)).ConfigureAwait(false);
        if (done == tcs.Task) return tcs.Task.Result;
        lock (_gate) _requests.Remove(id);
        return null;
    }

    // ================= Verbindung =================

    private void Loop()
    {
        var delay = RetryDelay;
        while (!_stop.IsCancellationRequested)
        {
            Connection? c = null;
            try
            {
                var pipe = AuditPipe.OpenClient(_pipeName);
                try
                {
                    pipe.Connect(500);
                    // Nur der Dienst in Sitzung 0 zählt, nie ein gleichnamiger Server eines Benutzers
                    if (!_serverAccepted(ServicePipe.ServerSession(pipe.SafePipeHandle)))
                    {
                        _outbox.SetProblem(AuditDeliveryProblem.WrongServer);
                        throw new IOException("wrong server");
                    }
                }
                catch { pipe.Dispose(); throw; }
                c = new Connection(pipe);
                lock (_gate)
                {
                    // Alles Wartende zuerst und in Reihenfolge, dann die verlorenen Einträge melden
                    foreach (var line in _outbox.ConnectionUp()) c.Outgoing.Add(line);
                    _connection = c;
                }
                StateChanged?.Invoke(true);
                var writer = new Thread(() => WriteLoop(c)) { IsBackground = true, Name = "Vitrine audit link writer" };
                writer.Start();
                ReadLoop(c);
                // Ohne eine einzige Antwort geschlossen: Der Dienst hat diese App abgelehnt (VIT-0331/VIT-0332 in seinem Protokoll)
                if (c.Answers == 0 && !_stop.IsCancellationRequested)
                    _outbox.SetProblem(AuditDeliveryProblem.ClosedWithoutAnswer);
            }
            catch (System.TimeoutException) { _outbox.SetProblem(AuditDeliveryProblem.NotReachable); }
            catch (UnauthorizedAccessException ex) { _outbox.SetProblem(AuditDeliveryProblem.AccessDenied, ex.Message); }
            catch (Exception ex) when (ex is IOException or InvalidOperationException)
            {
                if (_outbox.Problem is not (AuditDeliveryProblem.WrongServer or AuditDeliveryProblem.WriteFailed))
                    _outbox.SetProblem(c is null ? AuditDeliveryProblem.NotReachable : AuditDeliveryProblem.ClosedWithoutAnswer, ex.Message);
            }
            bool answered = c is { Answers: > 0 };
            if (c is not null) Disconnect(c);
            // Abgelehnt: seltener neu versuchen (der Dienst protokolliert jeden Versuch, wenn auch begrenzt); sonst zügig
            delay = answered || _outbox.Problem is AuditDeliveryProblem.NotReachable or AuditDeliveryProblem.WriteFailed
                ? RetryDelay
                : TimeSpan.FromSeconds(Math.Min(MaxRetryDelay.TotalSeconds, delay.TotalSeconds * 2));
            if (_stop.Token.WaitHandle.WaitOne(delay)) return;
        }
    }

    private static void WriteLoop(Connection c)
    {
        try
        {
            var w = new StreamWriter(c.Pipe, new UTF8Encoding(false)) { AutoFlush = true };
            foreach (var line in c.Outgoing.GetConsumingEnumerable()) w.WriteLine(line);
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException or InvalidOperationException)
        {
            try { c.Pipe.Dispose(); } catch (Exception inner) when (inner is IOException or ObjectDisposedException) { }
        }
    }

    private void ReadLoop(Connection c)
    {
        var r = new StreamReader(c.Pipe, Encoding.UTF8);
        while (r.ReadLine() is { } line)
        {
            JsonObject? answer;
            try { answer = JsonNode.Parse(line) as JsonObject; }
            catch (System.Text.Json.JsonException) { continue; }
            if (answer?["id"] is not JsonValue idv || !idv.TryGetValue<long>(out var id)) continue;
            c.Answers++;
            TaskCompletionSource<JsonObject?>? request;
            lock (_gate) _requests.Remove(id, out request);
            if (request is not null) { request.TrySetResult(answer); continue; }
            var ack = _outbox.Acknowledge(answer);
            switch (ack.Kind)
            {
                // Der Dienst konnte nicht schreiben (Ordner weg, Platte voll): Eintrag behalten, Verbindung neu aufbauen –
                // dann geht alles Wartende in Reihenfolge noch einmal an ihn
                case AuditOutbox.AckKind.Retry:
                    return;
                // Abgelehnt (z. B. Ereignis nur für den Dienst): nicht wiederholen; der Dienst hat den Versuch eingetragen
                case AuditOutbox.AckKind.Committed when ack.Entry is { } entry && ack.Committed is { } committed:
                    try { committed(entry); }
                    catch (Exception ex) when (ex is IOException or InvalidOperationException or ObjectDisposedException) { }
                    break;
            }
        }
    }

    private void Disconnect(Connection c)
    {
        List<TaskCompletionSource<JsonObject?>> open;
        lock (_gate)
        {
            if (_connection == c) _connection = null;
            open = [.. _requests.Values];
            _requests.Clear();
        }
        c.Outgoing.CompleteAdding();
        try { c.Pipe.Dispose(); } catch (Exception ex) when (ex is IOException or ObjectDisposedException) { }
        foreach (var t in open) t.TrySetResult(null);
        StateChanged?.Invoke(false);
    }

    private static string? Str(JsonObject o, string name) => o[name] is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;

    public void Dispose()
    {
        _stop.Cancel();
        _check?.Dispose();
        Connection? c;
        lock (_gate) c = _connection;
        if (c is not null) Disconnect(c);
    }
}
