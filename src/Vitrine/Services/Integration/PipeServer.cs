// SPDX-License-Identifier: MIT
using System.Globalization;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Windows.Threading;
using Vitrine.Core.About;
using Vitrine.Core.Audit;
using Vitrine.Core.Config;
using Vitrine.Core.Integration;
using Vitrine.Core.Localization;
using Vitrine.Core.Lock;
using Vitrine.Services.Interop;
using Vitrine.Services.Lock;

namespace Vitrine.Services.Integration;

/// <summary>
/// Lokale Schnittstelle für Fachanwendungen (LIMS, MES, Gerätesoftware, GxP-Adapter) und für Vitrine selbst (zweiter
/// Start → „sperren“ / „Einstellungen“ an die laufende Instanz).
///
/// Named Pipe: \\.\pipe\ICT-Baden.Vitrine.&lt;SitzungsID&gt;, nur für den angemeldeten Benutzer, SYSTEM und Administratoren.
/// Protokoll (<see cref="PipeProtocol"/>, docs/interface.md): eine JSON-Zeile pro Anfrage, eine JSON-Zeile Antwort
/// (bei "subscribe" ein Ereignis pro Zeile).
///
///   {"cmd":"status"}
///   {"cmd":"lock"}
///   {"cmd":"authenticate","reason":"Release batch 4711","meaning":"Approved","requester":"LIMS"}
///   {"cmd":"subscribe"}
/// </summary>
public sealed class PipeServer : IDisposable
{
    private readonly LockController _lock;
    private readonly ConfigStore _store;
    private readonly Dispatcher _ui;
    private readonly Action _openSettings;
    private readonly CancellationTokenSource _cts = new();
    private readonly string _name;
    private readonly List<StreamWriter> _subscribers = new();

    /// <summary>Ein anderer Prozess hatte den Pipe-Namen schon belegt; Vitrine bedient die Schnittstelle dann nicht.</summary>
    public bool NameTaken { get; private set; }

    public PipeServer(LockController lockController, ConfigStore store, Dispatcher ui, int sessionId, Action openSettings)
    {
        _lock = lockController;
        _store = store;
        _ui = ui;
        _openSettings = openSettings;
        _name = AppPaths.PipeName(sessionId);

        _lock.Audited += Broadcast;

        // Die erste Instanz vor allen Annahme-Schleifen und mit FirstPipeInstance: Hat ein anderer Prozess (auch eines
        // anderen Benutzers) den Namen vorher belegt, scheitert das – sonst würden Fachanwendungen mit dem fremden Prozess
        // sprechen. Danach weitere Instanzen ohne die Option.
        NamedPipeServerStream first;
        try { first = Create(PipeOptions.Asynchronous | PipeOptions.FirstPipeInstance); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            NameTaken = true;
            _ = _ui.BeginInvoke(() => _lock.Log(AuditEventType.Error, detail: $"{ErrorCodes.PipeNameTaken} pipe {_name} already exists: {ex.Message}"));
            return;
        }
        _ = Task.Run(() => AcceptLoop(first));
        for (int i = 0; i < 3; i++) _ = Task.Run(() => AcceptLoop(null));
    }

    private NamedPipeServerStream Create(PipeOptions options) =>
        NamedPipeServerStreamAcl.Create(_name, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances,
            PipeTransmissionMode.Byte, options, 0, 0, CreateSecurity());

    private async Task AcceptLoop(NamedPipeServerStream? initial)
    {
        while (!_cts.IsCancellationRequested)
        {
            NamedPipeServerStream? pipe = initial;
            initial = null;
            try
            {
                pipe ??= Create(PipeOptions.Asynchronous);
                await pipe.WaitForConnectionAsync(_cts.Token);
                _ = HandleAsync(pipe);
            }
            catch (OperationCanceledException) { pipe?.Dispose(); return; }
            catch { pipe?.Dispose(); await Task.Delay(500); }
        }
    }

    private static PipeSecurity CreateSecurity()
    {
        var ps = new PipeSecurity();
        using var me = WindowsIdentity.GetCurrent();
        ps.AddAccessRule(new PipeAccessRule(me.User!, PipeAccessRights.ReadWrite | PipeAccessRights.CreateNewInstance, AccessControlType.Allow));
        ps.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        ps.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), PipeAccessRights.ReadWrite, AccessControlType.Allow));
        return ps;
    }

    private async Task HandleAsync(NamedPipeServerStream pipe)
    {
        await using var _ = pipe;
        using var reader = new StreamReader(pipe, Encoding.UTF8, leaveOpen: true);
        var lines = new BoundedLineReader(reader, PipeProtocol.MaxLineLength);
        var writer = new StreamWriter(pipe, new UTF8Encoding(false), leaveOpen: true) { AutoFlush = true };
        try
        {
            while (pipe.IsConnected && !_cts.IsCancellationRequested)
            {
                string? line;
                try { line = await lines.ReadLineAsync(_cts.Token); }
                catch (LineTooLongException)
                {
                    await Reply(writer, PipeProtocol.Error(ErrorCodes.PipeRequestTooLong, $"Request longer than {PipeProtocol.MaxLineLength} characters"));
                    break; // Rest der Zeile nicht mehr lesen – Verbindung schließen
                }
                if (line is null) break;
                if (string.IsNullOrWhiteSpace(line)) continue;

                var req = PipeProtocol.Parse(line);
                bool api = _store.Current.Integration.PipeEnabled;
                if (!req.IsValid)
                {
                    // Bei abgeschalteter Schnittstelle nichts über die Befehle verraten
                    await Reply(writer, api || req.Command is "lock" or "settings"
                        ? PipeProtocol.Error(req.ErrorCode!, req.Error!)
                        : PipeProtocol.Error(ErrorCodes.PipeDisabled, "Interface is disabled"));
                    continue;
                }

                switch (req.Command)
                {
                    // „lock“ und „settings“ gehen immer – so übergibt ein zweiter Start von Vitrine an die laufende Instanz.
                    case "lock":
                        var trigger = string.IsNullOrEmpty(req.Trigger) ? LockTriggers.Api : $"{LockTriggers.Api}: {req.Trigger}";
                        await _ui.InvokeAsync(() => _lock.Lock(trigger));
                        await Reply(writer, Status());
                        break;
                    case "settings":
                        await _ui.InvokeAsync(_openSettings);
                        await Reply(writer, new JsonObject { ["ok"] = true });
                        break;
                    case "status" when api:
                        await Reply(writer, Status());
                        break;
                    case "authenticate" or "sign" when api && _lock.Status == LockStatus.Locked:
                        await Reply(writer, PipeProtocol.Error(ErrorCodes.PipeLocked, "Workstation is locked"));
                        break;
                    case "authenticate" or "sign" when api && PipeProtocol.CheckScopes(req.Scopes, _store.Current.Entra.AllowedTokenScopes) is { } bad:
                        await Reply(writer, PipeProtocol.Error(bad.Code, bad.Error));
                        break;
                    case "authenticate" or "sign" when api && req.Scopes.Count > 0 && string.IsNullOrWhiteSpace(_store.Current.Entra.ClientId):
                        await Reply(writer, PipeProtocol.Error(ErrorCodes.PipeEntraRequired, "Tokens need Microsoft Entra ID, which is not set up"));
                        break;
                    case "authenticate" or "sign" when api:
                        var reason = req.Reason!;
                        // Wer wirklich fragt: „requester“ gibt der Client selbst an, der Prozess lässt sich nicht fälschen
                        var client = Native.GetNamedPipeClientProcessId(pipe.SafePipeHandle, out var pid) ? Native.DescribeProcess(pid) : null;
                        var who = await await _ui.InvokeAsync(() => _lock.RequestSignatureAsync(reason, req.Meaning, req.Requester, client, req.Scopes));
                        var answer = who is null
                            ? PipeProtocol.Error(ErrorCodes.PipeSignatureNotGiven, "Cancelled or failed")
                            // Abgelehnt, z. B. Protokolldienst nicht erreichbar (VIT-0300): Code an die Anwendung
                            : !who.Success
                                ? PipeProtocol.Error(who.ErrorCode ?? ErrorCodes.PipeSignatureNotGiven, PipeProtocol.EnglishError(who.ErrorCode))
                                : PipeProtocol.SignatureAnswer(who, reason, req.Meaning, DateTimeOffset.UtcNow);
                        await Reply(writer, answer);
                        break;
                    case "subscribe" when api:
                        lock (_subscribers) _subscribers.Add(writer);
                        await Reply(writer, new JsonObject { ["ok"] = true, ["subscribed"] = true });
                        // Verbindung offen halten, bis der Client trennt
                        while (pipe.IsConnected && !_cts.IsCancellationRequested) await Task.Delay(1000, _cts.Token);
                        break;
                    default:
                        await Reply(writer, PipeProtocol.Error(ErrorCodes.PipeDisabled, "Interface is disabled"));
                        break;
                }
            }
        }
        catch { }
        finally
        {
            lock (_subscribers) _subscribers.Remove(writer);
        }
    }

    private JsonObject Status() => new()
    {
        ["ok"] = true,
        ["locked"] = _lock.Status == LockStatus.Locked,
        ["lockedSince"] = _lock.LockedSince?.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture),
        ["lastUnlockedBy"] = _lock.LastUnlockedBy,
        ["machine"] = Environment.MachineName,
        ["sessionUser"] = Environment.UserDomainName + "\\" + Environment.UserName,
    };

    private static async Task Reply(StreamWriter w, JsonObject o)
    {
        // Antworten und Ereignisse (Broadcast) dürfen sich nicht mischen
        var text = o.ToJsonString();
        await Task.Run(() => { lock (w) w.WriteLine(text); });
    }

    private void Broadcast(AuditEntry e)
    {
        StreamWriter[] subs;
        lock (_subscribers) subs = _subscribers.ToArray();
        if (subs.Length == 0) return;
        var json = JsonSerializer.Serialize(new
        {
            @event = e.Event.ToString(),
            time = e.Time,
            actor = e.Actor,
            method = e.Method,
            detail = e.Detail,
            seq = e.Seq,
            hash = e.Hash,
        });
        foreach (var w in subs)
        {
            try { lock (w) w.WriteLine(json); }
            catch { lock (_subscribers) _subscribers.Remove(w); }
        }
    }

    /// <summary>Schickt einen Befehl an eine bereits laufende Instanz. true = angekommen.</summary>
    public static bool TrySend(int sessionId, string cmd)
    {
        try
        {
            using var c = new NamedPipeClientStream(".", AppPaths.PipeName(sessionId), PipeDirection.InOut);
            c.Connect(1500);
            // Nur an Vitrine selbst übergeben, nie an einen Prozess, der den Namen belegt hat
            if (!Native.GetNamedPipeServerProcessId(c.SafePipeHandle, out var pid) || !IsVitrine(Native.ProcessPath(pid)))
                return false;
            using var w = new StreamWriter(c, new UTF8Encoding(false)) { AutoFlush = true };
            using var r = new StreamReader(c);
            w.WriteLine(new JsonObject { ["cmd"] = cmd }.ToJsonString());
            r.ReadLine();
            return true;
        }
        catch { return false; }
    }

    /// <summary>
    /// Ist der Pipe-Server ein Vitrine-Prozess? Gleiche Datei wie diese Instanz (auch als .scr-Kopie für den
    /// Bildschirmschoner oder unter einem 8.3-Namen) oder eine Datei mit Produktname „Vitrine“ und unserem Herausgeber.
    /// </summary>
    internal static bool IsVitrine(string? serverPath)
    {
        if (serverPath is null || Environment.ProcessPath is not { } self) return false;
        try
        {
            if (string.Equals(Path.GetFullPath(serverPath), Path.GetFullPath(self), StringComparison.OrdinalIgnoreCase)) return true;
            var info = System.Diagnostics.FileVersionInfo.GetVersionInfo(serverPath);
            return info.ProductName == Core.About.AppInfo.Name && info.CompanyName == Core.About.AppInfo.Publisher;
        }
        catch (Exception ex) when (ex is IOException or ArgumentException or UnauthorizedAccessException) { return false; }
    }

    public void Dispose()
    {
        _lock.Audited -= Broadcast;
        _cts.Cancel();
    }
}
