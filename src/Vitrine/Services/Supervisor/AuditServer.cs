// SPDX-License-Identifier: MIT
using System.IO.Pipes;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Vitrine.Abstractions;
using Vitrine.Core.About;
using Vitrine.Core.Auth;
using Vitrine.Core.Integration;
using Vitrine.Core.Localization;
using Vitrine.Core.Service;
using Vitrine.Services.Auth;

namespace Vitrine.Services.Supervisor;

/// <summary>
/// Rechte der Protokoll-Pipe \\.\pipe\ICT-Baden.Vitrine.Audit (#15). Anders als die Dienst-Pipe in beide Richtungen
/// (Antworten mit Nummer, Hash und Ticket); wie dort dürfen Benutzer keine eigenen Instanzen anlegen
/// (<see cref="PipeAccessRights.CreateNewInstance"/>), sonst könnten sie Verbindungen anderer Sitzungen abfangen.
/// Getestet in tests/…/Windows/AuditPipeTests.cs.
/// </summary>
internal static class AuditPipe
{
    public const PipeAccessRights ClientRights = PipeAccessRights.ReadData | PipeAccessRights.WriteData |
                                                 PipeAccessRights.ReadAttributes | PipeAccessRights.Synchronize;

    public const PipeAccessRights UserRights = ClientRights | PipeAccessRights.ReadPermissions;

    public const PipeAccessRights ForbiddenForUsers = PipeAccessRights.CreateNewInstance | PipeAccessRights.ChangePermissions |
                                                      PipeAccessRights.TakeOwnership | PipeAccessRights.Delete;

    public const int BufferSize = 64 * 1024;

    public static PipeSecurity Security()
    {
        var acl = new PipeSecurity();
        acl.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        acl.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        acl.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null), UserRights, AccessControlType.Allow));
        return acl;
    }

    /// <summary>Client-Ende: asynchron, damit Lesen (Antworten) und Schreiben (Anfragen) sich nicht gegenseitig blockieren.</summary>
    public static NamedPipeClientStream OpenClient(string name) =>
        new(".", name, ClientRights, PipeOptions.Asynchronous, TokenImpersonationLevel.Identification, HandleInheritability.None);
}

/// <summary>
/// Protokoll-Pipe im Dienst: nimmt Verbindungen an, stellt die Gegenstelle selbst fest (Prozess, Sitzung, Exe, Benutzer
/// aus dem Token) und lässt <see cref="AuditBroker"/> antworten. Anfragen einer Verbindung nacheinander, damit die
/// Reihenfolge der Einträge stimmt.
/// </summary>
internal sealed class AuditServer(AuditBroker broker, string exe, Action<string> error, string pipeName = AppPaths.AuditPipe)
{
    public async Task RunAsync(CancellationToken ct)
    {
        bool first = true;
        var delay = TimeSpan.FromSeconds(1);
        string? lastError = null;
        while (!ct.IsCancellationRequested)
        {
            NamedPipeServerStream pipe;
            try
            {
                pipe = NamedPipeServerStreamAcl.Create(pipeName, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances,
                    PipeTransmissionMode.Byte, PipeOptions.Asynchronous | (first ? PipeOptions.FirstPipeInstance : 0), AuditPipe.BufferSize,
                    AuditPipe.BufferSize, AuditPipe.Security());
                first = false;
                lastError = null;
                delay = TimeSpan.FromSeconds(1);
                await pipe.WaitForConnectionAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { return; }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                if (lastError != ex.Message) error($"Audit pipe: {ex.Message}");
                lastError = ex.Message;
                try { await Task.Delay(delay, ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { return; }
                delay = TimeSpan.FromSeconds(Math.Min(60, delay.TotalSeconds * 2));
                continue;
            }
            _ = Task.Run(() => ServeAsync(pipe, ct), ct);
        }
    }

    private async Task ServeAsync(NamedPipeServerStream pipe, CancellationToken ct)
    {
        await using var _ = pipe;
        uint pid = 0;
        try
        {
            // Prozess, Sitzung und Exe vor dem ersten Lesen; den Benutzer erst danach (ImpersonateNamedPipeClient geht erst,
            // wenn die Gegenstelle geschrieben hat)
            if (!Accept(pipe, out pid, out var session)) return;
            AuditClient? client = null;
            var reader = new BoundedLineReader(new StreamReader(pipe, Encoding.UTF8, leaveOpen: true), AuditBroker.MaxLineLength);
            await using var writer = new StreamWriter(pipe, new UTF8Encoding(false), leaveOpen: true) { AutoFlush = true };
            while (await reader.ReadLineAsync(ct).ConfigureAwait(false) is { } line)
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                client ??= Identify(pipe, pid, session);
                if (client is null) return;
                var answer = await broker.HandleAsync(client, line).ConfigureAwait(false);
                await writer.WriteLineAsync(answer.ToJsonString().AsMemory(), ct).ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (ex is IOException or OperationCanceledException or ObjectDisposedException) { }
        // Alles andere nicht still verschlucken (vorher endete die Aufgabe unbeobachtet, und die App pufferte endlos)
        catch (Exception ex)
        {
            Report($"pipe|{ex.GetType().Name}", $"{ErrorCodes.AuditPipeFailed} audit pipe client PID {pid}: {ex.GetType().Name}: {ex.Message}");
        }
    }

    /// <summary>
    /// Wer ist die Gegenstelle? Nur Vitrine.exe aus dem Programmordner des Dienstes (<see cref="ClientProcess"/>). Abgelehnt:
    /// Eintrag VIT-0331 mit PID, Sitzung, beiden Pfaden und Grund (höchstens alle 10 Minuten je Grund und Pfad).
    /// </summary>
    private bool Accept(NamedPipeServerStream pipe, out uint pid, out int session)
    {
        session = 0;
        if (!SessionApi.GetNamedPipeClientProcessId(pipe.SafePipeHandle, out pid) ||
            !SessionApi.GetNamedPipeClientSessionId(pipe.SafePipeHandle, out session))
        {
            Report("noid", $"{ErrorCodes.AuditClientRejected} audit pipe client refused: process or session of the client unknown (Win32 error {Marshal.GetLastPInvokeError()})");
            return false;
        }
        var check = ClientProcess.Check(pid, exe);
        if (check.Verdict.Accepted) return true;
        Report($"reject|{check.ClientFinal ?? check.ClientPath}|{check.Verdict.Reason}",
            $"{ErrorCodes.AuditClientRejected} audit pipe client refused: PID {pid}, session {session}, {check.Describe(exe)}");
        return false;
    }

    /// <summary>
    /// Benutzer und SID aus dem Token der Gegenstelle. Unter der Identität der Gegenstelle (Identifikationsstufe) nur das
    /// Token öffnen – per P/Invoke, nichts, was eine Assembly lädt: Das scheitert dort mit FileNotFoundException
    /// (System.Security.Claims beim ersten WindowsIdentity), und genau daran scheiterte seit 0.2.0 jede Verbindung.
    /// Name, SID und Gruppen danach mit den Rechten des Dienstes.
    /// </summary>
    private AuditClient? Identify(NamedPipeServerStream pipe, uint pid, int session)
    {
        nint token = 0;
        int error = 0;
        try
        {
            pipe.RunAsClient(() =>
            {
                token = Interop.Native.OpenCurrentThreadToken();
                if (token == 0) error = Marshal.GetLastPInvokeError();
            });
            if (token == 0)
            {
                Report($"token|{error}", $"{ErrorCodes.AuditClientUnidentified} audit pipe client PID {pid}, session {session}: token not readable (Win32 error {error})");
                return null;
            }
            using var id = new WindowsIdentity(token);
            var name = id.Name;
            var sid = id.User?.Value;
            // Groups enthält nur aktive Gruppen (nicht „deny only“ eines eingeschränkten Tokens)
            bool admin = id.Groups?.Any(g => g.Value == WindowsAccounts.AdministratorsSid) == true;
            if (string.IsNullOrEmpty(name) || sid is null)
            {
                Report("token|empty", $"{ErrorCodes.AuditClientUnidentified} audit pipe client PID {pid}, session {session}: token without user");
                return null;
            }
            // Gruppen nur als Mitgliedschaft (für Rollen beim Lesen der Schlüsselliste): aktive, „nur verweigern“ und verknüpftes Token
            var groups = WindowsAccounts.GetGroupSids(id);
            foreach (var c in id.Claims.Where(c => c.Type == System.Security.Claims.ClaimTypes.DenyOnlySid)) groups.Add(c.Value);
            return new AuditClient(session, name, sid, (int)pid, admin, groups);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or
                                       ArgumentException or System.Security.SecurityException or SystemException)
        {
            Report($"identify|{ex.GetType().Name}", $"{ErrorCodes.AuditClientUnidentified} audit pipe client PID {pid}, session {session}: {ex.GetType().Name}: {ex.Message}");
            return null;
        }
        finally
        {
            // WindowsIdentity hat sich eine eigene Kopie des Handles genommen
            if (token != 0) Interop.Native.CloseHandle(token);
        }
    }

    public static readonly TimeSpan ReportInterval = TimeSpan.FromMinutes(10);

    private readonly ReportLimiter _limiter = new(ReportInterval);

    /// <summary>Fehler ins Protokoll des Dienstes – gleiche Ursache höchstens alle 10 Minuten (die App verbindet sich alle paar Sekunden neu).</summary>
    private void Report(string key, string message)
    {
        if (!_limiter.ShouldReport(key)) return;
        try { error(message); }
        catch { /* nie deswegen die Pipe beenden */ }
    }

    static AuditServer()
    {
        // P/Invoke außerhalb jeder Identität einmal binden (DLL suchen, Stub erzeugen), damit unter der Identität der
        // Gegenstelle nichts mehr nachgeladen werden muss
        var t = Interop.Native.OpenCurrentThreadToken();
        if (t != 0) Interop.Native.CloseHandle(t);
        _ = Marshal.GetLastPInvokeError();
    }
}

/// <summary>
/// Gegenstelle einer Pipe des Dienstes: Ist es Vitrine.exe aus dem Ordner des Dienstes? Pfad mit
/// QueryFullProcessImageName (geht als SYSTEM über Sitzungen hinweg), beide Seiten mit GetFinalPathNameByHandle
/// normalisiert, Entscheidung in <see cref="AuditClientCheck"/> (Vitrine.Core).
/// </summary>
internal static class ClientProcess
{
    public sealed record Result(AuditClientVerdict Verdict, string? ClientPath, string? ClientFinal, string? ServiceFinal)
    {
        /// <summary>„client …, expected …: Grund“ für das Protokoll (englisch).</summary>
        public string Describe(string serviceExe) =>
            $"client {ClientPath ?? "(unknown)"}{(ClientFinal is not null && !ExecutablePath.Same(ClientFinal, ClientPath) ? $" ({ClientFinal})" : "")}, " +
            $"expected {serviceExe}{(ServiceFinal is not null && !ExecutablePath.Same(ServiceFinal, serviceExe) ? $" ({ServiceFinal})" : "")}: {Verdict.Reason}";
    }

    public static Result Check(uint pid, string serviceExe)
    {
        var image = Interop.Native.ProcessPath(pid);
        var clientFinal = image is null ? null : Interop.Native.FinalPath(image);
        var serviceFinal = Interop.Native.FinalPath(serviceExe);
        return new Result(AuditClientCheck.Evaluate(image, clientFinal, serviceExe, serviceFinal), image, clientFinal, serviceFinal);
    }
}

/// <summary>Prüfungen des Dienstes mit Windows-Mitteln: LogonUser, JWKS von Microsoft (Zwischenspeicher), Namen → SID.</summary>
internal sealed class ServiceSignatureVerifier : ISignatureVerifier
{
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(10) };
    private readonly Dictionary<string, (string Json, DateTimeOffset Fetched)> _keys = new(StringComparer.OrdinalIgnoreCase);
    private readonly SemaphoreSlim _fetch = new(1, 1);

    public Task<AuthOutcome> WindowsAsync(string user, string? domain, string secret, string clientSid) =>
        // Benutzer und Domäne hat die App mit LogonTarget.Resolve bestimmt; wer es ist, sagt das Token von LogonUser
        Task.Run(() => WindowsPasswordProvider.Logon(new LogonTarget(user, domain), secret, clientSid));

    public Task<(AuthOutcome Outcome, IDisposable? Token)> WindowsWithTokenAsync(string user, string? domain, string secret, string clientSid) =>
        Task.Run(() =>
        {
            var outcome = WindowsPasswordProvider.Logon(new LogonTarget(user, domain), secret, clientSid, keep: true, out var identity);
            return (outcome, (IDisposable?)identity);
        });

    public async Task<string?> EntraKeysAsync(string tenant, string clientId, bool refresh)
    {
        var cacheKey = $"{tenant}|{clientId}";
        await _fetch.WaitAsync().ConfigureAwait(false);
        try
        {
            var now = DateTimeOffset.UtcNow;
            if (_keys.TryGetValue(cacheKey, out var c))
            {
                // Neu holen höchstens alle 5 Minuten (ein unbekannter Schlüssel darf Microsoft nicht im Takt der Anfragen abfragen)
                if (!refresh && now - c.Fetched < TimeSpan.FromHours(12)) return c.Json;
                if (refresh && now - c.Fetched < TimeSpan.FromMinutes(5)) return c.Json;
            }
            try
            {
                var json = await Http.GetStringAsync(EntraIdToken.KeysUri(tenant, clientId)).ConfigureAwait(false);
                _keys[cacheKey] = (json, now);
                return json;
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or InvalidOperationException)
            {
                return _keys.TryGetValue(cacheKey, out var old) ? old.Json : null;
            }
        }
        finally { _fetch.Release(); }
    }

    public string? ResolveSid(string name) => WindowsAccounts.ToSid(name);
}
