// SPDX-License-Identifier: MIT
using System.IO.Pipes;
using System.ServiceProcess;
using Vitrine.Core.About;
using Vitrine.Core.Audit;
using Vitrine.Core.Config;
using Vitrine.Core.Service;
using Vitrine.Platform;

namespace Vitrine.Services.Supervisor;

/// <summary>
/// Windows-Dienst „ICT-Baden Vitrine“ (<c>Vitrine.exe --service</c>, läuft als SYSTEM in Sitzung 0, ohne Oberfläche).
/// Startet bei jeder Anmeldung die Sitzungs-App (<c>Vitrine.exe --agent</c>) als angemeldeter Benutzer und überwacht sie
/// über \\.\pipe\ICT-Baden.Vitrine.Service. Die Entscheidungen trifft <see cref="SessionSupervisor"/> (Vitrine.Core).
/// Fristen laufen auf einer monotonen Uhr ohne Schlafzeit (<see cref="SessionApi.MonotonicNow"/>).
/// </summary>
public sealed class VitrineService : ServiceBase
{
    private readonly SessionSupervisor _supervisor = new();
    private readonly object _gate = new();
    private readonly CancellationTokenSource _stop = new();
    private readonly string _exe = Environment.ProcessPath!;
    private readonly ReportLimiter _rejections = new(AuditServer.ReportInterval);
    /// <summary>Einziger Schreibweg des Dienstes ins Protokoll (signiert, sonst Format 2).</summary>
    private ServiceAuditLog? _log;
    private ConfigStore? _store;
    /// <summary>Eigener Protokollordner (Audit.Directory) abgelehnt, weil Benutzer ihn ändern könnten: Standardordner.</summary>
    private string? _checkedDirectory;
    private bool _customDirectoryRefused;
    private Timer? _tick;
    private bool _supervising;
    private long _ticks;

    public VitrineService()
    {
        ServiceName = AppPaths.ServiceName;
        CanHandleSessionChangeEvent = true;
        CanHandlePowerEvent = true;
        CanShutdown = true;
    }

    public static void RunService() => Run(new VitrineService());

    private static TimeSpan Now => SessionApi.MonotonicNow();

    protected override void OnStart(string[] args)
    {
        var store = _store = new ConfigStore(ConfigFiles.Default, RegistryPolicySource.All(), new AdminOnlyFiles());
        store.Load();
        _log = new ServiceAuditLog(new AuditLog(store.Current.Audit, "SYSTEM", new EventLogSink()), new EventLogSink());
        // Vom vorigen Dienst gesperrt zurückgelassene (getrennte) Sitzungen, z. B. während eines Updates der MSI
        var locked = TakeLockedSessions();
        // MSI mit SERVICE=0: Dienst installiert, überwacht aber nichts (Autostart wie früher); das Protokoll schreiben
        // dann die Apps selbst (Format 2, nicht Part-11-fähig)
        bool supervise = true;
        using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(AppPaths.ProductKey))
            if (key?.GetValue("Supervise") is int value && value == 0) supervise = false;
        if (!supervise)
        {
            HandBackAuditLog();
            Log(AuditEventType.ServiceStarted, $"Version {AppInfo.Version}, supervision off");
            return;
        }
        // Zuerst das Protokoll: Auch die folgenden Einträge des Dienstes sind dann signiert
        StartAuditLog();
        Log(AuditEventType.ServiceStarted, $"Version {AppInfo.Version}" +
            (locked.Count > 0 ? $", locked before the service stopped: session {ServiceState.Format(locked)}" : ""));
        _supervising = true;

        _ = Task.Run(() => AcceptLoop(_stop.Token));
        // Gesperrt waren: Vitrine startet dort gesperrt – sonst bekäme, wer die getrennte Sitzung mit dem Windows-Kennwort
        // wieder verbindet, eine entsperrte Vitrine
        lock (_gate)
            foreach (var session in SessionApi.UserSessions())
                Execute(_supervisor.SessionStarted(session, Now, locked: locked.Contains(session)));
        _tick = new Timer(_ =>
        {
            // Eine Ausnahme auf dem Timer-Thread beendete den ganzen Dienst: hier abfangen und protokollieren
            try
            {
                lock (_gate) Execute(_supervisor.Tick(Now));
                // Einstellungen (Protokollordner, Entra) jede Minute neu lesen: Der Dienst prüft Signaturen mit ihnen
                if (++_ticks % 60 == 0)
                {
                    // Verschwundene Sitzungen ohne Abmeldemeldung vergessen (abgebrochene Anmeldung u. Ä.)
                    if (SessionApi.ExistingSessions() is { } existing)
                        lock (_gate)
                            foreach (var gone in _supervisor.ForgetVanished(existing))
                                Log(AuditEventType.AgentStopped, $"Session {gone}: no longer exists, no longer supervised");
                    _store?.Load();
                    CheckCustomDirectory();
                }
            }
            catch (Exception ex)
            {
                try { Log(AuditEventType.Error, $"{Core.Localization.ErrorCodes.Unexpected} service tick: {ex.GetType().Name}: {ex.Message}"); }
                catch { /* nie den Dienst beenden */ }
            }
        }, null, 1000, 1000);
    }

    /// <summary>
    /// Protokoll übernehmen (#15): Schlüssel laden oder anlegen, Ordner für Benutzer nur lesbar, Protokoll-Pipe öffnen.
    /// Scheitert der Schlüssel, schreiben die Apps weiter selbst (Format 2) – mit Fehler VIT-0317 im Protokoll.
    /// </summary>
    private void StartAuditLog()
    {
        try
        {
            var keys = new CngAuditKeyStore();
            keys.Current();
            CheckCustomDirectory();
            var signed = new SignedAuditLog(SignedSettings, keys, new RegistryAnchorStore(writable: true), new EventLogSink());
            // Nur den Standardordner schützen; ein eigener Ordner (Audit.Directory) gilt nur, wenn ihn Benutzer nicht ändern können
            if (AuditState.IsDefaultLogFolder(signed.LogDirectory)) AuditState.ProtectLogFolder(signed.LogDirectory);
            AuditState.SetServiceWrites(true);
            _log!.Signed = signed;
            var broker = new AuditBroker(signed, new ServiceSignatureVerifier(), () => _store!.Current);
            StartFido(broker);
            var server = new AuditServer(broker, _exe, message => Log(AuditEventType.Error, message));
            _ = Task.Run(() => server.RunAsync(_stop.Token));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException or
                                       System.Security.Cryptography.CryptographicException or InvalidOperationException or ArgumentException)
        {
            if (_log is not null) _log.Signed = null;
            HandBackAuditLog();
            Log(AuditEventType.Error, $"{Core.Localization.ErrorCodes.AuditKeyError} {ex.Message}");
        }
    }

    /// <summary>
    /// Sicherheitsschlüssel (Verfahren „fido“): Der Dienst prüft sie über die Protokoll-Pipe, die Ablage
    /// (%ProgramData%\ICT-Baden\Vitrine\fido-credentials.json) schreibt nur er. Probleme der Ablage (VIT-0420/VIT-0421) und
    /// Schlüssel einer anderen RP ID (VIT-0422) einmal beim Start ins Protokoll.
    /// </summary>
    private void StartFido(AuditBroker broker)
    {
        // Dateien der Ablage nur noch für SYSTEM und Administratoren lesbar (auch vorhandene aus früheren Versionen)
        foreach (var file in new[] { Core.About.AppPaths.FidoCredentialsFile, Core.About.AppPaths.FidoDirectoryCacheFile })
        {
            try { new ProtectedFidoStoreFile(file).RestrictExisting(); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or System.Security.SecurityException)
            {
                Log(AuditEventType.Error, $"{Core.Localization.ErrorCodes.FidoStoreError} permissions of {file}: {ex.Message}");
            }
        }
        // Ablage wird beim Start gewählt (Fido.Store); ein Wechsel gilt nach dem Neustart des Dienstes
        Core.Fido.IFidoCredentialStore store;
        Core.Fido.IFidoGroupCache groups;
        if (_store!.Current.Fido.Store == Core.Config.FidoStoreKind.ActiveDirectory)
        {
            var directory = new Core.Fido.FidoDirectoryStore(new LdapFidoDirectory(() => _store!.Current.Fido),
                new ProtectedFidoStoreFile(Core.About.AppPaths.FidoDirectoryCacheFile), new RegistryFidoCounterStore(),
                () => _store!.Current.Fido, log: message => Log(AuditEventType.Error, message));
            store = directory;
            groups = directory;
        }
        else
        {
            var local = new Core.Fido.JsonFidoStore(new ProtectedFidoStoreFile());
            store = local;
            groups = local;
        }
        var fido = new Core.Fido.FidoService(store, groups, new WindowsFidoAccounts(() => _store!.Current), 
            // Registrierende: dieselbe Rollenprüfung wie in der App (Roles.Registrars, Security.LocalAdministratorsArePrivileged),
            // mit der Gerätekonfiguration und den Richtlinien, die der Dienst liest
            new Core.Auth.RoleCheck(() => _store!.Current, Services.Auth.WindowsAccounts.ToSid, () => new Services.Auth.LocalGroupDirectory()),
            () => _store!.Current.Fido, broker.WriteFidoEvent);
        broker.Fido = fido;
        _ = Task.Run(async () =>
        {
            try
            {
                var status = await fido.StatusAsync().ConfigureAwait(false);
                if (status.StoreError is { } error) Log(AuditEventType.Error, error);
                if (status.OtherRpId > 0)
                    Log(AuditEventType.Error, $"{Core.Localization.ErrorCodes.FidoRpIdChanged} {status.OtherRpId} security keys registered for another RP ID than Fido.RpId {status.RpId}");
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException) { }
            // Active Directory: jede Minute prüfen, ob ein Abgleich fällig ist (Fido.SyncMinutes, nach Fehlern RetryInterval)
            if (!store.RequiresWriteCredential) return;
            while (!_stop.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(TimeSpan.FromMinutes(1), _stop.Token).ConfigureAwait(false);
                    await fido.SyncAsync(_stop.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) { return; }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
                {
                    Log(AuditEventType.Error, $"{Core.Localization.ErrorCodes.FidoDirectoryUnavailable} {ex.Message}");
                }
            }
        });
    }

    /// <summary>
    /// Der Dienst schreibt das Protokoll nicht (SERVICE=0, Schlüssel nicht ladbar): Die Apps schreiben selbst, also im
    /// Standardordner wieder Anlegen und Anhängen für Benutzer erlauben (wie die MSI mit SERVICE=0) – sonst landeten ihre
    /// Einträge im ungeschützten Ordner pro Benutzer.
    /// </summary>
    private void HandBackAuditLog()
    {
        try
        {
            AuditState.SetServiceWrites(false);
            if (_store is { } store && AuditState.IsDefaultLogFolder(EffectiveDirectory(store.Current.Audit)))
                AuditState.AllowAppendForUsers(AppPaths.MachineLogDir);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException or InvalidOperationException)
        {
            Log(AuditEventType.Error, $"Audit folder permissions: {ex.Message}");
        }
    }

    private static string EffectiveDirectory(AuditSettings a) =>
        string.IsNullOrWhiteSpace(a.Directory) ? AppPaths.MachineLogDir : Environment.ExpandEnvironmentVariables(a.Directory);

    /// <summary>
    /// Ein eigener Ordner (Audit.Directory), den Benutzer ändern könnten (Besitz, Schreibrechte, Verknüpfung – auch im
    /// übergeordneten Ordner), wird nicht benutzt: Der Dienst schreibt als SYSTEM, ein Benutzer könnte ihn sonst über eine
    /// Verknüpfung auf andere Dateien umlenken oder die Dateien ändern. Dann gilt der Standardordner (VIT-0323).
    /// Außerhalb des Schreibens geprüft (Start, jede Minute), nie währenddessen.
    /// </summary>
    private void CheckCustomDirectory()
    {
        if (_store is not { } store) return;
        var dir = EffectiveDirectory(store.Current.Audit);
        if (string.Equals(dir, _checkedDirectory, StringComparison.OrdinalIgnoreCase)) return;
        _checkedDirectory = dir;
        bool refused = false;
        if (!AuditState.IsDefaultLogFolder(dir))
        {
            try { refused = !new AdminOnlyFiles().DirectoryIsProtected(dir); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException or InvalidOperationException) { refused = true; }
        }
        _customDirectoryRefused = refused;
        if (refused) Log(AuditEventType.Error, $"{Core.Localization.ErrorCodes.AuditDirectoryNotProtected} Audit.Directory {dir} can be changed by users – using {AppPaths.MachineLogDir}");
    }

    /// <summary>Einstellungen für das signierte Protokoll: mit abgelehntem eigenem Ordner der Standardordner.</summary>
    private AuditSettings SignedSettings()
    {
        var a = _store!.Current.Audit;
        if (!_customDirectoryRefused) return a;
        return new AuditSettings { Enabled = a.Enabled, Directory = null, NetworkDirectory = a.NetworkDirectory, EventLog = a.EventLog, LogLockState = a.LogLockState };
    }

    /// <summary>Eintrag des Dienstes – immer über <see cref="ServiceAuditLog"/> (signiert, wenn der Dienst das Protokoll schreibt).</summary>
    private void Log(AuditEventType type, string? detail = null) => _log?.Write(type, detail);

    /// <summary>Gemerkte gesperrte Sitzungen lesen und vergessen (gelten nur für den nächsten Start des Dienstes).</summary>
    private HashSet<int> TakeLockedSessions()
    {
        try
        {
            string? value;
            using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(AppPaths.ServiceStateKey))
                value = key?.GetValue(ServiceState.LockedSessionsValue) as string;
            if (value is null) return [];
            Microsoft.Win32.Registry.LocalMachine.DeleteSubKeyTree(AppPaths.ServiceStateKey, throwOnMissingSubKey: false);
            return ServiceState.Parse(value);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            Log(AuditEventType.Error, $"Service state: {ex.Message}");
            return [];
        }
    }

    /// <summary>
    /// Gesperrte Sitzungen für den nächsten Start des Dienstes merken: flüchtiger Schlüssel unter HKLM (übersteht das Update
    /// der MSI, nicht den Neustart von Windows – danach gibt es die Sitzungen auch nicht mehr).
    /// </summary>
    private void SaveLockedSessions(IReadOnlyCollection<int> sessions)
    {
        try
        {
            if (sessions.Count == 0)
            {
                Microsoft.Win32.Registry.LocalMachine.DeleteSubKeyTree(AppPaths.ServiceStateKey, throwOnMissingSubKey: false);
                return;
            }
            // Übergeordneten Schlüssel dauerhaft anlegen: Fehlt er, entstünde er sonst flüchtig – und mit ihm später die Werte der MSI
            Microsoft.Win32.Registry.LocalMachine.CreateSubKey(AppPaths.ProductKey)?.Dispose();
            using var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(AppPaths.ServiceStateKey, true, Microsoft.Win32.RegistryOptions.Volatile);
            key.SetValue(ServiceState.LockedSessionsValue, ServiceState.Format(sessions), Microsoft.Win32.RegistryValueKind.String);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            Log(AuditEventType.Error, $"Service state: {ex.Message}");
        }
    }

    /// <summary>
    /// Dienst wird beendet (von Hand, Update oder Deinstallation der MSI): Gesperrte Sitzungen werden getrennt und gemerkt.
    /// Sonst stünde eine gesperrte Sitzung ohne Überwachung da – und das Setup beendet gleich danach auch die App selbst.
    /// Der nächste Dienst startet Vitrine dort gesperrt (<see cref="TakeLockedSessions"/>).
    /// </summary>
    protected override void OnStop()
    {
        _stop.Cancel();
        _tick?.Dispose();
        if (_supervising)
        {
            List<int> locked;
            lock (_gate) locked = [.. _supervisor.LockedSessions];
            SaveLockedSessions(locked);
            foreach (var session in locked)
            {
                var ok = SessionApi.Disconnect(session);
                Log(AuditEventType.SessionDisconnected, $"Session {session}: service stopping{(ok ? "" : " (failed)")}");
            }
        }
        // Auch ohne Überwachung: Reste einer abgestürzten App (Win+L abgeschaltet) nicht über die Deinstallation hinaus stehen lassen
        RevertOrphanedWinLocks();
        Log(AuditEventType.ServiceStopped);
        // Die Netzkopie schreibt im Hintergrund; gleich endet der Prozess
        AuditLog.FlushNetworkCopies(TimeSpan.FromSeconds(2));
    }

    /// <summary>Herunterfahren: Die Apps verschwinden erwartungsgemäß; nichts neu starten, nichts trennen.</summary>
    protected override void OnShutdown()
    {
        lock (_gate) _supervisor.ShuttingDown();
        _stop.Cancel();
        _tick?.Dispose();
        Log(AuditEventType.ServiceStopped, "Windows shutdown");
        AuditLog.FlushNetworkCopies(TimeSpan.FromSeconds(2));
    }

    protected override bool OnPowerEvent(PowerBroadcastStatus powerStatus)
    {
        lock (_gate)
        {
            switch (powerStatus)
            {
                case PowerBroadcastStatus.Suspend:
                    _supervisor.Suspending(Now);
                    break;
                case PowerBroadcastStatus.ResumeSuspend or PowerBroadcastStatus.ResumeAutomatic or PowerBroadcastStatus.ResumeCritical:
                    _supervisor.Resumed(Now);
                    break;
            }
        }
        return true;
    }

    protected override void OnSessionChange(SessionChangeDescription change)
    {
        if (!_supervising) return;
        lock (_gate)
        {
            switch (change.Reason)
            {
                case SessionChangeReason.SessionLogon or SessionChangeReason.ConsoleConnect or SessionChangeReason.RemoteConnect:
                    Execute(_supervisor.SessionStarted(change.SessionId, Now));
                    break;
                case SessionChangeReason.SessionLogoff:
                    _supervisor.SessionEnded(change.SessionId);
                    break;
            }
        }
    }

    // ================= Pipe =================

    private async Task AcceptLoop(CancellationToken ct)
    {
        bool first = true;
        var delay = TimeSpan.FromSeconds(1);
        string? lastError = null;
        while (!ct.IsCancellationRequested)
        {
            NamedPipeServerStream pipe;
            try
            {
                pipe = NamedPipeServerStreamAcl.Create(AppPaths.ServicePipe, PipeDirection.In, NamedPipeServerStream.MaxAllowedServerInstances,
                    PipeTransmissionMode.Byte, PipeOptions.Asynchronous | (first ? PipeOptions.FirstPipeInstance : 0), ServicePipe.InBufferSize, 0, ServicePipe.Security());
                first = false;
                lastError = null;
                delay = TimeSpan.FromSeconds(1);
                await pipe.WaitForConnectionAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { return; }
            // Name belegt (anderer Prozess war schneller) oder kein Zugriff: einmal protokollieren, mit wachsender Pause neu
            // versuchen – nicht jede Sekunde einen Eintrag, und die Schleife darf nie still enden.
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                if (lastError != ex.Message) Log(AuditEventType.Error, $"Service pipe: {ex.Message}");
                lastError = ex.Message;
                try { await Task.Delay(delay, ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { return; }
                delay = TimeSpan.FromSeconds(Math.Min(60, delay.TotalSeconds * 2));
                continue;
            }
            _ = Task.Run(() => Serve(pipe, ct), ct);
        }
    }

    private async Task Serve(NamedPipeServerStream pipe, CancellationToken ct)
    {
        using (pipe)
        {
            // Gegenstelle selbst feststellen: Sitzung, Prozess und Exe – nur Vitrine.exe aus dem Programmordner zählt
            if (!SessionApi.GetNamedPipeClientProcessId(pipe.SafePipeHandle, out var upid) ||
                !SessionApi.GetNamedPipeClientSessionId(pipe.SafePipeHandle, out var session)) return;
            var pid = (int)upid;
            var check = ClientProcess.Check(upid, _exe);
            if (!check.Verdict.Accepted)
            {
                // Sichtbar machen statt still schließen (VIT-0331), gleiche Ursache höchstens alle 10 Minuten
                if (_rejections.ShouldReport($"{check.ClientFinal ?? check.ClientPath}|{check.Verdict.Reason}"))
                    Log(AuditEventType.Error, $"{Core.Localization.ErrorCodes.AuditClientRejected} service pipe client refused: PID {pid}, session {session}, {check.Describe(_exe)}");
                return;
            }

            lock (_gate) if (!_supervisor.AgentConnected(session, pid, Now)) return;
            // Nachweis, dass die Überwachung steht (prüft auch der Installationstest der CI)
            Log(AuditEventType.AgentConnected, $"Session {session}, PID {pid}");
            try
            {
                var reader = new Core.Integration.BoundedLineReader(new StreamReader(pipe), ServiceProtocol.MaxLineLength);
                while (await reader.ReadLineAsync(ct).ConfigureAwait(false) is { } line)
                    if (ServiceProtocol.Parse(line) is { } m)
                        lock (_gate) Execute(_supervisor.Message(session, pid, m, Now));
            }
            catch (Exception ex) when (ex is IOException or OperationCanceledException) { }
            if (ct.IsCancellationRequested) return;
            lock (_gate) Execute(_supervisor.AgentLost(session, pid, Now));
        }
    }

    // ================= Aktionen =================

    /// <summary>
    /// DisableLockWorkstation, das die verschwundene App gesetzt hat, im Hive des Sitzungsbenutzers entfernen
    /// (HKU\&lt;SID&gt;, nur mit Vitrines Merkwert – ein Wert einer Richtlinie bleibt). Sonst täte Win+L dort nichts, bis
    /// Vitrine wieder läuft.
    /// </summary>
    private void RevertWinLock(int session)
    {
        try
        {
            if (SessionApi.UserSid(session) is not { } sid) return;
            var policy = new Core.Lock.LockWorkstationPolicy(new RegistryUserPolicyStore(Microsoft.Win32.Registry.Users, sid),
                new RegistryMachinePolicyReader());
            if (policy.Revert()) Log(AuditEventType.AgentLost, $"Session {session}: DisableLockWorkstation removed");
        }
        // Breit abfangen: läuft auch auf dem Timer-Thread, eine Ausnahme dort beendete den Dienst
        catch (Exception ex)
        {
            Log(AuditEventType.Error, $"Session {session}: DisableLockWorkstation not removed: {Describe(ex)}");
        }
    }

    /// <summary>Ausnahme fürs Protokoll: Typ, HRESULT und Text – manche Registry-Ausnahmen haben keinen Text.</summary>
    private static string Describe(Exception ex) =>
        $"{ex.GetType().Name} 0x{ex.HResult:X8}" + (string.IsNullOrWhiteSpace(ex.Message) ? "" : $": {ex.Message}");

    /// <summary>
    /// Beim Beenden des Dienstes (auch vor der Deinstallation): Vitrines DisableLockWorkstation in allen geladenen
    /// Benutzer-Hives entfernen, in deren Sitzung keine Vitrine mehr läuft (abgestürzt, abgemeldet). Mit laufender App bleibt
    /// er; sie entfernt ihn beim Beenden selbst. Nicht geladene Hives (abgemeldete Benutzer) erreicht der Dienst nicht –
    /// dort räumt die App bei der nächsten Anmeldung auf (docs/installation.md).
    /// </summary>
    private void RevertOrphanedWinLocks()
    {
        try
        {
            var live = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            lock (_gate)
                foreach (var session in _supervisor.Sessions)
                    if (_supervisor.AgentPid(session) is not null && SessionApi.UserSid(session) is { } sid) live.Add(sid);
            foreach (var sid in Microsoft.Win32.Registry.Users.GetSubKeyNames())
            {
                if (!sid.StartsWith("S-1-", StringComparison.Ordinal) || sid.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase) || live.Contains(sid))
                    continue;
                try
                {
                    var policy = new Core.Lock.LockWorkstationPolicy(new RegistryUserPolicyStore(Microsoft.Win32.Registry.Users, sid),
                        new RegistryMachinePolicyReader());
                    if (policy.Revert()) Log(AuditEventType.AgentStopped, $"{sid}: DisableLockWorkstation removed (service stopping)");
                }
                catch (Exception ex) { Log(AuditEventType.Error, $"{sid}: DisableLockWorkstation not removed: {Describe(ex)}"); }
            }
        }
        catch (Exception ex) { Log(AuditEventType.Error, $"DisableLockWorkstation clean-up: {Describe(ex)}"); }
    }

    private void Execute(List<SupervisorAction> actions)
    {
        foreach (var a in actions)
        {
            if (a.Event is { } e) Log(e, $"Session {a.SessionId}{(a.Detail is null ? "" : $": {a.Detail}")}");
            switch (a.Kind)
            {
                case SupervisorActionKind.StartAgent:
                    var (_, error) = SessionApi.StartAsUser(a.SessionId, _exe, a.Relock ? "--agent --lock" : "--agent");
                    if (error != 0) Execute(_supervisor.StartFailed(a.SessionId, Now, $"Win32 error {error}"));
                    break;
                case SupervisorActionKind.DisconnectSession:
                    var ok = SessionApi.Disconnect(a.SessionId);
                    Log(AuditEventType.SessionDisconnected, $"Session {a.SessionId}{(ok ? "" : " (failed)")}");
                    break;
                case SupervisorActionKind.RevertWinLock:
                    RevertWinLock(a.SessionId);
                    break;
                case SupervisorActionKind.KillAgent when _supervisor.AgentPid(a.SessionId) is { } pid:
                    try { using var p = System.Diagnostics.Process.GetProcessById(pid); p.Kill(); }
                    catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception) { }
                    break;
            }
        }
    }
}
