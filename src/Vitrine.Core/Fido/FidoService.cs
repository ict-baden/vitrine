// SPDX-License-Identifier: MIT
using System.Security.Cryptography;
using Vitrine.Abstractions;
using Vitrine.Core.Audit;
using Vitrine.Core.Auth;
using Vitrine.Core.Config;
using Vitrine.Core.Localization;
using Vitrine.Core.Service;

namespace Vitrine.Core.Fido;

/// <summary>Einmal-Challenge für eine Anmeldung mit Sicherheitsschlüssel.</summary>
/// <param name="AllowCredentials">Credential-IDs (Base64url) aller aktiven Schlüssel dieser RP ID.</param>
public sealed record FidoChallenge(string Challenge, string RpId, IReadOnlyList<string> AllowCredentials, int TimeoutMs);

/// <summary>Antwort des Schlüssels, wie die App sie vom Windows-Sicherheitsdialog bekommt (alles Base64url).</summary>
public sealed record FidoAssertion(string Challenge, string CredentialId, string AuthenticatorData, string ClientDataJson, string Signature);

/// <summary>Begonnene Registrierung: was die App an MakeCredential gibt.</summary>
public sealed record FidoRegistrationStart(string RegistrationId, string Challenge, string RpId, string UserHandle, string UserName,
    string DisplayName, IReadOnlyList<string> ExcludeCredentials, IReadOnlyList<int> Algorithms, int TimeoutMs);

/// <summary>Ergebnis einer Operation des Dienstes: Erfolg mit Wert oder Fehlercode mit Grund.</summary>
public sealed record FidoResult<T>(T? Value, string? Code, string? Problem)
{
    public bool Ok => Code is null;
    public static FidoResult<T> Success(T value) => new(value, null, null);
    public static FidoResult<T> Fail(string code, string problem) => new(default, code, problem);
}

/// <summary>Stand für die App und die Einstellungen.</summary>
/// <param name="Active">Aktive Schlüssel mit der eingestellten RP ID.</param>
/// <param name="OtherRpId">Aktive Schlüssel, die mit einer anderen RP ID registriert wurden (gelten nicht, VIT-0422).</param>
/// <param name="Store">Art und Stand der Ablage (lokal oder Active Directory mit letztem Abgleich).</param>
public sealed record FidoStatus(string RpId, int Active, int OtherRpId, string? StoreError, FidoStoreInfo? Store = null);

/// <summary>Protokolleintrag, den der Dienst für ein Schlüssel-Ereignis schreibt.</summary>
public sealed record FidoAuditEvent(AuditClient? Client, AuditEventType Type, string Assurance, string? Actor, string Detail, Dictionary<string, string> Data);

/// <summary>
/// Sicherheitsschlüssel im Dienst (SYSTEM): Challenges ausgeben, Anmeldungen prüfen und die Person auflösen, Schlüssel
/// registrieren und widerrufen. Entscheidungen und Ablauf hier (testbar), Windows-Teile hinter
/// <see cref="IFidoAccounts"/>, Ablage hinter <see cref="IFidoCredentialStore"/>/<see cref="IFidoGroupCache"/>.
/// Die Sitzungs-App liefert nur die Antwort des Schlüssels; Person, Gruppen, Zähler und Status kommen aus der Ablage bzw.
/// von Windows.
/// </summary>
public sealed class FidoService
{
    private sealed record Pending(int Session, string Sid, FidoPurpose Purpose, DateTimeOffset Issued);

    /// <param name="Writer">Schreibzugang zur Ablage als registrierende Person (Active Directory), sonst null; wird freigegeben.</param>
    private sealed record Registration(int Session, string Sid, AuthOutcome Registrar, FidoAccount Account, string Label, string Reason,
        string Challenge, string UserHandle, FidoGroupSnapshot? Groups, DateTimeOffset Created, IFidoStoreWriter? Writer = null);

    private readonly IFidoCredentialStore _store;
    private readonly IFidoGroupCache _groups;
    private readonly IFidoAccounts _accounts;
    private readonly Func<FidoSettings> _settings;
    private readonly Func<DateTimeOffset> _clock;
    private readonly string _machine;
    private readonly Action<FidoAuditEvent> _audit;
    private readonly Dictionary<string, Pending> _challenges = new(StringComparer.Ordinal);
    private readonly Dictionary<string, Registration> _registrations = new(StringComparer.Ordinal);
    private readonly object _gate = new();
    // Prüfen und Zähler fortschreiben nacheinander, damit zwei Anmeldungen nicht denselben Zählerstand sehen. Nur Zähler
    // lesen, vergleichen und schreiben – die Auflösung der Person (S4U, Domänencontroller) läuft außerhalb, damit ein
    // langsamer Domänencontroller nicht alle Anmeldungen aufhält (Prüfung vom 2026-10-30).
    private readonly SemaphoreSlim _verify = new(1, 1);
    // Abschluss einer Registrierung (Höchstzahl prüfen und ablegen) nacheinander
    private readonly SemaphoreSlim _register = new(1, 1);
    private readonly Dictionary<int, Queue<DateTimeOffset>> _challengeTimes = new();

    /// <summary>Höchstens so viele Challenges je Sitzung und Minute (danach VIT-0314).</summary>
    public const int MaxChallengesPerMinute = 10;

    /// <summary>
    /// So lange darf die Auflösung der Person (S4U-Anmeldung) dauern; danach gilt sie als „offline“ (Zwischenspeicher mit
    /// Altersgrenze).
    /// </summary>
    public TimeSpan ResolveTimeout { get; set; } = TimeSpan.FromSeconds(15);

    public FidoService(IFidoCredentialStore store, IFidoGroupCache groups, IFidoAccounts accounts, IRoleCheck roles,
        Func<FidoSettings> settings, Action<FidoAuditEvent> audit, Func<DateTimeOffset>? clock = null, string? machine = null)
    {
        _store = store;
        _groups = groups;
        _accounts = accounts;
        Roles = roles;
        _settings = settings;
        _audit = audit;
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
        _machine = machine ?? Environment.MachineName;
    }

    public IRoleCheck Roles { get; }

    public FidoAttempts Attempts { get; } = new();

    private string RpId => string.IsNullOrWhiteSpace(_settings().RpId) ? FidoSettings.DefaultRpId : _settings().RpId.Trim();

    // ================= Stand =================

    public async Task<FidoStatus> StatusAsync(CancellationToken ct = default)
    {
        try
        {
            var all = (await _store.ListAsync(null, ct).ConfigureAwait(false)).Where(c => c.IsActive).ToList();
            int mine = all.Count(c => c.RpId == RpId);
            return new FidoStatus(RpId, mine, all.Count - mine, null, _store.Info);
        }
        catch (FidoStoreException ex) { return new FidoStatus(RpId, 0, 0, $"{ex.Code} {ex.Message}", _store.Info); }
    }

    /// <summary>Schreiben in die Ablage braucht die Anmeldedaten der registrierenden Person (Active Directory).</summary>
    public bool RequiresWriteCredential => _store.RequiresWriteCredential;

    /// <summary>Takt des Dienstes: mit der zentralen Ablage abgleichen, wenn fällig (lokal: nichts).</summary>
    public Task SyncAsync(CancellationToken ct = default) => _store.SyncAsync(false, ct);

    public Task<IReadOnlyList<FidoCredential>> ListAsync(CancellationToken ct = default) => _store.ListAsync(null, ct);

    // ================= Anmelden =================

    /// <param name="refresh">
    /// Der Schlüssel enthielt keinen der angebotenen: vorher mit der zentralen Ablage abgleichen (begrenzt), damit ein gerade
    /// auf einem anderen Rechner registrierter Schlüssel dabei ist.
    /// </param>
    public async Task<FidoResult<FidoChallenge>> ChallengeAsync(AuditClient client, FidoPurpose purpose, CancellationToken ct = default,
        bool refresh = false)
    {
        // Begrenzt je Sitzung: Challenges sind der Einstieg für Versuche mit gefälschten Antworten
        if (!TakeChallenge(client.Session)) return FidoResult<FidoChallenge>.Fail(ErrorCodes.ServiceTooManyChecks, "too many challenges, wait a minute");
        if (Attempts.Blocked(FidoAttempts.ForSession(client.Session, client.Sid), _clock()) is { } sessionWait)
            return FidoResult<FidoChallenge>.Fail(ErrorCodes.FidoBlocked, Math.Ceiling(sessionWait.TotalMinutes).ToString(System.Globalization.CultureInfo.InvariantCulture));
        if (refresh) await _store.SyncAsync(true, ct).ConfigureAwait(false);
        IReadOnlyList<FidoCredential> all;
        try { all = await _store.ListAsync(null, ct).ConfigureAwait(false); }
        catch (FidoStoreException ex) { return FidoResult<FidoChallenge>.Fail(ex.Code, ex.Message); }
        var rp = RpId;
        var allow = all.Where(c => c.IsActive && c.RpId == rp).Select(c => c.CredentialId).ToList();
        if (allow.Count == 0) return FidoResult<FidoChallenge>.Fail(ErrorCodes.FidoNoKeys, "no active security key registered");
        var challenge = FidoProtocol.NewChallenge();
        lock (_gate)
        {
            Expire();
            // Wenige offene je Sitzung: Ein Programm in der Sitzung soll den Speicher des Dienstes nicht füllen
            var mine = _challenges.Where(p => p.Value.Session == client.Session).OrderBy(p => p.Value.Issued).ToList();
            foreach (var (k, _) in mine.Take(Math.Max(0, mine.Count - 4))) _challenges.Remove(k);
            _challenges[challenge] = new Pending(client.Session, client.Sid, purpose, _clock());
        }
        return FidoResult<FidoChallenge>.Success(new FidoChallenge(challenge, rp, allow, FidoProtocol.TimeoutMilliseconds));
    }

    /// <summary>
    /// Assertion prüfen und die Person auflösen. Erfolg: Ergebnis wie beim Windows-Kennwort (Name, SID, Gruppen,
    /// Administrator), dazu in Details method, keyId, credential, aaguid, groupsSource. Ablehnungen schreibt der Dienst
    /// selbst als FidoKeyRejected bzw. FidoCloneSuspected.
    /// </summary>
    public async Task<FidoResult<AuthOutcome>> VerifyAsync(AuditClient client, FidoPurpose purpose, FidoAssertion a, CancellationToken ct = default)
    {
        var now = _clock();
        var settings = _settings();
        var rp = RpId;
        var data = new Dictionary<string, string> { ["purpose"] = purpose.ToString().ToLowerInvariant() };

        FidoResult<AuthOutcome> Reject(string code, string problem, FidoCredential? c = null, AuditEventType type = AuditEventType.FidoKeyRejected)
        {
            data["code"] = code;
            data["problem"] = problem;
            if (c is not null) Describe(c, data);
            _audit(new FidoAuditEvent(client, type, AuditAssurance.Service, c?.PersonName, $"{code} {problem}", data));
            return FidoResult<AuthOutcome>.Fail(code, problem);
        }

        // Fehler, die jeder erzeugen kann (ohne gültige Signatur des Schlüssels), zählen nur gegen die anfragende Sitzung
        var sessionKey = FidoAttempts.ForSession(client.Session, client.Sid);
        FidoResult<AuthOutcome> SessionFailed(string code, string problem, FidoCredential? c = null)
        {
            Attempts.RecordFailure(sessionKey, now, settings.MaxFailedAttempts, settings.BlockMinutes);
            return Reject(code, problem, c);
        }
        if (Attempts.Blocked(sessionKey, now) is { } sessionWait)
        {
            var minutes = Math.Ceiling(sessionWait.TotalMinutes).ToString(System.Globalization.CultureInfo.InvariantCulture);
            return Reject(ErrorCodes.FidoBlocked, $"session blocked after failed attempts for {minutes} min") with { Problem = minutes };
        }

        // 1. Challenge: genau einmal, nur in der Sitzung und für den Zweck, für den sie ausgegeben wurde
        Pending? pending;
        lock (_gate)
        {
            Expire();
            if (!_challenges.Remove(a.Challenge ?? "", out pending)) pending = null;
        }
        if (pending is null || pending.Session != client.Session || pending.Sid != client.Sid || pending.Purpose != purpose)
            return SessionFailed(ErrorCodes.FidoChallengeInvalid, "challenge unknown, expired, already used or issued for another session or purpose");

        var id = FidoProtocol.FromBase64Url(a.CredentialId);
        var authData = FidoProtocol.FromBase64Url(a.AuthenticatorData);
        var clientData = FidoProtocol.FromBase64Url(a.ClientDataJson);
        var signature = FidoProtocol.FromBase64Url(a.Signature);
        if (id is null || authData is null || clientData is null || signature is null)
            return SessionFailed(ErrorCodes.FidoAssertionInvalid, "assertion incomplete");
        var idHash = FidoProtocol.IdHash(id);
        data["keyId"] = idHash;

        FidoCredential c;
        string keyKey, personKey;
        await _verify.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            FidoCredential? found;
            try { found = await _store.GetAsync(idHash, ct).ConfigureAwait(false); }
            catch (FidoStoreException ex) { return Reject(ex.Code, ex.Message); }
            if (found is null) return SessionFailed(ErrorCodes.FidoKeyUnknown, "key not registered");
            c = found;
            keyKey = FidoAttempts.ForCredential(c.IdHash);
            personKey = FidoAttempts.ForPerson(c.PersonSid);

            // 2. Zuerst die Signatur: Ohne gültige Signatur des Schlüssels kann jedes Programm die Antwort gebaut haben –
            // solche Fehler zählen nur gegen die anfragende Sitzung, nie gegen Schlüssel oder Person
            var check = FidoVerifier.VerifyAssertion(c, a.Challenge!, rp, authData, clientData, signature);
            if (!check.SignatureValid) return SessionFailed(check.Code!, check.Problem!, c);

            // 3. Sperre nach Fehlversuchen (Schlüssel und Person) – erst nach gültiger Signatur
            if ((Attempts.Blocked(keyKey, now) ?? Attempts.Blocked(personKey, now)) is { } wait)
            {
                data["blockedSeconds"] = ((int)Math.Ceiling(wait.TotalSeconds)).ToString(System.Globalization.CultureInfo.InvariantCulture);
                var result = Reject(ErrorCodes.FidoBlocked, $"blocked after failed attempts for {Math.Ceiling(wait.TotalMinutes)} min", c);
                return result with { Problem = Math.Ceiling(wait.TotalMinutes).ToString(System.Globalization.CultureInfo.InvariantCulture) };
            }

            FidoResult<AuthOutcome> Failed(string code, string problem, AuditEventType type = AuditEventType.FidoKeyRejected)
            {
                Attempts.RecordFailure(keyKey, now, settings.MaxFailedAttempts, settings.BlockMinutes);
                Attempts.RecordFailure(personKey, now, settings.MaxFailedAttempts, settings.BlockMinutes);
                return Reject(code, problem, c, type);
            }

            // 4. Status, Modell, Flags, Zähler (die Antwort stammt vom Schlüssel)
            if (!c.IsActive) return Failed(ErrorCodes.FidoKeyRevoked, "key revoked");
            if (!FidoProtocol.ModelAllowed(c.Aaguid, settings.AllowedModels)) return Failed(ErrorCodes.FidoModelNotAllowed, $"model {c.Aaguid} not allowed");
            if (!check.Valid)
                return Failed(check.Code!, check.Problem!, check.CloneSuspected ? AuditEventType.FidoCloneSuspected : AuditEventType.FidoKeyRejected);
            try { await _store.TouchAsync(c.IdHash, check.SignCount, now, ct).ConfigureAwait(false); }
            catch (FidoStoreException ex) { return Reject(ex.Code, "counter not stored: " + ex.Message, c); }
        }
        finally { _verify.Release(); }

        // 5. Person: Kontostatus und Gruppen (live, sonst zwischengespeichert) – außerhalb der Sperre, mit Zeitlimit
        {
            var resolution = await ResolveWithTimeoutAsync(c, ct).ConfigureAwait(false);
            FidoGroupSnapshot? cached = null;
            try { cached = await _groups.GetAsync(c.PersonSid, ct).ConfigureAwait(false); }
            catch (FidoStoreException) { }
            var decision = FidoPeople.Decide(resolution, cached, now, settings.OfflineMaxHours);
            if (!decision.Allowed) return Reject(decision.Code!, decision.Problem!, c);
            if (decision.Source != FidoGroupsSource.Cached)
            {
                try
                {
                    await _groups.SetAsync(new FidoGroupSnapshot
                    {
                        Sid = c.PersonSid, Name = resolution.Name ?? c.PersonName, Groups = [.. decision.Groups], Source = decision.Source, ResolvedAt = now,
                    }, ct).ConfigureAwait(false);
                }
                catch (FidoStoreException) { /* Zwischenspeicher ist kein Muss für diese Anmeldung */ }
            }
            Attempts.Reset(keyKey);
            Attempts.Reset(personKey);

            var name = resolution.Name ?? cached?.Name ?? c.PersonName;
            var groups = decision.Groups.ToHashSet(StringComparer.OrdinalIgnoreCase);
            var details = new Dictionary<string, string> { ["method"] = FidoProtocol.MethodId };
            Describe(c, details);
            details["groupsSource"] = decision.Source;
            if (decision.Source == FidoGroupsSource.Cached && decision.ResolvedAt is { } at)
                details["groupsResolvedAt"] = at.ToString("O", System.Globalization.CultureInfo.InvariantCulture);
            if (c.PersonUpn is { } upn) details["upn"] = upn;
            return FidoResult<AuthOutcome>.Success(new AuthOutcome
            {
                Success = true,
                UserName = name,
                DisplayName = FidoPeople.DisplayName(name),
                UserId = c.PersonSid,
                Groups = groups,
                IsAdministrator = groups.Contains(EntraLocalGroups.AdministratorsSid),
                IsSessionUser = string.Equals(c.PersonSid, client.Sid, StringComparison.OrdinalIgnoreCase),
                Details = details,
            });
        }
    }

    /// <summary>Person auflösen; dauert es länger als <see cref="ResolveTimeout"/>, gilt die Person als „offline“.</summary>
    private async Task<FidoResolution> ResolveWithTimeoutAsync(FidoCredential c, CancellationToken ct)
    {
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var resolve = _accounts.ResolveAsync(c.PersonSid, c.PersonName, c.PersonUpn, limit.Token);
        var done = await Task.WhenAny(resolve, Task.Delay(ResolveTimeout, ct)).ConfigureAwait(false);
        if (done == resolve) return await resolve.ConfigureAwait(false);
        ct.ThrowIfCancellationRequested();
        limit.Cancel();
        // Läuft im Hintergrund weiter (S4U lässt sich nicht abbrechen); das Ergebnis wird verworfen
        _ = resolve.ContinueWith(t => _ = t.Exception, TaskScheduler.Default);
        return FidoResolution.Failed(FidoAccountState.Offline, $"account resolution took longer than {ResolveTimeout.TotalSeconds:0} s");
    }

    private bool TakeChallenge(int session)
    {
        var now = _clock();
        lock (_gate)
        {
            if (!_challengeTimes.TryGetValue(session, out var q)) _challengeTimes[session] = q = new Queue<DateTimeOffset>();
            while (q.Count > 0 && now - q.Peek() > TimeSpan.FromMinutes(1)) q.Dequeue();
            if (q.Count >= MaxChallengesPerMinute) return false;
            q.Enqueue(now);
            return true;
        }
    }

    // ================= Registrieren =================

    /// <param name="registrar">Vom Dienst geprüfte Anmeldung der registrierenden Person (Ticket mit Zweck „registrar“).</param>
    /// <param name="directory">
    /// Anmeldedaten der registrierenden Person für die Ablage im AD (Token oder Kennwort); gehört ab hier dem Dienst und wird
    /// immer freigegeben. Lokale Ablage: nicht nötig.
    /// </param>
    public async Task<FidoResult<FidoRegistrationStart>> BeginRegistrationAsync(AuditClient client, AuthOutcome registrar, string? account,
        string? label, string? reason, CancellationToken ct = default, FidoWriteCredential? directory = null)
    {
        using var credential = directory;
        var settings = _settings();
        FidoResult<FidoRegistrationStart> Fail(string code, string problem, FidoAccount? person = null)
        {
            var data = new Dictionary<string, string> { ["purpose"] = "registration", ["code"] = code, ["problem"] = problem };
            if (person is not null) { data["person"] = person.Name; data["personSid"] = person.Sid; }
            if (registrar.UserId is { } rs) data["registrarSid"] = rs;
            _audit(new FidoAuditEvent(client, AuditEventType.FidoKeyRejected, AuditAssurance.Verified, registrar.UserName, $"{code} {problem}", data));
            return FidoResult<FidoRegistrationStart>.Fail(code, problem);
        }

        label = label?.Trim() ?? "";
        reason = reason?.Trim() ?? "";
        if (!Roles.IsRegistrar(registrar)) return Fail(ErrorCodes.FidoNotRegistrar, "registrar role required");
        if (label.Length == 0 || label.Length > FidoProtocol.MaxLabelLength || !FidoProtocol.ReasonValid(reason))
            return Fail(ErrorCodes.FidoReasonTooShort, "label or reason missing or too short");
        if (string.IsNullOrWhiteSpace(account)) return Fail(ErrorCodes.FidoAccountNotFound, "no account given");
        var person = _accounts.Lookup(account.Trim());
        if (person is null) return Fail(ErrorCodes.FidoAccountNotFound, $"account '{account.Trim()}' not found");
        // Eigenes Konto: über alle Kennungen der registrierenden Person (SID, bei Microsoft-Anmeldungen die aus der oid gebildete
        // SID und onprem_sid, UPN). Lässt sie sich gar nicht als SID ausdrücken, ist der Vergleich nicht sicher – abgelehnt.
        if (!settings.AllowSelfRegistration && FidoPeople.SelfRegistration(person, registrar) is { } self)
            return Fail(ErrorCodes.FidoSelfRegistration, self, person);

        IReadOnlyList<FidoCredential> existing;
        try { existing = await _store.ListAsync(null, ct).ConfigureAwait(false); }
        catch (FidoStoreException ex) { return Fail(ex.Code, ex.Message, person); }
        int active = existing.Count(c => c.IsActive && string.Equals(c.PersonSid, person.Sid, StringComparison.OrdinalIgnoreCase));
        if (settings.MaxKeysPerPerson > 0 && active >= settings.MaxKeysPerPerson)
            return Fail(ErrorCodes.FidoTooManyKeys, $"{active} active keys, at most {settings.MaxKeysPerPerson}", person);

        // Konto muss nutzbar sein; ohne Domänencontroller wird registriert, aber ohne Gruppen-Zwischenspeicher
        var resolution = await _accounts.ResolveAsync(person.Sid, person.Name, person.Upn, ct).ConfigureAwait(false);
        if (resolution.State is not (FidoAccountState.Ok or FidoAccountState.Offline))
            return Fail(ErrorCodes.FidoAccountUnusable, $"account {resolution.State.ToString().ToLowerInvariant()}", person);
        var snapshot = resolution.State == FidoAccountState.Ok
            ? new FidoGroupSnapshot { Sid = person.Sid, Name = resolution.Name ?? person.Name, Groups = [.. resolution.Groups], Source = resolution.Source, ResolvedAt = _clock() }
            : null;

        // Active Directory: jetzt als registrierende Person anmelden (Kennwort bzw. Token nur dafür) – Fehler zeigen sich vor
        // der Berührung des Schlüssels
        IFidoStoreWriter? writer = null;
        if (_store.RequiresWriteCredential)
        {
            try { writer = await _store.OpenWriterAsync(credential, registrar.UserId ?? "", ct).ConfigureAwait(false); }
            catch (FidoStoreException ex) { return Fail(ex.Code, ex.Message, person); }
        }

        var id = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        var challenge = FidoProtocol.NewChallenge();
        var handle = FidoProtocol.ToBase64Url(RandomNumberGenerator.GetBytes(16));
        lock (_gate)
        {
            Expire();
            foreach (var k in _registrations.Where(p => p.Value.Session == client.Session).Select(p => p.Key).ToList())
            {
                _registrations[k].Writer?.Dispose();
                _registrations.Remove(k);
            }
            _registrations[id] = new Registration(client.Session, client.Sid, registrar, person, label, reason, challenge, handle, snapshot, _clock(), writer);
        }
        return FidoResult<FidoRegistrationStart>.Success(new FidoRegistrationStart(id, challenge, RpId, handle, person.Upn ?? person.Name,
            FidoPeople.DisplayName(person.Name), existing.Select(c => c.CredentialId).ToList(), FidoProtocol.SupportedAlgorithms,
            FidoProtocol.TimeoutMilliseconds));
    }

    public async Task<FidoResult<FidoCredential>> CompleteRegistrationAsync(AuditClient client, string? registrationId, string? clientDataJson,
        string? attestationObject, CancellationToken ct = default)
    {
        Registration? r;
        lock (_gate)
        {
            Expire();
            if (!_registrations.Remove(registrationId ?? "", out r)) r = null;
        }
        if (r is null || r.Session != client.Session || r.Sid != client.Sid)
        {
            r?.Writer?.Dispose();
            return FidoResult<FidoCredential>.Fail(ErrorCodes.FidoRegistrationExpired, "registration unknown, expired or from another session");
        }
        using var writer = r.Writer;

        var settings = _settings();
        var rp = RpId;
        var data = new Dictionary<string, string>
        {
            ["person"] = r.Account.Name, ["personSid"] = r.Account.Sid, ["label"] = r.Label, ["reason"] = r.Reason, ["rpId"] = rp,
            ["store"] = StoreName,
        };
        if (r.Registrar.UserId is { } rs) data["registrarSid"] = rs;
        FidoResult<FidoCredential> Fail(string code, string problem)
        {
            data["purpose"] = "registration";
            data["code"] = code;
            data["problem"] = problem;
            _audit(new FidoAuditEvent(client, AuditEventType.FidoKeyRejected, AuditAssurance.Verified, r.Registrar.UserName, $"{code} {problem}", data));
            return FidoResult<FidoCredential>.Fail(code, problem);
        }

        var cd = FidoProtocol.FromBase64Url(clientDataJson);
        var ao = FidoProtocol.FromBase64Url(attestationObject);
        if (cd is null || ao is null) return Fail(ErrorCodes.FidoRegistrationInvalid, "answer of the key incomplete");
        var check = FidoRegistrationVerifier.Verify(r.Challenge, rp, cd, ao);
        if (!check.Valid) return Fail(check.Code!, check.Problem!);
        var att = check.Attestation!;
        var cred = att.AuthData.Credential!;
        var aaguid = cred.Aaguid.ToString("D");
        data["aaguid"] = aaguid;
        data["keyId"] = FidoProtocol.IdHash(cred.CredentialId);
        data["attestation"] = att.Format;
        if (!FidoProtocol.ModelAllowed(aaguid, settings.AllowedModels)) return Fail(ErrorCodes.FidoModelNotAllowed, $"model {aaguid} not allowed");

        var credential = new FidoCredential
        {
            CredentialId = FidoProtocol.ToBase64Url(cred.CredentialId),
            IdHash = FidoProtocol.IdHash(cred.CredentialId),
            RpId = rp,
            PublicKey = FidoProtocol.ToBase64Url(cred.PublicKey),
            Algorithm = check.Key!.Algorithm,
            Aaguid = aaguid,
            AttestationFormat = att.Format,
            AttestationVerified = check.AttestationResult?.Verified == true,
            AttestationCertificate = check.AttestationResult?.Certificate,
            UserHandle = r.UserHandle,
            PersonSid = r.Account.Sid,
            PersonName = r.Account.Name,
            PersonUpn = r.Account.Upn,
            Label = r.Label,
            Reason = r.Reason,
            RegisteredAt = _clock(),
            RegisteredBySid = r.Registrar.UserId ?? "",
            RegisteredByName = r.Registrar.UserName ?? "",
            RegisteredOn = _machine,
            SignCount = att.AuthData.SignCount,
        };
        // Höchstzahl erneut prüfen und ablegen in einem Schritt: Zwei Registrierungen gleichzeitig dürfen nicht beide die
        // Prüfung bestehen (Prüfung vom 2026-10-30)
        await _register.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var active = (await _store.ListAsync(r.Account.Sid, ct).ConfigureAwait(false)).Count(c => c.IsActive);
            if (settings.MaxKeysPerPerson > 0 && active >= settings.MaxKeysPerPerson)
                return Fail(ErrorCodes.FidoTooManyKeys, $"{active} active keys, at most {settings.MaxKeysPerPerson}");
            if (await _store.GetAsync(credential.IdHash, ct).ConfigureAwait(false) is not null)
                return Fail(ErrorCodes.FidoKeyAlreadyRegistered, "key already registered");
            await _store.AddAsync(credential, writer, ct).ConfigureAwait(false);
            if (r.Groups is { } g) await _groups.SetAsync(g, ct).ConfigureAwait(false);
        }
        catch (FidoStoreException ex) { return Fail(ex.Code, ex.Message); }
        finally { _register.Release(); }

        data["attestationVerified"] = credential.AttestationVerified ? "true" : "false";
        if (credential.AttestationCertificate is { } certText) data["attestationCertificate"] = certText;
        if (check.AttestationResult?.Problem is { } p) data["attestationNote"] = p;
        _audit(new FidoAuditEvent(client, AuditEventType.FidoKeyRegistered, AuditAssurance.Verified, r.Registrar.UserName,
            $"Security key '{r.Label}' registered for {r.Account.Name}: {r.Reason}", data));
        return FidoResult<FidoCredential>.Success(credential);
    }

    // ================= Widerrufen =================

    /// <param name="directory">Wie bei <see cref="BeginRegistrationAsync"/>: für das AD, wird immer freigegeben.</param>
    public async Task<FidoResult<FidoCredential>> RevokeAsync(AuditClient client, AuthOutcome registrar, string? idHash, string? reason,
        CancellationToken ct = default, FidoWriteCredential? directory = null)
    {
        using var credential = directory;
        reason = reason?.Trim() ?? "";
        if (!Roles.IsRegistrar(registrar)) return FidoResult<FidoCredential>.Fail(ErrorCodes.FidoNotRegistrar, "registrar role required");
        if (!FidoProtocol.ReasonValid(reason)) return FidoResult<FidoCredential>.Fail(ErrorCodes.FidoReasonTooShort, "reason missing or too short");
        try
        {
            var c = await _store.GetAsync(idHash ?? "", ct).ConfigureAwait(false);
            if (c is null) return FidoResult<FidoCredential>.Fail(ErrorCodes.FidoKeyUnknown, "key not registered");
            if (!c.IsActive) return FidoResult<FidoCredential>.Fail(ErrorCodes.FidoKeyRevoked, "key already revoked");
            var revocation = new FidoRevocation(_clock(), registrar.UserId ?? "", registrar.UserName ?? "", reason);
            using var writer = _store.RequiresWriteCredential
                ? await _store.OpenWriterAsync(credential, registrar.UserId ?? "", ct).ConfigureAwait(false)
                : null;
            if (!await _store.RevokeAsync(c.IdHash, revocation, writer, ct).ConfigureAwait(false))
                return FidoResult<FidoCredential>.Fail(ErrorCodes.FidoKeyRevoked, "key already revoked");
            var data = new Dictionary<string, string> { ["reason"] = reason, ["store"] = StoreName };
            Describe(c, data);
            data["person"] = c.PersonName;
            data["personSid"] = c.PersonSid;
            if (registrar.UserId is { } rs) data["registrarSid"] = rs;
            _audit(new FidoAuditEvent(client, AuditEventType.FidoKeyRevoked, AuditAssurance.Verified, registrar.UserName,
                $"Security key '{c.Label}' of {c.PersonName} revoked: {reason}", data));
            c.Status = FidoCredentialStatus.Revoked;
            c.RevokedAt = revocation.At;
            c.RevokedBySid = revocation.BySid;
            c.RevokedByName = revocation.ByName;
            c.RevokeReason = reason;
            return FidoResult<FidoCredential>.Success(c);
        }
        catch (FidoStoreException ex) { return FidoResult<FidoCredential>.Fail(ex.Code, ex.Message); }
    }

    // ================= Hilfen =================

    /// <summary>Angaben zum Schlüssel fürs Protokoll (ohne öffentlichen Schlüssel).</summary>
    private static void Describe(FidoCredential c, Dictionary<string, string> data)
    {
        data["keyId"] = c.IdHash;
        data["credential"] = c.Label;
        data["aaguid"] = c.Aaguid;
    }

    /// <summary>Kennung der Ablage im Protokoll: „local“ oder „activeDirectory“.</summary>
    private string StoreName => _store.Info.Kind == FidoStoreKind.ActiveDirectory ? "activeDirectory" : "local";

    private void Expire()
    {
        var now = _clock();
        foreach (var k in _challenges.Where(p => now - p.Value.Issued > FidoProtocol.ChallengeLifetime).Select(p => p.Key).ToList()) _challenges.Remove(k);
        foreach (var k in _registrations.Where(p => now - p.Value.Created > FidoProtocol.RegistrationLifetime).Select(p => p.Key).ToList())
        {
            // Verbindung zum AD (als registrierende Person) nicht länger offen halten als die Registrierung gilt
            _registrations[k].Writer?.Dispose();
            _registrations.Remove(k);
        }
    }
}
