// SPDX-License-Identifier: MIT
using System.Text.Json;
using Vitrine.Core.Config;
using Vitrine.Core.Localization;

namespace Vitrine.Core.Fido;

/// <summary>Signaturzähler und letzte Nutzung eines Schlüssels auf diesem Rechner.</summary>
public sealed record FidoCounter(uint SignCount, DateTimeOffset? LastUsedAt);

/// <summary>
/// Signaturzähler je Rechner, wenn die Schlüssel im AD liegen (Rechner dürfen dort nicht schreiben). Windows:
/// HKLM\SOFTWARE\ICT-Baden\Vitrine\FidoCounters, nur SYSTEM; Tests: Speicher.
/// </summary>
public interface IFidoCounterStore
{
    FidoCounter? Get(string idHash);
    void Set(string idHash, FidoCounter counter);
}

/// <summary>Zwischenspeicher der Schlüssel aus dem AD (Datei fido-directory-cache.json, schreibt nur der Dienst).</summary>
public sealed class FidoDirectoryCache
{
    public int Version { get; set; } = 1;
    /// <summary>DN des Containers, aus dem gelesen wurde.</summary>
    public string? Location { get; set; }
    /// <summary>Letzter erfolgreicher vollständiger Abgleich (UTC).</summary>
    public DateTimeOffset? LastSync { get; set; }
    /// <summary>Schlüssel wie im AD, ohne Zähler.</summary>
    public List<FidoCredential> Credentials { get; set; } = new();
    /// <summary>Gruppen je Person (wie in der lokalen Datei; immer nur auf diesem Rechner).</summary>
    public List<FidoGroupSnapshot> People { get; set; } = new();
}

/// <summary>
/// Ablage im Active Directory (<c>Fido.Store = ActiveDirectory</c>): Ein Schlüssel, einmal registriert, gilt auf allen
/// Rechnern der Domäne. Der Dienst liest als Computerkonto und hält alle Schlüssel in einem lokalen Zwischenspeicher
/// (vollständiger Abgleich alle <c>Fido.SyncMinutes</c>, mit dem Dienst-Takt über <see cref="SyncAsync"/>). Ohne AD gilt der
/// Zwischenspeicher. Ist das AD erreichbar, liest er den vorgelegten Schlüssel bei jeder Anmeldung frisch (Widerruf wirkt
/// sofort); einen unbekannten Schlüssel sucht er gezielt (begrenzt). Geschrieben (Registrieren, Widerrufen) wird nur mit
/// den Anmeldedaten der registrierenden Person (<see cref="OpenWriterAsync"/>). Den Signaturzähler hält jeder Rechner
/// selbst (<see cref="IFidoCounterStore"/>) – die Erkennung kopierter Schlüssel gilt daher je Rechner.
/// </summary>
public sealed class FidoDirectoryStore : IFidoCredentialStore, IFidoGroupCache
{
    /// <summary>Nach einem gescheiterten Abgleich frühestens so spät wieder versuchen.</summary>
    public static readonly TimeSpan RetryInterval = TimeSpan.FromMinutes(1);

    /// <summary>Erzwungener Abgleich (Anmeldung mit einem Schlüssel, der in der Liste fehlte) höchstens so oft.</summary>
    public static readonly TimeSpan ForcedSyncInterval = TimeSpan.FromSeconds(30);

    /// <summary>Gezielte Suche nach derselben unbekannten Kennung höchstens einmal je Zeitraum …</summary>
    public static readonly TimeSpan LookupInterval = TimeSpan.FromMinutes(1);

    /// <summary>… und insgesamt höchstens so viele Suchen nach unbekannten Kennungen je <see cref="LookupWindow"/>.</summary>
    public const int MaxLookups = 20;
    public static readonly TimeSpan LookupWindow = TimeSpan.FromMinutes(10);

    private readonly IFidoDirectory _directory;
    private readonly IFidoStoreFile _file;
    private readonly IFidoCounterStore _counters;
    private readonly Func<FidoSettings> _settings;
    private readonly Func<DateTimeOffset> _clock;
    private readonly Action<string> _log;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly SemaphoreSlim _sync = new(1, 1);
    private readonly Dictionary<string, DateTimeOffset> _lookups = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _reported = new(StringComparer.Ordinal);
    private FidoDirectoryCache? _cache;
    private DateTimeOffset? _lastAttempt;
    private string? _lastError;

    /// <param name="log">Meldungen fürs Protokoll (englisch, mit Code): AD nicht erreichbar, ungültige Objekte, Zwischenspeicher.</param>
    public FidoDirectoryStore(IFidoDirectory directory, IFidoStoreFile cacheFile, IFidoCounterStore counters, Func<FidoSettings> settings,
        Func<DateTimeOffset>? clock = null, Action<string>? log = null)
    {
        _directory = directory;
        _file = cacheFile;
        _counters = counters;
        _settings = settings;
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
        _log = log ?? (_ => { });
    }

    public bool RequiresWriteCredential => true;

    /// <summary>Gilt das AD als erreichbar (letzter Zugriff gelang)?</summary>
    public bool Online => _lastError is null && _cache?.LastSync is not null;

    public FidoStoreInfo Info
    {
        get
        {
            var cache = _cache;
            var error = _lastError ?? (cache?.LastSync is null ? $"{ErrorCodes.FidoDirectoryNeverSynced} never synchronized with Active Directory" : null);
            return new FidoStoreInfo(FidoStoreKind.ActiveDirectory, cache?.LastSync, error, _directory.Location ?? cache?.Location);
        }
    }

    private TimeSpan SyncPeriod => TimeSpan.FromMinutes(Math.Clamp(_settings().SyncMinutes, 1, 1440));

    // ================= Abgleich =================

    /// <summary>
    /// Vollständiger Abgleich, wenn der Zwischenspeicher älter als <c>Fido.SyncMinutes</c> ist (nach Fehlern frühestens nach
    /// <see cref="RetryInterval"/>); <paramref name="force"/>: auch wenn frisch, höchstens alle <see cref="ForcedSyncInterval"/>.
    /// Fehler des AD werden festgehalten (<see cref="Info"/>), nicht geworfen.
    /// </summary>
    public async Task SyncAsync(bool force, CancellationToken ct = default)
    {
        await _sync.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await Ensure(ct).ConfigureAwait(false);
            var now = _clock();
            var since = _lastAttempt is { } a ? now - a : TimeSpan.MaxValue;
            if (force)
            {
                if (since < ForcedSyncInterval) return;
            }
            else
            {
                bool fresh = _cache!.LastSync is { } last && now - last < SyncPeriod && _lastError is null;
                if (fresh || (_lastError is not null && since < RetryInterval)) return;
            }
            _lastAttempt = now;

            IReadOnlyList<FidoDirectoryEntry> entries;
            try { entries = await _directory.ReadAllAsync(ct).ConfigureAwait(false); }
            catch (FidoStoreException ex)
            {
                Failed(ex);
                return;
            }

            var valid = new Dictionary<string, FidoCredential>(StringComparer.OrdinalIgnoreCase);
            foreach (var e in entries)
            {
                var d = FidoDirectoryCodec.Decode(e);
                if (d.Credential is { } c) valid.TryAdd(c.IdHash, c);
                else Report(e.Cn, d.Problem!);
            }
            await _gate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                _cache!.Credentials = [.. valid.Values.OrderBy(c => c.RegisteredAt)];
                _cache.LastSync = now;
                _cache.Location = _directory.Location ?? _cache.Location;
                Save();
            }
            finally { _gate.Release(); }
            if (_lastError is not null) _log($"Security keys: Active Directory reachable again, {valid.Count} keys synchronized");
            _lastError = null;
        }
        finally { _sync.Release(); }
    }

    private void Failed(FidoStoreException ex)
    {
        var text = $"{ex.Code} {ex.Message}";
        // Nur beim Wechsel ins Protokoll, nicht bei jedem Versuch
        if (_lastError is null || !_lastError.StartsWith(ex.Code, StringComparison.Ordinal))
            _log($"{ex.Code} Active Directory not usable ({ex.Message}); using the cache of {_cache?.LastSync?.ToString("O", System.Globalization.CultureInfo.InvariantCulture) ?? "never"}");
        _lastError = text;
    }

    private void Report(string cn, string problem)
    {
        if (_reported.Add(cn + "|" + problem)) _log($"{ErrorCodes.FidoDirectoryEntryInvalid} directory object {cn} ignored: {problem}");
    }

    // ================= Lesen =================

    public async Task<FidoCredential?> GetAsync(string idHash, CancellationToken ct = default)
    {
        await FirstSync(ct).ConfigureAwait(false);
        FidoCredential? cached;
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try { cached = Find(idHash); }
        finally { _gate.Release(); }

        // Bekannter Schlüssel bei erreichbarem AD: frisch lesen (Widerruf auf einem anderen Rechner gilt sofort).
        // Unbekannter: gezielt suchen, aber begrenzt – ein Programm in der Sitzung soll das AD nicht im Takt abfragen.
        bool live = cached is not null ? Online : LookupAllowed(idHash);
        if (!live) return cached is null ? null : WithCounter(cached);

        FidoDirectoryEntry? entry;
        try { entry = await _directory.ReadAsync(idHash.ToLowerInvariant(), ct).ConfigureAwait(false); }
        catch (FidoStoreException ex)
        {
            Failed(ex);
            return cached is null ? null : WithCounter(cached);
        }

        FidoCredential? fresh = null;
        if (entry is not null)
        {
            var d = FidoDirectoryCodec.Decode(entry);
            if (d.Credential is { } c && string.Equals(c.IdHash, idHash, StringComparison.OrdinalIgnoreCase)) fresh = c;
            else Report(entry.Cn, d.Problem ?? "cn does not match");
        }
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            // Gelöscht oder ungültig im AD: auch hier nicht mehr benutzen
            bool changed = fresh is null ? cached is not null
                : cached is null || JsonSerializer.Serialize(cached, JsonFidoStore.Json) != JsonSerializer.Serialize(fresh, JsonFidoStore.Json);
            if (changed)
            {
                _cache!.Credentials.RemoveAll(c => string.Equals(c.IdHash, idHash, StringComparison.OrdinalIgnoreCase));
                if (fresh is not null) _cache.Credentials.Add(fresh);
                Save();
            }
        }
        finally { _gate.Release(); }
        return fresh is null ? null : WithCounter(fresh);
    }

    public async Task<IReadOnlyList<FidoCredential>> ListAsync(string? personSid = null, CancellationToken ct = default)
    {
        await FirstSync(ct).ConfigureAwait(false);
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            return _cache!.Credentials
                .Where(c => personSid is null || string.Equals(c.PersonSid, personSid, StringComparison.OrdinalIgnoreCase))
                .Select(WithCounter).ToList();
        }
        finally { _gate.Release(); }
    }

    /// <summary>Noch nie abgeglichen: jetzt (nach Fehlern höchstens alle <see cref="RetryInterval"/>).</summary>
    private async Task FirstSync(CancellationToken ct)
    {
        await Ensure(ct).ConfigureAwait(false);
        if (_cache!.LastSync is null) await SyncAsync(false, ct).ConfigureAwait(false);
    }

    private bool LookupAllowed(string idHash)
    {
        var now = _clock();
        lock (_lookups)
        {
            foreach (var k in _lookups.Where(p => now - p.Value > LookupWindow).Select(p => p.Key).ToList()) _lookups.Remove(k);
            if (_lookups.TryGetValue(idHash, out var last) && now - last < LookupInterval) return false;
            if (_lookups.Count >= MaxLookups) return false;
            _lookups[idHash] = now;
            return true;
        }
    }

    // ================= Schreiben (als registrierende Person) =================

    public async Task<IFidoStoreWriter?> OpenWriterAsync(FidoWriteCredential? credential, string registrarSid, CancellationToken ct = default)
    {
        if (credential is null)
            throw new FidoStoreException(ErrorCodes.FidoDirectoryCredentialRequired, "writing to Active Directory needs the registrar's Windows password");
        var writer = await _directory.OpenWriterAsync(credential, ct).ConfigureAwait(false);
        if (!string.Equals(writer.BoundSid, registrarSid, StringComparison.OrdinalIgnoreCase))
        {
            writer.Dispose();
            throw new FidoStoreException(ErrorCodes.FidoDirectoryIdentityMismatch,
                $"signed in to Active Directory as {writer.BoundSid}, but the registrar is {registrarSid}");
        }
        return writer;
    }

    private static IFidoDirectoryWriter Writer(IFidoStoreWriter? writer) => writer as IFidoDirectoryWriter
        ?? throw new FidoStoreException(ErrorCodes.FidoDirectoryCredentialRequired, "no directory connection of the registrar");

    public async Task AddAsync(FidoCredential credential, IFidoStoreWriter? writer = null, CancellationToken ct = default)
    {
        var w = Writer(writer);
        var entry = FidoDirectoryCodec.Encode(credential);
        if (await w.ReadAsync(entry.Cn, ct).ConfigureAwait(false) is not null)
            throw new FidoStoreException(ErrorCodes.FidoKeyAlreadyRegistered, "credential already registered");
        await w.CreateAsync(entry, ct).ConfigureAwait(false);
        SetCounter(credential.IdHash, new FidoCounter(credential.SignCount, null));
        await Upsert(Strip(credential), ct).ConfigureAwait(false);
    }

    public async Task<bool> RevokeAsync(string idHash, FidoRevocation revocation, IFidoStoreWriter? writer = null, CancellationToken ct = default)
    {
        var w = Writer(writer);
        // Stand im AD maßgeblich (nicht der Zwischenspeicher)
        var entry = await w.ReadAsync(idHash.ToLowerInvariant(), ct).ConfigureAwait(false);
        if (entry is null) return false;
        var d = FidoDirectoryCodec.Decode(entry);
        if (d.Credential is not { IsActive: true } c) return false;
        c.Status = FidoCredentialStatus.Revoked;
        c.RevokedAt = revocation.At;
        c.RevokedBySid = revocation.BySid;
        c.RevokedByName = revocation.ByName;
        c.RevokeReason = revocation.Reason;
        await w.ReplaceAsync(FidoDirectoryCodec.Encode(c), ct).ConfigureAwait(false);
        await Upsert(c, ct).ConfigureAwait(false);
        return true;
    }

    /// <summary>Nur der Zähler dieses Rechners (das AD schreibt der Dienst nicht).</summary>
    public async Task<bool> TouchAsync(string idHash, uint signCount, DateTimeOffset usedAt, CancellationToken ct = default)
    {
        await Ensure(ct).ConfigureAwait(false);
        SetCounter(idHash, new FidoCounter(signCount, usedAt));
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try { return Find(idHash) is not null; }
        finally { _gate.Release(); }
    }

    private void SetCounter(string idHash, FidoCounter counter)
    {
        try { _counters.Set(idHash.ToLowerInvariant(), counter); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException or InvalidOperationException)
        {
            throw new FidoStoreException(ErrorCodes.FidoStoreError, "counter not stored: " + ex.Message, ex);
        }
    }

    private async Task Upsert(FidoCredential c, CancellationToken ct)
    {
        await Ensure(ct).ConfigureAwait(false);
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            _cache!.Credentials.RemoveAll(x => string.Equals(x.IdHash, c.IdHash, StringComparison.OrdinalIgnoreCase));
            _cache.Credentials.Add(c);
            Save();
        }
        finally { _gate.Release(); }
    }

    // ================= Gruppen =================

    async Task<FidoGroupSnapshot?> IFidoGroupCache.GetAsync(string sid, CancellationToken ct)
    {
        await Ensure(ct).ConfigureAwait(false);
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try { return _cache!.People.FirstOrDefault(p => string.Equals(p.Sid, sid, StringComparison.OrdinalIgnoreCase)); }
        finally { _gate.Release(); }
    }

    public async Task SetAsync(FidoGroupSnapshot snapshot, CancellationToken ct = default)
    {
        await Ensure(ct).ConfigureAwait(false);
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            _cache!.People.RemoveAll(p => string.Equals(p.Sid, snapshot.Sid, StringComparison.OrdinalIgnoreCase));
            _cache.People.Add(snapshot);
            Save();
        }
        finally { _gate.Release(); }
    }

    // ================= Zwischenspeicher =================

    private FidoCredential? Find(string idHash) =>
        _cache!.Credentials.FirstOrDefault(c => string.Equals(c.IdHash, idHash, StringComparison.OrdinalIgnoreCase));

    /// <summary>Kopie mit dem Zähler dieses Rechners (Aufrufer dürfen sie ändern, ohne den Zwischenspeicher zu ändern).</summary>
    private FidoCredential WithCounter(FidoCredential c)
    {
        var copy = Strip(c);
        FidoCounter? counter = null;
        try { counter = _counters.Get(c.IdHash.ToLowerInvariant()); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException or InvalidOperationException) { }
        copy.SignCount = counter?.SignCount ?? 0;
        copy.LastUsedAt = counter?.LastUsedAt;
        return copy;
    }

    /// <summary>Kopie ohne Zähler und letzte Nutzung (so steht ein Schlüssel im AD und im Zwischenspeicher).</summary>
    private static FidoCredential Strip(FidoCredential c)
    {
        var copy = JsonSerializer.Deserialize<FidoCredential>(JsonSerializer.Serialize(c, JsonFidoStore.Json), JsonFidoStore.Json)!;
        copy.SignCount = 0;
        copy.LastUsedAt = null;
        return copy;
    }

    private async Task Ensure(CancellationToken ct)
    {
        if (_cache is not null) return;
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try { _cache ??= Load(); }
        finally { _gate.Release(); }
    }

    /// <summary>
    /// Zwischenspeicher lesen. Unlesbar oder ungeschützt: leer beginnen und beim nächsten Abgleich neu schreiben – er ist nur
    /// eine Kopie des AD (anders als die lokale Datei, die nie überschrieben wird).
    /// </summary>
    private FidoDirectoryCache Load()
    {
        try
        {
            var text = _file.Read();
            if (string.IsNullOrWhiteSpace(text)) return new FidoDirectoryCache();
            var cache = JsonSerializer.Deserialize<FidoDirectoryCache>(text, JsonFidoStore.Json) ?? new FidoDirectoryCache();
            // Zähler gehören nicht in den Zwischenspeicher
            foreach (var c in cache.Credentials) { c.SignCount = 0; c.LastUsedAt = null; }
            return cache;
        }
        catch (Exception ex) when (ex is FidoStoreException or JsonException or IOException or UnauthorizedAccessException or InvalidDataException)
        {
            var code = ex is FidoStoreException f ? f.Code : ErrorCodes.FidoStoreError;
            _log($"{code} security key cache ignored, it is rebuilt from Active Directory: {ex.Message}");
            return new FidoDirectoryCache();
        }
    }

    private void Save()
    {
        try { _file.Write(JsonSerializer.Serialize(_cache, JsonFidoStore.Json)); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or System.Security.SecurityException)
        {
            // Nur eine Kopie: Der Stand im Speicher gilt weiter, beim nächsten Abgleich erneut schreiben
            _log($"{ErrorCodes.FidoStoreError} security key cache not written: {ex.Message}");
        }
    }
}
