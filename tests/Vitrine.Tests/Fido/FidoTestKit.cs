// SPDX-License-Identifier: MIT
using System.Buffers.Binary;
using System.Formats.Cbor;
using System.Security.Cryptography;
using Vitrine.Core.Fido;

namespace Vitrine.Tests.Fido;

/// <summary>
/// Nachgebauter Sicherheitsschlüssel für Tests: ES256-Schlüssel mit ECDsa, Authenticator-Daten, Attestierung und
/// Assertion wie ein echter Schlüssel sie liefert. Keine echten WebAuthn-Aufrufe.
/// </summary>
internal sealed class TestAuthenticator : IDisposable
{
    public static readonly Guid DefaultAaguid = Guid.Parse("cb69481e-8ff7-4039-93ec-0a2729a154a8");

    public ECDsa Key { get; } = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    public byte[] CredentialId { get; } = RandomNumberGenerator.GetBytes(48);
    public Guid Aaguid { get; init; } = DefaultAaguid;
    public uint Counter { get; set; }

    public string CredentialIdB64 => FidoProtocol.ToBase64Url(CredentialId);

    public byte[] CoseKey()
    {
        var p = Key.ExportParameters(false);
        var w = new CborWriter(CborConformanceMode.Lax);
        w.WriteStartMap(5);
        w.WriteInt32(1); w.WriteInt32(2);
        w.WriteInt32(3); w.WriteInt32(-7);
        w.WriteInt32(-1); w.WriteInt32(1);
        w.WriteInt32(-2); w.WriteByteString(p.Q.X!);
        w.WriteInt32(-3); w.WriteByteString(p.Q.Y!);
        w.WriteEndMap();
        return w.Encode();
    }

    public static byte[] AuthData(string rpId, byte flags, uint counter, byte[]? attested = null)
    {
        var count = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(count, counter);
        return [.. FidoProtocol.RpIdHash(rpId), flags, .. count, .. attested ?? []];
    }

    public byte[] Attested()
    {
        var len = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(len, (ushort)CredentialId.Length);
        var aaguid = new byte[16];
        Aaguid.TryWriteBytes(aaguid, bigEndian: true, out _);
        return [.. aaguid, .. len, .. CredentialId, .. CoseKey()];
    }

    public byte[] Sign(byte[] authData, byte[] clientData) =>
        Key.SignData([.. authData, .. SHA256.HashData(clientData)], HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

    /// <summary>Antwort auf MakeCredential: (clientDataJSON, attestationObject), Format „packed“ (Selbst-Attestierung) oder „none“.</summary>
    public (byte[] ClientData, byte[] Attestation) Register(string rpId, string challenge, string fmt = "packed",
        byte flags = 0x45, string? origin = null, bool corruptSignature = false)
    {
        var clientData = origin is null
            ? FidoProtocol.ClientDataJson(FidoProtocol.TypeCreate, challenge, rpId)
            : System.Text.Encoding.UTF8.GetBytes($"{{\"type\":\"webauthn.create\",\"challenge\":\"{challenge}\",\"origin\":\"{origin}\"}}");
        var authData = AuthData(rpId, flags, Counter, Attested());
        var w = new CborWriter(CborConformanceMode.Lax);
        w.WriteStartMap(3);
        w.WriteTextString("fmt"); w.WriteTextString(fmt);
        w.WriteTextString("attStmt");
        if (fmt == "packed")
        {
            var sig = Sign(authData, clientData);
            if (corruptSignature) sig[^1] ^= 0x55;
            w.WriteStartMap(2);
            w.WriteTextString("alg"); w.WriteInt32(-7);
            w.WriteTextString("sig"); w.WriteByteString(sig);
            w.WriteEndMap();
        }
        else
        {
            w.WriteStartMap(0);
            w.WriteEndMap();
        }
        w.WriteTextString("authData"); w.WriteByteString(authData);
        w.WriteEndMap();
        return (clientData, w.Encode());
    }

    /// <summary>Antwort auf GetAssertion. Zähler wird vorher erhöht (außer <paramref name="counter"/> ist gesetzt).</summary>
    public FidoAssertion Assert(string rpId, string challenge, byte flags = 0x05, uint? counter = null, string type = FidoProtocol.TypeGet,
        string? authRpId = null, Func<byte[], byte[]>? tamperSignature = null, string? clientChallenge = null)
    {
        var c = counter ?? ++Counter;
        var clientData = FidoProtocol.ClientDataJson(type, clientChallenge ?? challenge, rpId);
        var authData = AuthData(authRpId ?? rpId, flags, c);
        var sig = Sign(authData, clientData);
        if (tamperSignature is not null) sig = tamperSignature(sig);
        return new FidoAssertion(challenge, CredentialIdB64, FidoProtocol.ToBase64Url(authData), FidoProtocol.ToBase64Url(clientData),
            FidoProtocol.ToBase64Url(sig));
    }

    public void Dispose() => Key.Dispose();
}

/// <summary>Datei der Ablage im Speicher.</summary>
internal sealed class MemoryStoreFile : IFidoStoreFile
{
    public string? Content;
    public int Writes;
    public bool Unprotected;

    public string? Read() => Unprotected
        ? throw new FidoStoreException(Vitrine.Core.Localization.ErrorCodes.FidoStoreNotProtected, "not protected")
        : Content;

    public void Write(string json)
    {
        Content = json;
        Writes++;
    }
}

/// <summary>Konten ohne Windows: feste Liste, Zustand je SID einstellbar.</summary>
internal sealed class FakeAccounts : IFidoAccounts
{
    public readonly Dictionary<string, FidoAccount> ByName = new(StringComparer.OrdinalIgnoreCase);
    public readonly Dictionary<string, FidoResolution> State = new(StringComparer.OrdinalIgnoreCase);
    public int Resolves;

    public void Add(string name, string sid, string? upn, params string[] groups)
    {
        ByName[name] = new FidoAccount(sid, name, upn);
        State[sid] = new FidoResolution(FidoAccountState.Ok, name, groups, FidoGroupsSource.Live);
    }

    public FidoAccount? Lookup(string input) => ByName.GetValueOrDefault(input) ?? ByName.Values.FirstOrDefault(a => a.Sid == input);

    /// <summary>Auflösung, die erst endet, wenn der Test sie freigibt (langsamer Domänencontroller).</summary>
    public readonly Dictionary<string, TaskCompletionSource<FidoResolution>> Hanging = new(StringComparer.OrdinalIgnoreCase);

    public Task<FidoResolution> ResolveAsync(string sid, string name, string? upn, CancellationToken ct = default)
    {
        Interlocked.Increment(ref Resolves);
        if (Hanging.TryGetValue(sid, out var hanging)) return hanging.Task;
        return Task.FromResult(State.GetValueOrDefault(sid) ?? FidoResolution.Failed(FidoAccountState.NotFound, "unknown"));
    }
}
