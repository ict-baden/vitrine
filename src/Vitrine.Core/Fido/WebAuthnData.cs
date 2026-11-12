// SPDX-License-Identifier: MIT
using System.Buffers.Binary;
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace Vitrine.Core.Fido;

/// <summary>Credential-Daten aus den Authenticator-Daten einer Registrierung (attestedCredentialData).</summary>
public sealed record AttestedCredential(Guid Aaguid, byte[] CredentialId, byte[] PublicKey);

/// <summary>
/// Authenticator-Daten (WebAuthn Level 2, Abschnitt 6.1): SHA-256 der RP ID, Flags, Zähler, bei der Registrierung die
/// Credential-Daten, danach optional Erweiterungen (CBOR). Wirft <see cref="FormatException"/> bei kaputten Daten.
/// </summary>
public sealed record AuthenticatorData(byte[] RpIdHash, byte Flags, uint SignCount, AttestedCredential? Credential)
{
    public const byte FlagUserPresent = 0x01;
    public const byte FlagUserVerified = 0x04;
    public const byte FlagAttestedCredential = 0x40;
    public const byte FlagExtensions = 0x80;

    public bool UserPresent => (Flags & FlagUserPresent) != 0;
    public bool UserVerified => (Flags & FlagUserVerified) != 0;

    public static AuthenticatorData Parse(byte[] data)
    {
        if (data.Length < 37) throw new FormatException("authenticator data too short");
        var rpIdHash = data[..32];
        var flags = data[32];
        var count = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(33, 4));
        int pos = 37;
        AttestedCredential? credential = null;
        if ((flags & FlagAttestedCredential) != 0)
        {
            if (data.Length < pos + 18) throw new FormatException("attested credential data too short");
            var aaguid = new Guid(data.AsSpan(pos, 16), bigEndian: true);
            pos += 16;
            int idLength = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(pos, 2));
            pos += 2;
            if (idLength == 0 || idLength > 1023 || data.Length < pos + idLength) throw new FormatException("credential ID length invalid");
            var id = data[pos..(pos + idLength)];
            pos += idLength;
            int keyLength = CborItemLength(data, pos);
            var key = data[pos..(pos + keyLength)];
            pos += keyLength;
            credential = new AttestedCredential(aaguid, id, key);
        }
        if ((flags & FlagExtensions) != 0) pos += CborItemLength(data, pos);
        if (pos != data.Length) throw new FormatException("unexpected bytes after authenticator data");
        return new AuthenticatorData(rpIdHash, flags, count, credential);
    }

    /// <summary>Länge des CBOR-Elements ab <paramref name="offset"/>.</summary>
    private static int CborItemLength(byte[] data, int offset)
    {
        if (offset >= data.Length) throw new FormatException("CBOR item missing");
        try
        {
            var reader = new CborReader(data.AsMemory(offset), CborConformanceMode.Lax, allowMultipleRootLevelValues: true);
            reader.SkipValue();
            return data.Length - offset - reader.BytesRemaining;
        }
        catch (CborContentException ex) { throw new FormatException("CBOR: " + ex.Message, ex); }
        catch (InvalidOperationException ex) { throw new FormatException("CBOR: " + ex.Message, ex); }
    }
}

/// <summary>
/// Öffentlicher Schlüssel im COSE-Format (RFC 9052/9053), wie ihn ein Sicherheitsschlüssel bei der Registrierung liefert.
/// Unterstützt: ES256 (EC2, P-256) und RS256 (RSA, mindestens 2048 Bit).
/// </summary>
public sealed class CoseKey
{
    public int KeyType { get; }
    public int Algorithm { get; }
    private readonly ECParameters? _ec;
    private readonly RSAParameters? _rsa;

    private CoseKey(int kty, int alg, ECParameters? ec, RSAParameters? rsa)
    {
        KeyType = kty;
        Algorithm = alg;
        _ec = ec;
        _rsa = rsa;
    }

    /// <summary>Liest den Schlüssel. <see cref="FormatException"/> bei kaputten Daten, <see cref="NotSupportedException"/> bei anderen Algorithmen.</summary>
    public static CoseKey Parse(byte[] cose)
    {
        var ints = new Dictionary<long, long>();
        var bytes = new Dictionary<long, byte[]>();
        try
        {
            var r = new CborReader(cose, CborConformanceMode.Lax);
            int? count = r.ReadStartMap();
            while (r.PeekState() != CborReaderState.EndMap)
            {
                if (r.PeekState() is not (CborReaderState.UnsignedInteger or CborReaderState.NegativeInteger))
                {
                    r.SkipValue(); // Textschlüssel: nicht Teil von COSE_Key für WebAuthn
                    r.SkipValue();
                    continue;
                }
                long label = r.ReadInt64();
                switch (r.PeekState())
                {
                    case CborReaderState.UnsignedInteger or CborReaderState.NegativeInteger: ints[label] = r.ReadInt64(); break;
                    case CborReaderState.ByteString: bytes[label] = r.ReadByteString(); break;
                    default: r.SkipValue(); break;
                }
            }
            r.ReadEndMap();
            if (r.BytesRemaining != 0) throw new FormatException("unexpected bytes after COSE key");
            _ = count;
        }
        catch (CborContentException ex) { throw new FormatException("COSE key: " + ex.Message, ex); }
        catch (InvalidOperationException ex) { throw new FormatException("COSE key: " + ex.Message, ex); }
        catch (OverflowException ex) { throw new FormatException("COSE key: " + ex.Message, ex); }

        if (!ints.TryGetValue(1, out var kty)) throw new FormatException("COSE key without kty");
        if (!ints.TryGetValue(3, out var alg)) throw new FormatException("COSE key without alg");
        switch (kty)
        {
            case 2 when alg == FidoProtocol.AlgEs256:
            {
                // crv 1 = P-256, x (-2) und y (-3) je 32 Bytes
                if (!ints.TryGetValue(-1, out var crv) || crv != 1) throw new NotSupportedException("EC2 curve not supported");
                if (!bytes.TryGetValue(-2, out var x) || !bytes.TryGetValue(-3, out var y) || x.Length != 32 || y.Length != 32)
                    throw new FormatException("EC2 key coordinates invalid");
                // Selbst prüfen statt sich auf die Plattform zu verlassen (CNG und OpenSSL prüfen unterschiedlich streng)
                if (!OnP256(x, y)) throw new FormatException("EC2 point is not on P-256");
                var p = new ECParameters { Curve = ECCurve.NamedCurves.nistP256, Q = new ECPoint { X = x, Y = y } };
                return new CoseKey(2, FidoProtocol.AlgEs256, p, null);
            }
            case 3 when alg == FidoProtocol.AlgRs256:
            {
                if (!bytes.TryGetValue(-1, out var n) || !bytes.TryGetValue(-2, out var e) || e.Length == 0)
                    throw new FormatException("RSA key invalid");
                if (n.SkipWhile(b => b == 0).Count() * 8 < 2048) throw new NotSupportedException("RSA key shorter than 2048 bits");
                // Nur e = 65537: Mit e = 1 wäre jede „Signatur“ gleich der Nachricht (fälschbar), kleine e sind unüblich
                if (!e.SkipWhile(b => b == 0).SequenceEqual(new byte[] { 0x01, 0x00, 0x01 }))
                    throw new NotSupportedException("RSA public exponent must be 65537");
                return new CoseKey(3, FidoProtocol.AlgRs256, null, new RSAParameters { Modulus = n, Exponent = e });
            }
            default:
                throw new NotSupportedException($"COSE algorithm {alg} (kty {kty}) not supported");
        }
    }

    private static readonly System.Numerics.BigInteger P256Prime = Big("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
    private static readonly System.Numerics.BigInteger P256B = Big("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b");

    private static System.Numerics.BigInteger Big(string hex) => new(Convert.FromHexString(hex), isUnsigned: true, isBigEndian: true);

    /// <summary>Liegt (x, y) auf P-256 (y² = x³ − 3x + b mod p, Koordinaten kleiner als p)?</summary>
    internal static bool OnP256(byte[] x, byte[] y)
    {
        var p = P256Prime;
        var bx = new System.Numerics.BigInteger(x, isUnsigned: true, isBigEndian: true);
        var by = new System.Numerics.BigInteger(y, isUnsigned: true, isBigEndian: true);
        if (bx >= p || by >= p) return false;
        var left = System.Numerics.BigInteger.ModPow(by, 2, p);
        var right = ((System.Numerics.BigInteger.ModPow(bx, 3, p) - 3 * bx + P256B) % p + p) % p;
        return left == right;
    }

    /// <summary>Signatur über <paramref name="data"/> prüfen (ES256: DER-kodiert, wie WebAuthn sie liefert).</summary>
    public bool Verify(byte[] data, byte[] signature)
    {
        try
        {
            if (_ec is { } ec)
            {
                using var key = ECDsa.Create(ec);
                return key.VerifyData(data, signature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
            }
            if (_rsa is { } rsa)
            {
                using var key = RSA.Create(rsa);
                return key.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
        }
        catch (CryptographicException) { }
        return false;
    }
}

/// <summary>clientDataJSON, wie der Dienst es prüft.</summary>
public sealed record ClientData(string Type, string Challenge, string Origin, bool CrossOrigin)
{
    /// <summary>Liest das JSON; <see cref="FormatException"/>, wenn Felder fehlen oder es kein Objekt ist.</summary>
    public static ClientData Parse(byte[] json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object) throw new FormatException("clientDataJSON is not an object");
            string Text(string name) => root.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString()! : throw new FormatException($"clientDataJSON without {name}");
            bool cross = root.TryGetProperty("crossOrigin", out var c) && c.ValueKind == JsonValueKind.True;
            return new ClientData(Text("type"), Text("challenge"), Text("origin"), cross);
        }
        catch (JsonException ex) { throw new FormatException("clientDataJSON: " + ex.Message, ex); }
    }

    /// <summary>Problem (englisch, fürs Protokoll) oder null, wenn alles passt.</summary>
    public string? Problem(string expectedType, string expectedChallenge, string rpId)
    {
        if (Type != expectedType) return $"clientData type '{Type}', expected '{expectedType}'";
        if (!string.Equals(Challenge, expectedChallenge, StringComparison.Ordinal)) return "challenge does not match";
        if (Origin != FidoProtocol.Origin(rpId)) return $"origin '{Origin}' not accepted";
        if (CrossOrigin) return "crossOrigin is true";
        return null;
    }
}

/// <summary>Attestierungsobjekt einer Registrierung (fmt, attStmt, authData).</summary>
public sealed record AttestationObject(string Format, byte[] AuthDataRaw, AuthenticatorData AuthData, long? StatementAlgorithm,
    byte[]? StatementSignature, IReadOnlyList<byte[]> Certificates)
{
    public static AttestationObject Parse(byte[] cbor)
    {
        string? fmt = null;
        byte[]? authData = null;
        long? alg = null;
        byte[]? sig = null;
        var x5c = new List<byte[]>();
        try
        {
            var r = new CborReader(cbor, CborConformanceMode.Lax);
            r.ReadStartMap();
            while (r.PeekState() != CborReaderState.EndMap)
            {
                if (r.PeekState() != CborReaderState.TextString) { r.SkipValue(); r.SkipValue(); continue; }
                switch (r.ReadTextString())
                {
                    case "fmt": fmt = r.ReadTextString(); break;
                    case "authData": authData = r.ReadByteString(); break;
                    case "attStmt":
                        r.ReadStartMap();
                        while (r.PeekState() != CborReaderState.EndMap)
                        {
                            if (r.PeekState() != CborReaderState.TextString) { r.SkipValue(); r.SkipValue(); continue; }
                            switch (r.ReadTextString())
                            {
                                case "alg" when r.PeekState() is CborReaderState.NegativeInteger or CborReaderState.UnsignedInteger: alg = r.ReadInt64(); break;
                                case "sig" when r.PeekState() == CborReaderState.ByteString: sig = r.ReadByteString(); break;
                                case "x5c" when r.PeekState() == CborReaderState.StartArray:
                                    r.ReadStartArray();
                                    while (r.PeekState() != CborReaderState.EndArray)
                                    {
                                        if (r.PeekState() == CborReaderState.ByteString) x5c.Add(r.ReadByteString());
                                        else r.SkipValue();
                                    }
                                    r.ReadEndArray();
                                    break;
                                default: r.SkipValue(); break;
                            }
                        }
                        r.ReadEndMap();
                        break;
                    default: r.SkipValue(); break;
                }
            }
            r.ReadEndMap();
        }
        catch (CborContentException ex) { throw new FormatException("attestation object: " + ex.Message, ex); }
        catch (InvalidOperationException ex) { throw new FormatException("attestation object: " + ex.Message, ex); }
        catch (OverflowException ex) { throw new FormatException("attestation object: " + ex.Message, ex); }
        if (fmt is null || authData is null) throw new FormatException("attestation object without fmt or authData");
        return new AttestationObject(fmt, authData, AuthenticatorData.Parse(authData), alg, sig, x5c);
    }
}

/// <summary>Was die Prüfung der Attestierung ergab (nur festgehalten; die Zertifikatskette wird nicht geprüft).</summary>
/// <param name="Verified">Signatur der Attestierung passt (Format „packed“, mit Zertifikat oder Selbst-Attestierung).</param>
/// <param name="Certificate">Zertifikat der Attestierung: „Subject; SHA-256 &lt;hex&gt;“, sonst null.</param>
/// <param name="Problem">Warum nicht geprüft bzw. nicht bestanden (englisch), sonst null.</param>
public sealed record AttestationResult(bool Verified, string? Certificate, string? Problem);

/// <summary>
/// Prüfung der Attestierung beim Registrieren. Nur das Format „packed“ wird geprüft (Signatur über authData und den Hash
/// des clientDataJSON, mit dem Zertifikat aus x5c bzw. dem neuen Schlüssel selbst; AAGUID-Erweiterung des Zertifikats
/// muss zur AAGUID passen). Andere Formate (none, fido-u2f, tpm …) werden nur festgehalten. Die Kette bis zu einer Wurzel
/// des Herstellers prüft Vitrine nicht – die AAGUID ist deshalb eine Angabe des Schlüssels, keine bestätigte.
/// </summary>
public static class AttestationCheck
{
    /// <summary>OID der FIDO-Erweiterung mit der AAGUID im Attestierungszertifikat.</summary>
    public const string AaguidExtensionOid = "1.3.6.1.4.1.45724.1.1.4";

    public static AttestationResult Evaluate(AttestationObject att, byte[] clientDataHash, CoseKey credentialKey)
    {
        if (att.Format != "packed") return new AttestationResult(false, CertificateText(att), $"format '{att.Format}' recorded, not verified");
        if (att.StatementSignature is not { } sig || att.StatementAlgorithm is not { } alg)
            return new AttestationResult(false, null, "packed statement without alg or sig");
        var signed = att.AuthDataRaw.Concat(clientDataHash).ToArray();
        if (att.Certificates.Count == 0)
        {
            // Selbst-Attestierung: mit dem neuen Schlüssel, gleicher Algorithmus
            if (alg != credentialKey.Algorithm) return new AttestationResult(false, null, "self attestation with another algorithm");
            return credentialKey.Verify(signed, sig)
                ? new AttestationResult(true, null, null)
                : new AttestationResult(false, null, "self attestation signature invalid");
        }
        try
        {
            using var cert = X509CertificateLoader.LoadCertificate(att.Certificates[0]);
            var text = Describe(cert);
            bool ok = alg switch
            {
                FidoProtocol.AlgEs256 => cert.GetECDsaPublicKey() is { } ec && Using(ec, k => k.VerifyData(signed, sig, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence)),
                FidoProtocol.AlgRs256 => cert.GetRSAPublicKey() is { } rsa && Using(rsa, k => k.VerifyData(signed, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)),
                _ => false,
            };
            if (!ok) return new AttestationResult(false, text, $"attestation signature invalid or algorithm {alg} not supported");
            // AAGUID im Zertifikat (falls vorhanden) muss zur AAGUID der Authenticator-Daten passen
            if (cert.Extensions[AaguidExtensionOid] is { } ext && att.AuthData.Credential is { } c)
            {
                var raw = ext.RawData;
                if (raw.Length != 18 || raw[0] != 0x04 || raw[1] != 0x10 || new Guid(raw.AsSpan(2, 16), bigEndian: true) != c.Aaguid)
                    return new AttestationResult(false, text, "AAGUID in the attestation certificate does not match");
            }
            return new AttestationResult(true, text, null);
        }
        catch (CryptographicException ex) { return new AttestationResult(false, null, "attestation certificate unreadable: " + ex.Message); }
    }

    private static bool Using<T>(T key, Func<T, bool> f) where T : IDisposable
    {
        using (key) return f(key);
    }

    private static string? CertificateText(AttestationObject att)
    {
        if (att.Certificates.Count == 0) return null;
        try
        {
            using var cert = X509CertificateLoader.LoadCertificate(att.Certificates[0]);
            return Describe(cert);
        }
        catch (CryptographicException) { return null; }
    }

    private static string Describe(X509Certificate2 cert) =>
        $"{cert.Subject}; SHA-256 {Convert.ToHexString(SHA256.HashData(cert.RawData)).ToLowerInvariant()}";
}
