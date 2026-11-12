// SPDX-License-Identifier: MIT
using System.Runtime.InteropServices;
using Vitrine.Core.Fido;

namespace Vitrine.Services.Auth;

/// <summary>Antwort des Schlüssels auf GetAssertion (rohe Bytes).</summary>
public sealed record WebAuthnAssertion(byte[] CredentialId, byte[] AuthenticatorData, byte[] Signature);

/// <summary>Antwort des Schlüssels auf MakeCredential: Attestierungsobjekt (CBOR).</summary>
public sealed record WebAuthnAttestation(byte[] AttestationObject);

/// <summary>Ergebnis eines Aufrufs: Wert oder HRESULT mit Namen.</summary>
public sealed record WebAuthnResult<T>(T? Value, int HResult, string? ErrorName) where T : class
{
    public bool Ok => Value is not null;
}

/// <summary>
/// Windows-WebAuthn-API (webauthn.dll, Windows 10 1903 und neuer). Windows zeigt den Sicherheitsdialog (PIN, Berührung) und
/// spricht über USB oder NFC mit dem Schlüssel – Vitrine spricht nie selbst CTAP. Das clientDataJSON baut Vitrine
/// (<see cref="FidoProtocol.ClientDataJson"/>); Windows bildet nur dessen SHA-256.
/// </summary>
public static class WebAuthnApi
{
    /// <summary>Version der API, 0 wenn es sie nicht gibt.</summary>
    public static int ApiVersion
    {
        get
        {
            try
            {
                if (!NativeLibrary.TryLoad("webauthn.dll", typeof(WebAuthnApi).Assembly, DllImportSearchPath.System32, out var lib)) return 0;
                try
                {
                    // WebAuthNGetApiVersionNumber gibt es ab Version 1 (Windows 10 1903)
                    return NativeLibrary.TryGetExport(lib, "WebAuthNGetApiVersionNumber", out _) ? (int)WebAuthNGetApiVersionNumber() : 0;
                }
                finally { NativeLibrary.Free(lib); }
            }
            catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException) { return 0; }
        }
    }

    public static bool Available => ApiVersion >= 1;

    /// <summary>Anmelden: Assertion für eine der <paramref name="allowCredentials"/> mit Benutzerüberprüfung (PIN).</summary>
    /// <param name="ct">Abbruch (Zeitlimit des Entsperr-Dialogs): bricht den Windows-Sicherheitsdialog ab.</param>
    public static WebAuthnResult<WebAuthnAssertion> GetAssertion(nint owner, string rpId, byte[] clientDataJson,
        IReadOnlyList<byte[]> allowCredentials, int timeoutMs, CancellationToken ct)
    {
        using var mem = new Pinned();
        var creds = new WEBAUTHN_CREDENTIAL[allowCredentials.Count];
        for (int i = 0; i < creds.Length; i++)
            creds[i] = new WEBAUTHN_CREDENTIAL
            {
                dwVersion = 1, cbId = (uint)allowCredentials[i].Length, pbId = mem.Pin(allowCredentials[i]), pwszCredentialType = mem.Str("public-key"),
            };
        var cancel = Guid.Empty;
        bool hasCancel = WebAuthNGetCancellationId(out cancel) == 0;
        var options = new WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS
        {
            dwVersion = 3,
            dwTimeoutMilliseconds = (uint)timeoutMs,
            CredentialList = new WEBAUTHN_CREDENTIALS { cCredentials = (uint)creds.Length, pCredentials = mem.PinArray(creds) },
            dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM,
            dwUserVerificationRequirement = WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
            pCancellationId = hasCancel ? mem.PinStruct(cancel) : 0,
        };
        var client = ClientData(mem, clientDataJson);
        using var reg = hasCancel ? ct.Register(() => WebAuthNCancelCurrentOperation(ref cancel)) : default;
        int hr = WebAuthNAuthenticatorGetAssertion(owner, rpId, ref client, ref options, out var result);
        if (hr != 0 || result == 0) return new WebAuthnResult<WebAuthnAssertion>(null, hr, ErrorName(hr));
        try
        {
            var a = Marshal.PtrToStructure<WEBAUTHN_ASSERTION>(result);
            return new WebAuthnResult<WebAuthnAssertion>(new WebAuthnAssertion(Copy(a.Credential.pbId, a.Credential.cbId),
                Copy(a.pbAuthenticatorData, a.cbAuthenticatorData), Copy(a.pbSignature, a.cbSignature)), 0, null);
        }
        finally { WebAuthNFreeAssertion(result); }
    }

    /// <summary>Registrieren: neues Credential mit Benutzerüberprüfung, ohne „resident key“, Attestierung „direct“.</summary>
    public static WebAuthnResult<WebAuthnAttestation> MakeCredential(nint owner, string rpId, byte[] userId, string userName,
        string displayName, byte[] clientDataJson, IReadOnlyList<int> algorithms, IReadOnlyList<byte[]> exclude, int timeoutMs, CancellationToken ct)
    {
        using var mem = new Pinned();
        var rp = new WEBAUTHN_RP_ENTITY_INFORMATION { dwVersion = 1, pwszId = mem.Str(rpId), pwszName = mem.Str("Vitrine") };
        var user = new WEBAUTHN_USER_ENTITY_INFORMATION
        {
            dwVersion = 1, cbId = (uint)userId.Length, pbId = mem.Pin(userId), pwszName = mem.Str(userName), pwszDisplayName = mem.Str(displayName),
        };
        var algs = algorithms.Select(a => new WEBAUTHN_COSE_CREDENTIAL_PARAMETER { dwVersion = 1, pwszCredentialType = mem.Str("public-key"), lAlg = a }).ToArray();
        var parameters = new WEBAUTHN_COSE_CREDENTIAL_PARAMETERS { cCredentialParameters = (uint)algs.Length, pCredentialParameters = mem.PinArray(algs) };
        var creds = exclude.Select(e => new WEBAUTHN_CREDENTIAL
        {
            dwVersion = 1, cbId = (uint)e.Length, pbId = mem.Pin(e), pwszCredentialType = mem.Str("public-key"),
        }).ToArray();
        var cancel = Guid.Empty;
        bool hasCancel = WebAuthNGetCancellationId(out cancel) == 0;
        var options = new WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS
        {
            dwVersion = 2,
            dwTimeoutMilliseconds = (uint)timeoutMs,
            CredentialList = new WEBAUTHN_CREDENTIALS { cCredentials = (uint)creds.Length, pCredentials = creds.Length == 0 ? 0 : mem.PinArray(creds) },
            dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM,
            bRequireResidentKey = 0,
            dwUserVerificationRequirement = WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
            dwAttestationConveyancePreference = WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT,
            pCancellationId = hasCancel ? mem.PinStruct(cancel) : 0,
        };
        var client = ClientData(mem, clientDataJson);
        using var reg = hasCancel ? ct.Register(() => WebAuthNCancelCurrentOperation(ref cancel)) : default;
        int hr = WebAuthNAuthenticatorMakeCredential(owner, ref rp, ref user, ref parameters, ref client, ref options, out var result);
        if (hr != 0 || result == 0) return new WebAuthnResult<WebAuthnAttestation>(null, hr, ErrorName(hr));
        try
        {
            var a = Marshal.PtrToStructure<WEBAUTHN_CREDENTIAL_ATTESTATION>(result);
            return new WebAuthnResult<WebAuthnAttestation>(new WebAuthnAttestation(Copy(a.pbAttestationObject, a.cbAttestationObject)), 0, null);
        }
        finally { WebAuthNFreeCredentialAttestation(result); }
    }

    private static WEBAUTHN_CLIENT_DATA ClientData(Pinned mem, byte[] json) => new()
    {
        dwVersion = 1, cbClientDataJSON = (uint)json.Length, pbClientDataJSON = mem.Pin(json), pwszHashAlgId = mem.Str("SHA-256"),
    };

    private static string ErrorName(int hr)
    {
        try
        {
            var p = WebAuthNGetErrorName(hr);
            var name = p == 0 ? null : Marshal.PtrToStringUni(p);
            return $"{name ?? "error"} (0x{hr:X8})";
        }
        catch (EntryPointNotFoundException) { return $"0x{hr:X8}"; }
    }

    private static byte[] Copy(nint p, uint length)
    {
        if (p == 0 || length == 0) return [];
        var b = new byte[length];
        Marshal.Copy(p, b, 0, (int)length);
        return b;
    }

    /// <summary>Festgehaltener Speicher für die Dauer eines Aufrufs.</summary>
    private sealed class Pinned : IDisposable
    {
        private readonly List<GCHandle> _handles = new();
        private readonly List<nint> _strings = new();

        public nint Pin(byte[] data)
        {
            var h = GCHandle.Alloc(data, GCHandleType.Pinned);
            _handles.Add(h);
            return h.AddrOfPinnedObject();
        }

        public nint PinArray<T>(T[] items) where T : struct
        {
            if (items.Length == 0) return 0;
            int size = Marshal.SizeOf<T>();
            var p = Marshal.AllocHGlobal(size * items.Length);
            _strings.Add(p);
            for (int i = 0; i < items.Length; i++) Marshal.StructureToPtr(items[i], p + i * size, false);
            return p;
        }

        public nint PinStruct<T>(T item) where T : struct => PinArray([item]);

        public nint Str(string s)
        {
            var p = Marshal.StringToHGlobalUni(s);
            _strings.Add(p);
            return p;
        }

        public void Dispose()
        {
            foreach (var h in _handles) h.Free();
            foreach (var p in _strings) Marshal.FreeHGlobal(p);
        }
    }

    // ---------- Interop (webauthn.h) ----------

    private const uint WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM = 2;
    private const uint WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED = 1;
    private const uint WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT = 3;

    [StructLayout(LayoutKind.Sequential)]
    private struct WEBAUTHN_RP_ENTITY_INFORMATION
    {
        public uint dwVersion;
        public nint pwszId;
        public nint pwszName;
        public nint pwszIcon;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WEBAUTHN_USER_ENTITY_INFORMATION
    {
        public uint dwVersion;
        public uint cbId;
        public nint pbId;
        public nint pwszName;
        public nint pwszIcon;
        public nint pwszDisplayName;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WEBAUTHN_COSE_CREDENTIAL_PARAMETER
    {
        public uint dwVersion;
        public nint pwszCredentialType;
        public int lAlg;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WEBAUTHN_COSE_CREDENTIAL_PARAMETERS
    {
        public uint cCredentialParameters;
        public nint pCredentialParameters;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WEBAUTHN_CLIENT_DATA
    {
        public uint dwVersion;
        public uint cbClientDataJSON;
        public nint pbClientDataJSON;
        public nint pwszHashAlgId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WEBAUTHN_CREDENTIAL
    {
        public uint dwVersion;
        public uint cbId;
        public nint pbId;
        public nint pwszCredentialType;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WEBAUTHN_CREDENTIALS
    {
        public uint cCredentials;
        public nint pCredentials;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WEBAUTHN_EXTENSIONS
    {
        public uint cExtensions;
        public nint pExtensions;
    }

    /// <summary>Version 2: bis pCancellationId.</summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS
    {
        public uint dwVersion;
        public uint dwTimeoutMilliseconds;
        public WEBAUTHN_CREDENTIALS CredentialList;
        public WEBAUTHN_EXTENSIONS Extensions;
        public uint dwAuthenticatorAttachment;
        public int bRequireResidentKey;
        public uint dwUserVerificationRequirement;
        public uint dwAttestationConveyancePreference;
        public uint dwFlags;
        public nint pCancellationId;
    }

    /// <summary>Version 3: bis pCancellationId.</summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS
    {
        public uint dwVersion;
        public uint dwTimeoutMilliseconds;
        public WEBAUTHN_CREDENTIALS CredentialList;
        public WEBAUTHN_EXTENSIONS Extensions;
        public uint dwAuthenticatorAttachment;
        public uint dwUserVerificationRequirement;
        public uint dwFlags;
        public nint pwszU2fAppId;
        public nint pbU2fAppId;
        public nint pCancellationId;
    }

    /// <summary>Version 1 der Felder (spätere Versionen hängen nur an).</summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct WEBAUTHN_CREDENTIAL_ATTESTATION
    {
        public uint dwVersion;
        public nint pwszFormatType;
        public uint cbAuthenticatorData;
        public nint pbAuthenticatorData;
        public uint cbAttestation;
        public nint pbAttestation;
        public uint dwAttestationDecodeType;
        public nint pvAttestationDecode;
        public uint cbAttestationObject;
        public nint pbAttestationObject;
        public uint cbCredentialId;
        public nint pbCredentialId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WEBAUTHN_ASSERTION
    {
        public uint dwVersion;
        public uint cbAuthenticatorData;
        public nint pbAuthenticatorData;
        public uint cbSignature;
        public nint pbSignature;
        public WEBAUTHN_CREDENTIAL Credential;
        public uint cbUserId;
        public nint pbUserId;
    }

    [DllImport("webauthn.dll")]
    private static extern uint WebAuthNGetApiVersionNumber();

    [DllImport("webauthn.dll", CharSet = CharSet.Unicode)]
    private static extern int WebAuthNAuthenticatorGetAssertion(nint hWnd, string pwszRpId, ref WEBAUTHN_CLIENT_DATA clientData,
        ref WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS options, out nint assertion);

    [DllImport("webauthn.dll")]
    private static extern int WebAuthNAuthenticatorMakeCredential(nint hWnd, ref WEBAUTHN_RP_ENTITY_INFORMATION rp,
        ref WEBAUTHN_USER_ENTITY_INFORMATION user, ref WEBAUTHN_COSE_CREDENTIAL_PARAMETERS parameters, ref WEBAUTHN_CLIENT_DATA clientData,
        ref WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS options, out nint attestation);

    [DllImport("webauthn.dll")]
    private static extern void WebAuthNFreeAssertion(nint assertion);

    [DllImport("webauthn.dll")]
    private static extern void WebAuthNFreeCredentialAttestation(nint attestation);

    [DllImport("webauthn.dll")]
    private static extern int WebAuthNGetCancellationId(out Guid cancellationId);

    [DllImport("webauthn.dll")]
    private static extern int WebAuthNCancelCurrentOperation(ref Guid cancellationId);

    [DllImport("webauthn.dll")]
    private static extern nint WebAuthNGetErrorName(int hr);
}
