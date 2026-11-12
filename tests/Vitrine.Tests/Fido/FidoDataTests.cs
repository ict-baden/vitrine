// SPDX-License-Identifier: MIT
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Text;
using Vitrine.Core.Config;
using Vitrine.Core.Fido;
using Vitrine.Core.Localization;
using Vitrine.Core.Lock;

namespace Vitrine.Tests.Fido;

/// <summary>CBOR/COSE, Authenticator-Daten, clientDataJSON, Ablage und kleine Hilfen des Verfahrens „fido“.</summary>
public sealed class FidoDataTests
{
    [Fact]
    public void ES256_Schluessel_lesen_und_Signatur_pruefen()
    {
        using var key = new TestAuthenticator();
        var cose = CoseKey.Parse(key.CoseKey());
        Assert.Equal(FidoProtocol.AlgEs256, cose.Algorithm);
        var data = Encoding.UTF8.GetBytes("data");
        var sig = key.Key.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        Assert.True(cose.Verify(data, sig));
        Assert.False(cose.Verify(Encoding.UTF8.GetBytes("other"), sig));
        Assert.False(cose.Verify(data, [1, 2, 3]));
    }

    [Fact]
    public void RS256_Schluessel_lesen_und_Signatur_pruefen()
    {
        using var rsa = RSA.Create(2048);
        var p = rsa.ExportParameters(false);
        var w = new CborWriter(CborConformanceMode.Lax);
        w.WriteStartMap(4);
        w.WriteInt32(1); w.WriteInt32(3);
        w.WriteInt32(3); w.WriteInt32(-257);
        w.WriteInt32(-1); w.WriteByteString(p.Modulus!);
        w.WriteInt32(-2); w.WriteByteString(p.Exponent!);
        w.WriteEndMap();
        var cose = CoseKey.Parse(w.Encode());
        var data = Encoding.UTF8.GetBytes("data");
        Assert.True(cose.Verify(data, rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)));
    }

    [Fact]
    public void EdDSA_und_kurze_RSA_Schluessel_werden_nicht_unterstuetzt()
    {
        var w = new CborWriter(CborConformanceMode.Lax);
        w.WriteStartMap(4);
        w.WriteInt32(1); w.WriteInt32(1);   // OKP
        w.WriteInt32(3); w.WriteInt32(-8);  // EdDSA
        w.WriteInt32(-1); w.WriteInt32(6);  // Ed25519
        w.WriteInt32(-2); w.WriteByteString(new byte[32]);
        w.WriteEndMap();
        Assert.Throws<NotSupportedException>(() => CoseKey.Parse(w.Encode()));

        using var rsa = RSA.Create(1024);
        var p = rsa.ExportParameters(false);
        w = new CborWriter(CborConformanceMode.Lax);
        w.WriteStartMap(4);
        w.WriteInt32(1); w.WriteInt32(3);
        w.WriteInt32(3); w.WriteInt32(-257);
        w.WriteInt32(-1); w.WriteByteString(p.Modulus!);
        w.WriteInt32(-2); w.WriteByteString(p.Exponent!);
        w.WriteEndMap();
        Assert.Throws<NotSupportedException>(() => CoseKey.Parse(w.Encode()));
    }

    [Fact]
    public void Kaputte_COSE_Schluessel_werden_abgelehnt()
    {
        Assert.Throws<FormatException>(() => CoseKey.Parse([0xFF, 0x00]));
        Assert.Throws<FormatException>(() => CoseKey.Parse([0xA0])); // leere Map: ohne kty
        // Punkt nicht auf der Kurve
        var w = new CborWriter(CborConformanceMode.Lax);
        w.WriteStartMap(5);
        w.WriteInt32(1); w.WriteInt32(2);
        w.WriteInt32(3); w.WriteInt32(-7);
        w.WriteInt32(-1); w.WriteInt32(1);
        w.WriteInt32(-2); w.WriteByteString(new byte[32]);
        w.WriteInt32(-3); w.WriteByteString(Enumerable.Repeat((byte)1, 32).ToArray());
        w.WriteEndMap();
        Assert.Throws<FormatException>(() => CoseKey.Parse(w.Encode()));
    }

    [Fact]
    public void Authenticator_Daten_mit_Credential_lesen()
    {
        using var key = new TestAuthenticator { Counter = 7 };
        var raw = TestAuthenticator.AuthData("vitrine", 0x45, 7, key.Attested());
        var a = AuthenticatorData.Parse(raw);
        Assert.True(a.UserPresent);
        Assert.True(a.UserVerified);
        Assert.Equal(7u, a.SignCount);
        Assert.Equal(TestAuthenticator.DefaultAaguid, a.Credential!.Aaguid);
        Assert.Equal(key.CredentialId, a.Credential.CredentialId);
        Assert.Equal(key.CoseKey(), a.Credential.PublicKey);
        Assert.Equal(FidoProtocol.RpIdHash("vitrine"), a.RpIdHash);
    }

    [Fact]
    public void Authenticator_Daten_zu_kurz_oder_mit_Resten_werden_abgelehnt()
    {
        Assert.Throws<FormatException>(() => AuthenticatorData.Parse(new byte[36]));
        var raw = TestAuthenticator.AuthData("vitrine", 0x05, 1);
        Assert.Throws<FormatException>(() => AuthenticatorData.Parse([.. raw, 0x00]));
        // AT-Flag ohne Daten
        Assert.Throws<FormatException>(() => AuthenticatorData.Parse(TestAuthenticator.AuthData("vitrine", 0x45, 1)));
        // Erweiterungen (ED) als CBOR-Map werden übersprungen
        var ext = new CborWriter();
        ext.WriteStartMap(1);
        ext.WriteTextString("credProtect");
        ext.WriteInt32(2);
        ext.WriteEndMap();
        Assert.Equal(1u, AuthenticatorData.Parse([.. TestAuthenticator.AuthData("vitrine", 0x85, 1), .. ext.Encode()]).SignCount);
    }

    [Fact]
    public void ClientData_wird_wie_vom_Browser_gebaut_und_geprueft()
    {
        var json = FidoProtocol.ClientDataJson(FidoProtocol.TypeGet, "abc", "vitrine");
        Assert.Equal("""{"type":"webauthn.get","challenge":"abc","origin":"vitrine://vitrine","crossOrigin":false}""", Encoding.UTF8.GetString(json));
        var cd = ClientData.Parse(json);
        Assert.Null(cd.Problem(FidoProtocol.TypeGet, "abc", "vitrine"));
        Assert.NotNull(cd.Problem(FidoProtocol.TypeCreate, "abc", "vitrine"));
        Assert.NotNull(cd.Problem(FidoProtocol.TypeGet, "abd", "vitrine"));
        Assert.NotNull(cd.Problem(FidoProtocol.TypeGet, "abc", "other"));
        // Ein Browser auf https://vitrine erzeugt nie diesen Origin
        var web = ClientData.Parse("""{"type":"webauthn.get","challenge":"abc","origin":"https://vitrine"}"""u8.ToArray());
        Assert.NotNull(web.Problem(FidoProtocol.TypeGet, "abc", "vitrine"));
        var cross = ClientData.Parse("""{"type":"webauthn.get","challenge":"abc","origin":"vitrine://vitrine","crossOrigin":true}"""u8.ToArray());
        Assert.NotNull(cross.Problem(FidoProtocol.TypeGet, "abc", "vitrine"));
        Assert.Throws<FormatException>(() => ClientData.Parse("[]"u8.ToArray()));
        Assert.Throws<FormatException>(() => ClientData.Parse("{\"type\":1}"u8.ToArray()));
    }

    [Fact]
    public void Attestierungsobjekt_lesen()
    {
        using var key = new TestAuthenticator();
        var (cd, att) = key.Register("vitrine", "abc");
        var a = AttestationObject.Parse(att);
        Assert.Equal("packed", a.Format);
        Assert.Equal(-7, a.StatementAlgorithm);
        Assert.NotNull(a.StatementSignature);
        Assert.Empty(a.Certificates);
        var result = AttestationCheck.Evaluate(a, SHA256.HashData(cd), CoseKey.Parse(key.CoseKey()));
        Assert.True(result.Verified);
        Assert.Throws<FormatException>(() => AttestationObject.Parse([0xA0]));
    }

    [Fact]
    public void Base64url_Kennung_Modelle_und_Teilung()
    {
        Assert.Equal([0xFB, 0xFF], FidoProtocol.FromBase64Url("-_8"));
        Assert.Equal([0xFB, 0xFF], FidoProtocol.FromBase64Url("+/8="));
        Assert.Null(FidoProtocol.FromBase64Url("!!"));
        Assert.Null(FidoProtocol.FromBase64Url(null));
        Assert.Equal(64, FidoProtocol.IdHash([1, 2, 3]).Length);
        Assert.True(FidoProtocol.ModelAllowed("cb69481e-8ff7-4039-93ec-0a2729a154a8", []));
        Assert.True(FidoProtocol.ModelAllowed("cb69481e-8ff7-4039-93ec-0a2729a154a8", ["{CB69481E-8FF7-4039-93EC-0A2729A154A8}"]));
        Assert.False(FidoProtocol.ModelAllowed("00000000-0000-0000-0000-000000000000", ["cb69481e-8ff7-4039-93ec-0a2729a154a8"]));
        Assert.False(FidoProtocol.ModelAllowed(null, ["cb69481e-8ff7-4039-93ec-0a2729a154a8"]));
        var chunks = FidoProtocol.Chunk(Enumerable.Range(0, 35).ToList());
        Assert.Equal([16, 16, 3], chunks.Select(c => c.Count));
        Assert.Equal(34, chunks[2][2]);
        Assert.False(FidoProtocol.ReasonValid("  short   "));
        Assert.True(FidoProtocol.ReasonValid("long enough reason"));
    }

    [Fact]
    public void Fehler_des_Windows_Sicherheitsdialogs()
    {
        Assert.Equal(ErrorCodes.SignInCancelled, WebAuthnErrors.CodeFor(unchecked((int)0x80090036)));
        Assert.Equal(ErrorCodes.SignInCancelled, WebAuthnErrors.CodeFor(unchecked((int)0x800704C7)));
        Assert.Equal(ErrorCodes.FidoNoMatchingKey, WebAuthnErrors.CodeFor(unchecked((int)0x80090011)));
        Assert.Equal(ErrorCodes.FidoKeyAlreadyRegistered, WebAuthnErrors.CodeFor(unchecked((int)0x8009000F)));
        Assert.Equal(ErrorCodes.FidoWebAuthnError, WebAuthnErrors.CodeFor(unchecked((int)0x80004005)));
    }

    [Fact]
    public void Sicherheitsdialog_ist_standardmaessig_freigegeben_und_fehlende_Eintraege_werden_gemeldet()
    {
        var defaults = new SecuritySettings().AuthUiProcesses;
        foreach (var p in FidoSetup.DialogProcesses)
        {
            Assert.Contains(p, defaults);
            Assert.Contains(p, ExternalAuthWindows.Dedicated);
        }
        Assert.Empty(FidoSetup.MissingDialogProcesses(["fido"], defaults));
        Assert.Empty(FidoSetup.MissingDialogProcesses(["windows"], ["msedgewebview2.exe"]));
        Assert.Equal(["CredDialogHost.exe"], FidoSetup.MissingDialogProcesses([" FIDO "], ["credentialuibroker.exe"]));
    }

    [Fact]
    public void Verfahren_standardmaessig_aus_und_Schalter_ordnet_ein()
    {
        var u = new UnlockSettings();
        Assert.DoesNotContain("fido", u.Methods);
        u.MethodPin = true;
        u.MethodFido = true;
        Assert.Equal(["entra", "windows", "hello", "fido", "pin"], u.Methods);
        var f = new FidoSettings();
        Assert.Equal("vitrine", f.RpId);
        Assert.False(f.AllowSelfRegistration);
        Assert.Equal(2, f.MaxKeysPerPerson);
        Assert.Equal(5, f.MaxFailedAttempts);
        Assert.Equal(5, f.BlockMinutes);
        Assert.Equal(24, f.OfflineMaxHours);
        Assert.Empty(f.AllowedModels);
    }

    // ================= Ablage =================

    private static FidoCredential Cred(string idHash, string sid = "S-1-5-21-1") =>
        new() { IdHash = idHash, CredentialId = "AA", PersonSid = sid, PersonName = @"LAB\x", RpId = "vitrine", Label = "k" };

    [Fact]
    public async Task Ablage_speichert_widerruft_und_zaehlt()
    {
        var file = new MemoryStoreFile();
        var store = new JsonFidoStore(file);
        await store.AddAsync(Cred("aa"));
        await store.AddAsync(Cred("bb", "S-1-5-21-2"));
        var e = await Assert.ThrowsAsync<FidoStoreException>(() => store.AddAsync(Cred("AA")));
        Assert.Equal(ErrorCodes.FidoKeyAlreadyRegistered, e.Code);
        Assert.Single(await store.ListAsync("S-1-5-21-2"));
        Assert.True(await store.TouchAsync("aa", 5, DateTimeOffset.UnixEpoch));
        Assert.Equal(5u, (await store.GetAsync("aa"))!.SignCount);
        Assert.True(await store.RevokeAsync("aa", new FidoRevocation(DateTimeOffset.UnixEpoch, "S-1-5-21-9", @"LAB\admin", "lost key")));
        Assert.False(await store.RevokeAsync("aa", new FidoRevocation(DateTimeOffset.UnixEpoch, "S-1-5-21-9", @"LAB\admin", "lost key")));
        Assert.False(await store.TouchAsync("zz", 1, DateTimeOffset.UnixEpoch));

        // Neu geladen aus dem Dateiinhalt
        var reloaded = new JsonFidoStore(new MemoryStoreFile { Content = file.Content });
        var aa = await reloaded.GetAsync("aa");
        Assert.Equal(FidoCredentialStatus.Revoked, aa!.Status);
        Assert.Equal("lost key", aa.RevokeReason);
        Assert.Contains("\"Status\": \"Revoked\"", file.Content);

        await store.SetAsync(new FidoGroupSnapshot { Sid = "S-1-5-21-1", Groups = ["S-1-5-32-545"] });
        await store.SetAsync(new FidoGroupSnapshot { Sid = "s-1-5-21-1", Groups = ["S-1-5-32-544"] });
        var snap = await ((IFidoGroupCache)reloaded).GetAsync("S-1-5-21-1");
        Assert.Null(snap); // reloaded hat den alten Inhalt
        snap = await ((IFidoGroupCache)store).GetAsync("S-1-5-21-1");
        Assert.Equal(["S-1-5-32-544"], snap!.Groups);
    }

    [Fact]
    public async Task Kaputte_oder_ungeschuetzte_Ablage_wird_nicht_ueberschrieben()
    {
        var file = new MemoryStoreFile { Content = "{ kaputt" };
        var store = new JsonFidoStore(file);
        var e = await Assert.ThrowsAsync<FidoStoreException>(() => store.AddAsync(Cred("aa")));
        Assert.Equal(ErrorCodes.FidoStoreError, e.Code);
        Assert.Equal(0, file.Writes);
        Assert.Equal("{ kaputt", file.Content);

        file = new MemoryStoreFile { Content = "{}", Unprotected = true };
        e = await Assert.ThrowsAsync<FidoStoreException>(() => new JsonFidoStore(file).ListAsync());
        Assert.Equal(ErrorCodes.FidoStoreNotProtected, e.Code);
    }
}
