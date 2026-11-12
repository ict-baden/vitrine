// SPDX-License-Identifier: MIT
using System.Security.Cryptography;
using System.Text;
using Vitrine.Core.Audit;
using Vitrine.Core.Config;
using Vitrine.Tests.TestSupport;

namespace Vitrine.Tests.Audit;

/// <summary>Schlüssel im Speicher statt CNG-Maschinenschlüssel (Tests legen nie Maschinenschlüssel an).</summary>
internal sealed class MemoryKeyStore : IAuditKeyStore
{
    private sealed class Signer(ECDsa key) : IAuditSigner
    {
        public AuditPublicKey PublicKey { get; } = AuditPublicKey.From(key.ExportSubjectPublicKeyInfo());
        public byte[] Sign(byte[] data) => key.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

    private readonly List<Signer> _all = [];

    public IAuditSigner Current()
    {
        if (_all.Count == 0) _all.Add(new Signer(ECDsa.Create(ECCurve.NamedCurves.nistP256)));
        return _all[^1];
    }

    public IAuditSigner CreateNext()
    {
        Current();
        _all.Add(new Signer(ECDsa.Create(ECCurve.NamedCurves.nistP256)));
        return _all[^1];
    }

    public IReadOnlyList<AuditPublicKey> PublicKeys() => _all.Select(s => s.PublicKey).ToList();

    /// <summary>Fremder Schlüssel (Angreifer), nicht im Speicher.</summary>
    public static IAuditSigner Foreign() => new Signer(ECDsa.Create(ECCurve.NamedCurves.nistP256));
}

/// <summary>
/// Format 3 (#15): Der Dienst signiert jede Zeile, zählt über Monate weiter und hält Anker außerhalb der Datei. Die Prüfung
/// muss angehängte, geänderte, vertauschte und abgeschnittene Zeilen, gelöschte und ausgetauschte Dateien, fremde Schlüssel
/// und den Übergang aus Format 2 erkennen.
/// </summary>
public sealed class SignedAuditLogTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly MemoryKeyStore _keys = new();
    private readonly MemoryAnchorStore _anchors = new();
    private DateTimeOffset _now = new(2026, 10, 19, 8, 0, 0, TimeSpan.Zero);
    private const string Machine = "LAB-PC-07";

    public void Dispose() => _dir.Dispose();

    private SignedAuditLog Log() =>
        new(() => new AuditSettings { Directory = _dir.Path, EventLog = false }, _keys, _anchors, null, () => _now, Machine);

    private string October => Path.Combine(_dir.Path, "audit-2026-10.jsonl");
    private string September => Path.Combine(_dir.Path, "audit-2026-09.jsonl");

    private AuditVerifyOptions Options(bool anchors = true) => AuditVerifyOptions.ForPath(_dir.Path, anchors ? _anchors : null, Machine);

    private AuditVerifyResult Verify(string? file = null, bool anchors = true)
    {
        using var _ = new UiCulture("en");
        return AuditVerifier.VerifyFile(file ?? October, Options(anchors));
    }

    private AuditEntry W(SignedAuditLog log, AuditEventType type = AuditEventType.Locked, string? detail = null) =>
        log.Write(new AuditRecord(type, @"LAB\operator", AuditAssurance.Client) { Session = 2, Detail = detail })!;

    [Fact]
    public void Signierte_Kette_ist_vollstaendig_mit_Formatwechsel_am_Anfang()
    {
        var log = Log();
        for (int i = 0; i < 5; i++) W(log);
        var lines = File.ReadAllLines(October);
        Assert.Equal(6, lines.Length);
        var first = AuditLog.Parse(lines[0])!;
        Assert.Equal(AuditEventType.AuditFormatSwitched, first.Event);
        Assert.Equal(AuditAssurance.Service, first.Assurance);
        Assert.Equal(_keys.Current().PublicKey.Id, first.Data!["key"]);
        Assert.All(lines, l => Assert.Equal(3, AuditLog.Parse(l)!.V));
        var r = Verify();
        Assert.True(r.Ok, r.Message);
        Assert.Equal(6, r.SignedEntries);
        Assert.Equal(new AuditAnchor("2026-10", 6, AuditLog.Parse(lines[^1])!.Hash!), _anchors.Get("2026-10"));
        Assert.True(File.Exists(Path.Combine(_dir.Path, "audit-keys.json")));
    }

    [Fact]
    public void Zeit_Nummer_und_Rechner_setzt_der_Dienst()
    {
        var log = Log();
        var e = log.Write(new AuditRecord(AuditEventType.Unlocked, @"LAB\operator", AuditAssurance.Client)
        {
            Session = 3, ClientTime = _now.AddMinutes(-30), Actor = "someone",
        })!;
        Assert.Equal(_now, e.Time);
        Assert.Equal(_now.AddMinutes(-30), e.ClientTime);
        Assert.Equal(Machine, e.Machine);
        Assert.Equal(3, e.Session);
        Assert.Equal(2, e.Seq);
    }

    [Fact]
    public void Angehaengte_Zeile_mit_fremdem_Schluessel_wird_erkannt()
    {
        var log = Log();
        W(log);
        var last = AuditLog.Parse(File.ReadAllLines(October)[^1])!;
        var foreign = MemoryKeyStore.Foreign();
        var (line, _) = AuditFormat.SignLine(last with
        {
            Seq = last.Seq + 1, Prev = last.Hash, Event = AuditEventType.SignatureGranted, Actor = "CONTOSO\\qa-lead",
            Key = foreign.PublicKey.Id, Hash = null, Sig = null,
        }, foreign);
        File.AppendAllText(October, line + "\n");
        var r = Verify(anchors: false);
        Assert.False(r.Ok);
        Assert.Contains("VIT-0302", r.Message);
    }

    [Fact]
    public void Angehaengte_Zeile_im_alten_Format_mit_passendem_Hash_wird_erkannt()
    {
        var log = Log();
        W(log);
        var last = AuditLog.Parse(File.ReadAllLines(October)[^1])!;
        // Format 2 hat keinen Schlüssel: Jeder kann den Hash selbst ausrechnen
        var forged = new AuditEntry { V = 2, Seq = last.Seq + 1, Time = _now, Machine = Machine, SessionUser = @"LAB\operator",
            Event = AuditEventType.SignatureGranted, Actor = "CONTOSO\\qa-lead", Prev = last.Hash };
        var body = AuditFormat.Serialize(forged);
        var line = body[..^1] + $",\"Hash\":\"{AuditFormat.HashOf(body)}\"}}";
        File.AppendAllText(October, line + "\n");
        var r = Verify(anchors: false);
        Assert.False(r.Ok);
        Assert.Contains("VIT-0308", r.Message);
    }

    [Fact]
    public void Geaenderte_Zeile_wird_erkannt_auch_mit_neu_berechnetem_Hash()
    {
        var log = Log();
        W(log, detail: "Trigger: hotkey");
        W(log);
        var lines = File.ReadAllLines(October);
        var e = AuditLog.Parse(lines[1])!;
        var changed = e with { Detail = "Trigger: tray", Hash = null, Sig = null };
        var body = AuditFormat.Serialize(changed);
        var hash = AuditFormat.HashOf(body);
        // Hash passt zur geänderten Zeile, die Signatur nicht
        lines[1] = body[..^1] + $",\"Hash\":\"{hash}\",\"Sig\":\"{e.Sig}\"}}";
        File.WriteAllLines(October, lines);
        var r = Verify(anchors: false);
        Assert.False(r.Ok);
        Assert.Contains("VIT-0301", r.Message);
    }

    [Fact]
    public void Abgeschnittenes_Ende_meldet_der_Anker()
    {
        var log = Log();
        for (int i = 0; i < 4; i++) W(log);
        var lines = File.ReadAllLines(October);
        File.WriteAllLines(October, lines[..^2]);
        Assert.True(Verify(anchors: false).Ok); // ohne Anker eine gültige, kürzere Kette
        var r = Verify();
        Assert.False(r.Ok);
        Assert.Contains("VIT-0304", r.Message);
    }

    [Fact]
    public void Vertauschte_Zeilen_werden_erkannt()
    {
        var log = Log();
        for (int i = 0; i < 4; i++) W(log, detail: $"n{i}");
        var lines = File.ReadAllLines(October);
        (lines[2], lines[3]) = (lines[3], lines[2]);
        File.WriteAllLines(October, lines);
        var r = Verify(anchors: false);
        Assert.False(r.Ok);
        Assert.Contains("VIT-0021", r.Message);
    }

    [Fact]
    public void Geloeschte_Zeile_mitten_drin_wird_erkannt()
    {
        var log = Log();
        for (int i = 0; i < 4; i++) W(log);
        var lines = File.ReadAllLines(October).ToList();
        lines.RemoveAt(2);
        File.WriteAllLines(October, lines);
        Assert.False(Verify(anchors: false).Ok);
    }

    [Fact]
    public void Monate_setzen_Kette_und_Nummer_fort()
    {
        _now = new DateTimeOffset(2026, 9, 30, 23, 59, 0, TimeSpan.Zero);
        var log = Log();
        W(log);
        W(log);
        _now = new DateTimeOffset(2026, 10, 1, 0, 1, 0, TimeSpan.Zero);
        var e = W(log);
        Assert.Equal(4, e.Seq);
        Assert.Equal(AuditLog.Parse(File.ReadAllLines(September)[^1])!.Hash, e.Prev);
        using var _ = new UiCulture("en");
        var r = AuditVerifier.VerifyFolder(_dir.Path, Options());
        Assert.True(r.Ok, r.Message);
        Assert.Equal(4, r.SignedEntries);
    }

    [Fact]
    public void Geloeschte_Datei_wird_erkannt()
    {
        _now = new DateTimeOffset(2026, 9, 30, 23, 0, 0, TimeSpan.Zero);
        var log = Log();
        W(log);
        _now = new DateTimeOffset(2026, 10, 1, 1, 0, 0, TimeSpan.Zero);
        W(log);
        File.Delete(September);
        var r = Verify();
        Assert.False(r.Ok);
        Assert.Contains("VIT-0306", r.Message);
        File.Delete(October);
        using var _ = new UiCulture("en");
        Assert.Contains("VIT-0306", AuditVerifier.VerifyFolder(_dir.Path, Options()).Message);
    }

    [Fact]
    public void Ausgetauschte_Datei_des_Vormonats_wird_erkannt()
    {
        _now = new DateTimeOffset(2026, 9, 30, 23, 0, 0, TimeSpan.Zero);
        var log = Log();
        W(log);
        W(log);
        var older = File.ReadAllLines(September);
        _now = new DateTimeOffset(2026, 10, 1, 1, 0, 0, TimeSpan.Zero);
        W(log);
        // Vormonat durch einen älteren Stand ersetzt (eine Zeile weniger): Der Oktober setzt ihn nicht fort
        File.WriteAllLines(September, older[..^1]);
        var r = Verify(anchors: false);
        Assert.False(r.Ok);
        Assert.Contains("VIT-0309", r.Message);
    }

    [Fact]
    public void Datei_aus_einem_anderen_Monat_wird_erkannt()
    {
        _now = new DateTimeOffset(2026, 9, 10, 8, 0, 0, TimeSpan.Zero);
        var log = Log();
        W(log);
        // September-Datei als Oktober ausgegeben
        File.Copy(September, October);
        var r = Verify(anchors: false);
        Assert.False(r.Ok);
        Assert.Contains("VIT-0307", r.Message);
    }

    [Fact]
    public void Falscher_Schluessel_in_audit_keys_wird_erkannt()
    {
        var log = Log();
        W(log);
        File.WriteAllText(Path.Combine(_dir.Path, "audit-keys.json"), AuditKeyFile.Serialize(Machine, [MemoryKeyStore.Foreign().PublicKey]));
        var r = Verify(anchors: false);
        Assert.False(r.Ok);
        Assert.Contains("VIT-0302", r.Message);
        File.Delete(Path.Combine(_dir.Path, "audit-keys.json"));
        Assert.Contains("VIT-0310", Verify(anchors: false).Message);
    }

    [Fact]
    public void Schluesselwechsel_wird_mit_dem_alten_Schluessel_signiert_und_anerkannt()
    {
        var log = Log();
        W(log);
        var first = _keys.Current().PublicKey;
        var rotated = log.RotateKey("SYSTEM")!;
        Assert.Equal(first.Id, rotated.Key);
        var after = W(log);
        Assert.NotEqual(first.Id, after.Key);
        // Prüfer vertraut nur dem ersten Schlüssel (aus den Validierungsunterlagen): der zweite gilt über den Wechsel
        using var _ = new UiCulture("en");
        var r = AuditVerifier.VerifyFile(October, new AuditVerifyOptions { TrustedKeys = [first] });
        Assert.True(r.Ok, r.Message);
        Assert.Equal(2, r.Fingerprints.Count);
        // audit-keys.json enthält beide
        Assert.Equal(2, AuditKeyFile.Parse(File.ReadAllText(Path.Combine(_dir.Path, "audit-keys.json")))!.Value.Keys.Count);
    }

    [Fact]
    public void Ohne_Wechsel_eingeschobener_Schluessel_gilt_nicht()
    {
        var log = Log();
        W(log);
        var first = _keys.Current().PublicKey;
        _keys.CreateNext(); // neuer Schlüssel ohne AuditKeyRotated
        W(log);
        using var _ = new UiCulture("en");
        var r = AuditVerifier.VerifyFile(October, new AuditVerifyOptions { TrustedKeys = [first] });
        Assert.False(r.Ok);
        Assert.Contains("VIT-0302", r.Message);
    }

    [Fact]
    public void Uebergang_von_Format_2_mit_Formatwechsel_Eintrag()
    {
        var app = new AuditLog(new AuditSettings { Directory = _dir.Path, EventLog = false }, @"LAB\operator", null, () => _now);
        app.Write(AuditEventType.AppStarted);
        app.Write(AuditEventType.Locked);
        var log = Log();
        var e = W(log);
        var lines = File.ReadAllLines(October);
        Assert.Equal(4, lines.Length);
        var switched = AuditLog.Parse(lines[2])!;
        Assert.Equal(AuditEventType.AuditFormatSwitched, switched.Event);
        Assert.Equal(AuditLog.Parse(lines[1])!.Hash, switched.Prev);
        Assert.Equal(3, switched.Seq);
        Assert.Equal(4, e.Seq);
        var r = Verify();
        Assert.True(r.Ok, r.Message);
        Assert.Equal(2, r.SignedEntries);
        Assert.Equal(2, r.UnsignedEntries);
        // Alte Dateien (nur Format 2) bleiben prüfbar
        Assert.True(AuditLog.Verify(October).ok);
    }

    [Fact]
    public void Dienst_erkennt_abgeschnittenes_Ende_und_setzt_am_Anker_fort()
    {
        var log = Log();
        for (int i = 0; i < 3; i++) W(log);
        var lines = File.ReadAllLines(October);
        File.WriteAllLines(October, lines[..^1]);
        W(log);
        var after = File.ReadAllLines(October);
        var problem = AuditLog.Parse(after[^2])!;
        Assert.Equal(AuditEventType.Error, problem.Event);
        Assert.StartsWith("VIT-0316", problem.Detail);
        // Die Kette setzt am Anker fort: Die Lücke bleibt beim Prüfen sichtbar
        Assert.Equal(AuditLog.Parse(lines[^1])!.Hash, problem.Prev);
        Assert.False(Verify(anchors: false).Ok);
    }

    [Fact]
    public void Dienst_erkennt_geloeschte_Datei_des_Monats()
    {
        var log = Log();
        W(log);
        File.Delete(October);
        W(log);
        Assert.StartsWith("VIT-0316", AuditLog.Parse(File.ReadAllLines(October)[0])!.Detail);
    }

    [Fact]
    public void Abgestuerzt_zwischen_Zeile_und_Anker_setzt_an_der_Zeile_fort()
    {
        var log = Log();
        W(log);
        var anchor = _anchors.Get("2026-10")!;
        W(log);
        _anchors.Set(anchor); // Anker eine Zeile zurück
        var e = W(log);
        Assert.Equal(4, e.Seq);
        Assert.DoesNotContain(File.ReadAllLines(October), l => l.Contains("VIT-0316", StringComparison.Ordinal));
        Assert.True(Verify().Ok);
    }

    [Fact]
    public void Felder_des_Formats_3_in_einer_Zeile_im_Format_2_gelten_als_geaendert()
    {
        var app = new AuditLog(new AuditSettings { Directory = _dir.Path, EventLog = false }, @"LAB\operator", null, () => _now);
        app.Write(AuditEventType.Locked);
        var e = AuditLog.Parse(File.ReadAllLines(October)[0])!;
        var forged = e with { Assurance = AuditAssurance.Verified, Hash = null };
        var body = AuditFormat.Serialize(forged);
        File.WriteAllText(October, body[..^1] + $",\"Hash\":\"{AuditFormat.HashOf(body)}\"}}\n");
        Assert.Contains("VIT-0022", Verify(anchors: false).Message);
    }

    [Fact]
    public void Signatur_ist_Base64url_und_ueberlebt_die_Pruefung_der_Schreibweise()
    {
        var log = Log();
        for (int i = 0; i < 20; i++) W(log, detail: "a+b/c<d>&'");
        var r = Verify();
        Assert.True(r.Ok, r.Message);
        Assert.All(File.ReadAllLines(October), l => Assert.NotNull(AuditFormat.SplitSigned(l)));
    }

    [Fact]
    public void Schluesseldatei_eines_anderen_Rechners_im_Ordner_gilt_nicht()
    {
        // Prüfung vom 2026-10-26: Vorher galt jede *audit-keys.json im Ordner für jede Datei
        var log = Log();
        W(log);
        var last = AuditLog.Parse(File.ReadAllLines(October)[^1])!;
        var foreign = MemoryKeyStore.Foreign();
        File.WriteAllText(Path.Combine(_dir.Path, "EVIL-PC-audit-keys.json"), AuditKeyFile.Serialize("EVIL-PC", [foreign.PublicKey]));
        var (line, _) = AuditFormat.SignLine(last with { Seq = last.Seq + 1, Prev = last.Hash, Key = foreign.PublicKey.Id, Hash = null, Sig = null }, foreign);
        File.AppendAllText(October, line + "\n");
        Assert.Contains("VIT-0302", Verify(anchors: false).Message);
    }

    [Fact]
    public void Auf_dem_Rechner_gelten_die_Schluessel_aus_der_Registry_nicht_die_Datei_daneben()
    {
        var log = Log();
        W(log);
        var real = _keys.PublicKeys();
        var foreign = MemoryKeyStore.Foreign();
        // audit-keys.json ersetzt und eine mit dem fremden Schlüssel signierte Zeile angehängt
        File.WriteAllText(Path.Combine(_dir.Path, "audit-keys.json"), AuditKeyFile.Serialize(Machine, [foreign.PublicKey]));
        var o = new AuditVerifyOptions { KeysNextToFile = true, PreferredKeys = real, PreferredKeysMachine = Machine };
        using var _ = new UiCulture("en");
        Assert.True(AuditVerifier.VerifyFile(October, o).Ok);
        var last = AuditLog.Parse(File.ReadAllLines(October)[^1])!;
        var (line, _) = AuditFormat.SignLine(last with { Seq = last.Seq + 1, Prev = last.Hash, Key = foreign.PublicKey.Id, Hash = null, Sig = null }, foreign);
        File.AppendAllText(October, line + "\n");
        Assert.Contains("VIT-0302", AuditVerifier.VerifyFile(October, o).Message);
    }

    [Fact]
    public void Alter_Schluessel_nach_dem_Wechsel_gilt_nicht_mehr()
    {
        var log = Log();
        W(log);
        var old = _keys.Current();
        log.RotateKey("SYSTEM");
        W(log);
        // Mit dem alten (ausgemusterten, aber in audit-keys.json gelisteten) Schlüssel signierte Zeile angehängt
        var last = AuditLog.Parse(File.ReadAllLines(October)[^1])!;
        var (line, _) = AuditFormat.SignLine(last with { Seq = last.Seq + 1, Prev = last.Hash, Key = old.PublicKey.Id, Hash = null, Sig = null }, old);
        File.AppendAllText(October, line + "\n");
        var r = Verify(anchors: false);
        Assert.False(r.Ok);
        Assert.Contains("VIT-0324", r.Message);
    }

    [Fact]
    public void Schluessel_des_Vormonats_gilt_weiter_und_kein_anderer()
    {
        _now = new DateTimeOffset(2026, 9, 30, 23, 0, 0, TimeSpan.Zero);
        var log = Log();
        W(log);
        var first = _keys.Current();
        log.RotateKey("SYSTEM");
        _now = new DateTimeOffset(2026, 10, 1, 1, 0, 0, TimeSpan.Zero);
        W(log);
        Assert.True(Verify(anchors: false).Ok);
        // Oktober neu geschrieben, signiert mit dem alten Schlüssel (in audit-keys.json noch gelistet)
        var lines = File.ReadAllLines(October);
        var e = AuditLog.Parse(lines[0])!;
        var (line, _) = AuditFormat.SignLine(e with { Key = first.PublicKey.Id, Hash = null, Sig = null }, first);
        File.WriteAllText(October, line + "\n");
        Assert.Contains("VIT-0324", Verify(anchors: false).Message);
    }

    [Fact]
    public void Verknuepfung_statt_Datei_wird_nicht_beschrieben()
    {
        var target = Path.Combine(_dir.Path, "elsewhere.txt");
        File.WriteAllText(target, "keep");
        try { File.CreateSymbolicLink(October, target); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return; } // ohne Recht für Links (Windows ohne Entwicklermodus)
        Assert.Null(W(Log()));
        Assert.Equal("keep", File.ReadAllText(target));
    }

    [Fact]
    public void Ausgeschaltet_schreibt_der_Dienst_nichts()
    {
        var log = new SignedAuditLog(() => new AuditSettings { Directory = _dir.Path, Enabled = false }, _keys, _anchors, null, () => _now, Machine);
        Assert.Null(W(log));
        Assert.False(File.Exists(October));
    }

    [Fact]
    public void Schluesseldatei_hin_und_zurueck()
    {
        var k = _keys.Current().PublicKey;
        var json = AuditKeyFile.Serialize(Machine, [k], [new AuditAnchor("2026-10", 7, new string('a', 64))]);
        var parsed = AuditKeyFile.Parse(json)!.Value;
        Assert.Equal(Machine, parsed.Machine);
        Assert.Equal(k.Fingerprint, parsed.Keys.Single().Fingerprint);
        Assert.Equal(7, parsed.Anchors.Single().Seq);
        Assert.Null(AuditKeyFile.Parse("{nonsense"));
        Assert.True(k.Verify(Encoding.UTF8.GetBytes("x"), _keys.Current().Sign(Encoding.UTF8.GetBytes("x"))));
    }
}
