// SPDX-License-Identifier: MIT
using System.Text.Json.Nodes;
using Vitrine.Core.Audit;
using Vitrine.Core.Config;
using Vitrine.Core.Localization;
using Vitrine.Core.Service;
using Vitrine.Tests.TestSupport;

namespace Vitrine.Tests.Service;

/// <summary>
/// Einträge der Sitzungs-App an den signierten Protokoll des Dienstes (Regression aus #15, Gerätetest vom 2026-10-26):
/// Prüfung der Gegenstelle (Pfade), Entscheidung „Dienst schreibt“, Warteschlange mit Reihenfolge, Bestätigung und
/// Meldung VIT-0330 statt stillem Puffern, Ersatzordner beim Beenden.
/// </summary>
public sealed class AuditDeliveryTests
{
    private const string Exe = @"C:\Program Files\Vitrine\Vitrine.exe";

    // ---------------- Pfade der Gegenstelle ----------------

    [Theory]
    [InlineData(@"C:\Program Files\Vitrine\Vitrine.exe")]
    [InlineData(@"c:\program files\vitrine\VITRINE.EXE")]
    [InlineData(@"\\?\C:\Program Files\Vitrine\Vitrine.exe")]
    [InlineData(@"\??\C:\Program Files\Vitrine\Vitrine.exe")]
    [InlineData(@"C:/Program Files/Vitrine/Vitrine.exe")]
    [InlineData(@"C:\Program Files\\Vitrine\Vitrine.exe")]
    [InlineData("\"C:\\Program Files\\Vitrine\\Vitrine.exe\" ")]
    public void Gleiche_Exe_in_anderer_Schreibweise_ist_dieselbe(string path) => Assert.True(ExecutablePath.Same(path, Exe));

    [Fact]
    public void UNC_Präfix_wird_zum_UNC_Pfad() =>
        Assert.Equal(@"\\server\share\Vitrine.exe", ExecutablePath.Normalize(@"\\?\UNC\server\share\Vitrine.exe"));

    [Theory]
    [InlineData(@"C:\Users\operator\AppData\Local\Temp\Vitrine.exe")]
    [InlineData(@"C:\Program Files\Vitrine\Vitrine.exe.bak")]
    [InlineData(@"D:\Program Files\Vitrine\Vitrine.exe")]
    [InlineData("")]
    [InlineData(null)]
    public void Andere_oder_fehlende_Pfade_sind_nicht_dieselbe(string? path) => Assert.False(ExecutablePath.Same(path, Exe));

    [Fact]
    public void Gegenstelle_mit_gleicher_aufgelöster_Datei_wird_angenommen()
    {
        // 8.3-Name als Bildpfad, aufgelöst (GetFinalPathNameByHandle) aber derselbe Pfad wie beim Dienst
        var v = AuditClientCheck.Evaluate(@"C:\PROGRA~1\Vitrine\Vitrine.exe", @"\\?\C:\Program Files\Vitrine\Vitrine.exe", Exe,
            @"\\?\C:\Program Files\Vitrine\Vitrine.exe");
        Assert.True(v.Accepted);
    }

    [Fact]
    public void Gegenstelle_mit_anderer_aufgelöster_Datei_wird_abgelehnt()
    {
        // Gleicher Bildpfad, aber eine Verknüpfung zeigt woandershin (oder harte Verknüpfung in einem Benutzerordner)
        var v = AuditClientCheck.Evaluate(Exe, @"\\?\C:\Users\operator\Vitrine.exe", Exe, @"\\?\C:\Program Files\Vitrine\Vitrine.exe");
        Assert.False(v.Accepted);
        Assert.Contains("different file", v.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void Ohne_aufgelöste_Pfade_zählt_der_Rohpfad()
    {
        Assert.True(AuditClientCheck.Evaluate(@"c:\program files\vitrine\vitrine.exe", null, Exe, null).Accepted);
        var v = AuditClientCheck.Evaluate(@"C:\Temp\Vitrine.exe", null, Exe, @"C:\Program Files\Vitrine\Vitrine.exe");
        Assert.False(v.Accepted);
        Assert.Contains("different path", v.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void Unlesbarer_Pfad_der_Gegenstelle_wird_mit_Grund_abgelehnt()
    {
        var v = AuditClientCheck.Evaluate(null, null, Exe, Exe);
        Assert.False(v.Accepted);
        Assert.Contains("could not be read", v.Reason, StringComparison.Ordinal);
    }

    // ---------------- Schreibt der Dienst? ----------------

    private sealed class FakeServiceState(object? value, bool installed) : IAuditServiceState
    {
        public int InstalledQueries;
        public object? ServiceValue => value;

        public bool ServiceInstalled
        {
            get { InstalledQueries++; return installed; }
        }
    }

    [Theory]
    [InlineData(1, true, true)]      // DWORD, wie der Dienst ihn setzt
    [InlineData(1L, true, true)]     // QWORD (von Hand)
    [InlineData("1", true, true)]    // Zeichenkette (Skript)
    [InlineData(" 1 ", true, true)]
    [InlineData(0, true, false)]     // Dienst hat das Protokoll zurückgegeben (SERVICE=0, Schlüssel nicht ladbar)
    [InlineData(2, true, false)]
    [InlineData("0", true, false)]
    [InlineData(null, true, false)]  // Wert fehlt: portable Exe, ältere Version
    [InlineData(1, false, false)]    // Wert noch da, Dienst deinstalliert
    public void Dienst_schreibt_nur_mit_Wert_1_und_installiertem_Dienst(object? value, bool installed, bool expected) =>
        Assert.Equal(expected, AuditServiceDecision.Expected(new FakeServiceState(value, installed)));

    [Fact]
    public void Ohne_Wert_wird_die_Dienstverwaltung_nicht_gefragt()
    {
        var state = new FakeServiceState(null, true);
        Assert.False(AuditServiceDecision.Expected(state));
        Assert.Equal(0, state.InstalledQueries);
    }

    // ---------------- Warteschlange ----------------

    private DateTimeOffset _now = new(2026, 10, 26, 20, 0, 0, TimeSpan.Zero);

    private AuditOutbox Outbox() => new(() => _now);

    private static AuditEntry Draft(AuditEventType type, string? detail = null) =>
        new() { Time = new DateTimeOffset(2026, 10, 26, 20, 0, 0, TimeSpan.Zero), Event = type, Detail = detail, Method = "windows" };

    private static long IdOf(string line) => JsonNode.Parse(line)!["id"]!.GetValue<long>();

    private static JsonObject Ok(long id, long seq) => new() { ["id"] = id, ["ok"] = true, ["seq"] = seq, ["hash"] = $"h{seq}" };

    [Fact]
    public void Ohne_Dienst_gepufferte_Einträge_gehen_beim_Verbinden_in_Reihenfolge_raus()
    {
        var box = Outbox();
        box.Add(Draft(AuditEventType.Locked), null);
        box.Add(Draft(AuditEventType.Unlocked), null);
        box.Add(Draft(AuditEventType.ConfigChanged), null);
        var lines = box.ConnectionUp();
        Assert.Equal(["Locked", "Unlocked", "ConfigChanged"], lines.Select(l => JsonNode.Parse(l)!["event"]!.GetValue<string>()));
        Assert.Equal(lines.Select(IdOf).Order(), lines.Select(IdOf));
        // Eine zweite Verbindung (die erste brach ab) bekommt alles Unbestätigte noch einmal
        Assert.Equal(lines, box.ConnectionUp());
    }

    [Fact]
    public void Bestätigte_Einträge_verlassen_die_Warteschlange_mit_Nummer_und_Hash()
    {
        var box = Outbox();
        var line = box.Add(Draft(AuditEventType.Unlocked), null)!;
        var ack = box.Acknowledge(Ok(IdOf(line), 17));
        Assert.Equal(AuditOutbox.AckKind.Committed, ack.Kind);
        Assert.Equal(17, ack.Entry!.Seq);
        Assert.Equal("h17", ack.Entry.Hash);
        Assert.Equal(AuditFormat.Signed, ack.Entry.V);
        Assert.Equal(0, box.Count);
        Assert.Empty(box.ConnectionUp());
    }

    [Fact]
    public void Schreibfehler_des_Dienstes_behält_den_Eintrag_Ablehnung_nicht()
    {
        var box = Outbox();
        var a = IdOf(box.Add(Draft(AuditEventType.Unlocked), null)!);
        var b = IdOf(box.Add(Draft(AuditEventType.AppStarted), null)!);
        Assert.Equal(AuditOutbox.AckKind.Retry,
            box.Acknowledge(new JsonObject { ["id"] = a, ["ok"] = false, ["code"] = ErrorCodes.AuditWriteFailed, ["error"] = "disk full" }).Kind);
        Assert.Equal(AuditDeliveryProblem.WriteFailed, box.Problem);
        Assert.Equal(2, box.Count);
        Assert.Equal(AuditOutbox.AckKind.Rejected,
            box.Acknowledge(new JsonObject { ["id"] = b, ["ok"] = false, ["code"] = ErrorCodes.ServiceEntryRefused }).Kind);
        Assert.Equal(1, box.Count);
        Assert.Equal(AuditOutbox.AckKind.Unknown, box.Acknowledge(Ok(999, 1)).Kind);
    }

    [Fact]
    public void Volle_Warteschlange_verwirft_und_meldet_VIT_0318_beim_Verbinden()
    {
        var box = Outbox();
        for (int i = 0; i < AuditOutbox.MaxBuffered; i++) Assert.NotNull(box.Add(Draft(AuditEventType.Locked), null));
        Assert.Null(box.Add(Draft(AuditEventType.Unlocked), null));
        Assert.Null(box.Add(Draft(AuditEventType.Unlocked), null));
        Assert.Equal(2, box.Dropped);
        var lines = box.ConnectionUp();
        Assert.Equal(AuditOutbox.MaxBuffered + 1, lines.Count);
        Assert.Contains($"{ErrorCodes.AuditBufferOverflow} 2 entries lost", lines[^1], StringComparison.Ordinal);
        Assert.Equal(0, box.Dropped);
    }

    [Fact]
    public void Beim_Beenden_kommen_die_unbestätigten_Einträge_heraus()
    {
        var box = Outbox();
        var a = IdOf(box.Add(Draft(AuditEventType.Locked), null)!);
        box.Add(Draft(AuditEventType.Unlocked), null);
        box.Acknowledge(Ok(a, 1));
        var unsent = box.TakeUnsent();
        Assert.Equal(AuditEventType.Unlocked, Assert.Single(unsent).Event);
        Assert.Equal(0, box.Count);
    }

    [Fact]
    public void Zustellproblem_wird_nach_einer_Minute_einmal_gemeldet_und_nach_der_Zustellung_entwarnt()
    {
        var box = Outbox();
        var id = IdOf(box.Add(Draft(AuditEventType.Unlocked), null)!);
        box.SetProblem(AuditDeliveryProblem.ClosedWithoutAnswer);
        Assert.Null(box.Check());
        _now += TimeSpan.FromSeconds(59);
        Assert.Null(box.Check());
        _now += TimeSpan.FromSeconds(2);
        var report = box.Check();
        Assert.NotNull(report);
        Assert.False(report.Recovered);
        Assert.Equal(1, report.Pending);
        Assert.Equal(AuditDeliveryProblem.ClosedWithoutAnswer, report.Problem);
        Assert.StartsWith($"{ErrorCodes.AuditNotDelivered} 1 audit entries not delivered", report.LogText, StringComparison.Ordinal);
        Assert.True(box.Reported);
        // Nicht bei jedem Takt erneut
        _now += TimeSpan.FromMinutes(10);
        Assert.Null(box.Check());

        box.Acknowledge(Ok(id, 5));
        var recovered = box.Check();
        Assert.True(recovered!.Recovered);
        Assert.False(box.Reported);
        Assert.Null(box.Check());
    }

    [Fact]
    public void Ohne_bekannten_Grund_heißt_das_Problem_keine_Antwort()
    {
        var box = Outbox();
        box.Add(Draft(AuditEventType.Locked), null);
        _now += AuditOutbox.ReportAfter;
        Assert.Equal(AuditDeliveryProblem.NoAnswer, box.Check()!.Problem);
    }

    [Fact]
    public void Nach_einer_Antwort_des_Dienstes_ist_das_alte_Problem_vorbei()
    {
        var box = Outbox();
        var id = IdOf(box.Add(Draft(AuditEventType.Locked), null)!);
        box.Add(Draft(AuditEventType.Unlocked), null);
        box.SetProblem(AuditDeliveryProblem.NotReachable);
        box.Acknowledge(Ok(id, 1));
        Assert.Equal(AuditDeliveryProblem.None, box.Problem);
    }

    [Fact]
    public void Jede_Meldung_hat_einen_Text_in_allen_Sprachen()
    {
        foreach (var problem in Enum.GetValues<AuditDeliveryProblem>())
            foreach (var lang in new[] { "en", "de", "es", "fr", "zh-Hans" })
            {
                using var _ = new UiCulture(lang);
                var text = new AuditDeliveryReport(false, 3, null, problem, null).UserText();
                Assert.DoesNotContain("[", text, StringComparison.Ordinal);
                Assert.Contains("3", text, StringComparison.Ordinal);
                Assert.Contains(ErrorCodes.AuditNotDelivered, text, StringComparison.Ordinal);
            }
    }

    [Fact]
    public void Anfragezeile_trägt_Ereignis_Zeit_und_Daten()
    {
        var e = Draft(AuditEventType.UnlockFailed, "wrong password") with { Data = new() { ["code"] = "VIT-0101" } };
        var req = JsonNode.Parse(AuditOutbox.WriteRequest(7, e))!.AsObject();
        Assert.Equal("write", req["op"]!.GetValue<string>());
        Assert.Equal(7, req["id"]!.GetValue<long>());
        Assert.Equal("UnlockFailed", req["event"]!.GetValue<string>());
        Assert.Equal("2026-10-26T20:00:00.0000000+00:00", req["time"]!.GetValue<string>());
        Assert.Equal("VIT-0101", req["data"]!["code"]!.GetValue<string>());
    }

    // ---------------- Meldungen begrenzen ----------------

    [Fact]
    public void Gleiche_Ablehnung_höchstens_alle_zehn_Minuten()
    {
        var limiter = new ReportLimiter(TimeSpan.FromMinutes(10), () => _now);
        Assert.True(limiter.ShouldReport("reject|C:\\Temp\\x.exe"));
        Assert.False(limiter.ShouldReport("REJECT|c:\\temp\\x.exe"));
        Assert.True(limiter.ShouldReport("reject|other"));
        _now += TimeSpan.FromMinutes(10);
        Assert.True(limiter.ShouldReport("reject|C:\\Temp\\x.exe"));
    }

    // ---------------- Ersatzordner beim Beenden ----------------

    [Fact]
    public void Nicht_zugestellte_Einträge_landen_verkettet_im_Ersatzordner()
    {
        using var dir = new TempDir();
        var log = new AuditLog(new AuditSettings { Directory = dir.Path, EventLog = false }, @"LAB\operator", null, () => _now);
        log.WriteUnsent([Draft(AuditEventType.Locked), Draft(AuditEventType.Unlocked)], dir.Path);
        var file = Path.Combine(dir.Path, "audit-2026-10.jsonl");
        var entries = File.ReadAllLines(file).Select(l => AuditLog.Parse(l)!).ToList();
        Assert.Equal([AuditEventType.AuditLocalMode, AuditEventType.Locked, AuditEventType.Unlocked], entries.Select(e => e.Event));
        Assert.Contains("2 entries not delivered to the service", entries[0].Detail, StringComparison.Ordinal);
        Assert.Equal([1L, 2L, 3L], entries.Select(e => e.Seq));
        Assert.Equal(entries[0].Hash, entries[1].Prev);
        Assert.Equal(entries[1].Hash, entries[2].Prev);
    }
}
