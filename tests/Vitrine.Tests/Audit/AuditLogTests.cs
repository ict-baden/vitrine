// SPDX-License-Identifier: MIT
using System.Text.Json;
using System.Text.Json.Nodes;
using Vitrine.Core.Audit;
using Vitrine.Core.Config;
using Vitrine.Tests.TestSupport;

namespace Vitrine.Tests.Audit;

/// <summary>Protokoll mit Hash-Kette: Schreiben, Fortsetzen, Erkennen von Änderungen und Lücken.</summary>
public sealed class AuditLogTests : IDisposable
{
    private readonly TempDir _dir = new();
    private DateTimeOffset _now = new(2026, 10, 19, 8, 0, 0, TimeSpan.Zero);

    public void Dispose() => _dir.Dispose();

    private AuditLog Log(IAuditSink? sink = null, bool enabled = true) =>
        new(new AuditSettings { Directory = _dir.Path, EventLog = sink is not null, Enabled = enabled }, "LAB\\operator", sink, () => _now);

    private string File => Path.Combine(_dir.Path, "audit-2026-10.jsonl");

    [Fact]
    public void Kette_ist_vollstaendig_und_ueberlebt_einen_Neustart()
    {
        var log = Log();
        log.Write(AuditEventType.AppStarted);
        log.Write(AuditEventType.Locked, detail: "Trigger: hotkey");
        // Neue Instanz (Neustart von Vitrine) setzt die Kette am Dateiende fort
        var again = Log();
        var e = again.Write(AuditEventType.Unlocked, "LAB\\operator", "windows");
        Assert.Equal(3, e.Seq);
        var (ok, msg) = AuditLog.Verify(File);
        Assert.True(ok, msg);
        Assert.Contains("3", msg);
    }

    [Fact]
    public void Netzkopie_kommt_im_Hintergrund_in_derselben_Reihenfolge_an()
    {
        var share = Path.Combine(_dir.Path, "share");
        var log = new AuditLog(new AuditSettings { Directory = _dir.Path, NetworkDirectory = share, EventLog = false }, "LAB\\operator", null, () => _now);
        for (int i = 0; i < 50; i++) log.Write(AuditEventType.Locked, detail: $"Trigger: test {i}");
        Assert.True(AuditLog.FlushNetworkCopies(TimeSpan.FromSeconds(10)));
        var copy = Path.Combine(share, $"{Environment.MachineName}-audit-2026-10.jsonl");
        Assert.Equal(System.IO.File.ReadAllLines(File), System.IO.File.ReadAllLines(copy));
        Assert.True(AuditLog.Verify(copy).ok);
    }

    [Fact]
    public void Mehrere_Sitzungen_schreiben_abwechselnd_in_dieselbe_Datei_ohne_Kettenbruch()
    {
        // Zwei Vitrine-Prozesse (Remotedesktop, Benutzerwechsel) mit je eigener AuditLog-Instanz
        var a = Log();
        var b = new AuditLog(new AuditSettings { Directory = _dir.Path, EventLog = false }, "LAB\\other", null, () => _now);
        for (int i = 0; i < 5; i++)
        {
            a.Write(AuditEventType.Locked);
            b.Write(AuditEventType.Locked);
        }
        var (ok, msg) = AuditLog.Verify(File);
        Assert.True(ok, msg);
        Assert.Equal(10, AuditLog.Parse(System.IO.File.ReadAllLines(File)[^1])!.Seq);
    }

    [Fact]
    public void Paralleles_Schreiben_aus_mehreren_Threads_bleibt_eine_Kette()
    {
        var logs = Enumerable.Range(0, 4).Select(_ => Log()).ToArray();
        Parallel.For(0, 40, i => logs[i % 4].Write(AuditEventType.PromptShown));
        Assert.True(AuditLog.Verify(File).ok);
        Assert.Equal(40, System.IO.File.ReadAllLines(File).Length);
    }

    [Fact]
    public void Lange_letzte_Zeile_setzt_die_Kette_trotzdem_fort()
    {
        var log = Log();
        log.Write(AuditEventType.Error, detail: new string('x', 200_000));
        var e = log.Write(AuditEventType.Locked);
        Assert.Equal(2, e.Seq);
        Assert.True(AuditLog.Verify(File).ok);
    }

    [Fact]
    public void Dateiname_unabhaengig_vom_Kalender_der_Regionaleinstellung()
    {
        using var _ = new UiCulture("th-TH");
        Log().Write(AuditEventType.Locked);
        Assert.True(System.IO.File.Exists(File));
    }

    [Fact]
    public void Zeiten_sind_UTC()
    {
        _now = new DateTimeOffset(2026, 10, 19, 10, 0, 0, TimeSpan.FromHours(2));
        var e = Log().Write(AuditEventType.Locked);
        Assert.Equal(TimeSpan.Zero, e.Time.Offset);
        Assert.Equal(8, e.Time.Hour);
    }

    [Fact]
    public void Geaenderter_Eintrag_wird_erkannt()
    {
        using var _ = new UiCulture("en");
        var log = Log();
        log.Write(AuditEventType.UnlockFailed, "LAB\\mallory", "windows", "VIT-0101");
        log.Write(AuditEventType.Unlocked, "LAB\\operator", "windows");
        var lines = System.IO.File.ReadAllLines(File);
        lines[0] = lines[0].Replace("mallory", "someone");
        System.IO.File.WriteAllLines(File, lines);
        var (ok, msg) = AuditLog.Verify(File);
        Assert.False(ok);
        Assert.Contains("VIT-0022", msg);
    }

    [Fact]
    public void Neue_Zeilen_haben_Format_2_und_der_Hash_gilt_den_Bytes_der_Zeile()
    {
        Log().Write(AuditEventType.Locked, detail: "Trigger: hotkey");
        var line = System.IO.File.ReadAllLines(File)[0];
        Assert.StartsWith("{\"V\":2,\"Seq\":1,", line);
        var e = AuditLog.Parse(line)!;
        var body = line[..line.IndexOf(",\"Hash\":", StringComparison.Ordinal)] + "}";
        var expected = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(body))).ToLowerInvariant();
        Assert.Equal(expected, e.Hash);
        Assert.EndsWith($",\"Hash\":\"{expected}\"}}", line);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Zusaetzliches_unbekanntes_Feld_wird_erkannt(bool legacyFormat)
    {
        // Prüfung vom 2026-10-21: Der Hash galt der neu geschriebenen Zeile – ein angehängtes Feld fiel nicht auf
        using var _ = new UiCulture("en");
        if (legacyFormat) WriteLegacy(1); else Log().Write(AuditEventType.SignatureGranted, "LAB\\operator", "windows", "Batch 42");
        var lines = System.IO.File.ReadAllLines(File);
        Assert.True(AuditLog.Verify(File).ok);
        lines[0] = lines[0].Replace("\"Event\":", "\"Approved\":\"yes\",\"Event\":", StringComparison.Ordinal);
        System.IO.File.WriteAllLines(File, lines);
        var (ok, msg) = AuditLog.Verify(File);
        Assert.False(ok);
        Assert.Contains("VIT-0022", msg);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Doppeltes_Feld_und_andere_Schreibweise_werden_erkannt(bool legacyFormat)
    {
        using var _ = new UiCulture("en");
        if (legacyFormat) WriteLegacy(1); else Log().Write(AuditEventType.Unlocked, "LAB\\operator", "windows");
        var original = System.IO.File.ReadAllLines(File)[0];

        // Ein zweites „Actor“ am Anfang: gelesen wird das letzte, gehasht wäre alles – beides darf nicht durchgehen
        System.IO.File.WriteAllText(File, original.Replace("{", "{\"Actor\":\"LAB\\\\someone\",", StringComparison.Ordinal) + "\n");
        Assert.False(AuditLog.Verify(File).ok);

        // Gleicher Inhalt, andere Schreibweise (Leerzeichen)
        System.IO.File.WriteAllText(File, original.Replace(",\"Event\"", ", \"Event\"", StringComparison.Ordinal) + "\n");
        Assert.False(AuditLog.Verify(File).ok);
    }

    [Fact]
    public void Alte_Protokolle_ohne_Format_bleiben_gueltig_und_die_Kette_laeuft_weiter()
    {
        // Zeilen im Format 1 (vor 2026-10-21), danach schreibt die neue Version mit Format 2 weiter
        WriteLegacy(3);
        Assert.True(AuditLog.Verify(File).ok);
        var e = Log().Write(AuditEventType.Locked);
        Assert.Equal(4, e.Seq);
        Assert.Equal(2, e.V);
        var (ok, msg) = AuditLog.Verify(File);
        Assert.True(ok, msg);
    }

    [Fact]
    public void Datei_mit_BOM_und_einer_Zeile_wird_fortgesetzt()
    {
        Log().Write(AuditEventType.Locked);
        var bytes = System.IO.File.ReadAllBytes(File);
        System.IO.File.WriteAllBytes(File, [0xEF, 0xBB, 0xBF, .. bytes]);
        var e = Log().Write(AuditEventType.Unlocked);
        Assert.Equal(2, e.Seq);
        var (ok, msg) = AuditLog.Verify(File);
        Assert.True(ok, msg);
    }

    [Fact]
    public void Unbekanntes_Format_wird_nicht_als_gueltig_gemeldet()
    {
        Log().Write(AuditEventType.Locked);
        var line = System.IO.File.ReadAllLines(File)[0].Replace("{\"V\":2,", "{\"V\":3,", StringComparison.Ordinal);
        System.IO.File.WriteAllText(File, line + "\n");
        Assert.False(AuditLog.Verify(File).ok);
    }

    /// <summary>Zeilen, wie Vitrine sie bis 2026-10-21 schrieb: ohne „V“, Hash über die neu geschriebene Zeile.</summary>
    private void WriteLegacy(int count)
    {
        string? prev = null;
        var sb = new System.Text.StringBuilder();
        var opts = new JsonSerializerOptions
        {
            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
            Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() },
        };
        for (int i = 1; i <= count; i++)
        {
            var entry = new AuditEntry
            {
                Seq = i, Time = _now, Machine = "LAB-PC-07", SessionUser = "LAB\\operator", Event = AuditEventType.Locked,
                Detail = "Trigger: hotkey – ä", Data = new() { ["tid"] = "x" }, Prev = prev,
            };
            entry.Hash = AuditLog.ComputeHash(entry);
            prev = entry.Hash;
            sb.Append(JsonSerializer.Serialize(entry, opts)).Append('\n');
        }
        Directory.CreateDirectory(_dir.Path);
        System.IO.File.WriteAllText(File, sb.ToString());
    }

    [Fact]
    public void Geloeschter_Eintrag_in_der_Mitte_wird_erkannt()
    {
        using var _ = new UiCulture("en");
        var log = Log();
        for (int i = 0; i < 3; i++) log.Write(AuditEventType.Locked);
        var lines = System.IO.File.ReadAllLines(File).ToList();
        lines.RemoveAt(1);
        System.IO.File.WriteAllLines(File, lines);
        var (ok, msg) = AuditLog.Verify(File);
        Assert.False(ok);
        Assert.Contains("VIT-0021", msg);
    }

    [Fact]
    public void Neu_berechnete_Kette_faellt_ohne_Schutz_durch_Dateirechte_nicht_auf()
    {
        // Dokumentierte Grenze (docs/limitations.md): Wer die Datei schreiben darf, kann alle Hashes neu berechnen.
        var log = Log();
        log.Write(AuditEventType.UnlockFailed, "LAB\\mallory");
        var line = JsonNode.Parse(System.IO.File.ReadAllLines(File)[0])!.AsObject();
        line["Actor"] = "LAB\\someone";
        line.Remove("Hash");
        var opts = new JsonSerializerOptions
        {
            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
            Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() },
        };
        var entry = JsonSerializer.Deserialize<AuditEntry>(line.ToJsonString(), opts)!;
        entry.Hash = AuditLog.ComputeHash(entry);
        // In Vitrines eigener Schreibweise – dann hilft auch Format 2 nicht
        System.IO.File.WriteAllText(File, JsonSerializer.Serialize(entry, opts) + "\n");
        Assert.True(AuditLog.Verify(File).ok);
    }

    [Fact]
    public void Unlesbare_Zeile_wird_gemeldet_statt_abzustuerzen()
    {
        using var _ = new UiCulture("en");
        Log().Write(AuditEventType.Locked);
        System.IO.File.AppendAllText(File, "{ kaputt\n");
        var (ok, msg) = AuditLog.Verify(File);
        Assert.False(ok);
        Assert.Contains("VIT-0020", msg);
    }

    [Fact]
    public void Kaputte_letzte_Zeile_startet_eine_neue_Kette_der_Bruch_bleibt_sichtbar()
    {
        Log().Write(AuditEventType.Locked);
        System.IO.File.AppendAllText(File, "{ kaputt\n");
        var e = Log().Write(AuditEventType.Unlocked);
        Assert.Null(e.Prev);
        Assert.False(AuditLog.Verify(File).ok);
    }

    [Fact]
    public void Neuer_Monat_neue_Datei_mit_neuer_Kette()
    {
        var log = Log();
        log.Write(AuditEventType.Locked);
        _now = new DateTimeOffset(2026, 11, 1, 0, 0, 1, TimeSpan.Zero);
        var e = log.Write(AuditEventType.Unlocked);
        Assert.Equal(1, e.Seq);
        Assert.Null(e.Prev);
        Assert.True(System.IO.File.Exists(Path.Combine(_dir.Path, "audit-2026-11.jsonl")));
        Assert.Equal(Path.Combine(_dir.Path, "audit-2026-11.jsonl"), log.CurrentFile());
    }

    [Fact]
    public void Ausgeschaltet_wird_nichts_geschrieben()
    {
        Log(enabled: false).Write(AuditEventType.Locked);
        Assert.False(System.IO.File.Exists(File));
    }

    [Fact]
    public void Zusatzziel_bekommt_jeden_Eintrag_und_darf_scheitern()
    {
        var sink = new ListSink();
        var log = Log(sink);
        log.Write(AuditEventType.Locked);
        Assert.Single(sink.Entries);
        sink.Throw = true;
        log.Write(AuditEventType.Unlocked); // keine Ausnahme
        Assert.True(AuditLog.Verify(File).ok);
    }

    [Fact]
    public void LastLine_liest_auch_lange_Dateien()
    {
        var log = Log();
        for (int i = 0; i < 2000; i++) log.Write(AuditEventType.PromptShown, detail: new string('x', 100));
        var last = AuditLog.LastLine(File)!;
        Assert.Equal(2000, AuditLog.Parse(last)!.Seq);
    }

    private sealed class ListSink : IAuditSink
    {
        public List<AuditEntry> Entries { get; } = new();
        public bool Throw { get; set; }

        public void Write(AuditEntry entry)
        {
            if (Throw) throw new InvalidOperationException("event log broken");
            Entries.Add(entry);
        }
    }
}

public sealed class AuditDetailsTests
{
    [Theory]
    [InlineData(0, 0, 12, 31, "Locked for 00:12:31")]
    [InlineData(0, 23, 59, 59, "Locked for 23:59:59")]
    [InlineData(2, 14, 0, 0, "Locked for 62:00:00")] // vorher „14:00:00“
    [InlineData(40, 0, 0, 1, "Locked for 960:00:01")]
    public void Dauer_der_Sperre_mit_allen_Stunden(int days, int hours, int minutes, int seconds, string expected) =>
        Assert.Equal(expected, AuditDetails.LockedFor(new TimeSpan(days, hours, minutes, seconds)));

    [Fact]
    public void Negative_Dauer_wird_null()
        => Assert.Equal("Locked for 00:00:00", AuditDetails.LockedFor(TimeSpan.FromSeconds(-5)));

    [Fact]
    public void Erkennt_das_Detail_fuer_die_Anzeige()
    {
        Assert.True(AuditDetails.TryLockedFor("Locked for 62:00:00", out var d));
        Assert.Equal("62:00:00", d);
        Assert.False(AuditDetails.TryLockedFor("Trigger: hotkey", out _));
        Assert.False(AuditDetails.TryLockedFor(null, out _));
    }
}
