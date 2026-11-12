// SPDX-License-Identifier: MIT
using System.Runtime.InteropServices;
using System.Text;
using Vitrine.Abstractions;
using Vitrine.Core.Audit;
using Vitrine.Core.Config;
using Vitrine.Core.Localization;
using Vitrine.Core.Service;
using Vitrine.Services.Interop;
using Vitrine.Services.Supervisor;
using Vitrine.Tests.Audit;
using Vitrine.Tests.TestSupport;

namespace Vitrine.Tests.Windows;

/// <summary>
/// Protokoll-Pipe von Ende zu Ende im Testprozess (#15, Regression vom Gerätetest 2026-10-26): echter
/// <see cref="AuditServer"/> mit echter Prüfung der Gegenstelle und echtem <see cref="AuditBroker"/>, echter
/// <see cref="AuditLink"/> – unter einem eigenen Pipe-Namen, mit Schlüssel im Speicher und Protokoll im Temp-Ordner.
/// Kein Dienst, keine Registry, nichts gesperrt. Vor der Korrektur kam hier kein einziger Eintrag an: Der Server schloss
/// jede Verbindung still, weil das Feststellen des Benutzers unter der Identität der Gegenstelle eine Assembly laden wollte.
/// </summary>
public sealed class AuditPipeTests : IDisposable
{
    private sealed class NoVerifier : ISignatureVerifier
    {
        public Task<AuthOutcome> WindowsAsync(string user, string? domain, string secret, string clientSid) =>
            Task.FromResult(AuthOutcome.Fail("not in tests", ErrorCodes.SignInFailed));

        public Task<string?> EntraKeysAsync(string tenant, string clientId, bool refresh) => Task.FromResult<string?>(null);
        public string? ResolveSid(string name) => null;
    }

    private readonly TempDir _dir = new();
    private readonly CancellationTokenSource _stop = new();
    private readonly List<string> _serverErrors = [];
    private readonly string _pipe = $"ICT-Baden.Vitrine.Test.{Guid.NewGuid():N}";

    public void Dispose()
    {
        _stop.Cancel();
        _dir.Dispose();
    }

    private void StartServer(string exe)
    {
        var log = new SignedAuditLog(() => new AuditSettings { Directory = _dir.Path, EventLog = false }, new MemoryKeyStore(),
            new MemoryAnchorStore(), null, null, "LAB-PC-07");
        var broker = new AuditBroker(log, new NoVerifier(), () => new VitrineConfig());
        var server = new AuditServer(broker, exe, e => { lock (_serverErrors) _serverErrors.Add(e); }, _pipe);
        _ = Task.Run(() => server.RunAsync(_stop.Token));
    }

    // Testserver läuft in der Sitzung des Tests, nicht in Sitzung 0
    private AuditLink Link(Func<DateTimeOffset>? clock = null) => new(_pipe, _ => true, clock);

    private string LogText() => string.Join("\n", Directory.GetFiles(_dir.Path, "audit-*.jsonl").Select(File.ReadAllText));

    private string Errors() { lock (_serverErrors) return string.Join(" | ", _serverErrors); }

    // ---------------- Prüfung der Gegenstelle mit den echten Windows-Funktionen ----------------

    [Fact]
    public void Pfad_des_eigenen_Prozesses_mit_QueryFullProcessImageName()
    {
        var path = Native.ProcessPath((uint)Environment.ProcessId);
        Assert.True(ExecutablePath.Same(path, Environment.ProcessPath), $"{path} <> {Environment.ProcessPath}");
    }

    [Fact]
    public void Dienstprüfung_nimmt_den_eigenen_Prozess_an()
    {
        var self = Environment.ProcessPath!;
        Assert.True(ClientProcess.Check((uint)Environment.ProcessId, self).Verdict.Accepted);
        // Andere Schreibweise des Dienstpfads (Groß/klein, \\?\-Präfix) ändert nichts
        Assert.True(ClientProcess.Check((uint)Environment.ProcessId, self.ToUpperInvariant()).Verdict.Accepted);
        Assert.True(ClientProcess.Check((uint)Environment.ProcessId, @"\\?\" + self).Verdict.Accepted);
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern uint GetShortPathNameW(string longPath, StringBuilder shortPath, uint size);

    [Fact]
    public void Dienstprüfung_nimmt_den_8_3_Namen_derselben_Datei_an()
    {
        var self = Environment.ProcessPath!;
        var sb = new StringBuilder(1024);
        var n = GetShortPathNameW(self, sb, (uint)sb.Capacity);
        if (n == 0 || string.Equals(sb.ToString(), self, StringComparison.OrdinalIgnoreCase)) return; // keine 8.3-Namen auf diesem Laufwerk
        Assert.True(ClientProcess.Check((uint)Environment.ProcessId, sb.ToString()).Verdict.Accepted);
    }

    [Fact]
    public void Dienstprüfung_lehnt_eine_andere_Exe_mit_Grund_ab()
    {
        var other = Path.Combine(Environment.SystemDirectory, "cmd.exe");
        var r = ClientProcess.Check((uint)Environment.ProcessId, other);
        Assert.False(r.Verdict.Accepted);
        var text = r.Describe(other);
        Assert.Contains(Environment.ProcessPath!, text, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(other, text, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Dienstprüfung_lehnt_einen_beendeten_Prozess_ab()
    {
        // PID 0 (Leerlaufprozess) lässt sich nicht öffnen
        Assert.False(ClientProcess.Check(0, Environment.ProcessPath!).Verdict.Accepted);
    }

    // ---------------- Von Ende zu Ende ----------------

    [Fact]
    public async Task Einträge_der_App_landen_signiert_im_Protokoll_des_Dienstes()
    {
        StartServer(Environment.ProcessPath!);
        using var link = Link();
        var app = new AuditLog(new AuditSettings { Directory = _dir.Path, EventLog = false }, "operator");
        app.UseForwarder(link);
        AuditEntry? committed = null;
        link.Start();
        app.Write(AuditEventType.Unlocked, "operator", "windows", committed: e => committed = e);
        await WaitUntil(() => link.Pending == 0 && committed is not null);
        Assert.True(link.Pending == 0, $"pending {link.Pending}, server: {Errors()}");
        Assert.Equal(AuditFormat.Signed, committed!.V);
        var text = LogText();
        Assert.Contains("\"Event\":\"Unlocked\"", text, StringComparison.Ordinal);
        Assert.Contains("\"Assurance\":\"client\"", text, StringComparison.Ordinal);
        // Benutzer aus dem Token der Gegenstelle (nicht aus der Anfrage)
        Assert.Contains(System.Text.Json.JsonSerializer.Serialize(System.Security.Principal.WindowsIdentity.GetCurrent().Name), text, StringComparison.Ordinal);
        Assert.Empty(Errors());
    }

    [Fact]
    public async Task Ohne_Dienst_gepufferte_Einträge_kommen_an_sobald_er_da_ist()
    {
        using var link = Link();
        var app = new AuditLog(new AuditSettings { Directory = _dir.Path, EventLog = false }, "operator");
        app.UseForwarder(link);
        link.Start();
        app.Write(AuditEventType.Locked, detail: "Trigger: test");
        app.Write(AuditEventType.Unlocked, "operator", "windows");
        await Task.Delay(700);
        Assert.Equal(2, link.Pending);

        StartServer(Environment.ProcessPath!);
        await WaitUntil(() => link.Pending == 0, TimeSpan.FromSeconds(20));
        Assert.True(link.Pending == 0, $"pending {link.Pending}, server: {Errors()}");
        var text = LogText();
        Assert.True(text.IndexOf("\"Event\":\"Locked\"", StringComparison.Ordinal) < text.IndexOf("\"Event\":\"Unlocked\"", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Abgelehnte_App_wird_beim_Dienst_und_in_der_App_sichtbar()
    {
        var other = Path.Combine(Environment.SystemDirectory, "cmd.exe");
        StartServer(other);
        var now = DateTimeOffset.UtcNow;
        using var link = Link(() => now);
        var reports = new List<AuditDeliveryReport>();
        link.Delivery += r => { lock (reports) reports.Add(r); };
        var app = new AuditLog(new AuditSettings { Directory = _dir.Path, EventLog = false }, "operator");
        app.UseForwarder(link);
        link.Start();
        app.Write(AuditEventType.Unlocked, "operator", "windows");

        await WaitUntil(() => Errors().Length > 0);
        var error = Errors();
        Assert.Contains(ErrorCodes.AuditClientRejected, error, StringComparison.Ordinal);
        Assert.Contains($"PID {Environment.ProcessId}", error, StringComparison.Ordinal);
        Assert.Contains(Environment.ProcessPath!, error, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(other, error, StringComparison.OrdinalIgnoreCase);

        await WaitUntil(() => link.Pending == 1 && !link.Connected);
        now += AuditOutbox.ReportAfter;
        link.CheckDelivery();
        var report = Assert.Single(reports);
        Assert.Equal(AuditDeliveryProblem.ClosedWithoutAnswer, report.Problem);
        Assert.NotNull(link.Problem);
        Assert.DoesNotContain("Unlocked", LogText(), StringComparison.Ordinal);
        // Beim Beenden: Eintrag kommt heraus (für den Ersatzordner pro Benutzer)
        Assert.Equal(AuditEventType.Unlocked, Assert.Single(link.TakeUnsent()).Event);
    }

    private static async Task WaitUntil(Func<bool> condition, TimeSpan? timeout = null)
    {
        var until = DateTime.UtcNow + (timeout ?? TimeSpan.FromSeconds(10));
        while (!condition() && DateTime.UtcNow < until) await Task.Delay(25);
    }
}
