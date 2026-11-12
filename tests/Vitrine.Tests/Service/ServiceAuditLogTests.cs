// SPDX-License-Identifier: MIT
using System.Text.RegularExpressions;
using Vitrine.Core.Audit;
using Vitrine.Core.Config;
using Vitrine.Core.Service;
using Vitrine.Tests.Audit;
using Vitrine.Tests.TestSupport;

namespace Vitrine.Tests.Service;

/// <summary>
/// Der Dienst schreibt nur über <see cref="ServiceAuditLog"/>: signiert, solange er das Protokoll übernommen hat. Prüfung
/// vom 2026-10-26: Das Aufräumen von Win+L nach einem Absturz der App schrieb am signierten Protokoll vorbei eine
/// unsignierte Zeile in die Monatsdatei – danach meldete --verify-log VIT-0308.
/// </summary>
public sealed class ServiceAuditLogTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly DateTimeOffset _now = new(2026, 10, 19, 8, 0, 0, TimeSpan.Zero);

    public void Dispose() => _dir.Dispose();

    [Fact]
    public void Eintraege_nach_Verlust_der_App_und_Win_L_Aufraeumen_bleiben_signiert_und_pruefbar()
    {
        var settings = new AuditSettings { Directory = _dir.Path, EventLog = false };
        var log = new ServiceAuditLog(new AuditLog(settings, "SYSTEM", null, () => _now))
        {
            Signed = new SignedAuditLog(() => settings, new MemoryKeyStore(), new MemoryAnchorStore(), null, () => _now, "LAB-PC-07"),
        };
        log.Write(AuditEventType.ServiceStarted, "Version 0.1.1");
        log.Write(AuditEventType.AgentLost, "Session 2: locked");
        log.Write(AuditEventType.AgentLost, "Session 2: DisableLockWorkstation removed");
        log.Write(AuditEventType.Error, "Session 2: DisableLockWorkstation not removed: access denied");
        var file = Path.Combine(_dir.Path, "audit-2026-10.jsonl");
        Assert.All(File.ReadAllLines(file), l => Assert.Equal(AuditFormat.Signed, AuditLog.Parse(l)!.V));
        using var _ = new UiCulture("en");
        var r = AuditVerifier.VerifyFile(file, AuditVerifyOptions.ForPath(file));
        Assert.True(r.Ok, r.Message);
        Assert.Equal(0, r.UnsignedEntries);
    }

    [Fact]
    public void Ohne_Schluessel_schreibt_der_Dienst_wie_bisher()
    {
        var settings = new AuditSettings { Directory = _dir.Path, EventLog = false };
        var log = new ServiceAuditLog(new AuditLog(settings, "SYSTEM", null, () => _now));
        Assert.Equal(AuditFormat.Local, log.Write(AuditEventType.ServiceStarted)!.V);
    }

    [Fact]
    public void Der_Dienst_schreibt_nirgends_am_ServiceAuditLog_vorbei()
    {
        var source = File.ReadAllText(Path.Combine(RepoPaths.Root, "src/Vitrine/Services/Supervisor/VitrineService.cs"));
        Assert.DoesNotMatch(new Regex(@"\.Write\(\s*AuditEventType"), source);
        Assert.DoesNotMatch(new Regex(@"\bnew SignedAuditLog\([^)]*\)\s*\.\s*Write"), source);
    }
}
