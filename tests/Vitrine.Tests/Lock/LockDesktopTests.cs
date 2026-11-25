// SPDX-License-Identifier: MIT
using Vitrine.Abstractions;
using Vitrine.Core.Audit;
using Vitrine.Core.Config;
using Vitrine.Core.Localization;
using Vitrine.Core.Lock;

namespace Vitrine.Tests.Lock;

/// <summary>Sperre mit eigenem Desktop und Erkennung von Desktop-Wechseln – mit Attrappe, ohne echte Desktops.</summary>
public sealed class LockDesktopTests
{
    private sealed class FakeDesktop : ILockDesktop
    {
        public string LockDesktopName { get; } = "Vitrine-Lock-0123456789abcdef";
        public bool CreateWorks = true, ToLockWorks = true, ToDefaultWorks = true;
        public bool Created;
        public string? Input = "Default";
        public int SwitchesToLock, SwitchesToDefault;
        public int LastError { get; private set; }

        public bool Create()
        {
            if (!CreateWorks) { LastError = 5; return false; }
            Created = true;
            return true;
        }

        public bool SwitchToLock()
        {
            SwitchesToLock++;
            if (!ToLockWorks) { LastError = 5; return false; }
            Input = LockDesktopName;
            return true;
        }

        public bool SwitchToDefault()
        {
            SwitchesToDefault++;
            if (!ToDefaultWorks) { LastError = 5; return false; }
            Input = "Default";
            return true;
        }

        public string? InputDesktopName() => Input;

        /// <summary>Sitzung zeigt einen sicheren Desktop (Sperre, Strg+Alt+Entf, UAC).</summary>
        public bool SecurePrompt;
        public bool SecureDesktopExpected() => SecurePrompt;
    }

    private static (DesktopLockSession Session, FakeDesktop Desktop) Engaged()
    {
        var d = new FakeDesktop();
        var s = new DesktopLockSession(d);
        Assert.Empty(s.Lock(LockMode.Desktop, () => true, () => { }));
        return (s, d);
    }

    [Fact]
    public void Standard_ist_der_Abdeckungs_Modus_mit_Vorschau_alle_2_Sekunden()
    {
        var l = new LockSettings();
        Assert.Equal(LockMode.Overlay, l.Mode);
        Assert.True(l.DesktopShowPreview);
        Assert.Equal(2, l.DesktopPreviewSeconds);
    }

    [Fact]
    public void Abdeckungs_Modus_legt_keinen_Desktop_an()
    {
        var d = new FakeDesktop();
        var s = new DesktopLockSession(d);
        bool ui = false;
        Assert.Empty(s.Lock(LockMode.Overlay, () => ui = true, () => { }));
        Assert.False(d.Created);
        Assert.False(ui);
        Assert.False(s.Engaged);
        Assert.Equal(DesktopTarget.Default, s.Expected);
        Assert.True(s.Locked);
    }

    [Fact]
    public void Desktop_Modus_baut_erst_die_Oberflaeche_auf_und_wechselt_dann()
    {
        var d = new FakeDesktop();
        var s = new DesktopLockSession(d);
        var order = new List<string>();
        var audit = s.Lock(LockMode.Desktop, () => { order.Add($"ui (input {d.Input})"); return true; }, () => { });
        Assert.Empty(audit);
        Assert.Equal(["ui (input Default)"], order);
        Assert.True(s.OnLockDesktop);
        Assert.Equal(d.LockDesktopName, d.Input);
    }

    [Fact]
    public void Desktop_nicht_anlegbar_bleibt_bei_Abdeckungen_VIT0450()
    {
        var d = new FakeDesktop { CreateWorks = false };
        var s = new DesktopLockSession(d);
        var audit = s.Lock(LockMode.Desktop, () => true, () => { });
        Assert.StartsWith(ErrorCodes.LockDesktopCreateFailed, Assert.Single(audit).Detail);
        Assert.Equal(AuditEventType.Error, audit[0].Event);
        Assert.False(s.Engaged);
        Assert.Equal(0, d.SwitchesToLock);
        Assert.True(s.Locked);
    }

    [Fact]
    public void Oberflaeche_scheitert_oder_wirft_dann_Abdeckungen_VIT0453_und_Abbau()
    {
        foreach (Func<bool> ui in new Func<bool>[] { () => false, () => throw new InvalidOperationException("boom") })
        {
            var d = new FakeDesktop();
            var s = new DesktopLockSession(d);
            bool closed = false;
            var audit = s.Lock(LockMode.Desktop, ui, () => closed = true);
            Assert.StartsWith(ErrorCodes.LockDesktopUiFailed, Assert.Single(audit).Detail);
            Assert.True(closed);
            Assert.False(s.Engaged);
            Assert.Equal(0, d.SwitchesToLock);
        }
    }

    [Fact]
    public void Wechsel_scheitert_dann_Abdeckungen_VIT0451_und_Abbau()
    {
        var d = new FakeDesktop { ToLockWorks = false };
        var s = new DesktopLockSession(d);
        bool closed = false;
        var audit = s.Lock(LockMode.Desktop, () => true, () => closed = true);
        Assert.StartsWith(ErrorCodes.LockDesktopSwitchFailed, Assert.Single(audit).Detail);
        Assert.True(closed);
        Assert.False(s.Engaged);
        Assert.Equal(DesktopTarget.Default, s.Expected);
        // Danach ist der Windows-Desktop der erwartete – keine Flucht-Meldung
        Assert.Equal(GuardAction.None, s.Poll().Action);
    }

    [Fact]
    public void Eigener_Wechsel_gilt_nie_als_Flucht()
    {
        var (s, d) = Engaged();
        Assert.Same(GuardResult.Nothing, s.Poll());
        Assert.Empty(s.HandOff("sign-in"));
        Assert.Equal("Default", d.Input);
        Assert.Same(GuardResult.Nothing, s.Poll());
        Assert.Empty(s.Resume(() => { }));
        Assert.Same(GuardResult.Nothing, s.Poll());
        Assert.Empty(s.Unlock());
        Assert.Same(GuardResult.Nothing, s.Poll());
    }

    [Fact]
    public void Flucht_auf_den_Windows_Desktop_wird_einmal_gemeldet_und_zurueckgeschaltet()
    {
        var (s, d) = Engaged();
        d.Input = "Default"; // z. B. Task-Manager aus dem Strg+Alt+Entf-Menü
        var r = s.Poll();
        Assert.Equal(GuardAction.Restored, r.Action);
        var e = Assert.Single(r.Audit);
        Assert.Equal(AuditEventType.DesktopSwitchDetected, e.Event);
        Assert.Contains("Input desktop Default", e.Detail);
        Assert.Contains(d.LockDesktopName, e.Detail);
        Assert.Equal(d.LockDesktopName, d.Input);
    }

    [Fact]
    public void Ein_Vorfall_ein_Eintrag_auch_wenn_es_mehrmals_versucht_wird()
    {
        var (s, d) = Engaged();
        d.ToLockWorks = false;
        d.Input = "Default";
        Assert.Single(s.Poll().Audit);
        Assert.Empty(s.Poll().Audit);
        // Wieder auf dem Sperr-Desktop: Vorfall vorbei; der nächste wird wieder gemeldet
        d.ToLockWorks = true;
        d.Input = d.LockDesktopName;
        Assert.Same(GuardResult.Nothing, s.Poll());
        d.Input = "Default";
        Assert.Single(s.Poll().Audit);
    }

    [Fact]
    public void Nach_drei_gescheiterten_Versuchen_wird_Windows_gesperrt_VIT0452()
    {
        var (s, d) = Engaged();
        d.ToLockWorks = false;
        d.Input = "Default";
        Assert.Equal(GuardAction.None, s.Poll().Action);
        Assert.Equal(GuardAction.None, s.Poll().Action);
        var r = s.Poll();
        Assert.Equal(GuardAction.FallbackLock, r.Action);
        Assert.Contains(r.Audit, a => a.Detail.StartsWith(ErrorCodes.LockDesktopRestoreFailed, StringComparison.Ordinal));
        Assert.Equal(DesktopLockSession.MaxRestoreFailures, d.SwitchesToLock - 1);
    }

    [Fact]
    public void Sicherer_Desktop_von_Windows_bleibt_unberuehrt_und_wird_im_Eintrag_genannt()
    {
        var (s, d) = Engaged();
        d.SecurePrompt = true;
        foreach (var secure in new string?[] { null, "Winlogon", "winlogon", "Screen-saver", "Disconnect" })
        {
            d.Input = secure;
            for (int i = 0; i < 10; i++) Assert.Same(GuardResult.Nothing, s.Poll());
        }
        d.SecurePrompt = false;
        Assert.Equal(1, d.SwitchesToLock);
        // Zurück von Strg+Alt+Entf, aber auf dem Windows-Desktop statt dem Sperr-Desktop
        d.Input = "Default";
        var e = Assert.Single(s.Poll().Audit);
        Assert.Contains("after a secure desktop", e.Detail);
    }

    [Theory]
    [InlineData(LockMode.Desktop)]
    [InlineData(LockMode.Overlay)]
    public void Nicht_lesbarer_Desktop_ohne_sicheren_Zustand_der_Sitzung_gilt_nach_kurzer_Frist_als_fremd(LockMode mode)
    {
        // Befund M2: Ein Programm des Benutzers legt einen Desktop an, dessen Zugriffsliste den Benutzer aussperrt
        var d = new FakeDesktop();
        var s = new DesktopLockSession(d);
        s.Lock(mode, () => true, () => { });
        d.Input = null;
        for (int i = 1; i < DesktopLockSession.UnverifiedSecureGrace; i++) Assert.Same(GuardResult.Nothing, s.Poll());
        var r = s.Poll();
        Assert.Equal(GuardAction.Restored, r.Action);
        var e = Assert.Single(r.Audit);
        Assert.Equal(AuditEventType.DesktopSwitchDetected, e.Event);
        Assert.Contains("unreadable desktop", e.Detail);
        Assert.Contains("no Windows sign-in", e.Detail);
    }

    [Fact]
    public void Nicht_lesbarer_fremder_Desktop_ohne_Rueckweg_fuehrt_zur_Windows_Sperre()
    {
        var (s, d) = Engaged();
        d.Input = null;
        d.ToLockWorks = false;
        var actions = Enumerable.Range(0, DesktopLockSession.UnverifiedSecureGrace + DesktopLockSession.MaxRestoreFailures - 1)
            .Select(_ => s.Poll()).ToList();
        Assert.Equal(GuardAction.FallbackLock, actions[^1].Action);
        Assert.Contains(actions[^1].Audit, a => a.Detail.Contains("unreadable desktop") && a.Detail.StartsWith(ErrorCodes.LockDesktopRestoreFailed, StringComparison.Ordinal));
    }

    [Fact]
    public void Als_Screen_saver_getarnter_Desktop_ohne_Bildschirmschoner_gilt_als_fremd()
    {
        var (s, d) = Engaged();
        d.Input = "Screen-saver";
        GuardResult r = GuardResult.Nothing;
        for (int i = 0; i < DesktopLockSession.UnverifiedSecureGrace; i++) r = s.Poll();
        Assert.Equal(GuardAction.Restored, r.Action);
        Assert.Contains("Input desktop Screen-saver", Assert.Single(r.Audit).Detail);
    }

    [Fact]
    public void Kurzer_Winlogon_Desktop_vor_LogonUI_loest_keinen_Alarm_aus()
    {
        var (s, d) = Engaged();
        d.Input = null;
        for (int i = 1; i < DesktopLockSession.UnverifiedSecureGrace; i++) Assert.Same(GuardResult.Nothing, s.Poll());
        // Jetzt läuft LogonUI (Strg+Alt+Entf-Bildschirm): bleibt ruhig, auch lange
        d.SecurePrompt = true;
        for (int i = 0; i < 20; i++) Assert.Same(GuardResult.Nothing, s.Poll());
        // Zurück auf dem Sperr-Desktop, dann wieder kurz nicht lesbar: Frist beginnt von vorn
        d.SecurePrompt = false;
        d.Input = d.LockDesktopName;
        Assert.Same(GuardResult.Nothing, s.Poll());
        d.Input = null;
        for (int i = 1; i < DesktopLockSession.UnverifiedSecureGrace; i++) Assert.Same(GuardResult.Nothing, s.Poll());
    }

    [Fact]
    public void Entsperrt_wird_ein_nicht_lesbarer_Desktop_nicht_angefasst()
    {
        var d = new FakeDesktop { Input = null };
        var s = new DesktopLockSession(d);
        for (int i = 0; i < 10; i++) Assert.Same(GuardResult.Nothing, s.Poll());
        Assert.Equal(0, d.SwitchesToDefault);
    }

    [Fact]
    public void Abdeckungs_Modus_erkennt_fremde_Desktops_anderer_Programme()
    {
        var d = new FakeDesktop();
        var s = new DesktopLockSession(d);
        s.Lock(LockMode.Overlay, () => true, () => { });
        Assert.Same(GuardResult.Nothing, s.Poll());
        d.Input = "Sysinternals Desktop 1";
        var r = s.Poll();
        Assert.Equal(GuardAction.Restored, r.Action);
        Assert.Contains("expected Default", Assert.Single(r.Audit).Detail);
        Assert.Equal("Default", d.Input);
    }

    [Fact]
    public void Entsperrt_wird_ein_fremder_Desktop_nicht_angefasst()
    {
        var d = new FakeDesktop { Input = "Sysinternals Desktop 1" };
        var s = new DesktopLockSession(d);
        Assert.Same(GuardResult.Nothing, s.Poll());
        Assert.Equal(0, d.SwitchesToDefault);
    }

    [Fact]
    public void Entsperrt_wird_ein_liegen_gebliebener_Sperr_Desktop_verlassen_VIT0455_einmal()
    {
        var d = new FakeDesktop { Input = "Vitrine-Lock-deadbeefdeadbeef", ToDefaultWorks = false };
        var s = new DesktopLockSession(d);
        var r = s.Poll();
        Assert.StartsWith(ErrorCodes.LockDesktopStranded, Assert.Single(r.Audit).Detail);
        Assert.Empty(s.Poll().Audit);
        d.ToDefaultWorks = true;
        Assert.Equal(GuardAction.Restored, s.Poll().Action);
        Assert.Equal("Default", d.Input);
    }

    [Fact]
    public void Entsperren_schaltet_zurueck_und_meldet_Scheitern_VIT0454()
    {
        var (s, d) = Engaged();
        d.ToDefaultWorks = false;
        var audit = s.Unlock();
        Assert.StartsWith(ErrorCodes.LockDesktopReturnFailed, Assert.Single(audit).Detail);
        Assert.Equal(3, d.SwitchesToDefault);
        Assert.False(s.Engaged);
        Assert.False(s.Locked);
        // Die Prüfung versucht es weiter
        d.ToDefaultWorks = true;
        Assert.Equal(GuardAction.Restored, s.Poll().Action);
    }

    [Fact]
    public void Externe_Anmeldung_scheitert_am_Wechsel_dann_bleibt_der_Sperr_Desktop()
    {
        var (s, d) = Engaged();
        d.ToDefaultWorks = false;
        Assert.StartsWith(ErrorCodes.LockDesktopReturnFailed, Assert.Single(s.HandOff("sign-in")).Detail);
        Assert.True(s.OnLockDesktop);
    }

    [Fact]
    public void Zurueck_nach_externer_Anmeldung_scheitert_dann_Abdeckungen_fuer_den_Rest()
    {
        var (s, d) = Engaged();
        s.HandOff("sign-in");
        d.ToLockWorks = false;
        bool closed = false;
        Assert.StartsWith(ErrorCodes.LockDesktopSwitchFailed, Assert.Single(s.Resume(() => closed = true)).Detail);
        Assert.True(closed);
        Assert.False(s.Engaged);
        Assert.Equal(DesktopTarget.Default, s.Expected);
        Assert.Same(GuardResult.Nothing, s.Poll());
    }

    [Fact]
    public void Ausgefallene_Oberflaeche_fuehrt_zurueck_zu_den_Abdeckungen()
    {
        var (s, d) = Engaged();
        Assert.Empty(s.Abandon());
        Assert.True(s.Locked);
        Assert.False(s.Engaged);
        Assert.Equal("Default", d.Input);
        Assert.Same(GuardResult.Nothing, s.Poll());
        Assert.Empty(s.Abandon());
    }

    [Fact]
    public void Ausgefallene_Oberflaeche_ohne_Rueckweg_wird_von_der_Pruefung_weiter_versucht()
    {
        var (s, d) = Engaged();
        d.ToDefaultWorks = false;
        Assert.StartsWith(ErrorCodes.LockDesktopReturnFailed, Assert.Single(s.Abandon()).Detail);
        d.ToDefaultWorks = true;
        var r = s.Poll();
        Assert.Equal(GuardAction.Restored, r.Action);
        Assert.Equal(AuditEventType.DesktopSwitchDetected, Assert.Single(r.Audit).Event);
    }

    [Fact]
    public void HandOff_und_Resume_ohne_eigenen_Desktop_tun_nichts()
    {
        var d = new FakeDesktop();
        var s = new DesktopLockSession(d);
        s.Lock(LockMode.Overlay, () => true, () => { });
        Assert.Empty(s.HandOff("x"));
        Assert.Empty(s.Resume(() => { }));
        Assert.Equal(0, d.SwitchesToDefault + d.SwitchesToLock);
    }

    [Fact]
    public void Windows_Sperre_waehrend_der_Sperre_wird_gemeldet_mit_Ursache()
    {
        var (s, _) = Engaged();
        var now = DateTimeOffset.UtcNow;
        var e = s.WindowsLocked(now)!;
        Assert.Equal(AuditEventType.WindowsLockDetected, e.Event);
        Assert.Contains("not caused by Vitrine", e.Detail);
        Assert.Contains("on the lock desktop", e.Detail);

        s.NoteFallbackLock(now);
        Assert.Contains("caused by Vitrine's fallback lock", s.WindowsLocked(now.AddSeconds(3))!.Detail);
        Assert.Contains("not caused", s.WindowsLocked(now.AddSeconds(30))!.Detail);
    }

    [Fact]
    public void Windows_Sperre_ohne_Vitrine_Sperre_wird_nicht_gemeldet()
    {
        var s = new DesktopLockSession(new FakeDesktop());
        Assert.Null(s.WindowsLocked(DateTimeOffset.UtcNow));
        s.Lock(LockMode.Overlay, () => true, () => { });
        Assert.Contains("overlay mode", s.WindowsLocked(DateTimeOffset.UtcNow)!.Detail);
        s.Unlock();
        Assert.Null(s.WindowsLocked(DateTimeOffset.UtcNow));
    }

    [Theory]
    [InlineData(AuthInputKind.External, true)]
    [InlineData(AuthInputKind.UsernamePassword, false)]
    [InlineData(AuthInputKind.Secret, false)]
    public void Nur_externe_Anmeldungen_brauchen_den_Windows_Desktop(AuthInputKind input, bool needs) =>
        Assert.Equal(needs, DesktopSignIn.NeedsWindowsDesktop(input));

    [Theory]
    [InlineData("fido", AuthInputKind.External, true)]
    [InlineData("fido", AuthInputKind.Secret, true)] // Sicherheitsschlüssel: Windows-Sicherheitsdialog, auch wenn die Eingabeart anders lautet
    [InlineData("FIDO", AuthInputKind.UsernamePassword, true)]
    [InlineData("hello", AuthInputKind.External, true)]
    [InlineData("entra", AuthInputKind.External, true)]
    [InlineData("windowslogon", AuthInputKind.External, true)]
    [InlineData("windows", AuthInputKind.UsernamePassword, false)]
    [InlineData("pin", AuthInputKind.Secret, false)]
    [InlineData("acme-plugin", AuthInputKind.External, true)]
    public void Sicherheitsschluessel_und_andere_externe_Verfahren_wechseln_zum_Windows_Desktop(string id, AuthInputKind input, bool needs) =>
        Assert.Equal(needs, DesktopSignIn.NeedsWindowsDesktop(id, input));

    [Theory]
    [InlineData("Vitrine-Lock-0123456789abcdef", true)]
    [InlineData("vitrine-lock-x", true)]
    [InlineData("Default", false)]
    [InlineData("Winlogon", false)]
    [InlineData(null, false)]
    [InlineData("Sysinternals Desktop 1", false)]
    public void Waechter_schaltet_nur_von_eigenen_Sperr_Desktops_zurueck(string? input, bool expected) =>
        Assert.Equal(expected, DesktopRecovery.MustSwitchToDefault(input));

    [Fact]
    public void Name_des_Sperr_Desktops_ist_zufaellig_und_erkennbar()
    {
        var a = LockDesktopNames.NewLockDesktopName();
        var b = LockDesktopNames.NewLockDesktopName();
        Assert.NotEqual(a, b);
        Assert.True(LockDesktopNames.IsOwnLockDesktop(a));
        Assert.Matches("^Vitrine-Lock-[0-9a-f]{16}$", a);
    }

    [Fact]
    public void Ereignis_IDs_der_Version_0_5_sind_fest()
    {
        // Ereignis-ID = 1000 + Nummer; Filter in SIEM-Systemen hängen daran (docs/audit-log.md)
        Assert.Equal(1024, 1000 + (int)AuditEventType.UnlockBypass);
        Assert.Equal(1025, 1000 + (int)AuditEventType.ResponsibilityChanged);
        Assert.Equal(1026, 1000 + (int)AuditEventType.DesktopSwitchDetected);
        Assert.Equal(1027, 1000 + (int)AuditEventType.WindowsLockDetected);
        // Sicherheitsschlüssel (nur vom Dienst geschrieben)
        Assert.Equal(1028, 1000 + (int)AuditEventType.FidoKeyRegistered);
        Assert.Equal(1029, 1000 + (int)AuditEventType.FidoKeyRevoked);
        Assert.Equal(1030, 1000 + (int)AuditEventType.FidoKeyRejected);
        Assert.Equal(1031, 1000 + (int)AuditEventType.FidoCloneSuspected);
        Assert.Equal(AuditEventType.FidoCloneSuspected, Enum.GetValues<AuditEventType>().Max());
        foreach (var fido in new[] { AuditEventType.FidoKeyRegistered, AuditEventType.FidoKeyRevoked, AuditEventType.FidoKeyRejected, AuditEventType.FidoCloneSuspected })
            Assert.DoesNotContain(fido, Vitrine.Core.Service.AuditBroker.ClientEvents);
    }

    [Fact]
    public void Neue_Ereignisse_darf_die_Sitzungs_App_melden()
    {
        Assert.Contains(AuditEventType.DesktopSwitchDetected, Vitrine.Core.Service.AuditBroker.ClientEvents);
        Assert.Contains(AuditEventType.WindowsLockDetected, Vitrine.Core.Service.AuditBroker.ClientEvents);
    }
}

/// <summary>Vorschau des Windows-Desktops: nie mehr als der Abdeckungs-Modus mit derselben Darstellung.</summary>
public sealed class DesktopPreviewTests
{
    private static LockSettings DesktopMode(bool preview = true) => new() { Mode = LockMode.Desktop, DesktopShowPreview = preview };

    [Fact]
    public void Inhalt_folgt_der_Darstellung()
    {
        Assert.Equal(PreviewContent.AllWindows, DesktopPreview.ContentFor(DesktopMode(), new AppearanceSettings { Visual = LockVisual.Transparent }));
        Assert.Equal(PreviewContent.None, DesktopPreview.ContentFor(DesktopMode(), new AppearanceSettings { Visual = LockVisual.Blank }));
        Assert.Equal(PreviewContent.None, DesktopPreview.ContentFor(DesktopMode(), new AppearanceSettings { Visual = LockVisual.Windows }));
        Assert.Equal(PreviewContent.RevealedWindows, DesktopPreview.ContentFor(DesktopMode(),
            new AppearanceSettings { Visual = LockVisual.Windows, RevealProcesses = ["mes.exe"] }));
    }

    [Fact]
    public void Ausgeschaltet_oder_Abdeckungs_Modus_keine_Vorschau()
    {
        Assert.Equal(PreviewContent.None, DesktopPreview.ContentFor(DesktopMode(preview: false), new AppearanceSettings()));
        Assert.Equal(PreviewContent.None, DesktopPreview.ContentFor(new LockSettings(), new AppearanceSettings()));
    }

    [Theory]
    [InlineData(0, null)]
    [InlineData(-5, null)]
    [InlineData(1, 1)]
    [InlineData(2, 2)]
    [InlineData(600, 60)]
    public void Abstand_wird_begrenzt(int seconds, int? expected) =>
        Assert.Equal(expected is null ? null : TimeSpan.FromSeconds(expected.Value), DesktopPreview.Interval(seconds));

    [Fact]
    public void Fenster_von_unten_nach_oben_nur_auf_dem_Monitor_und_nur_freigegebene()
    {
        var monitor = new PixelRect(0, 0, 1920, 1080);
        (PixelRect, bool)[] windows =
        [
            (new PixelRect(100, 100, 500, 500), false),     // oben
            (new PixelRect(2000, 0, 2500, 400), true),      // anderer Monitor
            (new PixelRect(0, 0, 1920, 1040), true),        // unten
        ];
        Assert.Equal([2, 0], DesktopPreview.WindowsToDraw(windows, monitor, PreviewContent.AllWindows));
        Assert.Equal([2], DesktopPreview.WindowsToDraw(windows, monitor, PreviewContent.RevealedWindows));
        Assert.Empty(DesktopPreview.WindowsToDraw(windows, monitor, PreviewContent.None));
    }
}
