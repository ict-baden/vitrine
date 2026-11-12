// SPDX-License-Identifier: MIT
using Vitrine.Abstractions;
using Vitrine.Core.Auth;
using Vitrine.Core.Config;
using Vitrine.Core.Localization;
using Vitrine.Tests.TestSupport;

namespace Vitrine.Tests.Auth;

/// <summary>
/// Verfahren am Sperrbildschirm ohne Windows-Kontobroker (Build mit -p:WamBroker=false oder Entra.UseBroker = false) und Einstellungen, mit denen dann
/// niemand mehr entsperren kann (unabhängige Prüfung vom 2026-10-20).
/// </summary>
public sealed class LockScreenMethodsTests
{
    private static UnlockSettings Unlock(params string[] methods) => new() { Methods = [.. methods] };

    [Fact]
    public void Ohne_Broker_kein_Microsoft_am_Sperrbildschirm()
    {
        Assert.Equal(["windows", "hello"], LockScreenMethods.Filter(["entra", "windows", "hello"], entraOnLockScreen: false));
        Assert.Equal(["windows"], LockScreenMethods.Filter([" Entra ", "windows"], entraOnLockScreen: false)); // Schreibweise egal
        Assert.Equal(["entra", "windows"], LockScreenMethods.Filter(["entra", "windows"], entraOnLockScreen: true));
    }

    [Fact]
    public void Standard_ohne_Broker_ohne_Warnung()
    {
        Assert.Empty(LockScreenMethods.Warnings(new UnlockSettings(), entraOnLockScreen: false));
        Assert.Empty(LockScreenMethods.Warnings(new UnlockSettings(), entraOnLockScreen: true));
    }

    [Fact]
    public void Nur_Microsoft_ohne_Broker_meldet_den_Rueckfall_auf_das_Windows_Kennwort()
    {
        var w = Assert.Single(LockScreenMethods.Warnings(Unlock("entra"), entraOnLockScreen: false));
        Assert.Equal(ErrorCodes.UnlockFallsBackToWindows, w.Code);
        Assert.Equal("VIT-0016 Unlock.Methods", w.AuditDetail);
        using (new UiCulture("en")) Assert.EndsWith("(VIT-0016)", w.Message);
        // Mit Broker gibt es Microsoft am Sperrbildschirm
        Assert.Empty(LockScreenMethods.Warnings(Unlock("entra"), entraOnLockScreen: true));
    }

    [Fact]
    public void Domaenen_von_Microsoft_Konten_sperren_ohne_Broker_alle_aus()
    {
        // Eingerichtet für Microsoft (UPN-Suffix); nach dem Rückfall auf Windows heißt die Domäne „CONTOSO“
        var s = Unlock("entra");
        s.AllowedDomains = ["contoso.com"];
        var warnings = LockScreenMethods.Warnings(s, entraOnLockScreen: false);
        Assert.Equal([ErrorCodes.UnlockFallsBackToWindows, ErrorCodes.UnlockRulesNeverMatch], warnings.Select(w => w.Code));
        Assert.Equal("VIT-0017 Unlock.AllowedDomains: contoso.com", warnings[1].AuditDetail);

        // So sieht es die Entsperr-Regel: auch ein Administrator mit Windows-Kennwort wird abgelehnt
        var admin = new AuthOutcome { Success = true, UserName = "CONTOSO\\admin", IsAdministrator = true, IsSessionUser = true };
        Assert.Equal(ErrorCodes.DomainNotAllowed, UnlockPolicy.Evaluate(admin, s).Code);

        // Mit NetBIOS-Namen (oder einem Verfahren, das UPNs liefert) keine Warnung
        s.AllowedDomains = ["contoso.com", "CONTOSO"];
        Assert.Equal([ErrorCodes.UnlockFallsBackToWindows], LockScreenMethods.Warnings(s, false).Select(w => w.Code));
        s.AllowedDomains = ["contoso.com"];
        Assert.Empty(LockScreenMethods.Warnings(s, entraOnLockScreen: true));
    }

    [Fact]
    public void Gruppen_IDs_von_Microsoft_Entra_passen_nie_zu_Windows()
    {
        var s = Unlock("windows", "hello");
        s.Allowed = UnlockAllowed.Groups;
        s.AllowedGroups = ["6a1f3c2e-0d4b-4e8a-9b7c-1d2e3f4a5b6c"];
        var w = Assert.Single(LockScreenMethods.Warnings(s, entraOnLockScreen: false));
        Assert.Equal("Unlock.AllowedGroups", w.Setting);

        // Eine Windows-Gruppe dabei, oder Sitzungsbenutzer/Administratoren erlaubt: jemand kann entsperren
        s.AllowedGroups = ["6a1f3c2e-0d4b-4e8a-9b7c-1d2e3f4a5b6c", "CONTOSO\\Lab"];
        Assert.Empty(LockScreenMethods.Warnings(s, false));
        s.AllowedGroups = ["6a1f3c2e-0d4b-4e8a-9b7c-1d2e3f4a5b6c"];
        s.Allowed = UnlockAllowed.Groups | UnlockAllowed.Administrators;
        Assert.Empty(LockScreenMethods.Warnings(s, false));
    }

    [Fact]
    public void Gemeinsames_Kennwort_oder_Plugin_am_Sperrbildschirm_ohne_Regelwarnung()
    {
        // Das gemeinsame Kennwort gilt unabhängig von Domänen; ein Plugin kann UPNs liefern
        foreach (var other in new[] { "pin", "badge" })
        {
            var s = Unlock("entra", other);
            s.AllowedDomains = ["contoso.com"];
            Assert.Empty(LockScreenMethods.Warnings(s, entraOnLockScreen: false));
        }
    }

    [Fact]
    public void Mit_Broker_keine_Warnung_fuer_Microsoft_Regeln()
    {
        // Standard seit dem Broker in den Release-Paketen: Microsoft am Sperrbildschirm, UPN-Suffixe und Entra-Gruppen-IDs
        // passen dort – weder VIT-0016 noch VIT-0017, auch wenn Windows-Verfahren daneben stehen
        foreach (var methods in new[] { new[] { "entra" }, ["entra", "windows"], ["entra", "windows", "hello"] })
        {
            var s = Unlock(methods);
            s.AllowedDomains = ["contoso.com"];
            s.Allowed = UnlockAllowed.Groups;
            s.AllowedGroups = ["6a1f3c2e-0d4b-4e8a-9b7c-1d2e3f4a5b6c"];
            Assert.Empty(LockScreenMethods.Warnings(s, entraOnLockScreen: true));
            Assert.Equal(methods, LockScreenMethods.Filter(s.Methods, entraOnLockScreen: true));
        }
    }
}
