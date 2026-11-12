// SPDX-License-Identifier: MIT
using Vitrine.Core.Auth;

namespace Vitrine.Tests.Auth;

/// <summary>Benutzername im Dialog „Windows-Kennwort“ → Benutzer und Domäne für LogonUser (Issue #21, docs/sign-in.md).</summary>
public sealed class LogonTargetTests
{
    private const string Pc = "LAB-PC-07";

    private static LogonContext Entra(DeviceJoinState join = DeviceJoinState.EntraJoined) =>
        new(@"AzureAD\LabOperator", "operator@contoso.onmicrosoft.com", "AzureAD", IsEntraAccount: true, join, Pc);

    private static LogonContext Ad(DeviceJoinState join = DeviceJoinState.DomainJoined) =>
        new(@"CONTOSO\jdoe", "jdoe@contoso.com", "CONTOSO", IsEntraAccount: false, join, Pc);

    private static LogonContext Local(DeviceJoinState join = DeviceJoinState.Workgroup) =>
        new($@"{Pc}\admin", null, Pc, IsEntraAccount: false, join, Pc);

    private static void Is(LogonTarget t, string? user, string? domain)
    {
        Assert.Equal(user, t.User);
        Assert.Equal(domain, t.Domain);
    }

    // ---------- leer = Sitzungsbenutzer ----------

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Leer_Entra_Sitzung_UPN_mit_AzureAD(string? input) =>
        Is(LogonTarget.Resolve(input, Entra()), "operator@contoso.onmicrosoft.com", "AzureAD");

    [Fact]
    public void Leer_Entra_Sitzung_auch_bei_unbekanntem_oder_anderem_Join_Status() // Sitzungskonto entscheidet
    {
        Is(LogonTarget.Resolve("", Entra(DeviceJoinState.Unknown)), "operator@contoso.onmicrosoft.com", "AzureAD");
        Is(LogonTarget.Resolve("", Entra(DeviceJoinState.HybridJoined)), "operator@contoso.onmicrosoft.com", "AzureAD");
    }

    [Fact]
    public void Leer_Entra_Sitzung_ohne_UPN_abgelehnt() =>
        Assert.True(LogonTarget.Resolve("", Entra() with { Upn = null }).IsRefused);

    [Fact]
    public void Leer_AD_Sitzung_UPN_ohne_Domaene()
    {
        Is(LogonTarget.Resolve("", Ad()), "jdoe@contoso.com", null);
        Is(LogonTarget.Resolve("", Ad(DeviceJoinState.HybridJoined)), "jdoe@contoso.com", null);
    }

    [Fact]
    public void Leer_AD_Sitzung_ohne_UPN_Sam_Name() =>
        Is(LogonTarget.Resolve("", Ad() with { Upn = null }), "jdoe", "CONTOSO");

    [Fact]
    public void Leer_lokale_Sitzung_lokales_Konto()
    {
        Is(LogonTarget.Resolve("", Local()), "admin", Pc);
        Is(LogonTarget.Resolve(null, Local(DeviceJoinState.EntraJoined)), "admin", Pc);
    }

    // ---------- UPN ----------

    [Fact]
    public void Upn_auf_Entra_Geraet_mit_AzureAD()
    {
        Is(LogonTarget.Resolve("other@contoso.onmicrosoft.com", Entra()), "other@contoso.onmicrosoft.com", "AzureAD");
        // auch wenn ein lokales Konto angemeldet ist: auf Entra-Geräten haben nur Entra-Konten einen UPN
        Is(LogonTarget.Resolve("other@contoso.onmicrosoft.com", Local(DeviceJoinState.EntraJoined)), "other@contoso.onmicrosoft.com", "AzureAD");
    }

    [Theory]
    [InlineData(DeviceJoinState.DomainJoined)]
    [InlineData(DeviceJoinState.HybridJoined)]
    [InlineData(DeviceJoinState.Workgroup)]
    [InlineData(DeviceJoinState.Unknown)]
    public void Upn_auf_AD_Hybrid_oder_unbekannt_ohne_Domaene(DeviceJoinState join) =>
        Is(LogonTarget.Resolve("other@contoso.com", Ad(join)), "other@contoso.com", null);

    [Fact]
    public void Upn_bei_unbekanntem_Join_Status_folgt_der_Entra_Sitzung() =>
        Is(LogonTarget.Resolve("other@contoso.onmicrosoft.com", Entra(DeviceJoinState.Unknown)), "other@contoso.onmicrosoft.com", "AzureAD");

    [Fact]
    public void Eigener_Upn_der_Entra_Sitzung_auch_auf_Hybrid_mit_AzureAD() =>
        Is(LogonTarget.Resolve("OPERATOR@contoso.onmicrosoft.com", Entra(DeviceJoinState.HybridJoined)), "OPERATOR@contoso.onmicrosoft.com", "AzureAD");

    [Fact]
    public void Upn_Leerzeichen_entfernt() =>
        Is(LogonTarget.Resolve("  other@contoso.com \t", Ad()), "other@contoso.com", null);

    // ---------- AzureAD\… ----------

    [Theory]
    [InlineData(@"AzureAD\other@contoso.onmicrosoft.com")]
    [InlineData(@"azuread\other@contoso.onmicrosoft.com")]
    [InlineData(@"AZUREAD\other@contoso.onmicrosoft.com")]
    [InlineData(@" AzureAD\other@contoso.onmicrosoft.com ")]
    public void AzureAD_mit_Upn_vor_der_At_Pruefung_zerlegt(string input)
    {
        // Vorher: LogonUser("AzureAD\\upn", null) → Windows-Fehler 53 (VIT-0109)
        Is(LogonTarget.Resolve(input, Entra()), "other@contoso.onmicrosoft.com", "AzureAD");
        Is(LogonTarget.Resolve(input, Ad()), "other@contoso.onmicrosoft.com", "AzureAD");
    }

    [Theory]
    [InlineData(@"AzureAD\LabOperator")]
    [InlineData(@"azuread\laboperator")]
    public void AzureAD_Name_der_Sitzung_wird_zum_Upn(string input) =>
        Is(LogonTarget.Resolve(input, Entra()), "operator@contoso.onmicrosoft.com", "AzureAD");

    [Fact]
    public void AzureAD_Name_einer_anderen_Person_abgelehnt()
    {
        Assert.True(LogonTarget.Resolve(@"AzureAD\SomeoneElse", Entra()).IsRefused);
        // keine Entra-Sitzung: AzureAD\name lässt sich gar nicht auflösen
        Assert.True(LogonTarget.Resolve(@"AzureAD\jdoe", Ad()).IsRefused);
        Assert.True(LogonTarget.Resolve(@"AzureAD\LabOperator", Entra() with { Upn = null }).IsRefused);
    }

    // ---------- DOMÄNE\name, lokal, ohne Domäne ----------

    [Fact]
    public void Domaene_und_Sam_Name()
    {
        Is(LogonTarget.Resolve(@"CONTOSO\other", Ad()), "other", "CONTOSO");
        Is(LogonTarget.Resolve(@"CONTOSO\other", Entra()), "other", "CONTOSO");
        Is(LogonTarget.Resolve(@" CONTOSO \ other ", Ad()), "other", "CONTOSO");
    }

    [Fact]
    public void Punkt_ist_dieser_Rechner()
    {
        Is(LogonTarget.Resolve(@".\admin", Entra()), "admin", Pc);
        Is(LogonTarget.Resolve(@".\admin", Ad()), "admin", Pc);
    }

    [Fact]
    public void Rechnername_lokales_Konto() =>
        Is(LogonTarget.Resolve($@"{Pc}\admin", Entra()), "admin", Pc);

    [Fact]
    public void Name_ohne_Domaene()
    {
        Is(LogonTarget.Resolve("other", Ad()), "other", "CONTOSO");
        Is(LogonTarget.Resolve("other", Local(DeviceJoinState.EntraJoined)), "other", Pc);
        Assert.True(LogonTarget.Resolve("other", Entra()).IsRefused);
    }

    [Theory]
    [InlineData(@"\other")]
    [InlineData(@"CONTOSO\")]
    [InlineData(@"CONTOSO\a\b")]
    [InlineData(@"AzureAD\")]
    public void Unvollstaendige_Namen_abgelehnt(string input) =>
        Assert.True(LogonTarget.Resolve(input, Ad()).IsRefused);

    // ---------- UPN fürs Protokoll ----------

    [Fact]
    public void Upn_nur_bei_Anmeldung_per_Upn()
    {
        Assert.Equal("operator@contoso.onmicrosoft.com", LogonTarget.Resolve("", Entra()).Upn);
        Assert.Null(LogonTarget.Resolve(@"CONTOSO\other", Ad()).Upn);
        Assert.Null(LogonTarget.Refused.Upn);
    }
}
