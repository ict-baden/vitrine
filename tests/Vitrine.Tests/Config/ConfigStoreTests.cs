// SPDX-License-Identifier: MIT
using Vitrine.Core.Config;
using Vitrine.Core.Lock;
using Vitrine.Tests.TestSupport;

namespace Vitrine.Tests.Config;

/// <summary>
/// Schichten der Konfiguration: Standard → Gerät → Benutzer (falls erlaubt) → Richtlinien (HKCU, dann HKLM; alter Pfad
/// vor neuem). Dazu der Übergang von den alten Orten (%ProgramData%\Vitrine, SOFTWARE\Policies\Vitrine).
/// </summary>
public sealed class ConfigStoreTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly ConfigFiles _files;

    public ConfigStoreTests()
    {
        _files = new ConfigFiles(_dir.File("new/config.json"), _dir.File("old/config.json"), _dir.File("user/config.json"), _dir.File("olduser/config.json"));
    }

    public void Dispose() => _dir.Dispose();

    private void Write(string path, string json)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, json);
    }

    private ConfigStore Load(params IPolicySource[] policies)
    {
        var store = new ConfigStore(_files, policies);
        store.Load();
        return store;
    }

    private ConfigStore LoadGuarded(FakeGuard guard, params IPolicySource[] policies)
    {
        var store = new ConfigStore(_files, policies, guard);
        store.Load();
        return store;
    }

    [Fact]
    public void Ungeschuetzte_Geraetedatei_wird_nicht_gelesen()
    {
        using var _ = new UiCulture("en");
        // z. B. von einem normalen Benutzer angelegt: Regeln, Skripte, Entsperr-Kennwort für alle
        Write(_files.Machine, """{ "Unlock": { "Allowed": 16 }, "Scripts": { "OnLock": "calc" } }""");
        var store = LoadGuarded(new FakeGuard());
        Assert.Equal(UnlockAllowed.SessionUser | UnlockAllowed.Administrators, store.Current.Unlock.Allowed);
        Assert.Null(store.Current.Scripts.OnLock);
        Assert.Contains(store.LoadErrors, e => e.Contains("VIT-0012"));

        var trusted = LoadGuarded(new FakeGuard { Protected = { _files.Machine } });
        Assert.Equal(UnlockAllowed.AnyAuthenticated, trusted.Current.Unlock.Allowed);
    }

    [Fact]
    public void Untergeschobene_alte_Geraetedatei_wird_nicht_gelesen()
    {
        Write(_files.LegacyMachine, """{ "Security": { "SettingsAdminOnly": false } }""");
        Assert.True(LoadGuarded(new FakeGuard()).Current.Security.SettingsAdminOnly);
        Assert.False(LoadGuarded(new FakeGuard { Protected = { _files.LegacyMachine } }).Current.Security.SettingsAdminOnly);
    }

    [Fact]
    public void Speichern_sichert_Ordner_vorher_und_Datei_nachher()
    {
        var guard = new FakeGuard();
        var store = LoadGuarded(guard);
        store.Save(store.Editable);
        Assert.Equal([$"dir:{Path.GetDirectoryName(_files.Machine)}", $"file:{_files.Machine}"], guard.Calls);
        // Keine Reste: die Temp-Datei hat einen zufälligen Namen und wird nie wiederverwendet
        Assert.Single(Directory.GetFiles(Path.GetDirectoryName(_files.Machine)!));
    }

    [Fact]
    public void Vorab_angelegte_Temp_Datei_wird_nicht_benutzt()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_files.Machine)!);
        File.WriteAllText(_files.Machine + ".tmp", "von einem Benutzer");
        var store = Load();
        store.Save(store.Editable);
        Assert.Equal("von einem Benutzer", File.ReadAllText(_files.Machine + ".tmp"));
        Assert.Equal(0, ConfigStore.Validate(File.ReadAllText(_files.Machine)).Lock.IdleMinutes);
    }

    [Fact]
    public void Benutzerschicht_landet_nie_in_den_gespeicherten_Geraetewerten()
    {
        Write(_files.Machine, """{ "Security": { "AllowUserConfig": true }, "Lock": { "IdleMinutes": 4 } }""");
        Write(_files.User, """{ "Lock": { "IdleMinutes": 1 } }""");
        var store = Load();
        Assert.Equal(1, store.Current.Lock.IdleMinutes);
        Assert.Equal(4, store.Editable.Lock.IdleMinutes);
    }

    [Fact]
    public void Benutzerschicht_darf_nur_Darstellung_und_Sperren_setzen()
    {
        Write(_files.Machine, """{ "Security": { "AllowUserConfig": true } }""");
        Write(_files.User, """
            { "Appearance": { "DimPercent": 30 }, "Lock": { "Hotkey": "Ctrl+Alt+K" },
              "Security": { "SettingsAdminOnly": false, "Watchdog": false }, "Unlock": { "Allowed": 16, "PinHash": "x" },
              "Scripts": { "OnLock": "calc" }, "Audit": { "Enabled": false }, "Integration": { "LoadPlugins": true }, "Entra": { "TenantId": "x" } }
            """);
        var c = Load().Current;
        Assert.Equal(30, c.Appearance.DimPercent);
        Assert.Equal("Ctrl+Alt+K", c.Lock.Hotkey);
        Assert.True(c.Security.SettingsAdminOnly);
        Assert.True(c.Security.Watchdog);
        Assert.Equal(UnlockAllowed.SessionUser | UnlockAllowed.Administrators, c.Unlock.Allowed);
        Assert.Null(c.Unlock.PinHash);
        Assert.Null(c.Scripts.OnLock);
        Assert.True(c.Audit.Enabled);
        Assert.Equal("organizations", c.Entra.TenantId);
    }

    [Fact]
    public void Richtlinie_kann_Benutzerkonfiguration_abschalten()
    {
        Write(_files.Machine, """{ "Security": { "AllowUserConfig": true } }""");
        Write(_files.User, """{ "Lock": { "IdleMinutes": 1 } }""");
        Assert.Equal(0, Load(new FakePolicy("HKLM", ("Security", "AllowUserConfig", 0))).Current.Lock.IdleMinutes);
    }

    [Fact]
    public void Ohne_Dateien_gelten_die_Standardwerte()
    {
        var store = Load();
        Assert.Equal("Ctrl+Alt+L", store.Current.Lock.Hotkey);
        Assert.Equal(UnlockAllowed.SessionUser | UnlockAllowed.Administrators, store.Current.Unlock.Allowed);
        Assert.True(store.Current.Security.SettingsAdminOnly);
        Assert.True(store.Current.Security.ExitRequiresAdmin);
        Assert.True(store.Current.Entra.ForceFreshSignIn);
        Assert.Empty(store.LoadErrors);
        Assert.False(store.UsesLegacyMachineFile);
    }

    [Fact]
    public void Geraetedatei_wird_tief_zusammengefuehrt_ohne_Gross_Kleinschreibung()
    {
        Write(_files.Machine, """{ "lock": { "idleMinutes": 5 }, "Unlock": { "Methods": ["windows"] } }""");
        var store = Load();
        Assert.Equal(5, store.Current.Lock.IdleMinutes);
        Assert.Equal("Ctrl+Alt+L", store.Current.Lock.Hotkey); // Rest bleibt Standard
        Assert.Equal(["windows"], store.Current.Unlock.Methods);
    }

    [Fact]
    public void Alter_Ort_gilt_nur_solange_es_den_neuen_nicht_gibt()
    {
        Write(_files.LegacyMachine, """{ "Lock": { "IdleMinutes": 7 } }""");
        var store = Load();
        Assert.Equal(7, store.Current.Lock.IdleMinutes);
        Assert.True(store.UsesLegacyMachineFile);

        Write(_files.Machine, """{ "Lock": { "IdleMinutes": 9 } }""");
        store.Load();
        Assert.Equal(9, store.Current.Lock.IdleMinutes);
        Assert.False(store.UsesLegacyMachineFile);
    }

    [Fact]
    public void Speichern_schreibt_an_den_neuen_Ort_und_beendet_den_Uebergang()
    {
        Write(_files.LegacyMachine, """{ "Lock": { "IdleMinutes": 7 } }""");
        var store = Load();
        var edit = store.Editable;
        edit.Lock.IdleMinutes = 11;
        store.Save(edit);
        Assert.True(File.Exists(_files.Machine));
        Assert.False(store.UsesLegacyMachineFile);
        Assert.Equal(11, store.Current.Lock.IdleMinutes);
    }

    [Fact]
    public void Benutzerdatei_nur_wenn_das_Geraet_sie_erlaubt()
    {
        Write(_files.User, """{ "Lock": { "IdleMinutes": 3 } }""");
        Assert.Equal(0, Load().Current.Lock.IdleMinutes);

        Write(_files.Machine, """{ "Security": { "AllowUserConfig": true } }""");
        Assert.Equal(3, Load().Current.Lock.IdleMinutes);
    }

    [Fact]
    public void Benutzerdatei_kann_AllowUserConfig_nicht_selbst_einschalten()
    {
        Write(_files.User, """{ "Security": { "AllowUserConfig": true, "SettingsAdminOnly": false } }""");
        Assert.True(Load().Current.Security.SettingsAdminOnly);
    }

    [Fact]
    public void Alte_Benutzerdatei_als_Rueckfall()
    {
        Write(_files.Machine, """{ "Security": { "AllowUserConfig": true } }""");
        Write(_files.LegacyUser, """{ "Lock": { "IdleMinutes": 4 } }""");
        Assert.Equal(4, Load().Current.Lock.IdleMinutes);
    }

    [Fact]
    public void Richtlinie_hat_Vorrang_und_wird_als_verwaltet_markiert()
    {
        Write(_files.Machine, """{ "Lock": { "IdleMinutes": 5 } }""");
        var store = Load(new FakePolicy("HKLM", ("Lock", "IdleMinutes", 15), ("Security", "RestrictCtrlAltDel", 0)));
        Assert.Equal(15, store.Current.Lock.IdleMinutes);
        Assert.Equal(5, store.Editable.Lock.IdleMinutes); // Einstellungen speichern nie Richtlinienwerte
        Assert.False(store.Current.Security.RestrictCtrlAltDel);
        Assert.True(store.IsManaged("Lock.IdleMinutes"));
        Assert.True(store.IsManaged("security.restrictctrlaltdel"));
        Assert.False(store.IsManaged("Lock.Hotkey"));
    }

    [Fact]
    public void Reihenfolge_der_Quellen_letzte_gewinnt_alter_Pfad_wird_gemeldet()
    {
        var legacyUser = new FakeLegacyPolicy("HKCU-alt", ("Lock", "IdleMinutes", 1));
        var user = new FakePolicy("HKCU", ("Lock", "IdleMinutes", 2));
        var legacyMachine = new FakeLegacyPolicy("HKLM-alt", ("Lock", "IdleMinutes", 3), ("Lock", "KeepAwake", 0));
        var machine = new FakePolicy("HKLM", ("Lock", "IdleMinutes", 4));
        var store = Load(legacyUser, user, legacyMachine, machine);
        Assert.Equal(4, store.Current.Lock.IdleMinutes);
        Assert.False(store.Current.Lock.KeepAwake); // nur im alten Pfad gesetzt – gilt weiter
        Assert.True(store.UsesLegacyPolicy);

        Assert.False(Load(user, machine).UsesLegacyPolicy);
    }

    [Fact]
    public void Masken_und_freigegebene_Programme_per_Richtlinie()
    {
        var store = Load(new FakePolicy("HKLM",
            ("Appearance", "Masks", new[] { "1:0,0,30,100", "kaputt", "*:70,0,30,12" }),
            ("Appearance", "RevealProcesses", new[] { "Chromeleon.exe", "mes.exe" }),
            ("Appearance", "Visual", "Windows")));
        var look = store.Current.Appearance;
        Assert.Equal(["1:0,0,30,100", "*:70,0,30,12"], look.Masks.Select(m => m.Format()));
        Assert.Equal(["Chromeleon.exe", "mes.exe"], look.RevealProcesses);
        Assert.Equal(LockVisual.Windows, look.Visual);
        Assert.True(store.IsManaged("Appearance.Masks"));
    }

    [Fact]
    public void Masken_ueberstehen_Speichern_und_Laden()
    {
        var store = Load();
        var c = store.Editable;
        c.Appearance.Masks.Add(new MaskRegion { Monitor = 2, X = 10, Y = 20, Width = 30, Height = 40 });
        store.Save(c);
        Assert.Equal("2:10,20,30,40", Load().Current.Appearance.Masks.Single().Format());
    }

    [Fact]
    public void Kopie_der_Darstellung_hat_eigene_Listen()
    {
        var look = new AppearanceSettings { Masks = [new MaskRegion { Monitor = 1, Width = 10, Height = 10 }], RevealProcesses = ["a"] };
        var copy = look.Clone();
        copy.Masks.Clear();
        copy.RevealProcesses.Add("b");
        Assert.Single(look.Masks);
        Assert.Equal(["a"], look.RevealProcesses);
    }

    [Fact]
    public void Richtlinienwerte_aller_Typen()
    {
        var store = Load(new FakePolicy("HKLM",
            ("Unlock", "Allowed", 16),
            ("Unlock", "Trigger", "HotkeyOnly"),
            ("Unlock", "AllowedGroups", new[] { "LAB\\QA", " ", "S-1-5-32-544" }),
            ("Unlock", "AllowedDomains", "CONTOSO; contoso.com"),
            ("Security", "FailureAction", 1),
            ("Lock", "Schedule", new[] { "18:00@Mo,Di", "kaputt", "07:30" }),
            ("Appearance", "Language", "fr")));
        var c = store.Current;
        Assert.Equal(UnlockAllowed.AnyAuthenticated, c.Unlock.Allowed);
        Assert.Equal(UnlockTrigger.HotkeyOnly, c.Unlock.Trigger);
        Assert.Equal(["LAB\\QA", "S-1-5-32-544"], c.Unlock.AllowedGroups);
        Assert.Equal(["CONTOSO", "contoso.com"], c.Unlock.AllowedDomains);
        Assert.Equal(FailureAction.LockWorkstation, c.Security.FailureAction);
        Assert.Equal(2, c.Lock.Schedule.Count);
        Assert.Equal([DayOfWeek.Monday, DayOfWeek.Tuesday], c.Lock.Schedule[0].Days);
        Assert.Equal("fr", c.Appearance.Language);
        Assert.True(store.IsManaged("Appearance.Language"));
    }

    [Fact]
    public void Unbekannter_Enum_Name_in_der_Richtlinie_wird_ignoriert_statt_alles_zu_verwerfen()
    {
        var store = Load(new FakePolicy("HKLM", ("Security", "FailureAction", "Explode"), ("Lock", "IdleMinutes", 6)));
        Assert.Equal(FailureAction.None, store.Current.Security.FailureAction);
        Assert.Equal(6, store.Current.Lock.IdleMinutes);
        Assert.Empty(store.LoadErrors);
    }

    [Fact]
    public void Fehler_einer_Richtlinienquelle_verhindert_den_Start_nicht()
    {
        using var _ = new UiCulture("en");
        var store = Load(new ThrowingPolicy(), new FakePolicy("HKLM", ("Lock", "IdleMinutes", 6)));
        Assert.Equal(6, store.Current.Lock.IdleMinutes);
        Assert.Contains(store.LoadErrors, e => e.Contains("VIT-0002"));
    }

    [Fact]
    public void Kaputtes_JSON_meldet_VIT_0001_und_nutzt_Standardwerte()
    {
        using var _ = new UiCulture("en");
        Write(_files.Machine, "{ nicht json");
        var store = Load();
        Assert.Contains(store.LoadErrors, e => e.Contains("VIT-0001"));
        Assert.Equal("Ctrl+Alt+L", store.Current.Lock.Hotkey);
    }

    [Fact]
    public void Falscher_Typ_in_der_Datei_laesst_den_Start_nicht_scheitern()
    {
        using var _ = new UiCulture("en");
        Write(_files.Machine, """{ "Lock": { "IdleMinutes": "fünf" } }""");
        var store = Load();
        Assert.Contains(store.LoadErrors, e => e.Contains("VIT-0001"));
        Assert.True(store.Current.Security.SettingsAdminOnly);
    }

    [Fact]
    public void Falscher_Typ_verwirft_nur_diese_Datei_nicht_Richtlinien_und_andere_Schichten()
    {
        using var _ = new UiCulture("en");
        Write(_files.Machine, """{ "Security": { "AllowUserConfig": true }, "Lock": { "IdleMinutes": 4 } }""");
        Write(_files.User, """{ "Lock": { "IdleMinutes": "fünf" }, "Unlock": { "Trigger": "Explode" } }""");
        var store = Load(new FakePolicy("HKLM", ("Unlock", "AllowedDomains", "CONTOSO")));
        Assert.Equal(4, store.Current.Lock.IdleMinutes);
        Assert.Equal(["CONTOSO"], store.Current.Unlock.AllowedDomains);
        Assert.Single(store.LoadErrors);
        Assert.Contains("VIT-0001", store.LoadErrors[0]);
    }

    [Fact]
    public void Zu_grosse_Datei_wird_nicht_gelesen()
    {
        Write(_files.Machine, "{\"Appearance\":{\"Message\":\"" + new string('x', (int)ConfigStore.MaxFileBytes) + "\"}}");
        var store = Load();
        Assert.Null(store.Current.Appearance.Message);
        Assert.Single(store.LoadErrors);
    }

    [Fact]
    public void Verdeckte_Bereiche_in_der_Textform_verwerfen_die_Datei_nicht()
    {
        // Prüfung vom 2026-10-20: ["1:0,0,30,100"] (wie in docs/settings.md) setzte alle Gerätewerte auf Standard (VIT-0001)
        Write(_files.Machine, """
            { "Unlock": { "Allowed": 2 },
              "Appearance": { "Masks": ["1:0,0,30,100", "*:70,0,30,12", { "Monitor": 2, "X": 10, "Y": 20, "Width": 30, "Height": 40 }] } }
            """);
        var store = Load();
        Assert.Empty(store.LoadErrors);
        Assert.Equal(UnlockAllowed.Administrators, store.Current.Unlock.Allowed);
        Assert.Equal(["1:0,0,30,100", "*:70,0,30,12", "2:10,20,30,40"], store.Current.Appearance.Masks.Select(m => m.Format()));
        // Gespeichert wird die Objektform (lesen auch ältere Builds), und sie liest sich gleich zurück
        var json = System.Text.Json.JsonSerializer.Serialize(store.Current, ConfigStore.Json);
        Assert.Contains("\"Monitor\": 1", json);
        Assert.Equal(store.Current.Appearance.Masks.Select(m => m.Format()), ConfigStore.Validate(json).Appearance.Masks.Select(m => m.Format()));
    }

    [Fact]
    public void Ungueltiger_Bereich_in_der_Textform_wird_gemeldet()
    {
        Write(_files.Machine, """{ "Appearance": { "Masks": ["links oben"] } }""");
        var store = Load();
        Assert.Contains(store.LoadErrors, e => e.Contains("VIT-0001", StringComparison.Ordinal) && e.Contains("links oben", StringComparison.Ordinal));
    }

    [Fact]
    public void Benutzerschicht_kann_verdeckte_Bereiche_und_sichtbare_Programme_nicht_aendern()
    {
        Write(_files.Machine, """{ "Security": { "AllowUserConfig": true }, "Appearance": { "Masks": ["1:0,0,30,100"], "RevealProcesses": ["lims.exe"] } }""");
        Write(_files.User, """{ "Appearance": { "Masks": [], "RevealProcesses": ["browser.exe"], "DimPercent": 40 } }""");
        var c = Load().Current;
        Assert.Equal(40, c.Appearance.DimPercent);
        Assert.Single(c.Appearance.Masks);
        Assert.Equal(["lims.exe"], c.Appearance.RevealProcesses);
    }

    [Fact]
    public void Unlesbare_Eintraege_einer_Richtlinie_werden_gemeldet()
    {
        var store = Load(new FakePolicy("HKLM",
            ("Lock", "Schedule", new[] { "18:00@Mo-Fr", "18:00@Mo-Fx", "abends" }),
            ("Appearance", "Masks", new[] { "1:0,0,30,100", "links" })));
        Assert.Single(store.Current.Lock.Schedule);
        Assert.Single(store.Current.Appearance.Masks);
        Assert.Contains(store.LoadErrors, e => e.Contains("VIT-0015", StringComparison.Ordinal) && e.Contains("Lock.Schedule", StringComparison.Ordinal) && e.Contains("abends", StringComparison.Ordinal));
        Assert.Contains(store.LoadErrors, e => e.Contains("VIT-0015", StringComparison.Ordinal) && e.Contains("links", StringComparison.Ordinal));
    }

    [Fact]
    public void Unlesbare_Uhrzeit_in_der_Datei_wird_gemeldet()
    {
        Write(_files.Machine, """{ "Lock": { "Schedule": [ { "Time": "6:30 PM" }, { "Time": "18.00" } ] } }""");
        var store = Load();
        Assert.Single(store.LoadErrors);
        Assert.Contains("6:30 PM", store.LoadErrors[0]);
    }

    [Fact]
    public void Validate_lehnt_Nicht_Objekte_und_falsche_Typen_ab()
    {
        Assert.Throws<InvalidDataException>(() => ConfigStore.Validate("[1,2]"));
        Assert.ThrowsAny<Exception>(() => ConfigStore.Validate("""{ "Lock": { "IdleMinutes": "x" } }"""));
        Assert.Equal(5, ConfigStore.Validate("""{ "Lock": { "IdleMinutes": 5 } }""").Lock.IdleMinutes);
    }

    [Fact]
    public void Komfort_Eigenschaften_werden_nicht_gespeichert_und_halten_die_Reihenfolge()
    {
        var u = new UnlockSettings { Methods = ["windows"] };
        u.MethodPin = true;
        u.MethodEntra = true;
        u.Methods.Add("acme");
        u.MethodHello = true;
        Assert.Equal(["entra", "windows", "hello", "pin", "acme"], u.Methods);
        var json = System.Text.Json.JsonSerializer.Serialize(u, ConfigStore.Json);
        Assert.DoesNotContain("MethodPin", json);
        Assert.DoesNotContain("AllowAnyone", json);
    }

    private class FakePolicy(string name, params (string section, string value, object data)[] values) : IPolicySource
    {
        public string Name => name;

        public IReadOnlyDictionary<string, object>? ReadSection(string section)
        {
            var d = values.Where(v => v.section.Equals(section, StringComparison.OrdinalIgnoreCase))
                .ToDictionary(v => v.value, v => v.data, StringComparer.OrdinalIgnoreCase);
            return d.Count == 0 ? null : d;
        }
    }

    private sealed class FakeLegacyPolicy(string name, params (string section, string value, object data)[] values)
        : FakePolicy(name, values), ILegacyPolicySource;

    private sealed class FakeGuard : IConfigFileGuard
    {
        public HashSet<string> Protected { get; } = new();
        public List<string> Calls { get; } = new();
        public bool IsProtected(string file) => Protected.Contains(file);
        public string? ReadProtected(string file, long maxBytes) =>
            !File.Exists(file) ? null : IsProtected(file) ? File.ReadAllText(file) : throw new UnauthorizedAccessException(file);
        public void PrepareDirectory(string directory) { Calls.Add($"dir:{directory}"); Directory.CreateDirectory(directory); }
        public void Protect(string file) { Calls.Add($"file:{file}"); Protected.Add(file); }
    }

    private sealed class ThrowingPolicy : IPolicySource
    {
        public string Name => "HKCU";
        public IReadOnlyDictionary<string, object>? ReadSection(string section) => throw new UnauthorizedAccessException("denied");
    }
}
