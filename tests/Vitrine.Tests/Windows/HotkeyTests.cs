// SPDX-License-Identifier: MIT
using System.Windows.Input;
using Vitrine.Services.Interop;
using Vitrine.Services.Lock;
using Vitrine.Tests.TestSupport;

namespace Vitrine.Tests.Windows;

/// <summary>Tastenkürzel lesen, schreiben und in der Sprache der Oberfläche anzeigen (nur unter Windows: WPF-Tasten).</summary>
public sealed class HotkeyTests
{
    [Theory]
    [InlineData("Ctrl+Alt+L", Native.MOD_CONTROL | Native.MOD_ALT, 0x4C)]
    [InlineData("Strg + Umschalt + 1", Native.MOD_CONTROL | Native.MOD_SHIFT, 0x31)]
    [InlineData("Win+F12", Native.MOD_WIN, 0x7B)]
    public void Liest_englische_und_deutsche_Namen(string text, uint mods, uint vk)
    {
        var hk = Hotkey.Parse(text);
        Assert.Equal(mods, hk.Modifiers);
        Assert.Equal(vk, hk.VirtualKey);
    }

    [Fact]
    public void Leer_oder_unbekannt_ist_kein_Kuerzel()
    {
        Assert.True(Hotkey.Parse("").IsEmpty);
        Assert.True(Hotkey.Parse("Ctrl+Alt+Gibtsnicht").IsEmpty);
    }

    [Fact]
    public void Speichert_englisch_zeigt_in_der_Sprache()
    {
        var text = Hotkey.Format(ModifierKeys.Control | ModifierKeys.Alt, Key.D7);
        Assert.Equal("Ctrl+Alt+7", text);
        using (new UiCulture("de")) Assert.Equal("Strg + Alt + 7", Hotkey.Display(text));
        using (new UiCulture("en")) Assert.Equal("Ctrl + Alt + 7", Hotkey.Display(text));
        Assert.Equal("–", Hotkey.Display(null));
    }
}
