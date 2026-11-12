// SPDX-License-Identifier: MIT
using System.Windows.Input;
using Vitrine.Services.Interop;

namespace Vitrine.Services.Lock;

/// <summary>Tastenkürzel wie "Ctrl+Alt+L" bzw. "Strg+Alt+L" ↔ (Modifikatoren, virtueller Tastencode).</summary>
public readonly record struct Hotkey(uint Modifiers, uint VirtualKey)
{
    public bool IsEmpty => VirtualKey == 0;

    public static Hotkey Parse(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return default;
        uint mods = 0, vk = 0;
        foreach (var raw in text.Split('+', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            switch (raw.ToLowerInvariant())
            {
                case "ctrl" or "strg" or "control": mods |= Native.MOD_CONTROL; break;
                case "alt": mods |= Native.MOD_ALT; break;
                case "shift" or "umschalt": mods |= Native.MOD_SHIFT; break;
                case "win" or "windows": mods |= Native.MOD_WIN; break;
                default:
                    var name = raw.Length == 1 && char.IsDigit(raw[0]) ? "D" + raw : raw;
                    if (Enum.TryParse<Key>(name, true, out var key))
                        vk = (uint)KeyInterop.VirtualKeyFromKey(key);
                    break;
            }
        }
        return new Hotkey(mods, vk);
    }

    public static string Format(ModifierKeys mods, Key key)
    {
        var parts = new List<string>();
        if (mods.HasFlag(ModifierKeys.Control)) parts.Add("Ctrl");
        if (mods.HasFlag(ModifierKeys.Alt)) parts.Add("Alt");
        if (mods.HasFlag(ModifierKeys.Shift)) parts.Add("Shift");
        if (mods.HasFlag(ModifierKeys.Windows)) parts.Add("Win");
        var k = key.ToString();
        if (k.Length == 2 && k[0] == 'D' && char.IsDigit(k[1])) k = k[1..];
        parts.Add(k);
        return string.Join("+", parts);
    }

    /// <summary>Für die Anzeige in der Sprache der Oberfläche: "Ctrl+Alt+L" → „Strg + Alt + L“.</summary>
    public static string Display(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return "–";
        var parts = text.Split('+', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(p => p.ToLowerInvariant() switch
            {
                "ctrl" or "strg" or "control" => UI.Loc.T("Key_Ctrl"),
                "shift" or "umschalt" => UI.Loc.T("Key_Shift"),
                "alt" => UI.Loc.T("Key_Alt"),
                "win" or "windows" => UI.Loc.T("Key_Win"),
                _ => p,
            });
        return string.Join(" + ", parts);
    }
}
