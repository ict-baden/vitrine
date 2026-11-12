// SPDX-License-Identifier: MIT
using Vitrine.Core.Config;

namespace Vitrine.Core.Lock;

/// <summary>Was die Vorschau auf dem Sperr-Desktop zeigt.</summary>
public enum PreviewContent
{
    /// <summary>Keine Vorschau (ausgeschaltet oder „verdeckt“).</summary>
    None,
    /// <summary>Alle Fenster wie im Abdeckungs-Modus „durchsichtig“, mit verdeckten Bereichen.</summary>
    AllWindows,
    /// <summary>Nur die Fenster der freigegebenen Programme (<see cref="AppearanceSettings.RevealProcesses"/>), mit verdeckten Bereichen.</summary>
    RevealedWindows,
}

/// <summary>
/// Vorschau des Windows-Desktops auf dem Sperr-Desktop. Ein Desktop, der nicht Eingabe-Desktop ist, wird von Windows
/// nicht gezeichnet; BitBlt vom Bildschirm liefert dort nichts. Vitrine setzt die Vorschau deshalb aus den einzelnen
/// Fenstern zusammen (PrintWindow auf einem Thread des Windows-Desktops). Sie zeigt nie mehr als der Abdeckungs-Modus mit
/// derselben Darstellung: „verdeckt“ zeigt nichts, „nur freigegebene Programme“ nur diese, verdeckte Bereiche bleiben verdeckt.
/// </summary>
public static class DesktopPreview
{
    /// <summary>Kürzester und längster Abstand zwischen zwei Bildern.</summary>
    public const int MinSeconds = 1, MaxSeconds = 60;

    public static PreviewContent ContentFor(LockSettings lockSettings, AppearanceSettings look)
    {
        if (lockSettings.Mode != LockMode.Desktop || !lockSettings.DesktopShowPreview) return PreviewContent.None;
        return look.Visual switch
        {
            LockVisual.Blank => PreviewContent.None,
            LockVisual.Windows => look.RevealProcesses.Any(p => !string.IsNullOrWhiteSpace(p)) ? PreviewContent.RevealedWindows : PreviewContent.None,
            _ => PreviewContent.AllWindows,
        };
    }

    /// <summary>Abstand der Bilder; null = nur ein Bild beim Sperren (Einstellung 0 oder kleiner).</summary>
    public static TimeSpan? Interval(int seconds) =>
        seconds <= 0 ? null : TimeSpan.FromSeconds(Math.Clamp(seconds, MinSeconds, MaxSeconds));

    /// <summary>
    /// Fenster, die auf einem Monitor in die Vorschau gezeichnet werden, als Indizes in <paramref name="windowsTopToBottom"/>
    /// in Zeichenreihenfolge (unterstes zuerst). Fenster ohne Fläche auf dem Monitor fallen weg; bei
    /// <see cref="PreviewContent.RevealedWindows"/> alle außer denen der freigegebenen Programme.
    /// </summary>
    public static List<int> WindowsToDraw(IReadOnlyList<(PixelRect Rect, bool Reveal)> windowsTopToBottom, PixelRect monitor, PreviewContent content)
    {
        var list = new List<int>();
        if (content == PreviewContent.None) return list;
        for (int i = windowsTopToBottom.Count - 1; i >= 0; i--)
        {
            var (rect, reveal) = windowsTopToBottom[i];
            if (rect.Intersect(monitor).IsEmpty) continue;
            if (content == PreviewContent.RevealedWindows && !reveal) continue;
            list.Add(i);
        }
        return list;
    }
}
