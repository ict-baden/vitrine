// SPDX-License-Identifier: MIT
namespace Vitrine.Core.Lock;

/// <summary>
/// Auslöser einer Sperre, wie sie im Protokoll, im Ereignis „subscribe“ und in %VITRINE_TRIGGER% der Skripte stehen.
/// Feste englische Kennungen, damit Auswertungen nicht von der Sprache der Oberfläche abhängen (bis 2026-10 deutsche
/// Texte wie „Tastenkürzel“, siehe CHANGELOG).
/// </summary>
public static class LockTriggers
{
    public const string Hotkey = "hotkey";
    public const string Tray = "tray";
    public const string TrayBlank = "tray-blank";
    public const string Settings = "settings";
    public const string Startup = "startup";
    public const string Screensaver = "screensaver";
    public const string Api = "api";
    /// <summary>Win+L mit <c>Lock.ReplaceWinL</c>.</summary>
    public const string WinL = "win-l";

    public static string Idle(int minutes) => $"idle ({minutes} min)";

    public static string Scheduled(string time) => $"schedule {time}";
}
