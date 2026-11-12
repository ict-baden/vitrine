// SPDX-License-Identifier: MIT
using Vitrine.Core.Auth;
using Vitrine.Services.Interop;

namespace Vitrine.Services.Auth;

/// <summary>
/// Schließt Windows-Anmeldedialoge eines abgebrochenen Versuchs (WM_CLOSE) und gibt den Entsperr-Dialog wieder frei
/// (modale Dialoge deaktivieren ihren Besitzer). Welche Fenster, entscheidet <see cref="OwnedAuthDialogs"/>.
/// </summary>
internal static class AuthDialogCloser
{
    /// <summary>Sichtbare oberste Fenster der Dialog-Prozesse (Momentaufnahme vor dem Versuch).</summary>
    public static HashSet<nint> Snapshot() => Windows().Where(w => w.ProcessName is { } p && OwnedAuthDialogs.Processes.Contains(p))
        .Select(w => w.Window).ToHashSet();

    public static void Close(nint owner, IReadOnlySet<nint> before)
    {
        try
        {
            foreach (var w in OwnedAuthDialogs.ToClose(Windows(), owner, before))
                Native.PostMessage(w, Native.WM_CLOSE, 0, 0);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException) { }
        if (owner != 0 && !Native.IsWindowEnabled(owner)) Native.EnableWindow(owner, true);
    }

    private static List<TopWindow> Windows()
    {
        var list = new List<TopWindow>();
        var names = new Dictionary<uint, string?>();
        Native.EnumWindows((h, _) =>
        {
            if (!Native.IsWindowVisible(h)) return true;
            Native.GetWindowThreadProcessId(h, out var pid);
            if (!names.TryGetValue(pid, out var name)) names[pid] = name = Native.GetProcessImageName(pid);
            list.Add(new TopWindow(h, Native.GetWindow(h, Native.GW_OWNER), name));
            return true;
        }, 0);
        return list;
    }
}
