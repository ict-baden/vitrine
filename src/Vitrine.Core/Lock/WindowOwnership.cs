// SPDX-License-Identifier: MIT
namespace Vitrine.Core.Lock;

/// <summary>
/// Während einer externen Anmeldung dürfen auch Fenster Eingaben bekommen, die einem ausdrücklich freigegebenen Fenster
/// von Vitrine gehören (Besitzer-Kette, GW_OWNER) – unabhängig vom Prozess. Anmeldedialoge von Windows werden mit dem
/// übergebenen Fenster als Besitzer geöffnet (MSAL: WithParentActivityOrWindow); ihr Prozess wechselt mit der
/// Windows-Version (Microsoft.AAD.BrokerPlugin.exe, AccountsControlHost.exe in ApplicationFrameHost …). Vorher zählte nur
/// der Prozess, und das Broker-Fenster bekam gesperrt keine Eingaben (Gerätetest 2026-10-26).
/// </summary>
public static class WindowOwnership
{
    /// <summary>Höchstens so viele Besitzer-Stufen (gegen Schleifen).</summary>
    public const int MaxDepth = 8;

    /// <param name="window">Oberstes Fenster unter dem Zeiger bzw. im Vordergrund.</param>
    /// <param name="owner">GW_OWNER eines Fensters (0 = keiner).</param>
    /// <param name="allowed">Ausdrücklich freigegebenes Fenster (Dialog, Anmeldefenster von Vitrine)?</param>
    public static bool OwnedByAllowed(nint window, Func<nint, nint> owner, Func<nint, bool> allowed)
    {
        var current = window;
        for (int i = 0; i < MaxDepth && current != 0; i++)
        {
            current = owner(current);
            if (current == 0 || current == window) return false;
            if (allowed(current)) return true;
        }
        return false;
    }
}
