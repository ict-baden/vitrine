// SPDX-License-Identifier: MIT
using System.Runtime.InteropServices;

namespace Vitrine.Services.Lock;

/// <summary>Blendet den Mauszeiger systemweit aus, indem alle Systemzeiger durch einen leeren ersetzt werden.</summary>
public static class CursorHider
{
    private static readonly uint[] CursorIds =
    {
        32512, 32513, 32514, 32515, 32516, 32642, 32643, 32644, 32645, 32646, 32648, 32649, 32650, 32651,
    };

    private static bool _hidden;

    public static void Hide()
    {
        if (_hidden) return;
        var and = Enumerable.Repeat((byte)0xFF, 32 * 4).ToArray();
        var xor = new byte[32 * 4];
        foreach (var id in CursorIds)
        {
            var c = CreateCursor(0, 0, 0, 32, 32, and, xor);
            if (c != 0) SetSystemCursor(c, id); // SetSystemCursor übernimmt und zerstört das Handle
        }
        _hidden = true;
    }

    public static void Show()
    {
        if (!_hidden) return;
        RestoreSystemCursors();
        _hidden = false;
    }

    public static void RestoreSystemCursors() => SystemParametersInfo(0x0057 /* SPI_SETCURSORS */, 0, 0, 0);

    [DllImport("user32.dll")]
    private static extern nint CreateCursor(nint hInst, int xHotSpot, int yHotSpot, int nWidth, int nHeight, byte[] pvANDPlane, byte[] pvXORPlane);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetSystemCursor(nint hcur, uint id);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SystemParametersInfo(uint uiAction, uint uiParam, nint pvParam, uint fWinIni);
}
