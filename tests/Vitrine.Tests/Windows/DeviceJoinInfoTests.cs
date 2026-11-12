// SPDX-License-Identifier: MIT
using Vitrine.Core.Auth;
using Vitrine.Services.Auth;

namespace Vitrine.Tests.Windows;

/// <summary>Join-Status nur lesen (NetGetAadJoinInformation/NetGetJoinInformation) – ändert nichts am Rechner.</summary>
public sealed class DeviceJoinInfoTests
{
    [Fact]
    public void Liefert_einen_Zustand_ohne_Ausnahme_und_bleibt_gleich()
    {
        var info = new WindowsDeviceJoinInfo();
        var first = info.Get();
        Assert.True(Enum.IsDefined(first));
        Assert.Equal(first, info.Get());
    }
}
