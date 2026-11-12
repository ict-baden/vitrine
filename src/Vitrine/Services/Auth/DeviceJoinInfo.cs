// SPDX-License-Identifier: MIT
using System.Runtime.InteropServices;
using Vitrine.Core.Auth;
using Vitrine.Services.Interop;

namespace Vitrine.Services.Auth;

/// <summary>Anbindung des Geräts (Entra-joined, AD, Hybrid); in Tests durch eine Attrappe ersetzbar.</summary>
public interface IDeviceJoinInfo
{
    DeviceJoinState Get();
}

/// <summary>
/// Ermittelt die Anbindung wie <c>dsregcmd /status</c>: NetGetAadJoinInformation (Entra) und NetGetJoinInformation (AD).
/// Bei Fehlern <see cref="DeviceJoinState.Unknown"/> – dann entscheidet <see cref="LogonTarget"/> nach dem Sitzungskonto.
/// Einmal pro Prozess ermittelt.
/// </summary>
public sealed class WindowsDeviceJoinInfo : IDeviceJoinInfo
{
    private readonly Lazy<DeviceJoinState> _state = new(Query);

    public DeviceJoinState Get() => _state.Value;

    private static DeviceJoinState Query()
    {
        bool? entra = QueryEntra();
        bool? domain = QueryDomain();
        if (entra is null || domain is null)
        {
            // Teilweise bekannt: In einer AD-Domäne löst der Domänencontroller UPNs auf (AD oder Hybrid, gleiche Folge)
            return domain == true ? DeviceJoinState.DomainJoined : DeviceJoinState.Unknown;
        }
        return (entra.Value, domain.Value) switch
        {
            (true, true) => DeviceJoinState.HybridJoined,
            (true, false) => DeviceJoinState.EntraJoined,
            (false, true) => DeviceJoinState.DomainJoined,
            _ => DeviceJoinState.Workgroup,
        };
    }

    private static bool? QueryEntra()
    {
        try
        {
            if (Native.NetGetAadJoinInformation(null, out var info) != 0) return null;
            if (info == 0) return false;
            try
            {
                // DSREG_JOIN_INFO beginnt mit joinType (DSREG_JOIN_TYPE, 32 Bit); Arbeitsplatz-Registrierung zählt nicht
                return Marshal.ReadInt32(info) == Native.DSREG_DEVICE_JOIN;
            }
            finally { Native.NetFreeAadJoinInformation(info); }
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException) { return null; }
    }

    private static bool? QueryDomain()
    {
        try
        {
            if (Native.NetGetJoinInformation(null, out var name, out var type) != 0) return null;
            if (name != 0) Native.NetApiBufferFree(name);
            return type == Native.NetSetupDomainName;
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException) { return null; }
    }
}
