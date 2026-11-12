// SPDX-License-Identifier: MIT
using System.ComponentModel;
using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using Vitrine.Services.Supervisor;

namespace Vitrine.Tests.Windows;

/// <summary>
/// Rechte der Dienst-Pipe: Ein normaler Benutzer (Administratoren nur „deny only“ wie unter der Benutzerkontensteuerung)
/// muss sich mit genau den Rechten verbinden können, die die Sitzungs-App verlangt – und darf keine eigenen Instanzen
/// der Pipe anlegen. Die Tests bauen die echte Zugriffsliste des Dienstes und verbinden sich mit einem eingeschränkten
/// Token des Testbenutzers. Kein Dienst wird installiert, nichts gesperrt.
/// </summary>
public sealed class ServicePipeTests
{
    private static readonly SecurityIdentifier AuthenticatedUsers = new(WellKnownSidType.AuthenticatedUserSid, null);
    private static readonly SecurityIdentifier Administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);

    /// <summary>FILE_GENERIC_WRITE: So viel verlangte der Client früher mit PipeDirection.Out (GENERIC_WRITE).</summary>
    private const int FileGenericWrite = 0x120116;

    private static int Granted(PipeSecurity acl, SecurityIdentifier sid) =>
        acl.GetAccessRules(true, false, typeof(SecurityIdentifier)).Cast<PipeAccessRule>()
            .Where(r => r.IdentityReference.Equals(sid) && r.AccessControlType == AccessControlType.Allow)
            .Aggregate(0, (mask, r) => mask | (int)r.PipeAccessRights);

    [Fact]
    public void Benutzer_bekommen_was_der_Client_verlangt_aber_keine_eigenen_Instanzen()
    {
        var users = Granted(ServicePipe.Security(), AuthenticatedUsers);
        Assert.Equal((int)ServicePipe.ClientRights, users & (int)ServicePipe.ClientRights);
        Assert.Equal(0, users & (int)ServicePipe.ForbiddenForUsers);
        Assert.Equal(0, (int)ServicePipe.ClientRights & (int)PipeAccessRights.CreateNewInstance);
    }

    [Fact]
    public void Die_alte_Zugriffsliste_deckte_den_alten_Client_nicht()
    {
        // Befund der Prüfung vom 2026-10-20: gewährt Write|Synchronize, verlangt GENERIC_WRITE – READ_CONTROL fehlte
        const int oldGrant = (int)(PipeAccessRights.Write | PipeAccessRights.Synchronize);
        Assert.NotEqual(FileGenericWrite, FileGenericWrite & oldGrant);
    }

    [Fact]
    public async Task Normaler_Benutzer_verbindet_sich_und_sieht_die_Sitzung_des_Servers()
    {
        var name = $"ICT-Baden.Vitrine.Test.{Guid.NewGuid():N}";
        using var server = NamedPipeServerStreamAcl.Create(name, PipeDirection.In, 1, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous, ServicePipe.InBufferSize, 0, ServicePipe.Security());
        // Warten auf die Verbindung beginnt vor dem Client (sonst „The pipe is being closed“, wenn er schon wieder weg ist)
        var connected = server.WaitForConnectionAsync();
        int? serverSession = null;

        using (var token = StandardUserToken())
            WindowsIdentity.RunImpersonated(token, () =>
            {
                using var client = ServicePipe.OpenClient(name);
                client.Connect(5000);
                serverSession = ServicePipe.ServerSession(client.SafePipeHandle);
                client.Write("hello\n"u8);
            });

        await connected.WaitAsync(TimeSpan.FromSeconds(10));
        // Steht im Puffer der Pipe (ServicePipe.InBufferSize), auch nachdem der Client geschlossen hat
        var buffer = new byte[6];
        await server.ReadExactlyAsync(buffer).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal("hello\n"u8.ToArray(), buffer);
        Assert.Equal(Process.GetCurrentProcess().SessionId, serverSession);
    }

    [Fact]
    public void Mit_den_alten_Rechten_wurde_ein_normaler_Benutzer_abgewiesen()
    {
        // Nur aussagekräftig, wenn die Pipe nicht dem Testbenutzer selbst gehört (Besitzer bekommt READ_CONTROL immer):
        // Ein Administrator-Prozess legt Objekte mit dem Besitzer „Administratoren“ an, im eingeschränkten Token nur „deny only“.
        if (!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator)) return;
        var old = new PipeSecurity();
        old.SetOwner(Administrators);
        old.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        old.AddAccessRule(new PipeAccessRule(Administrators, PipeAccessRights.FullControl, AccessControlType.Allow));
        old.AddAccessRule(new PipeAccessRule(AuthenticatedUsers, PipeAccessRights.Write | PipeAccessRights.Synchronize, AccessControlType.Allow));
        var name = $"ICT-Baden.Vitrine.Test.{Guid.NewGuid():N}";
        using var server = NamedPipeServerStreamAcl.Create(name, PipeDirection.In, 1, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous, ServicePipe.InBufferSize, 0, old);
        _ = server.WaitForConnectionAsync();

        using var token = StandardUserToken();
        WindowsIdentity.RunImpersonated(token, () =>
            Assert.Throws<UnauthorizedAccessException>(() =>
            {
                using var client = new NamedPipeClientStream(".", name, PipeDirection.Out);
                client.Connect(5000);
            }));
    }

    // ---------------- Protokoll-Pipe (#15) ----------------

    [Fact]
    public void Protokoll_Pipe_Benutzer_lesen_und_schreiben_aber_legen_keine_Instanzen_an()
    {
        var users = Granted(AuditPipe.Security(), AuthenticatedUsers);
        Assert.Equal((int)AuditPipe.ClientRights, users & (int)AuditPipe.ClientRights);
        Assert.Equal(0, users & (int)AuditPipe.ForbiddenForUsers);
        Assert.Equal(0, (int)AuditPipe.ClientRights & (int)PipeAccessRights.CreateNewInstance);
    }

    [Fact]
    public async Task Protokoll_Pipe_normaler_Benutzer_bekommt_eine_Antwort_und_der_Server_kennt_ihn()
    {
        var name = $"ICT-Baden.Vitrine.Test.{Guid.NewGuid():N}";
        using var server = NamedPipeServerStreamAcl.Create(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous, AuditPipe.BufferSize, AuditPipe.BufferSize, AuditPipe.Security());
        var connected = server.WaitForConnectionAsync();
        string? answer = null;
        string? clientName = null;

        using var token = StandardUserToken();
        var client = Task.Run(() => WindowsIdentity.RunImpersonated(token, () =>
        {
            using var c = AuditPipe.OpenClient(name);
            c.Connect(5000);
            var w = new StreamWriter(c) { AutoFlush = true }; // ohne using: schließt sonst die Pipe vor dem Lesen
            var r = new StreamReader(c);
            w.WriteLine("{\"op\":\"write\"}");
            answer = r.ReadLine();
        }));

        await connected.WaitAsync(TimeSpan.FromSeconds(10));
        var reader = new StreamReader(server);
        var line = await reader.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal("{\"op\":\"write\"}", line);
        // Wie im Dienst (AuditServer.Identify): unter der Identität der Gegenstelle nur das Token öffnen, den Namen danach –
        // verwalteter Code dort (WindowsIdentity.GetCurrent) scheitert, sobald er eine Assembly laden muss
        nint clientToken = 0;
        server.RunAsClient(() => clientToken = Vitrine.Services.Interop.Native.OpenCurrentThreadToken());
        Assert.NotEqual((nint)0, clientToken);
        try
        {
            using var id = new WindowsIdentity(clientToken);
            clientName = id.Name;
        }
        finally { Vitrine.Services.Interop.Native.CloseHandle(clientToken); }
        var writer = new StreamWriter(server) { AutoFlush = true };
        await writer.WriteLineAsync("{\"ok\":true}");
        await client.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal("{\"ok\":true}", answer);
        Assert.Equal(WindowsIdentity.GetCurrent().Name, clientName);
    }

    // ---------------- Eingeschränktes Token ----------------

    [StructLayout(LayoutKind.Sequential)]
    private struct SID_AND_ATTRIBUTES
    {
        public IntPtr Sid;
        public uint Attributes;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CreateRestrictedToken(SafeAccessTokenHandle existing, uint flags, uint disableSidCount,
        SID_AND_ATTRIBUTES[] sidsToDisable, uint deletePrivilegeCount, IntPtr privilegesToDelete, uint restrictedSidCount,
        IntPtr sidsToRestrict, out SafeAccessTokenHandle newToken);

    /// <summary>Token des Testbenutzers wie bei einem normalen Benutzer: Administratoren nur „deny only“, keine Privilegien.</summary>
    private static SafeAccessTokenHandle StandardUserToken()
    {
        using var me = WindowsIdentity.GetCurrent(TokenAccessLevels.Duplicate | TokenAccessLevels.Query |
                                                  TokenAccessLevels.AssignPrimary | TokenAccessLevels.Impersonate);
        var bytes = new byte[Administrators.BinaryLength];
        Administrators.GetBinaryForm(bytes, 0);
        var sid = Marshal.AllocHGlobal(bytes.Length);
        try
        {
            Marshal.Copy(bytes, 0, sid, bytes.Length);
            const uint DisableMaxPrivilege = 0x1;
            if (!CreateRestrictedToken(me.AccessToken, DisableMaxPrivilege, 1, [new SID_AND_ATTRIBUTES { Sid = sid }], 0, IntPtr.Zero, 0,
                    IntPtr.Zero, out var token))
                throw new Win32Exception();
            return token;
        }
        finally { Marshal.FreeHGlobal(sid); }
    }
}
