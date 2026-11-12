// SPDX-License-Identifier: MIT
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace Vitrine.Services.Supervisor;

/// <summary>
/// Rechte der Dienst-Pipe \\.\pipe\ICT-Baden.Vitrine.Service an einer Stelle: was die Sitzungs-App beim Öffnen verlangt
/// und was die Zugriffsliste des Dienstes angemeldeten Benutzern gewährt. Beides muss zusammenpassen – sonst scheitert
/// jede Verbindung eines normalen Benutzers mit „Zugriff verweigert“ (so in 0.1.0-ci.21: Der Client öffnete mit
/// PipeDirection.Out = GENERIC_WRITE, das Windows zu FILE_GENERIC_WRITE 0x120116 inklusive READ_CONTROL und
/// FILE_APPEND_DATA erweitert; gewährt waren nur 0x100112). Getestet in tests/…/Windows/ServicePipeTests.cs.
/// </summary>
internal static class ServicePipe
{
    /// <summary>
    /// Was die Sitzungs-App beim Öffnen verlangt: schreiben, Attribute lesen (Zustand der Pipe), warten. Ausdrücklich
    /// nicht <see cref="PipeAccessRights.CreateNewInstance"/> (= FILE_APPEND_DATA): Wer das darf, kann selbst Instanzen
    /// der Dienst-Pipe anlegen und Verbindungen anderer Sitzungen abfangen.
    /// </summary>
    public const PipeAccessRights ClientRights = PipeAccessRights.WriteData | PipeAccessRights.ReadAttributes | PipeAccessRights.Synchronize;

    /// <summary>Was angemeldete Benutzer dürfen: genau <see cref="ClientRights"/>, dazu die Rechte lesen.</summary>
    public const PipeAccessRights UserRights = ClientRights | PipeAccessRights.ReadPermissions;

    /// <summary>Rechte, die normale Benutzer nie bekommen dürfen.</summary>
    public const PipeAccessRights ForbiddenForUsers = PipeAccessRights.CreateNewInstance | PipeAccessRights.ChangePermissions |
                                                      PipeAccessRights.TakeOwnership | PipeAccessRights.Delete | PipeAccessRights.ReadData;

    /// <summary>
    /// Puffer der Pipe beim Dienst (Bytes). Mit 0 wartet jedes Schreiben der App, bis der Dienst gelesen hat; Nachrichten
    /// sind höchstens 64 Zeichen lang, so passen viele hinein, falls der Dienst kurz beschäftigt ist.
    /// </summary>
    public const int InBufferSize = 4096;

    /// <summary>Zugriffsliste der Pipe: SYSTEM und Administratoren voll, angemeldete Benutzer nur <see cref="UserRights"/>.</summary>
    public static PipeSecurity Security()
    {
        var acl = new PipeSecurity();
        acl.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        acl.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        acl.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null), UserRights, AccessControlType.Allow));
        return acl;
    }

    /// <summary>Client-Ende mit genau <see cref="ClientRights"/> (nicht PipeDirection.Out, das wäre GENERIC_WRITE).</summary>
    public static NamedPipeClientStream OpenClient(string name) =>
        new(".", name, ClientRights, PipeOptions.None, TokenImpersonationLevel.Identification, HandleInheritability.None);

    /// <summary>
    /// Sitzung des Pipe-Servers, ohne Zugriff auf seinen Prozess (den hat ein normaler Benutzer bei einem SYSTEM-Dienst
    /// nicht; ProcessIdToSessionId scheiterte deshalb). null, wenn Windows sie nicht liefert.
    /// </summary>
    public static int? ServerSession(SafePipeHandle pipe) =>
        SessionApi.GetNamedPipeServerSessionId(pipe, out var session) ? session : null;
}
