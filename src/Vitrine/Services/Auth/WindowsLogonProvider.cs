// SPDX-License-Identifier: MIT
using System.Runtime.InteropServices;
using System.Security.Principal;
using Vitrine.Abstractions;
using Vitrine.Core.Auth;
using Vitrine.Core.Localization;
using Vitrine.Services.Interop;

namespace Vitrine.Services.Auth;

/// <summary>
/// Windows-Anmeldedialog („windowslogon“): der Dialog „Windows-Sicherheit“ mit allen Anmeldeanbietern, die Windows dort
/// anbietet (Kennwort, PIN, Smartcard, FIDO2-Sicherheitsschlüssel …), für jede Person – auch eine, die sich an diesem
/// Gerät noch nie angemeldet hat. Geprüft wird mit genau einem LsaLogonUser (Interaktiv); Name, SID und Gruppen kommen
/// aus dem Token, wie beim Windows-Kennwort. Der Dienst kann das nicht nachprüfen (#15): Signaturen als „client“.
/// </summary>
public sealed class WindowsLogonProvider : IAuthProvider
{
    private readonly SessionInfo _session;
    private readonly IWindowsCredentialDialog _dialog;

    // Höchstens ein Dialog: Der Aufruf blockiert, bis der Dialog zu ist. Statisch, weil Einstellungen und Sperre je eigene
    // Anbieter-Objekte haben können, aber derselbe Prozess den Dialog zeigt.
    private static readonly PromptGate Gate = new();
    private static nint _openOwner;
    private static IReadOnlySet<nint> _openBefore = new HashSet<nint>();

    public WindowsLogonProvider(SessionInfo session, IWindowsCredentialDialog? dialog = null)
    {
        _session = session;
        _dialog = dialog ?? new CredUiDialog();
    }

    public string Id => WindowsLogonDialog.MethodId;
    public string DisplayName => UI.Loc.T("Method_WindowsLogon");
    public string Glyph => ""; // Shield: „Windows-Sicherheit“
    public AuthInputKind Input => AuthInputKind.External;

    public Task<bool> IsAvailableAsync(CancellationToken ct) =>
        Task.FromResult(WindowsLogonDialog.IsAvailable(Environment.OSVersion.Version, CredUiDialog.Present()));

    public async Task<AuthOutcome> AuthenticateAsync(AuthRequest request, CancellationToken ct)
    {
        // Läuft noch der Dialog eines abgebrochenen Versuchs: schließen und kurz warten, nie einen zweiten öffnen
        if (Gate.Busy)
        {
            AuthDialogCloser.Close(_openOwner, _openBefore);
            for (int i = 0; i < 20 && Gate.Busy; i++) await Task.Delay(100, CancellationToken.None);
        }
        if (!Gate.TryEnter())
            return AuthOutcome.Fail(CoreText.Error(ErrorCodes.WindowsLogonStillOpen), ErrorCodes.WindowsLogonStillOpen);
        _openOwner = request.OwnerWindow;
        _openBefore = AuthDialogCloser.Snapshot();

        // Der Dialog ist modal und blockiert: eigener STA-Thread, der Dispatcher der Oberfläche läuft weiter. Beim Zeitlimit
        // kehrt die Aufgabe als „abgebrochen“ zurück; was der Dialog danach noch liefert, wird verworfen (nicht angemeldet).
        // Texte hier holen: Der neue Thread hat nicht unbedingt die Sprache der Oberfläche
        var caption = $"Vitrine – {request.Reason}";
        var message = UI.Loc.T("Prompt_WindowsLogonMessage");
        var tcs = new TaskCompletionSource<AuthOutcome>(TaskCreationOptions.RunContinuationsAsynchronously);
        var owner = request.OwnerWindow;
        var before = _openBefore;
        var thread = new Thread(() =>
        {
            try
            {
                tcs.TrySetResult(WindowsLogonDialog.Authenticate(_dialog, owner, caption, message, _session.Sid, ct));
            }
            catch (Exception ex)
            {
                tcs.TrySetResult(AuthOutcome.Fail(ErrorCodes.WithCode(ex.Message, ErrorCodes.WindowsLogonError), ErrorCodes.WindowsLogonError));
            }
            finally { Gate.Exit(); }
        }) { IsBackground = true, Name = "Vitrine CredUI" };
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        // Zeitlimit oder Abbruch: Dialog schließen und den Entsperr-Dialog wieder freigeben (vorher blieb beides hängen)
        using var reg = ct.Register(() => AuthDialogCloser.Close(owner, before));
        try { return await tcs.Task.WaitAsync(ct).ConfigureAwait(false); }
        catch (OperationCanceledException)
        {
            AuthDialogCloser.Close(owner, before);
            throw;
        }
    }
}

/// <summary>CredUIPromptForWindowsCredentials und LsaLogonUser (credui.dll, secur32.dll).</summary>
internal sealed class CredUiDialog : IWindowsCredentialDialog
{
    public static bool Present() => File.Exists(Path.Combine(Environment.SystemDirectory, "credui.dll"));

    public int Prompt(nint owner, string caption, string message, out IWindowsCredential? credential)
    {
        credential = null;
        var info = new CREDUI_INFO
        {
            cbSize = Marshal.SizeOf<CREDUI_INFO>(),
            hwndParent = owner,
            pszMessageText = message,
            pszCaptionText = caption,
        };
        uint package = 0;
        // Flags 0: alle Windows-Anmeldeanbieter; kein vorausgefüllter Benutzer
        int err = CredUIPromptForWindowsCredentials(ref info, 0, ref package, 0, 0, out var buffer, out var size, 0, 0);
        if (err != 0)
        {
            if (buffer != 0) new Credential(buffer, size, package).Dispose();
            return err;
        }
        credential = new Credential(buffer, size, package);
        return 0;
    }

    public int Logon(IWindowsCredential credential, out WindowsAccountInfo? account)
    {
        account = null;
        var c = (Credential)credential;
        int status = LsaConnectUntrusted(out var lsa);
        if (status != 0) return LsaNtStatusToWinError(status);
        var origin = Marshal.StringToHGlobalAnsi("Vitrine");
        try
        {
            var originName = new LSA_STRING { Length = 7, MaximumLength = 8, Buffer = origin };
            var source = new TOKEN_SOURCE { SourceName = "Vitrine\0"u8.ToArray() };
            AllocateLocallyUniqueId(out source.SourceIdentifier);
            status = LsaLogonUser(lsa, ref originName, 2 /* Interactive */, c.Package, c.Buffer, c.Size, 0, ref source,
                out var profile, out _, out _, out var token, out _, out int subStatus);
            if (profile != 0) LsaFreeReturnBuffer(profile);
            if (status != 0)
            {
                if (token != 0) Native.CloseHandle(token);
                // STATUS_ACCOUNT_RESTRICTION: Der Unterstatus sagt, was genau (Kennwort abgelaufen, Anmeldezeiten …)
                if ((uint)status == 0xC000006E && subStatus != 0) status = subStatus;
                return LsaNtStatusToWinError(status);
            }
            try
            {
                using var id = new WindowsIdentity(token);
                var groups = WindowsAccounts.GetGroupSids(id);
                account = new WindowsAccountInfo(id.Name, id.User?.Value, groups, groups.Contains(WindowsAccounts.AdministratorsSid));
                return 0;
            }
            finally { Native.CloseHandle(token); }
        }
        finally
        {
            Marshal.FreeHGlobal(origin);
            LsaDeregisterLogonProcess(lsa);
        }
    }

    /// <summary>Auth-Puffer von CredUI: beim Verwerfen überschreiben und mit CoTaskMemFree freigeben.</summary>
    private sealed class Credential(nint buffer, uint size, uint package) : IWindowsCredential
    {
        public nint Buffer { get; private set; } = buffer;
        public uint Size { get; } = size;
        public uint Package { get; } = package;

        public void Dispose()
        {
            if (Buffer == 0) return;
            if (Size > 0) Marshal.Copy(new byte[Size], 0, Buffer, (int)Size);
            Marshal.FreeCoTaskMem(Buffer);
            Buffer = 0;
        }
    }

    // ---------- Interop ----------

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CREDUI_INFO
    {
        public int cbSize;
        public nint hwndParent;
        public string pszMessageText;
        public string pszCaptionText;
        public nint hbmBanner;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LSA_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public nint Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_SOURCE
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] SourceName;
        public LUID SourceIdentifier;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct QUOTA_LIMITS
    {
        public nint PagedPoolLimit;
        public nint NonPagedPoolLimit;
        public nint MinimumWorkingSetSize;
        public nint MaximumWorkingSetSize;
        public nint PagefileLimit;
        public long TimeLimit;
    }

    [DllImport("credui.dll", CharSet = CharSet.Unicode)]
    private static extern int CredUIPromptForWindowsCredentials(ref CREDUI_INFO pUiInfo, int dwAuthError, ref uint pulAuthPackage,
        nint pvInAuthBuffer, uint ulInAuthBufferSize, out nint ppvOutAuthBuffer, out uint pulOutAuthBufferSize, nint pfSave, uint dwFlags);

    [DllImport("secur32.dll")]
    private static extern int LsaConnectUntrusted(out nint lsaHandle);

    [DllImport("secur32.dll")]
    private static extern int LsaLogonUser(nint lsaHandle, ref LSA_STRING originName, int logonType, uint authenticationPackage,
        nint authenticationInformation, uint authenticationInformationLength, nint localGroups, ref TOKEN_SOURCE sourceContext,
        out nint profileBuffer, out uint profileBufferLength, out LUID logonId, out nint token, out QUOTA_LIMITS quotas, out int subStatus);

    [DllImport("secur32.dll")]
    private static extern int LsaFreeReturnBuffer(nint buffer);

    [DllImport("secur32.dll")]
    private static extern int LsaDeregisterLogonProcess(nint lsaHandle);

    [DllImport("advapi32.dll")]
    private static extern int LsaNtStatusToWinError(int status);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AllocateLocallyUniqueId(out LUID luid);
}
