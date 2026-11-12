// SPDX-License-Identifier: MIT
using System.ServiceProcess;
using System.Windows.Threading;
using Vitrine.Core.About;
using Vitrine.Core.Service;

namespace Vitrine.Services.Supervisor;

/// <summary>Ergebnis eines Verbindungsversuchs zum Dienst.</summary>
public enum ServiceLinkResult
{
    Connected,
    /// <summary>Dienst nicht installiert oder nicht gestartet (portable Exe, SERVICE=0 schaltet nur die Überwachung ab).</summary>
    NoService,
    /// <summary>Pipe nicht erreichbar (Dienst startet gerade, Zeitüberschreitung).</summary>
    Unavailable,
    /// <summary>Zugriff verweigert – die Rechte der Pipe passen nicht (siehe <see cref="ServicePipe"/>).</summary>
    Denied,
    /// <summary>Der Pipe-Server läuft nicht in Sitzung 0, ist also nicht der Dienst.</summary>
    WrongServer,
}

/// <summary>
/// Verbindung der Sitzungs-App zum Dienst „ICT-Baden Vitrine“: meldet Sperrzustand und Lebenszeichen. Gibt es keinen
/// Dienst (oder bricht die Verbindung ab), übernimmt wie bisher der Wächterprozess (<see cref="Lock.Watchdog"/>).
/// <see cref="TryConnect"/> blockiert bis zu einer halben Sekunde und gehört deshalb nicht auf den UI-Thread (außer beim Start).
/// Geschrieben wird in einem eigenen Thread: Liest der Dienst gerade nicht (beschäftigt oder hängend), hält das nie die
/// Oberfläche an – auch nicht beim Sperren.
/// </summary>
public static class ServiceLink
{
    private sealed class Connection(System.IO.Pipes.NamedPipeClientStream pipe)
    {
        public readonly System.IO.Pipes.NamedPipeClientStream Pipe = pipe;
        public readonly StreamWriter Writer = new(pipe) { AutoFlush = true };
        public readonly System.Collections.Concurrent.BlockingCollection<(AgentMessage Message, ManualResetEventSlim? Done)> Queue = new(256);
    }

    private static readonly object Gate = new();
    private static Connection? _connection;
    private static Timer? _beat;
    private static DispatcherTimer? _uiAlive;
    private static long _uiTick = Environment.TickCount64;
    private static volatile bool _locked;

    /// <summary>Verbindung abgebrochen (Dienst beendet). Wird höchstens einmal je Verbindung ausgelöst, auf einem Hintergrund-Thread.</summary>
    public static event Action? Lost;

    public static bool Connected { get { lock (Gate) return _connection is not null; } }

    /// <summary>
    /// Einmal beim Start auf dem UI-Thread: Lebenszeichen der Oberfläche messen. Der Dienst bekommt „beat“ nur, solange die
    /// Oberfläche reagiert – hängt sie, merkt er es.
    /// </summary>
    public static void Initialize(Dispatcher ui)
    {
        if (_uiAlive is not null) return;
        Interlocked.Exchange(ref _uiTick, Environment.TickCount64);
        _uiAlive = new DispatcherTimer(TimeSpan.FromSeconds(1), DispatcherPriority.Normal, (_, _) => Interlocked.Exchange(ref _uiTick, Environment.TickCount64), ui);
        _uiAlive.Start();
    }

    /// <summary>Läuft der Dienst? Ohne ihn gar nicht erst auf die Pipe warten (portable Exe: kein Halt alle 30 s).</summary>
    private static bool ServiceRunning()
    {
        try
        {
            using var sc = new ServiceController(AppPaths.ServiceName);
            return sc.Status is ServiceControllerStatus.Running or ServiceControllerStatus.StartPending;
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception) { return false; }
    }

    /// <summary>
    /// Mit dem Dienst verbinden und den aktuellen (bzw. mit <see cref="Signal"/> vorgemerkten) Sperrzustand melden. Nur
    /// ein Pipe-Server in Sitzung 0 zählt; ein gleichnamiger Server eines Benutzers nicht.
    /// </summary>
    public static ServiceLinkResult TryConnect()
    {
        if (Connected) return ServiceLinkResult.Connected;
        if (!ServiceRunning()) return ServiceLinkResult.NoService;
        System.IO.Pipes.NamedPipeClientStream? pipe = null;
        Connection connection;
        try
        {
            pipe = ServicePipe.OpenClient(AppPaths.ServicePipe);
            pipe.Connect(500);
            if (ServicePipe.ServerSession(pipe.SafePipeHandle) != 0)
            {
                pipe.Dispose();
                return ServiceLinkResult.WrongServer;
            }
            lock (Gate)
            {
                if (_connection is not null) { pipe.Dispose(); return ServiceLinkResult.Connected; }
                _connection = connection = new Connection(pipe);
                // Erste Meldungen vor allen anderen in die Warteschlange
                connection.Queue.Add((AgentMessage.Hello, null));
                connection.Queue.Add((_locked ? AgentMessage.Locked : AgentMessage.Unlocked, null));
                _beat?.Dispose();
                _beat = new Timer(_ =>
                {
                    if (Environment.TickCount64 - Interlocked.Read(ref _uiTick) < 5000) Send(AgentMessage.Beat);
                }, null, SessionSupervisor.BeatInterval, SessionSupervisor.BeatInterval);
            }
        }
        catch (UnauthorizedAccessException)
        {
            pipe?.Dispose();
            return ServiceLinkResult.Denied;
        }
        catch (Exception ex) when (ex is IOException or System.TimeoutException)
        {
            pipe?.Dispose();
            return ServiceLinkResult.Unavailable;
        }

        new Thread(() => WriteLoop(connection)) { IsBackground = true, Name = "Vitrine service link" }.Start();
        return ServiceLinkResult.Connected;
    }

    /// <summary>Sperrzustand melden – oder vor dem Verbinden vormerken (Neustart nach Absturz: gleich „gesperrt“).</summary>
    public static void Signal(bool locked)
    {
        _locked = locked;
        Send(locked ? AgentMessage.Locked : AgentMessage.Unlocked);
    }

    /// <summary>
    /// Beenden wurde von einem Administrator bestätigt: Dienst startet die App bis zur nächsten Anmeldung nicht neu. Wartet
    /// kurz, bis die Nachricht geschrieben ist – gleich danach endet der Prozess.
    /// </summary>
    public static void Exit() => Send(AgentMessage.Exit, wait: true);

    /// <summary>Windows meldet ab oder fährt herunter: Das Ende der App ist dann kein Verlust (wartet wie <see cref="Exit"/>).</summary>
    public static void Logoff() => Send(AgentMessage.Logoff, wait: true);

    private static void Send(AgentMessage m, bool wait = false)
    {
        Connection? c;
        lock (Gate) c = _connection;
        if (c is null) return;
        var done = wait ? new ManualResetEventSlim() : null;
        try
        {
            // Voll heißt: Der Dienst liest seit langem nicht – er merkt das selbst; hier nie blockieren
            if (!c.Queue.TryAdd((m, done))) return;
        }
        catch (InvalidOperationException) { return; } // Verbindung gerade beendet
        done?.Wait(TimeSpan.FromSeconds(1));
    }

    private static void WriteLoop(Connection c)
    {
        try
        {
            foreach (var (message, done) in c.Queue.GetConsumingEnumerable())
            {
                try { c.Writer.WriteLine(ServiceProtocol.Format(message)); }
                finally { done?.Set(); }
            }
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException or InvalidOperationException)
        {
            Action? lost;
            lock (Gate)
            {
                if (_connection != c) return;
                _connection = null;
                _beat?.Dispose();
                _beat = null;
                lost = Lost;
            }
            c.Queue.CompleteAdding();
            foreach (var (_, done) in c.Queue.GetConsumingEnumerable()) done?.Set();
            try { c.Pipe.Dispose(); } catch { }
            lost?.Invoke();
        }
    }
}
