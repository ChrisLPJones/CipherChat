using System.Net;
using System.Net.Sockets;
using System.Text;

namespace CipherChatServer;

// TCP chat server speaking wire protocol v3 (see README "Protocol v3").
// The server routes by opaque channel tag only. It never decrypts anything: payloads and
// presence blobs are validated for charset and length and relayed byte-identical.
// It logs no payloads, presence blobs, tags or IP addresses.
public class ChatServer : IDisposable
{
    private const int WriteTimeoutMs = 5000;

    // One lock guards the registry (clients, channels, per-connection joined sets) and
    // serialises sends so per-channel ordering matches id order.
    private readonly object sync = new();
    private readonly List<Connection> clients = [];
    private readonly Dictionary<string, Channel> channels = [];
    private int nextMid;

    private readonly TcpListener listener;
    private readonly TaskCompletionSource<bool> stopped = new();
    private Task acceptTask;
    private int stopRequested;

    // The port the listener is actually bound to (useful when started on port 0)
    public int Port { get; private set; }

    // Completes when Stop() has finished shutting the server down
    public Task Stopped => stopped.Task;

    public ChatServer(string host, int port)
    {
        IPAddress address = host == "localhost" ? IPAddress.Loopback : IPAddress.Parse(host);
        listener = new(address, port);
    }

    // Starts the TCP server listening and begins accepting client connections
    public void Start()
    {
        listener.Start();
        Port = ((IPEndPoint)listener.LocalEndpoint).Port;
        acceptTask = Task.Run(AcceptLoop);
    }

    // Stops accepting connections, closes all clients and waits for the accept loop to finish
    public void Stop()
    {
        if (Interlocked.Exchange(ref stopRequested, 1) == 1) return;

        listener.Stop();

        lock (sync)
        {
            foreach (var client in clients) client.Close();
        }

        acceptTask?.Wait();
        stopped.TrySetResult(true);
    }

    public void Dispose()
    {
        Stop();
    }

    private void AcceptLoop()
    {
        while (true)
        {
            TcpClient tcp;
            try
            {
                tcp = listener.AcceptTcpClient();
            }
            catch (Exception)
            {
                // Listener was stopped
                break;
            }

            Connection conn = new(tcp, Interlocked.Increment(ref nextMid));
            lock (sync)
            {
                clients.Add(conn);
            }
            _ = Task.Run(() => HandleClient(conn));
        }
    }

    // Manages communication with a single connected client
    private void HandleClient(Connection conn)
    {
        try
        {
            StreamReader reader = new(conn.Stream, Encoding.ASCII);

            // Handshake: the first line must be exactly "HELLO 3". Anything else (including a
            // bare Base64 line from a v2 client) gets ERR version and the connection is closed.
            string first = ProtocolLimits.ReadBoundedLine(reader, ProtocolLimits.MaxLineChars);
            if (first == null) return;
            if (!ServerFrame.TryParse(first, out ClientCommand hello) || hello.Verb != ClientVerb.Hello)
            {
                conn.Send(ServerFrame.Err("version"));
                return;
            }
            conn.Send(ServerFrame.Welcome(conn.Mid));

            while (true)
            {
                string line = ProtocolLimits.ReadBoundedLine(reader, ProtocolLimits.MaxLineChars);
                if (line == null) break;

                // Any line outside the grammar drops this client only
                if (!ServerFrame.TryParse(line, out ClientCommand cmd)) break;
                if (!Dispatch(conn, cmd)) break;
            }
        }
        catch (InvalidDataException)
        {
            // Over-length line: close this client only
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException or InvalidOperationException)
        {
            // Client went away or the server is stopping
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error handling client: {ex.GetType().Name}");
        }
        finally
        {
            Cleanup(conn);
        }
    }

    // Executes one validated command; returns false to close the connection.
    private bool Dispatch(Connection conn, ClientCommand cmd)
    {
        switch (cmd.Verb)
        {
            case ClientVerb.Hello:
                return false; // handshake already done

            case ClientVerb.Ping:
                conn.Send(ServerFrame.Pong);
                return true;

            case ClientVerb.Join:
                lock (sync)
                {
                    if (conn.Joined.ContainsKey(cmd.Tag)) { conn.Send(ServerFrame.Err("alreadyjoined")); return true; }
                    if (conn.Joined.Count >= ProtocolLimits.MaxChannelsPerClient) { conn.Send(ServerFrame.Err("limit")); return true; }

                    if (!channels.TryGetValue(cmd.Tag, out Channel channel))
                        channels[cmd.Tag] = channel = new Channel();

                    // Roster: everyone already in the channel, then the joiner itself last
                    // (clients use the self entry as the end-of-roster marker).
                    foreach (Connection m in channel.Members)
                        conn.Send(ServerFrame.Member(cmd.Tag, m.Mid, m.Joined[cmd.Tag]));
                    conn.Joined[cmd.Tag] = cmd.Data;
                    conn.Send(ServerFrame.Member(cmd.Tag, conn.Mid, cmd.Data));
                    foreach (Connection m in channel.Members)
                        m.Send(ServerFrame.Joined(cmd.Tag, conn.Mid, cmd.Data));
                    channel.Members.Add(conn);
                }
                return true;

            case ClientVerb.Leave:
                lock (sync)
                {
                    if (!conn.Joined.ContainsKey(cmd.Tag)) { conn.Send(ServerFrame.Err("notjoined")); return true; }
                    RemoveFromChannel(conn, cmd.Tag);
                }
                return true;

            case ClientVerb.Msg:
                lock (sync)
                {
                    if (!conn.Joined.ContainsKey(cmd.Tag)) { conn.Send(ServerFrame.Err("notjoined")); return true; }
                    Channel channel = channels[cmd.Tag];
                    long id = ++channel.LastId;
                    foreach (Connection m in channel.Members)
                        if (m != conn) m.Send(ServerFrame.Msg(cmd.Tag, id, cmd.Data));
                    conn.Send(ServerFrame.Ack(cmd.Tag, id));
                }
                return true;

            case ClientVerb.Hist:
                lock (sync)
                {
                    // History is a later feature; the grammar is already fixed.
                    conn.Send(ServerFrame.Err(conn.Joined.ContainsKey(cmd.Tag) ? "unsupported" : "notjoined"));
                }
                return true;

            default:
                return false;
        }
    }

    // Caller holds sync. Removes the connection from a channel and tells the others.
    private void RemoveFromChannel(Connection conn, string tag)
    {
        conn.Joined.Remove(tag);
        if (!channels.TryGetValue(tag, out Channel channel)) return;
        channel.Members.Remove(conn);
        foreach (Connection m in channel.Members) m.Send(ServerFrame.Left(tag, conn.Mid));
        if (channel.Members.Count == 0) channels.Remove(tag);
    }

    // Emits LEFT for every channel the connection was in (also covers crashes) and closes the socket.
    private void Cleanup(Connection conn)
    {
        lock (sync)
        {
            clients.Remove(conn);
            foreach (string tag in conn.Joined.Keys.ToList())
                RemoveFromChannel(conn, tag);
        }
        conn.Close();
    }

    private sealed class Channel
    {
        public readonly List<Connection> Members = [];
        public long LastId;
    }

    private sealed class Connection
    {
        private readonly TcpClient tcp;
        private readonly object writeLock = new();

        public Connection(TcpClient tcp, int mid)
        {
            this.tcp = tcp;
            Mid = mid;
            Stream = tcp.GetStream();
            Stream.WriteTimeout = WriteTimeoutMs;
        }

        public int Mid { get; }
        public NetworkStream Stream { get; }

        // tag -> presence blob (opaque); guarded by the server's sync lock
        public Dictionary<string, string> Joined { get; } = [];

        // Writes one line; a failing or stuck peer is closed instead of blocking the server.
        public void Send(string line)
        {
            byte[] buffer = Encoding.ASCII.GetBytes(line + "\n");
            lock (writeLock)
            {
                try
                {
                    Stream.Write(buffer, 0, buffer.Length);
                }
                catch (Exception)
                {
                    Close();
                }
            }
        }

        public void Close()
        {
            try { tcp.Close(); } catch (Exception) { }
        }
    }
}
