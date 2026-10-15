using System.Net;
using System.Net.Sockets;
using System.Text;

namespace CipherChatServer;

// TCP rendezvous server for protocol v5 (paired-code chat). It pairs exactly two connections that present the same
// rendezvous id, then relays KEY / CONFIRM / MSG lines byte-identical between them. It does no cryptography, holds no
// secret and never stores anything on disk. Logging policy: nothing about clients (no rid, nonce, IP or blob) is
// ever written; only exception type names for unexpected errors.
public class ChatServer : IDisposable
{
    private const int WriteTimeoutMs = 5000;

    // One lock guards the registry (connections, per-IP counts, rid table, limiters). Sends to clients happen
    // outside it, so a stuck peer cannot stall the others.
    private readonly object sync = new();
    private readonly List<Connection> clients = [];
    private readonly Dictionary<string, int> perIp = [];
    private readonly Dictionary<string, Entry> rids = [];
    private readonly Dictionary<string, RateLimiter> helloLimiters = [];
    private readonly Dictionary<string, RateLimiter> failLimiters = [];

    private readonly ServerLimits limits;
    private readonly Func<long> clock;
    private readonly TcpListener listener;
    private readonly TaskCompletionSource<bool> stopped = new();
    private Task acceptTask;
    private int stopRequested;

    private enum RidState { Waiting, Paired, Burned }
    private enum Stage { AwaitHello, Waiting, AwaitKey, AwaitConfirm, AwaitMsg }

    private sealed class Entry
    {
        public RidState State;
        public Connection Waiter;
        public long BurnedUntil;
        public long BurnedAt;
    }

    private sealed class Pair
    {
        public Connection A, B;               // A = role 1, B = role 2
        public string Rid;
        public bool Productive;               // at least one MSG was relayed
        public bool Ended;
        public bool Quiet;                    // both sides were told ERR timeout: no GONE on top
        public CancellationTokenSource ConfirmTimer = new();
        public Connection Other(Connection c) => c == A ? B : A;
    }

    // The port the listener is actually bound to (useful when started on port 0)
    public int Port { get; private set; }

    // Completes when Stop() has finished shutting the server down
    public Task Stopped => stopped.Task;

    // Counters for tests (they reveal nothing about clients)
    public int ConnectionCount { get { lock (sync) return clients.Count; } }
    public int WaiterCount { get { lock (sync) return rids.Values.Count(e => e.State == RidState.Waiting); } }
    public int BurnedCount { get { lock (sync) return rids.Values.Count(e => e.State == RidState.Burned); } }

    // Throws ArgumentException / FormatException for a bad host address.
    public ChatServer(string host, int port, ChatServerOptions options = null)
    {
        options ??= new ChatServerOptions();
        limits = options.Limits;
        clock = options.Clock;
        IPAddress address = host == "localhost" ? IPAddress.Loopback : IPAddress.Parse(host);
        listener = new(address, port);
    }

    public void Start()
    {
        listener.Start();
        Port = ((IPEndPoint)listener.LocalEndpoint).Port;
        acceptTask = Task.Run(AcceptLoop);
    }

    public void Stop()
    {
        if (Interlocked.Exchange(ref stopRequested, 1) == 1) return;
        listener.Stop();
        List<Connection> all;
        lock (sync) all = clients.ToList();
        foreach (var c in all) c.Close();
        acceptTask?.Wait();
        stopped.TrySetResult(true);
    }

    public void Dispose() => Stop();

    private void AcceptLoop()
    {
        while (true)
        {
            TcpClient tcp;
            try { tcp = listener.AcceptTcpClient(); }
            catch (Exception) { break; } // listener stopped

            string ip = "?";
            try
            {
                IPAddress a = ((IPEndPoint)tcp.Client.RemoteEndPoint).Address;
                ip = (a.IsIPv4MappedToIPv6 ? a.MapToIPv4() : a).ToString();
            }
            catch (Exception) { }

            Connection conn;
            bool full;
            lock (sync)
            {
                perIp.TryGetValue(ip, out int n);
                full = clients.Count >= limits.MaxConnections || n >= limits.MaxConnectionsPerIp;
                conn = new Connection(tcp, ip, limits, clock);
                if (!full) { clients.Add(conn); perIp[ip] = n + 1; conn.Counted = true; }
            }
            if (full)
            {
                _ = Task.Run(() => { conn.Send(ServerFrame.Err("full")); conn.Close(); });
                continue;
            }
            // One dedicated thread per connection (blocking reads); pool threads ramp up too slowly for hundreds of clients.
            _ = Task.Factory.StartNew(() => HandleClient(conn), TaskCreationOptions.LongRunning);
        }
    }

    private void HandleClient(Connection conn)
    {
        conn.Arm(limits.HelloDeadlineMs, () => conn.Stage == Stage.AwaitHello);
        try
        {
            StreamReader reader = new(conn.Stream, Encoding.ASCII);

            // The first line must be a valid "HELLO 5 <rid> <nonce>"; anything else (HELLO 4, junk) gets ERR version.
            string first = ProtocolLimits.ReadBoundedLine(reader, ProtocolLimits.MaxLineChars);
            if (first == null) return;
            if (!ServerFrame.TryParse(first, out ClientCommand hello) || hello.Verb != ClientVerb.Hello)
            {
                conn.Send(ServerFrame.Err("version"));
                return;
            }
            if (!HandleHello(conn, hello)) return;

            while (true)
            {
                string line = ProtocolLimits.ReadBoundedLine(reader, ProtocolLimits.MaxLineChars);
                if (line == null) break;
                // Any line outside the grammar, or out of order, drops this client (its peer gets GONE)
                if (!ServerFrame.TryParse(line, out ClientCommand cmd)) break;
                if (!Dispatch(conn, cmd)) break;
            }
        }
        catch (InvalidDataException)
        {
            // Over-length line: close this client only
        }
        catch (IOException ex) when (ex.InnerException is SocketException { SocketErrorCode: SocketError.TimedOut })
        {
            conn.Send(ServerFrame.Err("timeout"));
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

    private RateLimiter LimiterFor(Dictionary<string, RateLimiter> map, string ip, int capacity, double perSecond)
    {
        // caller holds sync; idle entries are pruned so the maps cannot grow without bound
        if (map.Count > 10_000)
            foreach (string k in map.Where(kv => kv.Value.IsIdle).Select(kv => kv.Key).ToList()) map.Remove(k);
        if (!map.TryGetValue(ip, out RateLimiter l)) map[ip] = l = new RateLimiter(capacity, perSecond, clock);
        return l;
    }

    // Returns false to close the connection.
    private bool HandleHello(Connection conn, ClientCommand hello)
    {
        string errorReply = null;
        Pair pair = null;
        lock (sync)
        {
            long now = clock();
            if (!LimiterFor(helloLimiters, conn.Ip, limits.HellosPerIpPerMinute, limits.HellosPerIpPerMinute / 60.0).TryTake()
                || !LimiterFor(failLimiters, conn.Ip, limits.UnproductivePairingsPerIpPerHour, limits.UnproductivePairingsPerIpPerHour / 3600.0).HasToken)
            {
                errorReply = ServerFrame.Err("rate");
            }
            else
            {
                if (rids.TryGetValue(hello.Rid, out Entry e) && e.State == RidState.Burned && e.BurnedUntil <= now)
                {
                    rids.Remove(hello.Rid);
                    e = null;
                }
                if (e == null)
                {
                    if (rids.Values.Count(x => x.State == RidState.Waiting) >= limits.MaxWaiters) errorReply = ServerFrame.Err("full");
                    else
                    {
                        rids[hello.Rid] = new Entry { State = RidState.Waiting, Waiter = conn };
                        conn.Rid = hello.Rid; conn.Nonce = hello.Nonce; conn.Stage = Stage.Waiting;
                    }
                }
                else if (e.State == RidState.Waiting)
                {
                    Connection first = e.Waiter;
                    e.State = RidState.Paired;
                    e.Waiter = null;
                    pair = new Pair { A = first, B = conn, Rid = hello.Rid };
                    first.Pair = pair; first.Role = 1; first.Stage = Stage.AwaitKey;
                    conn.Pair = pair; conn.Role = 2; conn.Nonce = hello.Nonce; conn.Rid = hello.Rid; conn.Stage = Stage.AwaitKey;
                }
                else errorReply = ServerFrame.Err("used");   // paired right now, or burned
            }
        }
        if (errorReply != null) { conn.Send(errorReply); return false; }

        if (pair == null)
        {
            conn.Disarm();   // waiting alone has no time limit; the read timeout (keepalive PINGs) detects dead connections
            conn.Send(ServerFrame.Wait);
            return true;
        }

        pair.A.Disarm(); conn.Disarm();
        // The earlier connection learns its role and the newcomer's nonce first, then the newcomer.
        pair.A.Send(ServerFrame.Paired(1, pair.B.Nonce));
        pair.A.PairedSent.Set();
        conn.Send(ServerFrame.Paired(2, pair.A.Nonce));
        conn.PairedSent.Set();
        StartConfirmTimer(pair);
        return true;
    }

    private void StartConfirmTimer(Pair pair)
    {
        _ = Task.Delay(limits.ConfirmDeadlineMs, pair.ConfirmTimer.Token).ContinueWith(t =>
        {
            if (t.IsCanceled || pair.Ended || (pair.A.ConfirmSeen && pair.B.ConfirmSeen)) return;
            lock (sync) pair.Quiet = true;
            pair.A.Send(ServerFrame.Err("timeout"));
            pair.B.Send(ServerFrame.Err("timeout"));
            pair.A.Close();
            pair.B.Close();
        }, TaskScheduler.Default);
    }

    // Executes one validated command; returns false to close the connection.
    private bool Dispatch(Connection conn, ClientCommand cmd)
    {
        if (cmd.Verb == ClientVerb.Hello) return false;   // only the first line may be HELLO

        if (cmd.Verb == ClientVerb.Ping)
        {
            if (!conn.Ping.TryTake()) { conn.Send(ServerFrame.Err("rate")); return false; }
            conn.Send(ServerFrame.Pong);
            return true;
        }

        switch (cmd.Verb)
        {
            case ClientVerb.Key when conn.Stage == Stage.AwaitKey:
                conn.Stage = Stage.AwaitConfirm;
                break;
            case ClientVerb.Confirm when conn.Stage == Stage.AwaitConfirm:
                conn.Stage = Stage.AwaitMsg;
                conn.ConfirmSeen = true;
                break;
            case ClientVerb.Msg when conn.Stage == Stage.AwaitMsg:
                if (!conn.Msg.TryTake()) { conn.Send(ServerFrame.Err("rate")); return false; }
                break;
            default:
                return false;   // out of order, or alone and not allowed to send anything but PING
        }

        Pair pair = conn.Pair;
        Connection peer = pair.Other(conn);
        // The peer must have been told about the pairing before anything is relayed to it.
        if (!peer.PairedSent.Wait(WriteTimeoutMs)) return false;
        if (cmd.Verb == ClientVerb.Msg) pair.Productive = true;
        peer.Send(ServerFrame.Relay(cmd.Verb, cmd.Data));
        return true;
    }

    // Removes the connection; frees or burns its rid; tells the peer (GONE) and closes it.
    private void Cleanup(Connection conn)
    {
        Connection peerToDrop = null;
        bool quiet = false;
        lock (sync)
        {
            if (clients.Remove(conn) && conn.Counted && perIp.TryGetValue(conn.Ip, out int n))
            {
                if (n <= 1) perIp.Remove(conn.Ip); else perIp[conn.Ip] = n - 1;
            }
            if (conn.Rid != null && conn.Pair == null && rids.TryGetValue(conn.Rid, out Entry w) && w.State == RidState.Waiting && w.Waiter == conn)
                rids.Remove(conn.Rid);   // a waiter that leaves frees the rid

            Pair pair = conn.Pair;
            if (pair != null && !pair.Ended)
            {
                pair.Ended = true;
                long now = clock();
                rids[pair.Rid] = new Entry { State = RidState.Burned, BurnedAt = now, BurnedUntil = now + limits.BurnMs };
                PruneBurned(now);
                if (!pair.Productive)
                {
                    // An unproductive pairing counts against both IPs (once if they are the same).
                    foreach (string ip in new[] { pair.A.Ip, pair.B.Ip }.Distinct())
                        LimiterFor(failLimiters, ip, limits.UnproductivePairingsPerIpPerHour, limits.UnproductivePairingsPerIpPerHour / 3600.0).Charge();
                }
                peerToDrop = pair.Other(conn);
                quiet = pair.Quiet;
                try { pair.ConfirmTimer.Cancel(); } catch (ObjectDisposedException) { }
            }
        }
        if (peerToDrop != null)
        {
            if (!quiet) peerToDrop.Send(ServerFrame.Gone);
            peerToDrop.Close();
        }
        conn.Disarm();
        conn.Close();
    }

    // Caller holds sync. Drops expired burns, then the oldest ones above the cap.
    private void PruneBurned(long now)
    {
        var burned = rids.Where(kv => kv.Value.State == RidState.Burned).ToList();
        foreach (var kv in burned.Where(kv => kv.Value.BurnedUntil <= now)) rids.Remove(kv.Key);
        burned = rids.Where(kv => kv.Value.State == RidState.Burned).ToList();
        int excess = burned.Count - limits.MaxBurned;
        if (excess > 0)
            foreach (var kv in burned.OrderBy(kv => kv.Value.BurnedAt).Take(excess)) rids.Remove(kv.Key);
    }

    private sealed class Connection
    {
        private readonly TcpClient tcp;
        private readonly object writeLock = new();
        private CancellationTokenSource timer;

        public Connection(TcpClient tcp, string ip, ServerLimits l, Func<long> clock)
        {
            this.tcp = tcp;
            Ip = ip;
            Stream = tcp.GetStream();
            Stream.WriteTimeout = WriteTimeoutMs;
            tcp.ReceiveTimeout = l.ReadTimeoutMs;
            Msg = new RateLimiter(l.MsgBurst, l.MsgPerSecond, clock);
            Ping = new RateLimiter(l.PingBurst, l.PingPerSecond, clock);
        }

        public string Ip { get; }
        public bool Counted { get; set; }
        public NetworkStream Stream { get; }
        public RateLimiter Msg { get; }
        public RateLimiter Ping { get; }
        public volatile Stage Stage = Stage.AwaitHello;
        public string Rid { get; set; }
        public string Nonce { get; set; }
        public int Role { get; set; }
        public Pair Pair { get; set; }
        public volatile bool ConfirmSeen;
        public ManualResetEventSlim PairedSent { get; } = new(false);

        // One-shot timer: after ms, if stillRelevant() holds, answer ERR timeout and close.
        public void Arm(int ms, Func<bool> stillRelevant)
        {
            Disarm();
            CancellationTokenSource cts = new();
            timer = cts;
            _ = Task.Delay(ms, cts.Token).ContinueWith(t =>
            {
                if (t.IsCanceled || !stillRelevant()) return;
                Send(ServerFrame.Err("timeout"));
                Close();
            }, TaskScheduler.Default);
        }

        public void Disarm()
        {
            CancellationTokenSource old = Interlocked.Exchange(ref timer, null);
            try { old?.Cancel(); } catch (ObjectDisposedException) { }
        }

        // Writes one line; a failing or stuck peer is closed instead of blocking the server.
        public void Send(string line)
        {
            byte[] buffer = Encoding.ASCII.GetBytes(line + "\n");
            lock (writeLock)
            {
                try { Stream.Write(buffer, 0, buffer.Length); }
                catch (Exception) { Close(); }
            }
        }

        public void Close()
        {
            try { tcp.Close(); } catch (Exception) { }
        }
    }
}
