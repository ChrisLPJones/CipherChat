using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace CipherChatServer;

// TCP server speaking wire protocol v4 (see README "Protocol v4" and agent-reports/architecture-e2e-redesign.md).
// Users authenticate with a signature over a per-connection challenge (their identity key is registered once,
// first come first served). The server then relays OFFER/ACCEPT/CONFIRM/MSG/KNOCK blobs byte-identical with the
// authenticated sender name; it never decodes them, never holds a private key and cannot read or forge content.
// Logging policy: startup lines and exception type names only (no user names, IPs, keys or blobs).
public class ChatServer : IDisposable
{
    private const int WriteTimeoutMs = 5000;
    private const int MaxUsersListed = ProtocolLimits.MaxUserListEntries;

    // One lock guards the registry (online users, per-IP counts, contacts) and serialises sends to a connection's peers.
    private readonly object sync = new();
    private readonly List<Connection> clients = [];
    private readonly Dictionary<string, Connection> online = [];
    private readonly Dictionary<string, int> perIp = [];

    private readonly ServerLimits limits;
    private readonly Func<long> clock;
    private readonly AccountStore accounts;
    private readonly KnockStore knocks;
    private readonly Dictionary<string, RateLimiter> registrationsByIp = [];
    private readonly RateLimiter registrationsGlobal;

    private readonly TcpListener listener;
    private readonly TaskCompletionSource<bool> stopped = new();
    private Task acceptTask;
    private int stopRequested;

    // The port the listener is actually bound to (useful when started on port 0)
    public int Port { get; private set; }

    // Completes when Stop() has finished shutting the server down
    public Task Stopped => stopped.Task;

    public bool PersistentAccounts => accounts.Persistent;
    public int AccountCount => accounts.Count;
    public int KnockCount => knocks.Count;

    // Throws IOException / UnauthorizedAccessException / InvalidDataException when the data directory cannot be used.
    public ChatServer(string host, int port, ChatServerOptions options = null)
    {
        options ??= new ChatServerOptions();
        limits = options.Limits;
        clock = options.Clock;
        IPAddress address = host == "localhost" ? IPAddress.Loopback : IPAddress.Parse(host);
        listener = new(address, port);
        accounts = new AccountStore(options.DataDirectory);
        knocks = new KnockStore(limits, clock);
        registrationsGlobal = new RateLimiter(limits.RegistrationsGlobalPerHour, limits.RegistrationsGlobalPerHour / 3600.0, clock);
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
        lock (sync)
        {
            foreach (var client in clients) client.Close();
        }
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
                if (!full)
                {
                    clients.Add(conn);
                    perIp[ip] = n + 1;
                    conn.Counted = true;
                }
            }
            if (full)
            {
                _ = Task.Run(() => { conn.Send(ServerFrame.Err("full")); conn.Close(); });
                continue;
            }
            // One dedicated thread per connection (blocking reads); pool threads would ramp up too slowly for hundreds of clients.
            _ = Task.Factory.StartNew(() => HandleClient(conn), TaskCreationOptions.LongRunning);
        }
    }

    private void HandleClient(Connection conn)
    {
        // Must authenticate within the deadline (covers HELLO as well, so silent connections do not pile up).
        CancellationTokenSource deadline = new();
        conn.Deadline = deadline;
        _ = Task.Delay(limits.AuthDeadlineMs, deadline.Token).ContinueWith(t =>
        {
            if (t.IsCanceled || conn.Authed) return;
            conn.Send(ServerFrame.Err("timeout"));
            conn.Close();
        }, TaskScheduler.Default);

        try
        {
            StreamReader reader = new(conn.Stream, Encoding.ASCII);

            // The first line must be exactly "HELLO 4"; anything else (a v3 client, junk) gets ERR version.
            string first = ProtocolLimits.ReadBoundedLine(reader, ProtocolLimits.MaxLineChars);
            if (first == null) return;
            if (!ServerFrame.TryParse(first, out ClientCommand hello) || hello.Verb != ClientVerb.Hello)
            {
                conn.Send(ServerFrame.Err("version"));
                return;
            }
            conn.Challenge = RandomNumberGenerator.GetBytes(AuthVerifier.ChallengeBytes);
            conn.Send(ServerFrame.Welcome(Convert.ToBase64String(conn.Challenge)));

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

    // Executes one validated command; returns false to close the connection.
    private bool Dispatch(Connection conn, ClientCommand cmd)
    {
        if (cmd.Verb == ClientVerb.Hello) return false; // handshake already done

        if (!conn.Allow(cmd.Verb))
        {
            conn.Send(ServerFrame.Err("rate"));
            return ++conn.RateErrors < limits.MaxConsecutiveRateErrors;
        }
        conn.RateErrors = 0;

        if (cmd.Verb == ClientVerb.Ping)
        {
            conn.Send(ServerFrame.Pong);
            return true;
        }

        if (!conn.Authed)
        {
            switch (cmd.Verb)
            {
                case ClientVerb.Register: return HandleRegister(conn, cmd);
                case ClientVerb.Login: return HandleLogin(conn, cmd);
                default:
                    conn.Send(ServerFrame.Err("notauth"));
                    return false;
            }
        }

        switch (cmd.Verb)
        {
            case ClientVerb.Register:
            case ClientVerb.Login:
                conn.Send(ServerFrame.Err("notauth")); // already authenticated
                return false;

            case ClientVerb.Key:
                if (accounts.TryGet(cmd.User, out byte[] pub)) conn.Send(ServerFrame.Key(cmd.User, Convert.ToBase64String(pub)));
                else conn.Send(ServerFrame.Err("nouser", cmd.User));
                return true;

            case ClientVerb.Users:
                SendUserList(conn);
                return true;

            case ClientVerb.Offer:
            case ClientVerb.Accept:
            case ClientVerb.Confirm:
            case ClientVerb.Msg:
                return Relay(conn, cmd);

            case ClientVerb.Knock:
                return HandleKnock(conn, cmd);

            default:
                return false;
        }
    }

    private static string VerbName(ClientVerb v) => v switch
    {
        ClientVerb.Offer => "OFFER",
        ClientVerb.Accept => "ACCEPT",
        ClientVerb.Confirm => "CONFIRM",
        ClientVerb.Msg => "MSG",
        _ => "KNOCK",
    };

    // OFFER/ACCEPT/CONFIRM/MSG: relayed byte-identical to the target with the authenticated sender as 'from'.
    private bool Relay(Connection conn, ClientCommand cmd)
    {
        if (cmd.User == conn.User) { conn.Send(ServerFrame.Err("self")); return true; }
        lock (sync)
        {
            if (!online.TryGetValue(cmd.User, out Connection target))
            {
                conn.Send(ServerFrame.Offline(cmd.User));
                return true;
            }
            conn.Contacts.Add(cmd.User);
            target.Contacts.Add(conn.User);
            target.Send(ServerFrame.Relay(VerbName(cmd.Verb), conn.User, cmd.Data));
        }
        return true;
    }

    private bool HandleKnock(Connection conn, ClientCommand cmd)
    {
        if (cmd.User == conn.User) { conn.Send(ServerFrame.Err("self")); return true; }
        if (!accounts.TryGet(cmd.User, out _)) { conn.Send(ServerFrame.Err("nouser", cmd.User)); return true; }
        lock (sync)
        {
            if (online.TryGetValue(cmd.User, out Connection target))
            {
                target.Send(ServerFrame.Relay("KNOCK", conn.User, cmd.Data));
                return true;
            }
            // No OFFLINE answer for KNOCK; limits are reported as ERR limit / ERR rate.
            KnockResult r = knocks.Add(conn.User, cmd.User, cmd.Data);
            if (r == KnockResult.SenderLimit) conn.Send(ServerFrame.Err("rate"));
            else if (r != KnockResult.Stored) conn.Send(ServerFrame.Err("limit", cmd.User));
        }
        return true;
    }

    private void SendUserList(Connection conn)
    {
        List<string> names;
        lock (sync)
            names = online.Keys.Where(u => u != conn.User).OrderBy(u => u, StringComparer.Ordinal).Take(MaxUsersListed).ToList();
        conn.Send(ServerFrame.UserList(names));
    }

    private bool HandleRegister(Connection conn, ClientCommand cmd)
    {
        byte[] pub = Convert.FromBase64String(cmd.Pub);
        byte[] sig = Convert.FromBase64String(cmd.Data);

        if (accounts.TryGet(cmd.User, out byte[] existing))
        {
            if (!existing.AsSpan().SequenceEqual(pub))
            {
                conn.Send(ServerFrame.Err("taken", cmd.User));
                return ++conn.AuthAttempts < limits.MaxAuthAttempts;
            }
            // Same name, same key: this is a login with a proof of possession.
            if (!AuthVerifier.Verify(pub, AuthVerifier.RegisterData(conn.Challenge, cmd.User, pub), sig))
            {
                conn.Send(ServerFrame.Err("auth"));
                return false;
            }
            return Authenticate(conn, cmd.User);
        }

        // New name: registration limits apply before any signature work.
        if (accounts.Count >= limits.MaxAccounts) { conn.Send(ServerFrame.Err("limit")); return false; }
        if (!TakeRegistrationSlot(conn.Ip)) { conn.Send(ServerFrame.Err("rate")); return false; }
        if (!AuthVerifier.IsValidPublicKey(pub)
            || !AuthVerifier.Verify(pub, AuthVerifier.RegisterData(conn.Challenge, cmd.User, pub), sig))
        {
            conn.Send(ServerFrame.Err("auth"));
            return false;
        }
        bool added;
        try { added = accounts.TryAdd(cmd.User, pub, clock() / 1000); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Console.WriteLine($"Account store write failed: {ex.GetType().Name}");
            conn.Send(ServerFrame.Err("limit"));
            return false;
        }
        if (!added)
        {
            conn.Send(ServerFrame.Err("taken", cmd.User));
            return ++conn.AuthAttempts < limits.MaxAuthAttempts;
        }
        return Authenticate(conn, cmd.User);
    }

    private bool HandleLogin(Connection conn, ClientCommand cmd)
    {
        if (!accounts.TryGet(cmd.User, out byte[] pub))
        {
            conn.Send(ServerFrame.Err("nouser", cmd.User));
            return false;
        }
        if (!AuthVerifier.Verify(pub, AuthVerifier.LoginData(conn.Challenge, cmd.User), Convert.FromBase64String(cmd.Data)))
        {
            conn.Send(ServerFrame.Err("auth"));
            return false;
        }
        return Authenticate(conn, cmd.User);
    }

    private bool TakeRegistrationSlot(string ip)
    {
        RateLimiter perIpLimiter;
        lock (sync)
        {
            if (registrationsByIp.Count > 10_000)
                foreach (string k in registrationsByIp.Where(kv => kv.Value.IsIdle).Select(kv => kv.Key).ToList()) registrationsByIp.Remove(k);
            if (!registrationsByIp.TryGetValue(ip, out perIpLimiter))
                registrationsByIp[ip] = perIpLimiter = new RateLimiter(limits.RegistrationsPerIpPerHour, limits.RegistrationsPerIpPerHour / 3600.0, clock);
        }
        return perIpLimiter.TryTake() && registrationsGlobal.TryTake();
    }

    // Marks the connection authenticated, replaces an older connection of the same user, answers READY
    // and delivers stored knocks.
    private bool Authenticate(Connection conn, string user)
    {
        lock (sync)
        {
            if (online.TryGetValue(user, out Connection old) && old != conn)
            {
                old.Send(ServerFrame.Err("replaced"));
                old.Close();
            }
            conn.User = user;
            conn.Authed = true;
            online[user] = conn;
            try { conn.Deadline?.Cancel(); } catch (ObjectDisposedException) { }
            conn.Send(ServerFrame.Ready(user));
            foreach (var (sender, blob) in knocks.Take(user))
                conn.Send(ServerFrame.Relay("KNOCK", sender, blob));
        }
        return true;
    }

    // Removes the connection from the registry and tells the users it exchanged lines with (GONE).
    private void Cleanup(Connection conn)
    {
        lock (sync)
        {
            if (clients.Remove(conn) && conn.Counted)
            {
                if (perIp.TryGetValue(conn.Ip, out int n))
                {
                    if (n <= 1) perIp.Remove(conn.Ip); else perIp[conn.Ip] = n - 1;
                }
            }
            if (conn.User != null)
            {
                if (online.TryGetValue(conn.User, out Connection cur) && cur == conn) online.Remove(conn.User);
                foreach (string other in conn.Contacts)
                {
                    if (other != conn.User && online.TryGetValue(other, out Connection t))
                    {
                        t.Contacts.Remove(conn.User);
                        t.Send(ServerFrame.Gone(conn.User));
                    }
                }
            }
        }
        try { conn.Deadline?.Cancel(); conn.Deadline?.Dispose(); } catch (ObjectDisposedException) { }
        conn.Close();
    }

    private sealed class Connection
    {
        private readonly TcpClient tcp;
        private readonly object writeLock = new();
        private readonly RateLimiter msg, offer, offerWindow, key, knock, ping, users, reply;

        public Connection(TcpClient tcp, string ip, ServerLimits l, Func<long> clock)
        {
            this.tcp = tcp;
            Ip = ip;
            Stream = tcp.GetStream();
            Stream.WriteTimeout = WriteTimeoutMs;
            tcp.ReceiveTimeout = l.ReadTimeoutMs;
            msg = new(l.MsgBurst, l.MsgPerSecond, clock);
            offer = new(l.OfferBurst, l.OfferPerSecond, clock);
            offerWindow = new(l.OfferWindowMax, l.OfferWindowMax / 120.0, clock);
            key = new(l.KeyBurst, l.KeyPerSecond, clock);
            knock = new(l.KnockBurst, l.KnockPerSecond, clock);
            ping = new(l.PingBurst, l.PingPerSecond, clock);
            users = new(l.UsersBurst, l.UsersPerSecond, clock);
            reply = new(l.ReplyBurst, l.ReplyPerSecond, clock);
        }

        public string Ip { get; }
        public bool Counted { get; set; }
        public NetworkStream Stream { get; }
        public byte[] Challenge { get; set; }
        public volatile bool Authed;
        public string User { get; set; }
        public int AuthAttempts { get; set; }
        public int RateErrors { get; set; }
        public CancellationTokenSource Deadline { get; set; }

        // Names of users this connection exchanged relayed lines with; guarded by the server's sync lock.
        public HashSet<string> Contacts { get; } = [];

        // Verbs with a per-connection limit (REGISTER/LOGIN are limited by attempts instead).
        public bool Allow(ClientVerb v) => v switch
        {
            ClientVerb.Msg => msg.TryTake(),
            ClientVerb.Offer => offer.TryTake() && offerWindow.TryTake(),
            ClientVerb.Key => key.TryTake(),
            ClientVerb.Knock => knock.TryTake(),
            ClientVerb.Ping => ping.TryTake(),
            ClientVerb.Users => users.TryTake(),
            ClientVerb.Accept or ClientVerb.Confirm => reply.TryTake(),
            _ => true,
        };

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
