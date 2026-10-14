using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Channels;

namespace CipherChatClient;

public enum ChatPhase { Offering, Accepting, Active, Ended }
public enum AuthResult { Ok, NameTaken, UnknownUser, Rejected, RateLimited, ServerFull, VersionMismatch, Failed }
public enum KeyStatus { Ok, NoUser, Invalid, Failed }
public enum PeerKeyState { Ok, FirstContact, Changed, NoUser, Failed }

public sealed class PeerChat
{
    internal PeerChat(string peer) { Peer = peer; }

    public string Peer { get; }
    public ChatPhase Phase { get; internal set; }
    public List<string> Messages { get; } = [];
    public int Unread { get; set; }

    internal Handshake.Initiator Initiator;
    internal Handshake.Responder Responder;
    internal SecureChannel Channel;
    internal int Warnings;
    internal long ActivatedAtMs;
}

public sealed class IncomingRequest
{
    public string User { get; init; }
    public bool Verified { get; init; }
    public long ReceivedAtMs { get; init; }
    internal Handshake.Responder Responder;
}

public sealed record PeerStatus(bool Pinned, bool Verified, bool KeyChanged, bool Blocked);
public sealed record VerifyInfo(string Error, string SafetyNumber, bool KeyChanged, bool AlreadyVerified);

public sealed class ChatSessionOptions
{
    public int OfferTimeoutMs { get; init; } = 120_000;   // "alice did not answer"
    public int AcceptTimeoutMs { get; init; } = 60_000;   // CONFIRM never arrived
    public int PingIntervalMs { get; init; } = 30_000;
    public int ReplyTimeoutMs { get; init; } = 10_000;    // KEY and USERS answers, and the login reply
    public Func<long> Clock { get; init; } = () => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
}

// One authenticated connection plus the 1:1 end-to-end encrypted chats over it (wire protocol v4).
// UI-agnostic: the console front end subscribes to the events (raised on a separate dispatcher thread,
// never while the session's lock is held). Session keys live in memory only; the identity key and the
// pinned peer keys come from the unlocked Profile (which the caller owns).
public sealed class ChatSession : IDisposable
{
    private readonly string host;
    private readonly int port;
    private readonly Profile profile;
    private readonly ChatSessionOptions options;
    private readonly TcpClient tcp = new();
    private readonly object writeLock = new();
    private readonly object gate = new();     // guards all state below and the profile's peer book
    private readonly Dictionary<string, PeerChat> chats = [];
    private readonly Dictionary<string, IncomingRequest> requests = [];
    private readonly Dictionary<string, byte[]> keyChanged = [];      // user -> the key the server now serves
    private readonly Dictionary<string, byte[]> verifyCandidate = []; // user -> key shown by BeginVerifyAsync
    private readonly Dictionary<string, List<TaskCompletionSource<(KeyStatus, byte[])>>> keyWaiters = [];
    private readonly List<TaskCompletionSource<IReadOnlyList<string>>> userWaiters = [];
    private readonly SidCache sidCache = new();
    private readonly Channel<ServerEvent> slowWork = Channel.CreateUnbounded<ServerEvent>();   // OFFER/KNOCK need a KEY lookup
    private readonly Channel<Action> eventQueue = Channel.CreateUnbounded<Action>();
    private readonly CancellationTokenSource cts = new();
    private StreamReader reader;
    private NetworkStream stream;
    private byte[] challenge;
    private int closed;
    private int homeWarnings;

    public ChatSession(string host, int port, string userName, Profile profile, ChatSessionOptions options = null)
    {
        if (!Proto.IsUserName(userName)) throw new ArgumentException("Invalid user name.");
        this.host = host;
        this.port = port;
        UserName = userName;
        this.profile = profile;
        this.options = options ?? new ChatSessionOptions();
        _ = Task.Run(DispatchEvents);
    }

    public string UserName { get; }
    public bool IsClosed => Volatile.Read(ref closed) == 1;
    public List<string> HomeLines { get; } = [];

    // The chat the user is looking at (its new messages are not counted as unread); null = home. Set by the UI.
    public PeerChat Active { get; set; }

    // A line to show in a chat (null = the home tab). Raised on the dispatcher thread.
    public event Action<PeerChat, string> LineAdded;
    // A new incoming request is waiting for /accept or /block.
    public event Action<IncomingRequest> RequestReceived;
    // A chat became active (handshake finished) or ended.
    public event Action<PeerChat> ChatStateChanged;
    public event Action<string> Status;
    public event Action Disconnected;

    public IReadOnlyList<PeerChat> Chats { get { lock (gate) return chats.Values.ToList(); } }
    public IReadOnlyList<IncomingRequest> Requests { get { lock (gate) return requests.Values.OrderBy(r => r.ReceivedAtMs).ToList(); } }
    public PeerChat FindChat(string peer) { lock (gate) return chats.GetValueOrDefault(peer); }

    public PeerStatus GetPeerStatus(string user)
    {
        lock (gate)
        {
            PeerRecord r = profile.Peers.Get(user);
            return new PeerStatus(r?.Pub != null, r is { Verified: true }, keyChanged.ContainsKey(user), r is { Blocked: true });
        }
    }

    // ---- connection and login ----

    // Connects and performs HELLO/WELCOME. Throws IOException with a readable reason on failure.
    public async Task ConnectAsync()
    {
        await tcp.ConnectAsync(host, port);
        stream = tcp.GetStream();
        reader = new StreamReader(stream, Encoding.ASCII);
        WriteLine(ClientFrame.Hello());
        ServerEvent ev = await ReadEventAsync("handshake");
        if (ev is { Kind: ServerEventKind.Err, Data: "version" })
            throw new IOException("The server does not speak protocol v4: upgrade server and clients together.");
        if (ev == null || ev.Kind != ServerEventKind.Welcome)
            throw new IOException("Unexpected handshake reply from the server: protocol mismatch? This client speaks protocol v4.");
        challenge = ClientFrame.DecodeBlob(ev.Data);
    }

    // Signs the server's challenge: REGISTER claims the name with this profile's identity key, LOGIN proves it.
    // On success the receive loop starts (stored knocks follow right after READY).
    public async Task<AuthResult> AuthenticateAsync(bool register)
    {
        IdentityKey id = profile.Identity;
        if (register)
        {
            byte[] sig = id.Sign(Proto.Concat(Proto.Label("CipherChat-v4/register"), challenge, Proto.Lp(UserName), id.PublicKey));
            WriteLine(ClientFrame.Register(UserName, id.PublicKey, sig));
        }
        else
        {
            byte[] sig = id.Sign(Proto.Concat(Proto.Label("CipherChat-v4/login"), challenge, Proto.Lp(UserName)));
            WriteLine(ClientFrame.Login(UserName, sig));
        }
        ServerEvent ev = await ReadEventAsync("login");
        if (ev is { Kind: ServerEventKind.Ready } && ev.User == UserName)
        {
            _ = Task.Run(ReceiveLoop);
            _ = Task.Run(SlowWorker);
            _ = Task.Run(PingLoop);
            return AuthResult.Ok;
        }
        if (ev is { Kind: ServerEventKind.Err })
            return ev.Data switch
            {
                "taken" => AuthResult.NameTaken,
                "nouser" => AuthResult.UnknownUser,
                "auth" => AuthResult.Rejected,
                "rate" or "limit" => AuthResult.RateLimited,
                "full" => AuthResult.ServerFull,
                "version" => AuthResult.VersionMismatch,
                _ => AuthResult.Failed,
            };
        return AuthResult.Failed;
    }

    private async Task<ServerEvent> ReadEventAsync(string what)
    {
        try
        {
            string line = await ProtocolLimits.ReadBoundedLineAsync(reader, ProtocolLimits.MaxLineChars)
                .WaitAsync(TimeSpan.FromMilliseconds(options.ReplyTimeoutMs));
            if (line == null) throw new IOException($"The server closed the connection during the {what}.");
            return ClientFrame.TryParse(line, out ServerEvent ev) ? ev : null;
        }
        catch (Exception ex) when (ex is InvalidDataException or TimeoutException)
        {
            throw new IOException($"No valid reply from the server during the {what}: protocol mismatch? This client speaks protocol v4.", ex);
        }
    }

    // ---- starting chats ----

    // Looks the peer's key up on the server and compares it with the pinned key (TOFU).
    public async Task<(PeerKeyState State, byte[] Pub)> ResolvePeerAsync(string user)
    {
        var (status, pub) = await FetchKeyAsync(user);
        if (status == KeyStatus.NoUser) return (PeerKeyState.NoUser, null);
        if (status != KeyStatus.Ok) return (PeerKeyState.Failed, null);
        lock (gate)
        {
            byte[] pinned = profile.Peers.GetKey(user);
            if (pinned == null)
            {
                profile.Peers.Pin(user, pub, options.Clock() / 1000);
                return (PeerKeyState.FirstContact, pub);
            }
            if (pinned.AsSpan().SequenceEqual(pub))
            {
                keyChanged.Remove(user);
                return (PeerKeyState.Ok, pub);
            }
            keyChanged[user] = pub;
            return (PeerKeyState.Changed, pub);
        }
    }

    private static string ChangedWarning(string user) =>
        $"WARNING: {user}'s identity key changed. This happens if they reinstalled, or if the server is attacking you. Compare safety numbers: /verify {user}. No chat with {user} is possible until then.";

    // /chat <user>: sends an OFFER. Returns the chat (phase Offering, or the existing one) or an error text.
    public async Task<(PeerChat Chat, string Error)> StartChatAsync(string user)
    {
        user = MessageRules.Canonicalize(user);
        if (IsClosed) return (null, "Not connected.");
        if (!Proto.IsUserName(user)) return (null, "Invalid user name.");
        if (user == UserName) return (null, "You cannot chat with yourself.");

        IncomingRequest req;
        lock (gate)
        {
            if (profile.Peers.IsBlocked(user)) return (null, $"You blocked {user}. /unblock {user} first.");
            if (chats.TryGetValue(user, out PeerChat existing) && existing.Phase != ChatPhase.Ended) return (existing, null);
            requests.TryGetValue(user, out req);
        }
        if (req != null) return Accept(user); // they already asked: starting a chat with them is consent

        var (state, pub) = await ResolvePeerAsync(user);
        switch (state)
        {
            case PeerKeyState.NoUser: return (null, $"There is no user '{user}'.");
            case PeerKeyState.Failed: return (null, "Could not look up the user's key (no answer from the server).");
            case PeerKeyState.Changed: Home(ChangedWarning(user)); return (null, $"{user}'s identity key changed: /verify {user} first.");
        }

        lock (gate)
        {
            if (profile.Peers.IsBlocked(user)) return (null, $"You blocked {user}. /unblock {user} first.");
            if (chats.TryGetValue(user, out PeerChat existing) && existing.Phase != ChatPhase.Ended) return (existing, null);
            // They asked while we were looking their key up: our /chat is consent, so answer their request instead.
            if (requests.ContainsKey(user)) return Accept(user);
            if (LiveChats() >= ProtocolLimits.MaxChats) return (null, $"You can have at most {ProtocolLimits.MaxChats} chats at once. /end one first.");
            Handshake.Initiator init = Handshake.Initiator.Create(profile.Identity, UserName, user, pub, false, options.Clock());
            PeerChat chat = new(user) { Phase = ChatPhase.Offering, Initiator = init };
            chats[user] = chat;
            try { WriteLine(ClientFrame.Offer(user, init.Offer)); }
            catch (Exception ex) when (ex is IOException or ObjectDisposedException)
            {
                chat.Phase = ChatPhase.Ended; init.Dispose(); chat.Initiator = null;
                return (null, "Not connected.");
            }
            AddLine(chat, $"Waiting for {user} to accept...", false);
            Expire(chat, init, options.OfferTimeoutMs, $"{user} did not answer.");
            return (chat, null);
        }
    }

    private int LiveChats() => chats.Values.Count(c => c.Phase != ChatPhase.Ended);

    // /accept [user]: answers the newest (or the named) request. Returns the chat or an error text.
    public (PeerChat Chat, string Error) Accept(string user = null)
    {
        lock (gate)
        {
            IncomingRequest req = user == null
                ? requests.Values.OrderByDescending(r => r.ReceivedAtMs).FirstOrDefault()
                : requests.GetValueOrDefault(MessageRules.Canonicalize(user));
            if (req == null) return (null, user == null ? "There is no pending request." : $"There is no request from {user}.");
            user = req.User;
            if (keyChanged.ContainsKey(user)) return (null, $"{user}'s identity key changed: /verify {user} first.");
            if (profile.Peers.IsBlocked(user)) return (null, $"You blocked {user}.");
            if (chats.TryGetValue(user, out PeerChat old) && old.Phase is ChatPhase.Offering or ChatPhase.Accepting)
                return (null, $"A handshake with {user} is already running.");
            bool replacing = old != null && old.Phase == ChatPhase.Active;
            if (!replacing && LiveChats() >= ProtocolLimits.MaxChats) return (null, $"You can have at most {ProtocolLimits.MaxChats} chats at once. /end one first.");

            byte[] accept;
            try { accept = req.Responder.Accept(); }
            catch (CryptographicException) { requests.Remove(user); req.Responder.Dispose(); return (null, "The request could not be accepted (key agreement failed)."); }
            requests.Remove(user);
            try { WriteLine(ClientFrame.Accept(user, accept)); }
            catch (Exception ex) when (ex is IOException or ObjectDisposedException) { req.Responder.Dispose(); return (null, "Not connected."); }
            if (old != null) EndLocal(old, null);
            PeerChat chat = new(user) { Phase = ChatPhase.Accepting, Responder = req.Responder };
            chats[user] = chat;
            AddLine(chat, $"Accepted. Establishing a secure session with {user}...", false);
            Expire(chat, req.Responder, options.AcceptTimeoutMs, $"{user} did not complete the handshake.");
            return (chat, null);
        }
    }

    // /decline: local and silent.
    public string Decline(string user = null)
    {
        lock (gate)
        {
            IncomingRequest req = user == null
                ? requests.Values.OrderByDescending(r => r.ReceivedAtMs).FirstOrDefault()
                : requests.GetValueOrDefault(MessageRules.Canonicalize(user));
            if (req == null) return "There is no such request.";
            requests.Remove(req.User);
            req.Responder.Dispose();
            return null;
        }
    }

    public string Block(string user)
    {
        user = MessageRules.Canonicalize(user);
        if (!Proto.IsUserName(user) || user == UserName) return "Invalid user name.";
        lock (gate)
        {
            profile.Peers.SetBlocked(user, true);
            if (requests.Remove(user, out IncomingRequest r)) r.Responder.Dispose();
            if (chats.TryGetValue(user, out PeerChat c) && c.Phase != ChatPhase.Ended) EndLocal(c, $"You blocked {user}; the chat was closed.");
        }
        return null;
    }

    public string Unblock(string user)
    {
        user = MessageRules.Canonicalize(user);
        if (!Proto.IsUserName(user)) return "Invalid user name.";
        lock (gate)
        {
            if (!profile.Peers.IsBlocked(user)) return $"{user} is not blocked.";
            profile.Peers.SetBlocked(user, false);
        }
        return null;
    }

    // ---- verification ----

    // Fetches the peer's current key from the server and returns the safety number for it. If the key differs
    // from the pinned one, the chat stays blocked until FinishVerify(user, true).
    public async Task<VerifyInfo> BeginVerifyAsync(string user)
    {
        user = MessageRules.Canonicalize(user);
        if (!Proto.IsUserName(user) || user == UserName) return new VerifyInfo("Invalid user name.", null, false, false);
        var (state, pub) = await ResolvePeerAsync(user);
        if (state == PeerKeyState.NoUser) return new VerifyInfo($"There is no user '{user}'.", null, false, false);
        if (state == PeerKeyState.Failed) return new VerifyInfo("Could not look up the user's key (no answer from the server).", null, false, false);
        lock (gate)
        {
            verifyCandidate[user] = pub;
            string number = SafetyNumber.Compute(UserName, profile.Identity.PublicKey, user, pub);
            return new VerifyInfo(null, number, state == PeerKeyState.Changed, profile.Peers.Get(user) is { Verified: true } && state == PeerKeyState.Ok);
        }
    }

    // The user compared the number out of band. same = true marks the key verified (and re-pins a changed key).
    public string FinishVerify(string user, bool same)
    {
        user = MessageRules.Canonicalize(user);
        lock (gate)
        {
            if (!verifyCandidate.Remove(user, out byte[] pub)) return "Run /verify first.";
            if (!same)
                return keyChanged.ContainsKey(user)
                    ? $"Not verified. {user} stays blocked; do not trust this key."
                    : $"Not verified. Do not trust {user} until the numbers match.";
            if (keyChanged.Remove(user))
                profile.Peers.Pin(user, pub, options.Clock() / 1000, replace: true);
            profile.Peers.SetVerified(user, true);
            return null;
        }
    }

    // ---- /users ----

    public async Task<IReadOnlyList<string>> ListUsersAsync()
    {
        if (IsClosed) return null;
        TaskCompletionSource<IReadOnlyList<string>> tcs = new(TaskCreationOptions.RunContinuationsAsynchronously);
        lock (gate) userWaiters.Add(tcs);
        try
        {
            WriteLine(ClientFrame.Users());
            return await tcs.Task.WaitAsync(TimeSpan.FromMilliseconds(options.ReplyTimeoutMs));
        }
        catch (Exception ex) when (ex is TimeoutException or IOException or ObjectDisposedException)
        {
            lock (gate) userWaiters.Remove(tcs);
            return null;
        }
    }

    // ---- messages ----

    // Encrypts and sends a message in an active chat; returns an error text or null. The local echo is added here.
    public string Send(PeerChat chat, string text)
    {
        if (IsClosed) return "Not connected. Press Esc to quit and start the client again.";
        if (text.Length > ProtocolLimits.MaxMessageChars) return $"Message too long (max {ProtocolLimits.MaxMessageChars} characters).";
        lock (gate)
        {
            if (chat.Phase != ChatPhase.Active) return chat.Phase == ChatPhase.Ended ? "This chat has ended. /chat to start a new one." : "The chat is not established yet.";
            try
            {
                byte[] msg = chat.Channel.SealText(text);
                WriteLine(ClientFrame.Msg(chat.Peer, msg));
            }
            catch (InvalidOperationException)
            {
                EndLocal(chat, "This session reached its message limit. /chat to start a new one.");
                return null;
            }
            catch (Exception ex) when (ex is IOException or ObjectDisposedException or ArgumentException)
            {
                return $"Error sending message: {ex.Message}";
            }
            AddLine(chat, $"{UserName}: {MessageRules.SanitizeForDisplay(text)}", false);
            return null;
        }
    }

    // /end: tells the peer (encrypted end-of-session) and zeroes the keys.
    public string End(PeerChat chat)
    {
        lock (gate)
        {
            if (chat.Phase == ChatPhase.Ended) return "This chat has already ended.";
            if (chat.Phase == ChatPhase.Active)
            {
                try { WriteLine(ClientFrame.Msg(chat.Peer, chat.Channel.SealEnd())); }
                catch (Exception ex) when (ex is IOException or ObjectDisposedException or InvalidOperationException) { }
            }
            EndLocal(chat, "Chat ended.");
            return null;
        }
    }

    public void AddLocal(PeerChat chat, string text) => AddLine(chat, text, false);

    // ---- internals ----

    // Caller holds gate. Zeroes keys and marks the chat ended.
    private void EndLocal(PeerChat chat, string line)
    {
        chat.Initiator?.Dispose(); chat.Initiator = null;
        chat.Responder?.Dispose(); chat.Responder = null;
        chat.Channel?.Dispose(); chat.Channel = null;
        if (chat.Phase == ChatPhase.Ended) return;
        chat.Phase = ChatPhase.Ended;
        if (line != null) AddLine(chat, line, false);
        Raise(() => ChatStateChanged?.Invoke(chat));
    }

    // Ends a still-pending handshake after the timeout (token = the object that identifies this attempt).
    private void Expire(PeerChat chat, object token, int ms, string message)
    {
        _ = Task.Delay(ms, cts.Token).ContinueWith(t =>
        {
            if (t.IsCanceled) return;
            lock (gate)
            {
                bool same = chat.Phase is ChatPhase.Offering or ChatPhase.Accepting
                            && (ReferenceEquals(chat.Initiator, token) || ReferenceEquals(chat.Responder, token));
                if (same) EndLocal(chat, message);
            }
        }, TaskScheduler.Default);
    }

    private void WriteLine(string line)
    {
        byte[] buffer = Encoding.ASCII.GetBytes(line + "\n");
        lock (writeLock)
        {
            stream.Write(buffer, 0, buffer.Length);
            stream.Flush();
        }
    }

    private void Raise(Action a) => eventQueue.Writer.TryWrite(a);

    private async Task DispatchEvents()
    {
        await foreach (Action a in eventQueue.Reader.ReadAllAsync())
        {
            try { a(); } catch (Exception) { /* a faulty UI handler must not stop the session */ }
        }
    }

    // null chat = home tab
    private void AddLine(PeerChat chat, string text, bool unread)
    {
        lock (gate)
        {
            if (chat == null) HomeLines.Add(text);
            else
            {
                chat.Messages.Add(text);
                if (unread && chat != Active) chat.Unread++;
            }
        }
        Raise(() => LineAdded?.Invoke(chat, text));
    }

    private void Home(string text) => AddLine(null, text, false);

    private void Warn(PeerChat chat, string text)
    {
        // First warning, then every 20th, so a flooding peer or server cannot flood the screen.
        if (chat != null ? chat.Warnings++ % 20 == 0 : homeWarnings++ % 20 == 0) AddLine(chat, text, false);
    }

    private async Task PingLoop()
    {
        try
        {
            while (!IsClosed)
            {
                await Task.Delay(options.PingIntervalMs, cts.Token);
                WriteLine(ClientFrame.Ping());
            }
        }
        catch (Exception ex) when (ex is OperationCanceledException or IOException or ObjectDisposedException) { }
    }

    private async Task ReceiveLoop()
    {
        int malformed = 0;
        try
        {
            while (!IsClosed)
            {
                string line = await ProtocolLimits.ReadBoundedLineAsync(reader, ProtocolLimits.MaxLineChars);
                if (line == null) break;
                if (!ClientFrame.TryParse(line, out ServerEvent ev))
                {
                    if (malformed++ % 10 == 0) Raise(() => Status?.Invoke("Malformed line from the server ignored."));
                    continue;
                }
                Handle(ev);
            }
        }
        catch (InvalidDataException)
        {
            Raise(() => Status?.Invoke("Received an over-length line from the server; stopping."));
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException)
        {
            // Connection ended
        }
        finally
        {
            Interlocked.Exchange(ref closed, 1);
            lock (gate)
            {
                foreach (PeerChat c in chats.Values.ToList()) if (c.Phase != ChatPhase.Ended) EndLocal(c, "Connection lost; the chat ended.");
                foreach (IncomingRequest r in requests.Values) r.Responder.Dispose();
                requests.Clear();
                foreach (var list in keyWaiters.Values) foreach (var w in list) w.TrySetResult((KeyStatus.Failed, null));
                keyWaiters.Clear();
            }
            Raise(() => Disconnected?.Invoke());
        }
    }

    private async Task SlowWorker()
    {
        await foreach (ServerEvent ev in slowWork.Reader.ReadAllAsync())
        {
            try
            {
                if (ev.Kind == ServerEventKind.Offer) await HandleOfferAsync(ev);
                else await HandleKnockAsync(ev);
            }
            catch (Exception ex) when (ex is IOException or ObjectDisposedException or CryptographicException or InvalidOperationException) { }
        }
    }

    // Applies one server event (public as a test seam).
    public void Handle(ServerEvent ev)
    {
        switch (ev.Kind)
        {
            case ServerEventKind.Offer:
            case ServerEventKind.Knock:
                // Dropped early for blocked users (no key lookup, no work for a flooder)
                lock (gate) if (profile.Peers.IsBlocked(ev.User)) return;
                slowWork.Writer.TryWrite(ev);
                break;

            case ServerEventKind.Key:
            {
                byte[] pub = ClientFrame.DecodeBlob(ev.Data);
                CompleteKey(ev.User, pub != null && IdentityKey.IsValidPublicKey(pub) ? KeyStatus.Ok : KeyStatus.Invalid, pub);
                break;
            }

            case ServerEventKind.Accept: HandleAccept(ev); break;
            case ServerEventKind.Confirm: HandleConfirm(ev); break;
            case ServerEventKind.Msg: HandleMsg(ev); break;
            case ServerEventKind.Offline: HandleOffline(ev.User); break;

            case ServerEventKind.Gone:
                lock (gate)
                {
                    if (requests.Remove(ev.User, out IncomingRequest r)) r.Responder.Dispose();
                    if (chats.TryGetValue(ev.User, out PeerChat c) && c.Phase != ChatPhase.Ended) EndLocal(c, $"{ev.User} disconnected; the chat ended.");
                }
                break;

            case ServerEventKind.UserList:
                TaskCompletionSource<IReadOnlyList<string>> w = null;
                lock (gate) { if (userWaiters.Count > 0) { w = userWaiters[0]; userWaiters.RemoveAt(0); } }
                w?.TrySetResult(ev.Users);
                break;

            case ServerEventKind.Err:
                if (ev.Data == "nouser" && ev.User != null) CompleteKey(ev.User, KeyStatus.NoUser, null);
                else if (ev.Data == "replaced") Raise(() => Status?.Invoke("You logged in somewhere else; this connection was closed."));
                else Raise(() => Status?.Invoke(ev.User == null ? $"Server error: {ev.Data}" : $"Server error: {ev.Data} ({ev.User})"));
                break;
            // Welcome, Ready and Pong need no action after login.
        }
    }

    private void CompleteKey(string user, KeyStatus status, byte[] pub)
    {
        List<TaskCompletionSource<(KeyStatus, byte[])>> list;
        lock (gate) keyWaiters.Remove(user, out list);
        if (list != null) foreach (var w in list) w.TrySetResult((status, pub));
    }

    private async Task<(KeyStatus, byte[])> FetchKeyAsync(string user)
    {
        if (IsClosed) return (KeyStatus.Failed, null);
        TaskCompletionSource<(KeyStatus, byte[])> tcs = new(TaskCreationOptions.RunContinuationsAsynchronously);
        bool send;
        lock (gate)
        {
            if (!keyWaiters.TryGetValue(user, out var list)) keyWaiters[user] = list = [];
            send = list.Count == 0;
            list.Add(tcs);
        }
        try
        {
            if (send) WriteLine(ClientFrame.Key(user));
            return await tcs.Task.WaitAsync(TimeSpan.FromMilliseconds(options.ReplyTimeoutMs));
        }
        catch (Exception ex) when (ex is TimeoutException or IOException or ObjectDisposedException)
        {
            lock (gate) { if (keyWaiters.TryGetValue(user, out var l)) { l.Remove(tcs); if (l.Count == 0) keyWaiters.Remove(user); } }
            return (KeyStatus.Failed, null);
        }
    }

    private async Task HandleOfferAsync(ServerEvent ev)
    {
        string from = ev.User;
        byte[] offer = ClientFrame.DecodeBlob(ev.Data);
        if (offer == null) return;
        var (state, pub) = await ResolvePeerAsync(from);
        if (state == PeerKeyState.Changed) { Home(ChangedWarning(from)); return; }
        if (state is PeerKeyState.NoUser or PeerKeyState.Failed) return;

        lock (gate)
        {
            if (profile.Peers.IsBlocked(from)) return;
            HandshakeStatus st = Handshake.Responder.TryReceiveOffer(profile.Identity, UserName, from, pub, offer, options.Clock(), sidCache, out Handshake.Responder resp);
            if (st != HandshakeStatus.Ok)
            {
                Warn(null, st == HandshakeStatus.Stale
                    ? $"Ignored a request from {from} with a wrong timestamp (is the clock of either computer off by more than 10 minutes?)."
                    : $"Ignored an invalid chat request claiming to be from {from}.");
                return;
            }
            if (resp.Rekey) { resp.Dispose(); return; } // automatic rekey is not supported yet

            chats.TryGetValue(from, out PeerChat chat);
            // An offer that crossed ours on the wire and is processed after our session came up: moot.
            if (chat is { Phase: ChatPhase.Active } && options.Clock() - chat.ActivatedAtMs < 10_000) { resp.Dispose(); return; }
            if (chat is { Phase: ChatPhase.Offering })
            {
                // Both sides asked at the same time: the lower name keeps its offer; the other one auto-accepts.
                if (string.CompareOrdinal(UserName, from) < 0) { resp.Dispose(); return; }
                chat.Initiator?.Dispose(); chat.Initiator = null;
                byte[] accept = resp.Accept();
                chat.Responder = resp;
                chat.Phase = ChatPhase.Accepting;
                WriteLine(ClientFrame.Accept(from, accept));
                AddLine(chat, $"{from} asked too; accepted. Establishing a secure session...", false);
                Expire(chat, resp, options.AcceptTimeoutMs, $"{from} did not complete the handshake.");
                return;
            }

            if (requests.Remove(from, out IncomingRequest older)) older.Responder.Dispose(); // newest offer per user wins
            if (requests.Count >= ProtocolLimits.MaxPendingRequests)
            {
                resp.Dispose();
                Warn(null, "Too many pending chat requests; a new one was ignored. /decline or /block some.");
                return;
            }
            PeerRecord rec = profile.Peers.Get(from);
            bool verified = rec is { Verified: true };
            IncomingRequest req = new() { User = from, Verified = verified, ReceivedAtMs = options.Clock(), Responder = resp };
            requests[from] = req;
            AddLine(null, $"{from} wants to chat ({(verified ? "verified" : "unverified")} key). /accept {from} or /block {from}", false);
            Raise(() => RequestReceived?.Invoke(req));
        }
    }

    private async Task HandleKnockAsync(ServerEvent ev)
    {
        string from = ev.User;
        byte[] knock = ClientFrame.DecodeBlob(ev.Data);
        if (knock == null) return;
        var (state, pub) = await ResolvePeerAsync(from);
        if (state == PeerKeyState.Changed) { Home(ChangedWarning(from)); return; }
        if (state is PeerKeyState.NoUser or PeerKeyState.Failed) return;
        lock (gate)
        {
            if (profile.Peers.IsBlocked(from)) return;
            HandshakeStatus st = Handshake.VerifyKnock(knock, from, pub, UserName, profile.Identity.PublicKey, options.Clock(), out long ts);
            if (st != HandshakeStatus.Ok)
            {
                if (st != HandshakeStatus.Stale) Warn(null, $"Ignored a forged knock claiming to be from {from}.");
                return;
            }
            string when = DateTimeOffset.FromUnixTimeMilliseconds(ts).ToLocalTime().ToString("yyyy-MM-dd HH:mm");
            AddLine(null, $"{from} tried to reach you at {when}; /chat {from}", false);
        }
    }

    private void HandleAccept(ServerEvent ev)
    {
        byte[] accept = ClientFrame.DecodeBlob(ev.Data);
        if (accept == null) return;
        lock (gate)
        {
            if (!chats.TryGetValue(ev.User, out PeerChat chat) || chat.Phase != ChatPhase.Offering || chat.Initiator == null) return; // unsolicited
            HandshakeStatus st = chat.Initiator.ProcessAccept(accept, out SecureChannel channel, out byte[] confirm);
            if (st != HandshakeStatus.Ok)
            {
                if (st != HandshakeStatus.UnknownSession) Warn(chat, $"Ignored an invalid answer from {ev.User} ({st}).");
                return;
            }
            try { WriteLine(ClientFrame.Confirm(ev.User, confirm)); }
            catch (Exception ex) when (ex is IOException or ObjectDisposedException) { channel.Dispose(); return; }
            chat.Initiator.Dispose(); chat.Initiator = null;
            if (requests.Remove(ev.User, out IncomingRequest crossed)) crossed.Responder.Dispose(); // their crossing offer is moot
            chat.Channel = channel;
            chat.Phase = ChatPhase.Active;
            chat.ActivatedAtMs = options.Clock();
            AddLine(chat, $"Secure session with {ev.User} established.", false);
            Raise(() => ChatStateChanged?.Invoke(chat));
        }
    }

    private void HandleConfirm(ServerEvent ev)
    {
        byte[] confirm = ClientFrame.DecodeBlob(ev.Data);
        if (confirm == null) return;
        lock (gate)
        {
            if (!chats.TryGetValue(ev.User, out PeerChat chat) || chat.Phase != ChatPhase.Accepting || chat.Responder == null) return;
            HandshakeStatus st = chat.Responder.ProcessConfirm(confirm, out SecureChannel channel);
            if (st != HandshakeStatus.Ok)
            {
                if (st != HandshakeStatus.UnknownSession) Warn(chat, $"Ignored an invalid confirmation from {ev.User} ({st}).");
                return;
            }
            chat.Responder.Dispose(); chat.Responder = null;
            chat.Channel = channel;
            chat.Phase = ChatPhase.Active;
            chat.ActivatedAtMs = options.Clock();
            AddLine(chat, $"Secure session with {ev.User} established.", false);
            Raise(() => ChatStateChanged?.Invoke(chat));
        }
    }

    private void HandleMsg(ServerEvent ev)
    {
        byte[] msg = ClientFrame.DecodeBlob(ev.Data);
        if (msg == null) return;
        lock (gate)
        {
            if (!chats.TryGetValue(ev.User, out PeerChat chat) || chat.Phase != ChatPhase.Active) return;
            OpenResult r = chat.Channel.Open(msg);
            switch (r.Status)
            {
                case OpenStatus.Ok:
                    if (r.Lost > 0) AddLine(chat, $"{r.Lost} message(s) from {ev.User} were lost or withheld.", false);
                    if (r.Kind == MessageKind.EndOfSession) EndLocal(chat, $"{ev.User} ended the chat.");
                    else AddLine(chat, $"{ev.User}: {MessageRules.SanitizeForDisplay(r.Text)}", true);
                    break;
                case OpenStatus.Replay: Warn(chat, $"A replayed or duplicated message from {ev.User} was dropped."); break;
                case OpenStatus.TooFarAhead: Warn(chat, $"A message from {ev.User} with a far-future number was dropped."); break;
                case OpenStatus.AuthFailed: Warn(chat, $"A message from {ev.User} failed authentication and was dropped."); break;
                case OpenStatus.BadPlaintext: Warn(chat, $"A malformed message from {ev.User} was dropped."); break;
                case OpenStatus.Exhausted: EndLocal(chat, "This session reached its message limit. /chat to start a new one."); break;
                // UnknownSession and Malformed: dropped silently (no crypto work done)
            }
        }
    }

    private void HandleOffline(string user)
    {
        lock (gate)
        {
            if (!chats.TryGetValue(user, out PeerChat chat)) return;
            if (chat.Phase == ChatPhase.Offering)
            {
                byte[] pub = profile.Peers.GetKey(user);
                string note = $"{user} is offline.";
                if (pub != null)
                {
                    try
                    {
                        WriteLine(ClientFrame.Knock(user, Handshake.BuildKnock(profile.Identity, UserName, user, pub, options.Clock())));
                        note += $" A signed knock was left; {user} will see it at the next login.";
                    }
                    catch (Exception ex) when (ex is IOException or ObjectDisposedException) { }
                }
                EndLocal(chat, note);
            }
            else if (chat.Phase == ChatPhase.Accepting) EndLocal(chat, $"{user} is offline; the handshake was abandoned.");
            else if (chat.Phase == ChatPhase.Active) AddLine(chat, $"{user} appears to be offline; the last message may not have been delivered.", false);
        }
    }

    public void Dispose()
    {
        Interlocked.Exchange(ref closed, 1);
        try { cts.Cancel(); } catch (ObjectDisposedException) { }
        try { tcp.Close(); } catch (Exception) { }
        lock (gate)
        {
            foreach (PeerChat c in chats.Values) { c.Initiator?.Dispose(); c.Responder?.Dispose(); c.Channel?.Dispose(); }
            foreach (IncomingRequest r in requests.Values) r.Responder.Dispose();
            requests.Clear();
        }
        slowWork.Writer.TryComplete();
        eventQueue.Writer.TryComplete();
    }
}
