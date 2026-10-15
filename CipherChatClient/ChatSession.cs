using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Channels;

namespace CipherChatClient;

public enum SessionState { Idle, Preparing, Connecting, Waiting, Handshaking, Chatting, Ended }

public enum EndReason
{
    None, UserQuit, NobodyJoined, SecurityFailure, ServerBusy, VersionMismatch, CannotConnect, ConnectionLost,
    MessageFailed, PeerLeft, PeerDisconnected, SessionLimit, NotEnoughMemory, CryptoUnavailable,
}

public sealed class ChatSessionOptions
{
    public int ConnectTimeoutMs { get; init; } = 10_000;
    public int AloneTimeoutMs { get; init; } = 10 * 60_000 + 10_000;  // the server ends the wait after 10 minutes
    public int HandshakeTimeoutMs { get; init; } = 35_000;            // the server's own limit is 30 s
    public int PingIntervalMs { get; init; } = 30_000;

    // Test hook: skip the slow Argon2id derivation and use this rendezvous id.
    internal string RidOverride { get; init; }
}

// One paired-code chat over one connection (wire protocol v5): derive the rendezvous id, HELLO, wait for the other
// person, run CPace over the relay (KEY, CONFIRM), then talk over a SecureChannel. There is no resume: when the
// session ends the object is finished and the program is expected to exit.
//
// UI-agnostic. Events are raised on a dispatcher thread, never while the session's lock is held.
// Failure policy: every failure after HELLO looks the same on the wire (the connection is closed, nothing more is
// sent) and shows one of the few messages in Describe().
public sealed class ChatSession : IDisposable
{
    private readonly string host;
    private readonly int port;
    private readonly string code;                 // normalized and validated
    private readonly ChatSessionOptions options;
    private readonly TcpClient tcp = new();
    private readonly object writeLock = new();
    private readonly object gate = new();         // guards state; events are never raised while it is held
    private readonly Channel<Action> eventQueue = Channel.CreateUnbounded<Action>();
    private readonly CancellationTokenSource cts = new();
    private readonly TaskCompletionSource<EndReason> completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly List<string> lines = [];
    private StreamReader reader;
    private NetworkStream stream;
    private CPace cpace;
    private SecureChannel channel;
    private byte[] ownNonce;
    private string rid;
    private int malformed;
    private SessionState state = SessionState.Idle;

    // The code must already be normalized (PairCode.Normalize) and valid (PairCode.Validate returns null).
    public ChatSession(string host, int port, string normalizedCode, ChatSessionOptions options = null)
    {
        if (PairCode.Validate(normalizedCode) != null || PairCode.Normalize(normalizedCode) != normalizedCode)
            throw new ArgumentException("The code is not a normalized, valid code.");
        this.host = host;
        this.port = port;
        code = normalizedCode;
        this.options = options ?? new ChatSessionOptions();
        _ = Task.Run(DispatchEvents);
    }

    public SessionState State { get { lock (gate) return state; } }
    public EndReason Reason { get; private set; }
    public bool IsEnded => State == SessionState.Ended;

    // Completes with the reason when the session has ended.
    public Task<EndReason> Completion => completion.Task;

    // Raised for every line shown to the user: "You: ...", "Them: ..." or "* status".
    public event Action<string> LineAdded;
    public event Action<SessionState> StateChanged;
    public event Action<EndReason> Ended;

    public List<string> SnapshotLines() { lock (lines) return lines.ToList(); }

    public static string Describe(EndReason reason) => reason switch
    {
        EndReason.NobodyJoined => "Nobody joined with this code within 10 minutes. Check that you both typed exactly the same code.",
        EndReason.SecurityFailure => "Could not connect securely. Someone else may have used your code, or the connection was tampered with. Make up a NEW code together before trying again.",
        EndReason.ServerBusy => "Server busy, try again shortly.",
        EndReason.VersionMismatch => "The server does not speak this version of the protocol: upgrade the server and the clients together.",
        EndReason.CannotConnect => "Could not connect to the server.",
        EndReason.ConnectionLost => "The connection to the server was lost.",
        EndReason.MessageFailed => "A message failed verification. The chat was ended for safety.",
        EndReason.PeerLeft => "The other person left the chat.",
        EndReason.PeerDisconnected => "The other person disconnected.",
        EndReason.SessionLimit => "This chat reached its message limit and was ended.",
        EndReason.NotEnoughMemory => "Not enough free memory to prepare the code (about 256 MiB are needed).",
        EndReason.CryptoUnavailable => "The cryptography library could not be loaded on this computer.",
        EndReason.UserQuit => "You left the chat.",
        _ => "",
    };

    // True for outcomes where the program should exit with a failure code.
    public static bool IsFailure(EndReason reason) => reason is not (EndReason.UserQuit or EndReason.PeerLeft);

    // ---- start ----

    // Derives the rendezvous id, connects and sends HELLO. Everything after that is event driven.
    public async Task StartAsync()
    {
        SetState(SessionState.Preparing);
        AddLine("* Preparing...");
        try
        {
            rid = options.RidOverride ?? await Task.Run(() => PairCode.DeriveRid(code));
        }
        catch (InsufficientMemoryException) { End(EndReason.NotEnoughMemory); return; }
        catch (CryptographicUnavailableException) { End(EndReason.CryptoUnavailable); return; }

        SetState(SessionState.Connecting);
        AddLine("* Connecting...");
        try
        {
            await tcp.ConnectAsync(host, port).WaitAsync(TimeSpan.FromMilliseconds(options.ConnectTimeoutMs));
            stream = tcp.GetStream();
            reader = new StreamReader(stream, Encoding.ASCII);
            ownNonce = RandomNumberGenerator.GetBytes(CPace.NonceBytes);
            WriteLine(ClientFrame.Hello(rid, Convert.ToHexString(ownNonce).ToLowerInvariant()));
        }
        catch (Exception ex) when (ex is SocketException or IOException or TimeoutException or ObjectDisposedException)
        {
            End(EndReason.CannotConnect);
            return;
        }
        if (IsEnded) return;

        _ = Task.Run(ReceiveLoop);
        _ = Task.Run(PingLoop);
        StartTimer(options.AloneTimeoutMs, () => state is SessionState.Connecting or SessionState.Waiting, EndReason.NobodyJoined);
    }

    // ---- sending ----

    // Sends a message in an established chat; returns an error text or null. The local echo is added here.
    public string Send(string text)
    {
        if (text == null || text.Length == 0) return null;
        if (text.Length > ProtocolLimits.MaxMessageChars) return $"Message too long (max {ProtocolLimits.MaxMessageChars} characters).";
        lock (gate)
        {
            if (state != SessionState.Chatting) return "The chat is not established.";
            try
            {
                WriteLine(ClientFrame.Msg(channel.SealText(text)));
            }
            catch (InvalidOperationException) { EndLocked(EndReason.SessionLimit); return null; }
            catch (Exception ex) when (ex is IOException or ObjectDisposedException)
            {
                EndLocked(EndReason.ConnectionLost);
                return null;
            }
            AddLine("You: " + MessageRules.SanitizeForDisplay(text));
            return null;
        }
    }

    // Leaves: tells the other person (encrypted end-of-session), then closes. Exit afterwards.
    public void Quit()
    {
        lock (gate)
        {
            if (state == SessionState.Chatting)
            {
                try { WriteLine(ClientFrame.Msg(channel.SealEnd())); }
                catch (Exception ex) when (ex is IOException or ObjectDisposedException or InvalidOperationException) { }
            }
            EndLocked(EndReason.UserQuit);
        }
    }

    // ---- receiving ----

    private async Task ReceiveLoop()
    {
        try
        {
            while (!IsEnded)
            {
                string line = await ProtocolLimits.ReadBoundedLineAsync(reader, ProtocolLimits.MaxLineChars);
                if (line == null) break;
                if (!ClientFrame.TryParse(line, out ServerEvent ev))
                {
                    // Garbage cannot change any state; a server that sends nothing else is just broken.
                    lock (gate) if (malformed++ == 0) AddLine("* Ignored a malformed line from the server.");
                    continue;
                }
                Handle(ev);
            }
        }
        catch (InvalidDataException)
        {
            End(state == SessionState.Chatting ? EndReason.MessageFailed : EndReason.SecurityFailure);
            return;
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException)
        {
        }
        // The connection closed on its own.
        lock (gate)
        {
            if (state == SessionState.Ended) return;
            EndLocked(state is SessionState.Connecting or SessionState.Waiting ? EndReason.ConnectionLost
                    : state == SessionState.Handshaking ? EndReason.SecurityFailure : EndReason.ConnectionLost);
        }
    }

    // Applies one server event (public as a test seam).
    public void Handle(ServerEvent ev)
    {
        lock (gate)
        {
            if (state == SessionState.Ended || ev.Kind == ServerEventKind.Pong) return;
            switch (state)
            {
                case SessionState.Connecting:
                case SessionState.Waiting:
                    HandleWaiting(ev);
                    break;
                case SessionState.Handshaking:
                    HandleHandshake(ev);
                    break;
                case SessionState.Chatting:
                    HandleChat(ev);
                    break;
            }
        }
    }

    private void HandleWaiting(ServerEvent ev)
    {
        switch (ev.Kind)
        {
            case ServerEventKind.Wait:
                if (state == SessionState.Connecting)
                {
                    SetState(SessionState.Waiting);
                    AddLine("* Waiting for the other person (up to 10 minutes)...");
                }
                break;
            case ServerEventKind.Paired:
                BeginHandshake(ev);
                break;
            case ServerEventKind.Err:
                EndLocked(ev.Data switch
                {
                    "timeout" => EndReason.NobodyJoined,
                    "full" or "rate" => EndReason.ServerBusy,
                    "version" => EndReason.VersionMismatch,
                    _ => EndReason.SecurityFailure,          // "used": the code was already taken by someone else
                });
                break;
            default:
                EndLocked(EndReason.SecurityFailure);
                break;
        }
    }

    private void BeginHandshake(ServerEvent ev)
    {
        byte[] peerNonce = Convert.FromHexString(ev.Nonce);
        // The server must not hand our own nonce back to us (a replay would make both session ids equal to a guess).
        if (CryptographicOperations.FixedTimeEquals(peerNonce, ownNonce)) { EndLocked(EndReason.SecurityFailure); return; }
        try
        {
            cpace = new CPace(ev.Role, code, rid, ownNonce, peerNonce);
            byte[] y = cpace.CreateKeyMessage();
            SetState(SessionState.Handshaking);
            AddLine("* Connected. Checking the code...");
            WriteLine(ClientFrame.Key(y));
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException)
        {
            EndLocked(EndReason.ConnectionLost);
            return;
        }
        catch (CryptographicException) { EndLocked(EndReason.SecurityFailure); return; }
        StartTimer(options.HandshakeTimeoutMs, () => state == SessionState.Handshaking, EndReason.SecurityFailure);
    }

    private void HandleHandshake(ServerEvent ev)
    {
        try
        {
            switch (ev.Kind)
            {
                case ServerEventKind.Key:
                    if (cpace.State != CPaceState.KeySent || !cpace.ReceiveKey(ClientFrame.DecodeBlob(ev.Data))) { EndLocked(EndReason.SecurityFailure); return; }
                    WriteLine(ClientFrame.Confirm(cpace.CreateConfirm()));
                    break;
                case ServerEventKind.Confirm:
                    if (cpace.State != CPaceState.KeyReceived || !cpace.VerifyConfirm(ClientFrame.DecodeBlob(ev.Data))) { EndLocked(EndReason.SecurityFailure); return; }
                    channel = cpace.CreateChannel();
                    cpace.Dispose();
                    cpace = null;
                    SetState(SessionState.Chatting);
                    AddLine("* Connected. The other person proved they know the code.");
                    break;
                default:
                    // MSG before the handshake finished, GONE, ERR, a second PAIRED/WAIT: all the same failure.
                    EndLocked(EndReason.SecurityFailure);
                    break;
            }
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException)
        {
            EndLocked(EndReason.ConnectionLost);
        }
        catch (Exception ex) when (ex is InvalidOperationException or CryptographicException or ArgumentException)
        {
            EndLocked(EndReason.SecurityFailure);
        }
    }

    private void HandleChat(ServerEvent ev)
    {
        switch (ev.Kind)
        {
            case ServerEventKind.Msg:
                byte[] blob = ClientFrame.DecodeBlob(ev.Data);
                OpenResult r = blob == null ? new OpenResult { Status = OpenStatus.Malformed } : channel.Open(blob);
                if (r.Status != OpenStatus.Ok) { EndLocked(r.Status == OpenStatus.Exhausted ? EndReason.SessionLimit : EndReason.MessageFailed); return; }
                if (r.Kind == MessageKind.EndOfSession) EndLocked(EndReason.PeerLeft);
                else AddLine("Them: " + MessageRules.SanitizeForDisplay(r.Text));
                break;
            case ServerEventKind.Gone:
                EndLocked(EndReason.PeerDisconnected);
                break;
            case ServerEventKind.Err:
                EndLocked(EndReason.ConnectionLost);
                break;
            default:
                EndLocked(EndReason.MessageFailed);    // KEY/CONFIRM/PAIRED/WAIT in the middle of a chat
                break;
        }
    }

    // ---- ending ----

    private void End(EndReason reason)
    {
        lock (gate) EndLocked(reason);
    }

    // Caller holds gate. Idempotent. Zeroes keys, closes the connection (nothing more is ever sent), raises events.
    private void EndLocked(EndReason reason)
    {
        if (state == SessionState.Ended) return;
        state = SessionState.Ended;
        Reason = reason;
        try { cts.Cancel(); } catch (ObjectDisposedException) { }
        cpace?.Dispose(); cpace = null;
        channel?.Dispose(); channel = null;
        try { tcp.Close(); } catch (Exception) { }
        string text = Describe(reason);
        if (text.Length > 0) AddLine("* " + text);
        Raise(() => StateChanged?.Invoke(SessionState.Ended));
        Raise(() => Ended?.Invoke(reason));
        completion.TrySetResult(reason);
    }

    private void SetState(SessionState s)
    {
        lock (gate) { if (state == SessionState.Ended) return; state = s; }
        Raise(() => StateChanged?.Invoke(s));
    }

    private void StartTimer(int ms, Func<bool> stillRelevant, EndReason reason)
    {
        _ = Task.Delay(ms, cts.Token).ContinueWith(t =>
        {
            if (t.IsCanceled) return;
            lock (gate) { if (stillRelevant()) EndLocked(reason); }
        }, TaskScheduler.Default);
    }

    private async Task PingLoop()
    {
        try
        {
            while (!IsEnded)
            {
                await Task.Delay(options.PingIntervalMs, cts.Token);
                WriteLine(ClientFrame.Ping());
            }
        }
        catch (Exception ex) when (ex is OperationCanceledException or IOException or ObjectDisposedException) { }
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

    // ---- events ----

    private void AddLine(string text)
    {
        lock (lines) lines.Add(text);
        Raise(() => LineAdded?.Invoke(text));
    }

    private void Raise(Action a) => eventQueue.Writer.TryWrite(a);

    private async Task DispatchEvents()
    {
        await foreach (Action a in eventQueue.Reader.ReadAllAsync())
        {
            try { a(); } catch (Exception) { /* a faulty UI handler must not stop the session */ }
        }
    }

    public void Dispose()
    {
        lock (gate) EndLocked(EndReason.UserQuit);
        eventQueue.Writer.TryComplete();
    }
}
