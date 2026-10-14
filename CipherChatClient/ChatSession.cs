using System.Net.Sockets;
using System.Text;

namespace CipherChatClient;

// One connection to the server plus the channels joined over it (wire protocol v3).
// UI-agnostic: the console front end subscribes to the events. Keys live in memory only.
public sealed class ChatSession : IDisposable
{
    private readonly string host;
    private readonly int port;
    private readonly string loginKey;
    private readonly TcpClient tcp = new();
    private readonly object writeLock = new();
    private readonly List<ChannelState> channels = [];
    private StreamReader reader;
    private NetworkStream stream;
    private Task receiveTask;
    private int closed;

    public ChatSession(string host, int port, string userName, string loginKey)
    {
        this.host = host;
        this.port = port;
        UserName = userName;
        this.loginKey = loginKey;
    }

    public string UserName { get; }
    public int Mid { get; private set; }
    public bool IsClosed => Volatile.Read(ref closed) == 1;

    // A line to show in a channel (chat text, joins/leaves, hints). Raised on the receive thread.
    public event Action<ChannelState, string> LineAdded;
    // Connection-level status (errors, protocol problems).
    public event Action<string> Status;
    // The connection ended (server closed it, or a protocol/IO error).
    public event Action Disconnected;

    public IReadOnlyList<ChannelState> Channels
    {
        get { lock (channels) return channels.ToList(); }
    }

    // Connects, performs the HELLO/WELCOME handshake and starts the receive loop.
    public async Task ConnectAsync()
    {
        await tcp.ConnectAsync(host, port);
        stream = tcp.GetStream();
        reader = new StreamReader(stream, Encoding.ASCII);
        WriteLine(ClientFrame.Hello());

        string line;
        try
        {
            line = await ProtocolLimits.ReadBoundedLineAsync(reader, ProtocolLimits.MaxLineChars)
                .WaitAsync(TimeSpan.FromSeconds(10));
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or TimeoutException)
        {
            throw new IOException("No valid handshake reply from the server: protocol mismatch? This client speaks protocol v3.", ex);
        }
        if (line == null)
            throw new IOException("The server closed the connection during the handshake: protocol mismatch? This client speaks protocol v3.");
        if (!ClientFrame.TryParse(line, out ServerEvent ev) || ev.Kind != ServerEventKind.Welcome)
            throw new IOException(ev is { Kind: ServerEventKind.Err, Data: "version" }
                ? "The server does not speak protocol v3: upgrade server and clients together."
                : "Unexpected handshake reply from the server: protocol mismatch? This client speaks protocol v3.");
        Mid = ev.Mid;

        receiveTask = Task.Run(ReceiveLoop);
    }

    // Derives the tag (slow: PBKDF2) and joins the lobby channel with the login key.
    public Task<ChannelState> JoinLobbyAsync() =>
        Task.Run(() => OpenChannel(ChannelKind.Lobby, ChannelId.LobbyName, ChannelId.LobbyName,
            loginKey, ChannelId.DeriveRoomTag(ChannelId.LobbyName, loginKey)));

    // Opens (or returns) the private channel with another user. Both sides must type the same pair key.
    public Task<ChannelState> OpenDmAsync(string peer, string pairKey) =>
        Task.Run(() =>
        {
            string tag = ChannelId.DeriveDmTag(UserName, peer, pairKey);
            return OpenChannel(ChannelKind.Dm, ChannelId.DmName(UserName, peer), "dm:" + peer, pairKey, tag);
        });

    private ChannelState OpenChannel(ChannelKind kind, string name, string displayName, string key, string tag)
    {
        ChannelState ch;
        lock (channels)
        {
            ch = channels.FirstOrDefault(c => c.Tag == tag);
            if (ch != null) return ch;
            if (channels.Count >= ProtocolLimits.MaxChannelsPerClient)
                throw new InvalidOperationException($"You can join at most {ProtocolLimits.MaxChannelsPerClient} channels.");
            ch = new ChannelState(kind, name, displayName, key, tag);
            channels.Add(ch);
        }
        string presence = AESecureString.EncryptString(UserName, key, tag);
        WriteLine(ClientFrame.Join(tag, presence));
        return ch;
    }

    // Encrypts and sends a chat message to a channel; returns an error text or null. Local echo is the caller's job via AddLocal.
    public string Send(ChannelState ch, string text)
    {
        if (IsClosed) return "Not connected. Press Esc to quit and start the client again.";
        try
        {
            string shown = $"{UserName}: {text}";
            string payload = AESecureString.EncryptString(shown, ch.Key, ch.Tag);
            WriteLine(ClientFrame.Msg(ch.Tag, payload));
            AddLine(ch, shown, unread: false);
            return null;
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException or ArgumentException)
        {
            return $"Error sending message: {ex.Message}";
        }
    }

    // Shows a local (system) line in a channel.
    public void AddLocal(ChannelState ch, string text) => AddLine(ch, text, unread: false);

    private void WriteLine(string line)
    {
        byte[] buffer = Encoding.ASCII.GetBytes(line + "\n");
        lock (writeLock)
        {
            stream.Write(buffer, 0, buffer.Length);
            stream.Flush();
        }
    }

    private ChannelState Find(string tag)
    {
        lock (channels) return channels.FirstOrDefault(c => c.Tag == tag);
    }

    private void AddLine(ChannelState ch, string text, bool unread)
    {
        lock (ch.Messages)
        {
            ch.Messages.Add(text);
            if (unread) ch.Unread++;
        }
        LineAdded?.Invoke(ch, text);
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
                    if (malformed++ % 10 == 0) Status?.Invoke("Malformed line from the server ignored.");
                    continue;
                }
                Handle(ev);
            }
        }
        catch (InvalidDataException)
        {
            Status?.Invoke("Received an over-length line from the server; stopping.");
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException)
        {
            // Connection ended
        }
        finally
        {
            Interlocked.Exchange(ref closed, 1);
            Disconnected?.Invoke();
        }
    }

    // Applies one server event. Decryption (PBKDF2 per blob) runs on the receive thread.
    internal void Handle(ServerEvent ev)
    {
        switch (ev.Kind)
        {
            case ServerEventKind.Member:
            case ServerEventKind.Joined:
            {
                ChannelState ch = Find(ev.Tag);
                if (ch == null) return;
                string name = DecryptPresence(ch, ev.Data);
                lock (ch.Members) ch.Members[ev.Mid] = name;
                if (ev.Kind == ServerEventKind.Joined)
                {
                    AddLine(ch, $"{name} joined", unread: false);
                }
                else if (ev.Mid == Mid && !ch.RosterComplete)
                {
                    // The server lists itself last: the roster is complete
                    ch.RosterComplete = true;
                    int others;
                    lock (ch.Members) others = ch.Members.Count - 1;
                    if (others == 0)
                        AddLine(ch, $"You are alone in {ch.DisplayName}. If others should be here, check the name and the key (a wrong key opens a different, empty channel).", unread: false);
                }
                break;
            }
            case ServerEventKind.Left:
            {
                ChannelState ch = Find(ev.Tag);
                if (ch == null) return;
                string name;
                lock (ch.Members)
                {
                    if (!ch.Members.Remove(ev.Mid, out name)) return;
                }
                AddLine(ch, $"{name} left", unread: false);
                break;
            }
            case ServerEventKind.Msg:
            {
                ChannelState ch = Find(ev.Tag);
                if (ch == null) return;
                ch.LastId = ev.Id;
                switch (MessageRules.TryDecrypt(ev.Data, ch.Key, ch.Tag, out string plain))
                {
                    case DecryptStatus.Ok:
                        AddLine(ch, MessageRules.SanitizeForDisplay(plain), unread: true);
                        break;
                    case DecryptStatus.WrongKey:
                        // First failure then every 10th; never disconnect
                        if (ch.WrongKeyCount++ % 10 == 0)
                            AddLine(ch, "Could not decrypt a message: it was tampered with or moved from another channel.", unread: false);
                        break;
                    default:
                        AddLine(ch, "Malformed message ignored.", unread: false);
                        break;
                }
                break;
            }
            case ServerEventKind.Ack:
            {
                ChannelState ch = Find(ev.Tag);
                if (ch != null) ch.LastId = Math.Max(ch.LastId, ev.Id);
                break;
            }
            case ServerEventKind.Err:
                Status?.Invoke($"Server error: {ev.Data}");
                break;
            // Hist/HistEnd/Pong arrive only once those features exist; ignored for now.
        }
    }

    private static string DecryptPresence(ChannelState ch, string blob)
    {
        return MessageRules.TryDecrypt(blob, ch.Key, ch.Tag, out string name) == DecryptStatus.Ok
            ? MessageRules.SanitizeForDisplay(name)
            : "?";
    }

    public void Dispose()
    {
        Interlocked.Exchange(ref closed, 1);
        try { tcp.Close(); } catch (Exception) { }
    }
}
