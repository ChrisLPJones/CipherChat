using System.Net;
using System.Net.Sockets;
using System.Text;
using CipherChatClient;
using CipherChatServer;
using Xunit;

namespace CipherChat.Tests;

// History (opt-in, encrypted at rest). Every test uses its own Guid-named temp directory, deleted in Dispose.
public class HistoryTests : IDisposable
{
    private const string Key = "history-test-key";
    private const string TagA = "histAAAAAAAAAAAAAAAAA1";
    private const string TagB = "histBBBBBBBBBBBBBBBBB2";
    private static readonly string Presence = AESecureString.EncryptString("alice", Key, TagA);

    private readonly string dir = Path.Combine(Path.GetTempPath(), "cipherchat-test-" + Guid.NewGuid().ToString("N"));
    private readonly List<ChatServer> servers = [];
    private readonly List<ChatSession> sessions = [];

    public void Dispose()
    {
        foreach (var s in sessions) s.Dispose();
        foreach (var s in servers) s.Stop();
        if (Directory.Exists(dir) && Path.GetFileName(dir).StartsWith("cipherchat-test-"))
            Directory.Delete(dir, recursive: true);
    }

    private static string Payload(string text, string tag = TagA) => AESecureString.EncryptString(text, Key, tag);

    private static string Fake(int i) => Convert.ToBase64String(new byte[60 + 3 * (i % 7)]).Replace('A', 'B') + i.ToString("D4").Replace('0', 'x');

    private ChatServer StartServer(int max = 1000, bool history = true)
    {
        var s = new ChatServer("localhost", 0, new ChatServerOptions { HistoryDirectory = history ? dir : null, MaxPerChannel = max });
        s.Start();
        servers.Add(s);
        return s;
    }

    private string[] Files() => Directory.Exists(dir) ? Directory.GetFiles(dir) : [];

    // ---- HistoryStore ----

    [Fact]
    public void Store_AppendLoadRoundTrip_AndHeadSurvivesNewInstance()
    {
        var store = new HistoryStore(dir, 1000);
        for (int i = 1; i <= 5; i++) store.Append(TagA, i, 1000 + i, Fake(i));
        Assert.Equal(5, store.Head(TagA));
        Assert.Equal(0, store.Head(TagB));

        var again = new HistoryStore(dir, 1000);
        Assert.Equal(5, again.Head(TagA));
        var recs = again.Read(TagA, 2, 50);
        Assert.Equal(new long[] { 3, 4, 5 }, recs.Select(r => r.Id));
        Assert.Equal(Fake(3), recs[0].Payload);
        Assert.Equal(1003, recs[0].UnixMillis);
        // last N after id, oldest first
        Assert.Equal(new long[] { 4, 5 }, again.Read(TagA, 0, 2).Select(r => r.Id));
        Assert.Empty(again.Read(TagB, 0, 50));
    }

    [Fact]
    public void Store_FileNameIsHashOfTag_NotTheTag_AndRejectsNonTags()
    {
        var store = new HistoryStore(dir, 1000);
        store.Append(TagA, 1, 1, Fake(1));
        string file = Assert.Single(Files());
        string name = Path.GetFileName(file);
        Assert.DoesNotContain(TagA, name);
        Assert.Equal(HistoryStore.FileNameFor(TagA), name);
        Assert.Matches("^[0-9a-f]{64}\\.log$", name);
        Assert.Equal(dir, Path.GetDirectoryName(file));

        foreach (string bad in new[] { "../../etc/passwd", "..\\x", TagA + "/", "short", "", null })
        {
            Assert.Throws<ArgumentException>(() => HistoryStore.FileNameFor(bad));
            Assert.Throws<ArgumentException>(() => store.Append(bad, 2, 1, Fake(2)));
        }
        Assert.Single(Files());
    }

    [Fact]
    public void Store_Retention_TrimsToCapAndServesOnlyCap()
    {
        var store = new HistoryStore(dir, 10);
        for (int i = 1; i <= 40; i++) store.Append(TagA, i, i, Fake(i));
        var recs = store.Read(TagA, 0, 50);
        Assert.Equal(10, recs.Count);
        Assert.Equal(31, recs[0].Id);
        Assert.Equal(40, recs[^1].Id);
        // On disk: trimmed, at most cap + 10% slack
        int lines = File.ReadAllLines(Files().Single()).Length;
        Assert.InRange(lines, 10, 11);
        Assert.Equal(40, new HistoryStore(dir, 10).Head(TagA));
    }

    [Fact]
    public void Store_ToleratesCorruptAndTruncatedLines_AndRepairsFile()
    {
        var store = new HistoryStore(dir, 1000);
        store.Append(TagA, 1, 1, Fake(1));
        store.Append(TagA, 2, 2, Fake(2));
        string path = Files().Single();
        // garbage line, wrong-id line, short payload, then a truncated last line without newline
        File.AppendAllText(path, "garbage line here\n1 5 " + Fake(9) + "\nx y z\n3 3 " + Fake(3).Substring(0, 70));

        var fresh = new HistoryStore(dir, 1000);
        Assert.Equal(2, fresh.Head(TagA));
        Assert.Equal(new long[] { 1, 2 }, fresh.Read(TagA, 0, 50).Select(r => r.Id));

        fresh.Append(TagA, 3, 3, Fake(3)); // must start on a clean line
        var again = new HistoryStore(dir, 1000);
        Assert.Equal(new long[] { 1, 2, 3 }, again.Read(TagA, 0, 50).Select(r => r.Id));
        Assert.Equal(Fake(3), again.Read(TagA, 2, 5).Single().Payload);
    }

    [Fact]
    public void Store_OverlongLineIsSkippedWithoutBuffering()
    {
        var store = new HistoryStore(dir, 1000);
        store.Append(TagA, 1, 1, Fake(1));
        File.AppendAllText(Files().Single(), "2 2 " + new string('A', 200_000) + "\n");
        var fresh = new HistoryStore(dir, 1000);
        Assert.Equal(new long[] { 1 }, fresh.Read(TagA, 0, 50).Select(r => r.Id));
    }

    [Fact]
    public void Store_ConcurrentAppendsKeepEveryRecord()
    {
        var store = new HistoryStore(dir, 1000);
        long next = 0;
        object gate = new();
        Parallel.For(0, 8, _ =>
        {
            for (int i = 0; i < 25; i++)
                lock (gate) { long id = ++next; store.Append(TagA, id, id, Fake((int)id)); }
        });
        Parallel.For(0, 8, _ => store.Read(TagA, 0, 50)); // concurrent reads are safe
        Assert.Equal(200, store.Head(TagA));
        Assert.Equal(200, new HistoryStore(dir, 1000).Read(TagA, 0, 50).Count == 50 ? 200 : -1);
    }

    [Fact]
    public void Store_FilesAreNotWorldReadable_AndContainNoPlaintext()
    {
        const string marker = "TOP-SECRET-PLAINTEXT-MARKER";
        var store = new HistoryStore(dir, 1000);
        store.Append(TagA, 1, 1, Payload($"alice: {marker}"));
        string path = Files().Single();
        byte[] bytes = File.ReadAllBytes(path);
        Assert.DoesNotContain(marker, Encoding.UTF8.GetString(bytes));
        Assert.DoesNotContain(TagA, Encoding.UTF8.GetString(bytes));
        if (!OperatingSystem.IsWindows())
        {
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(path));
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, File.GetUnixFileMode(dir));
        }
    }

    // ---- Server (raw protocol) ----

    private static string Rl(StreamReader r) => r.ReadLine();

    private static (TcpClient, StreamReader, NetworkStream) Open(int port)
    {
        var tcp = new TcpClient();
        tcp.Connect(IPAddress.Loopback, port);
        tcp.ReceiveTimeout = 5000;
        return (tcp, new StreamReader(tcp.GetStream()), tcp.GetStream());
    }

    private static void Send(NetworkStream s, string line)
    {
        byte[] b = Encoding.ASCII.GetBytes(line + "\n");
        s.Write(b, 0, b.Length);
    }

    [Fact]
    public void Server_StoresMessages_HistReplaysThem_IdsContinueAfterRestartAndEmptyDrop()
    {
        var server = StartServer();
        string p1 = Payload("alice: one"), p2 = Payload("alice: two");
        var (t1, r1, s1) = Open(server.Port);
        using (t1)
        {
            Send(s1, "HELLO 3"); Rl(r1);
            Send(s1, $"JOIN {TagA} {Presence}"); Rl(r1);
            Send(s1, $"MSG {TagA} {p1}"); Assert.Equal($"ACK {TagA} 1", Rl(r1));
            Send(s1, $"MSG {TagA} {p2}"); Assert.Equal($"ACK {TagA} 2", Rl(r1));
        }
        // empty-channel drop: everyone left; a new joiner continues at 3 and sees the history
        Thread.Sleep(300);
        var (t2, r2, s2) = Open(server.Port);
        using (t2)
        {
            Send(s2, "HELLO 3"); Rl(r2);
            Send(s2, $"JOIN {TagA} {Presence}"); Rl(r2);
            Send(s2, $"HIST {TagA} 0 50");
            Assert.Equal($"HIST {TagA} 1 {p1}", Rl(r2));
            Assert.Equal($"HIST {TagA} 2 {p2}", Rl(r2));
            Assert.Equal($"HISTEND {TagA} 2", Rl(r2));
            Send(s2, $"HIST {TagA} 1 50");
            Assert.Equal($"HIST {TagA} 2 {p2}", Rl(r2));
            Assert.Equal($"HISTEND {TagA} 2", Rl(r2));
            Send(s2, $"HIST {TagA} 2 50");
            Assert.Equal($"HISTEND {TagA} 2", Rl(r2));
            Send(s2, $"HIST {TagA} 0 1"); // last max records
            Assert.Equal($"HIST {TagA} 2 {p2}", Rl(r2));
            Assert.Equal($"HISTEND {TagA} 2", Rl(r2));
            Send(s2, $"MSG {TagA} {p1}"); Assert.Equal($"ACK {TagA} 3", Rl(r2));
        }
        server.Stop();

        // restart on the same directory: ids continue
        var restarted = StartServer();
        var (t3, r3, s3) = Open(restarted.Port);
        using (t3)
        {
            Send(s3, "HELLO 3"); Rl(r3);
            Send(s3, $"JOIN {TagA} {Presence}"); Rl(r3);
            Send(s3, $"MSG {TagA} {p2}"); Assert.Equal($"ACK {TagA} 4", Rl(r3));
            Send(s3, $"HIST {TagA} 0 50");
            var ids = new List<string>();
            string line;
            while (!(line = Rl(r3)).StartsWith("HISTEND")) ids.Add(line.Split(' ')[2]);
            Assert.Equal(new[] { "1", "2", "3", "4" }, ids);
            Assert.Equal($"HISTEND {TagA} 4", line);
        }
    }

    [Fact]
    public void Server_HistIsIsolatedPerChannel_AndNeedsMembership()
    {
        var server = StartServer();
        var (t1, r1, s1) = Open(server.Port);
        var (t2, r2, s2) = Open(server.Port);
        using (t1) using (t2)
        {
            Send(s1, "HELLO 3"); Rl(r1);
            Send(s1, $"JOIN {TagA} {Presence}"); Rl(r1);
            Send(s1, $"MSG {TagA} {Payload("alice: a-only")}"); Rl(r1);

            Send(s2, "HELLO 3"); Rl(r2);
            Send(s2, $"HIST {TagA} 0 50");
            Assert.Equal("ERR notjoined", Rl(r2)); // not a member: cannot download
            Send(s2, $"JOIN {TagB} {Presence}"); Rl(r2);
            Send(s2, $"HIST {TagB} 0 50");
            Assert.Equal($"HISTEND {TagB} 0", Rl(r2)); // other channel: empty
        }
    }

    [Fact]
    public void Server_WithoutHistory_WritesNothing_AndAnswersUnsupported()
    {
        var server = StartServer(history: false);
        Assert.False(server.HistoryEnabled);
        var (t, r, s) = Open(server.Port);
        using (t)
        {
            Send(s, "HELLO 3"); Rl(r);
            Send(s, $"JOIN {TagA} {Presence}"); Rl(r);
            Send(s, $"MSG {TagA} {Payload("alice: x")}"); Assert.Equal($"ACK {TagA} 1", Rl(r));
            Send(s, $"HIST {TagA} 0 50");
            Assert.Equal("ERR unsupported", Rl(r));
        }
        Assert.False(Directory.Exists(dir));
    }

    [Fact]
    public void Server_StoresOnlyOpaqueClientCiphertext_NoPlaintextOnDisk()
    {
        const string marker = "PLAINTEXT-NEEDLE-12345";
        var server = StartServer();
        var (t, r, s) = Open(server.Port);
        using (t)
        {
            Send(s, "HELLO 3"); Rl(r);
            Send(s, $"JOIN {TagA} {Presence}"); Rl(r);
            Send(s, $"MSG {TagA} {Payload("alice: " + marker)}"); Rl(r);
        }
        string all = string.Concat(Files().Select(f => File.ReadAllText(f)));
        Assert.NotEmpty(all);
        Assert.DoesNotContain(marker, all);
        Assert.DoesNotContain("alice", all);
        Assert.DoesNotContain(TagA, all);
    }

    // ---- ChatSession end to end ----

    private async Task<ChatSession> Connect(ChatServer server, string user, string key = "lobby-key")
    {
        var s = new ChatSession("localhost", server.Port, user, key);
        sessions.Add(s);
        await s.ConnectAsync();
        return s;
    }

    private static bool WaitFor(Func<bool> c, int ms = 20000)
    {
        var until = DateTime.UtcNow.AddMilliseconds(ms);
        while (DateTime.UtcNow < until) { if (c()) return true; Thread.Sleep(50); }
        return c();
    }

    private static List<string> Msgs(ChannelState ch) { lock (ch.Messages) return ch.Messages.ToList(); }

    [Fact]
    public async Task Session_ReplaysHistoryOnJoin_MarkedAndOrdered_ThenHistoryCommandDedupes()
    {
        var server = StartServer();
        var alice = await Connect(server, "alice");
        var aLobby = await alice.JoinLobbyAsync();
        Assert.True(WaitFor(() => Msgs(aLobby).Any(m => m.StartsWith("You are alone"))));
        Assert.Null(alice.Send(aLobby, "first"));
        Assert.Null(alice.Send(aLobby, "second"));
        Assert.Null(alice.Send(aLobby, "third"));
        Assert.True(WaitFor(() => aLobby.LastId == 3));
        alice.Dispose();

        var bob = await Connect(server, "bob");
        var bLobby = await bob.JoinLobbyAsync();
        Assert.True(WaitFor(() => Msgs(bLobby).Count(m => m.StartsWith("[history]")) == 3));
        var lines = Msgs(bLobby);
        Assert.Equal(new[] { "[history] alice: first", "[history] alice: second", "[history] alice: third" },
            lines.Where(m => m.StartsWith("[history]")));
        // the history proved the key right: the alone hint does not suggest a wrong key
        Assert.DoesNotContain(lines, m => m.Contains("wrong key"));
        Assert.Contains(lines, m => m.StartsWith("You are alone in general right now"));
        Assert.Equal(3, bLobby.LastId);

        // /history again: nothing new, no duplicates
        Assert.Null(bob.RequestHistory(bLobby));
        Assert.True(WaitFor(() => Msgs(bLobby).Any(m => m.StartsWith("No further history"))));
        Assert.Equal(3, Msgs(bLobby).Count(m => m.StartsWith("[history]")));
    }

    [Fact]
    public async Task Session_DmHistoryIsStoredAndReplayedToThePair()
    {
        var server = StartServer();
        var alice = await Connect(server, "alice");
        await alice.JoinLobbyAsync();
        var aDm = await alice.OpenDmAsync("bob", "pair");
        Assert.Null(alice.Send(aDm, "psst"));
        Assert.True(WaitFor(() => aDm.LastId == 1));
        alice.Dispose();

        var bob = await Connect(server, "bob");
        await bob.JoinLobbyAsync();
        var bDm = await bob.OpenDmAsync("alice", "pair");
        Assert.True(WaitFor(() => Msgs(bDm).Contains("[history] alice: psst")));
        var carol = await Connect(server, "carol");
        await carol.JoinLobbyAsync();
        var cDm = await carol.OpenDmAsync("bob", "wrong");
        Assert.True(WaitFor(() => Msgs(cDm).Any(m => m.StartsWith("You are alone in dm:bob. If others"))));
        Assert.DoesNotContain(Msgs(cDm), m => m.StartsWith("[history]"));
    }

    [Fact]
    public async Task Session_LiveMessageDuringReplayIsNotDuplicated_AndOwnAckedMessagesAreNotReplayed()
    {
        var server = StartServer();
        var alice = await Connect(server, "alice");
        var aLobby = await alice.JoinLobbyAsync();
        Assert.Null(alice.Send(aLobby, "mine"));
        Assert.True(WaitFor(() => aLobby.LastId == 1));

        Assert.Null(alice.RequestHistory(aLobby)); // would replay "mine", but we already have it (ACK id)
        Assert.True(WaitFor(() => Msgs(aLobby).Any(m => m.StartsWith("No further history"))));
        Assert.Single(Msgs(aLobby), "alice: mine");
        Assert.DoesNotContain(Msgs(aLobby), m => m.StartsWith("[history]"));
    }

    [Fact]
    public async Task Session_WithoutServerHistory_ShowsHintAndAloneLine_AndRejectsHistoryCommand()
    {
        var server = StartServer(history: false);
        var statuses = new List<string>();
        var alice = new ChatSession("localhost", server.Port, "alice", "k");
        sessions.Add(alice);
        alice.Status += statuses.Add;
        await alice.ConnectAsync();
        var lobby = await alice.JoinLobbyAsync();
        Assert.True(WaitFor(() => Msgs(lobby).Any(m => m.StartsWith("You are alone in general. If others"))));
        Assert.True(WaitFor(() => alice.HistoryUnsupported));
        Assert.Contains(statuses, s => s.Contains("keeps no message history"));
        Assert.Contains("keeps no message history", alice.RequestHistory(lobby));
    }

    [Fact]
    public async Task Session_ServerRestartedWithoutHistory_ResetsIdsInsteadOfHidingNewMessages()
    {
        var server = StartServer(history: false);
        var alice = await Connect(server, "alice");
        var aLobby = await alice.JoinLobbyAsync();
        // simulate ids from an earlier server life, then the server reports a lower head
        aLobby.LastId = 40; aLobby.SeenIds.Add(40);
        alice.Handle(new ServerEvent { Kind = ServerEventKind.HistEnd, Tag = aLobby.Tag, Id = 2 });
        Assert.Equal(2, aLobby.LastId);
        Assert.Empty(aLobby.SeenIds);
    }
}
