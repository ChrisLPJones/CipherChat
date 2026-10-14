using System.Net;
using System.Net.Sockets;
using System.Text;
using CipherChatClient;
using CipherChatServer;
using Xunit;

namespace CipherChat.Tests;

// Raw-socket tests of wire protocol v3 against an in-process server on an ephemeral port (throwaway, no stored data).
public class ChatServerIntegrationTests : IDisposable
{
    private const string Key = "integration-test-key";
    private const string TagRoom = "roomAAAAAAAAAAAAAAAAA1";  // 22 chars of [A-Za-z0-9_-]
    private const string TagOther = "roomBBBBBBBBBBBBBBBBB2";
    private const string TagDm = "dm_CCCCCCCCCCCCCCCCC-3";

    // Valid-looking payloads (the server only checks charset and length)
    private static readonly string Presence = AESecureString.EncryptString("alice", Key, TagRoom);
    private static readonly string Payload = AESecureString.EncryptString("alice: hello", Key, TagRoom);

    private ChatServer server;

    public void Dispose()
    {
        server?.Stop();
        server?.Dispose();
    }

    private int StartServer()
    {
        server = new ChatServer("localhost", 0);
        server.Start();
        return server.Port;
    }

    private static TestClient Hello(int port)
    {
        var c = new TestClient(port);
        c.SendLine("HELLO 3");
        Assert.StartsWith("WELCOME 3 ", c.ReadLine());
        return c;
    }

    // Joins and returns this client's mid (taken from the self MEMBER line, the last roster entry).
    private static int Join(TestClient c, string tag, string presence, int othersAlreadyThere = 0)
    {
        c.SendLine($"JOIN {tag} {presence}");
        string line = null;
        for (int i = 0; i <= othersAlreadyThere; i++) line = c.ReadLine();
        string[] t = line.Split(' ');
        Assert.Equal("MEMBER", t[0]);
        Assert.Equal(tag, t[1]);
        return int.Parse(t[2]);
    }

    [Fact]
    public void Handshake_ReturnsWelcomeWithMid()
    {
        int port = StartServer();
        using var c = new TestClient(port);
        c.SendLine("HELLO 3");
        string[] t = c.ReadLine().Split(' ');
        Assert.Equal(new[] { "WELCOME", "3" }, t[..2]);
        Assert.True(int.Parse(t[2]) > 0);
    }

    [Fact]
    public void Join_SendsRosterSelfLast_AndAnnouncesToOthers()
    {
        int port = StartServer();
        using var a = Hello(port);
        int midA = Join(a, TagRoom, Presence);

        using var b = Hello(port);
        b.SendLine($"JOIN {TagRoom} {Presence}");
        string first = b.ReadLine();   // existing member A
        string second = b.ReadLine();  // B itself, last
        Assert.Equal($"MEMBER {TagRoom} {midA} {Presence}", first);
        Assert.StartsWith($"MEMBER {TagRoom} ", second);
        int midB = int.Parse(second.Split(' ')[2]);
        Assert.NotEqual(midA, midB);

        Assert.Equal($"JOINED {TagRoom} {midB} {Presence}", a.ReadLine());
    }

    [Fact]
    public void Msg_IsRelayedOnlyToMembersOfThatTag_ByteIdentical_AndAcked()
    {
        int port = StartServer();
        using var a = Hello(port);
        using var b = Hello(port);
        using var outsider = Hello(port);
        Join(a, TagRoom, Presence);
        Join(b, TagRoom, Presence, 1);
        a.ReadLine(); // JOINED b
        Join(outsider, TagOther, Presence);

        a.SendLine($"MSG {TagRoom} {Payload}");
        Assert.Equal($"ACK {TagRoom} 1", a.ReadLine());
        Assert.Equal($"MSG {TagRoom} 1 {Payload}", b.ReadLine());
        AssertNothingArrives(outsider);

        b.SendLine($"MSG {TagRoom} {Payload}");
        Assert.Equal($"ACK {TagRoom} 2", b.ReadLine());
        Assert.Equal($"MSG {TagRoom} 2 {Payload}", a.ReadLine());
    }

    [Fact]
    public void Server_RelaysPayloadItCannotDecrypt_Unchanged()
    {
        int port = StartServer();
        string random = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(200));
        using var a = Hello(port);
        using var b = Hello(port);
        Join(a, TagRoom, Presence);
        Join(b, TagRoom, Presence, 1);
        a.ReadLine();
        a.SendLine($"MSG {TagRoom} {random}");
        a.ReadLine();
        Assert.Equal($"MSG {TagRoom} 1 {random}", b.ReadLine());
    }

    [Fact]
    public void ServerAssembly_DoesNotReferenceTheClientCrypto()
    {
        var refs = typeof(ChatServer).Assembly.GetReferencedAssemblies().Select(n => n.Name);
        Assert.DoesNotContain("CipherChatClient", refs);
    }

    [Fact]
    public void NonMember_CannotMsgOrHist_AndMemberHistIsUnsupported()
    {
        int port = StartServer();
        using var a = Hello(port);
        a.SendLine($"MSG {TagRoom} {Payload}");
        Assert.Equal("ERR notjoined", a.ReadLine());
        a.SendLine($"HIST {TagRoom} 0 10");
        Assert.Equal("ERR notjoined", a.ReadLine());
        a.SendLine($"LEAVE {TagRoom}");
        Assert.Equal("ERR notjoined", a.ReadLine());

        Join(a, TagRoom, Presence);
        a.SendLine($"HIST {TagRoom} 0 10");
        Assert.Equal("ERR unsupported", a.ReadLine());
    }

    [Fact]
    public void Dm_IsIsolatedFromRoom()
    {
        int port = StartServer();
        using var a = Hello(port);
        using var b = Hello(port);
        using var c = Hello(port);
        Join(a, TagRoom, Presence);
        Join(b, TagRoom, Presence, 1);
        a.ReadLine();
        Join(a, TagDm, Presence);
        Join(c, TagDm, Presence, 1);
        a.ReadLine(); // JOINED c on the DM

        c.SendLine($"MSG {TagDm} {Payload}");
        c.ReadLine(); // ACK
        Assert.Equal($"MSG {TagDm} 1 {Payload}", a.ReadLine());
        AssertNothingArrives(b);
    }

    [Fact]
    public void Leave_AnnouncesLeft_AndStopsDelivery()
    {
        int port = StartServer();
        using var a = Hello(port);
        using var b = Hello(port);
        Join(a, TagRoom, Presence);
        int midB = Join(b, TagRoom, Presence, 1);
        a.ReadLine();

        b.SendLine($"LEAVE {TagRoom}");
        Assert.Equal($"LEFT {TagRoom} {midB}", a.ReadLine());
        a.SendLine($"MSG {TagRoom} {Payload}");
        a.ReadLine(); // ACK
        AssertNothingArrives(b);
    }

    [Fact]
    public void Disconnect_EmitsLeftForEveryChannel()
    {
        int port = StartServer();
        using var a = Hello(port);
        var b = Hello(port);
        Join(a, TagRoom, Presence);
        Join(a, TagDm, Presence);
        int midB = Join(b, TagRoom, Presence, 1);
        a.ReadLine();
        Join(b, TagDm, Presence, 1);
        a.ReadLine();

        b.Dispose(); // crash-like: no LEAVE sent
        var lines = new[] { a.ReadLine(), a.ReadLine() };
        Assert.Contains($"LEFT {TagRoom} {midB}", lines);
        Assert.Contains($"LEFT {TagDm} {midB}", lines);
    }

    [Fact]
    public void OldStyleBase64FirstLine_GetsErrVersion_AndIsClosed()
    {
        int port = StartServer();
        using var c = new TestClient(port);
        c.SendLine(Payload);
        Assert.Equal("ERR version", c.ReadLine());
        Assert.Null(ReadOrNull(c));
    }

    [Theory]
    [InlineData("HELLO 2")]
    [InlineData("HELLO")]
    [InlineData("JOIN x y")]
    public void BadFirstLine_GetsErrVersion(string first)
    {
        int port = StartServer();
        using var c = new TestClient(port);
        c.SendLine(first);
        Assert.Equal("ERR version", c.ReadLine());
        Assert.Null(ReadOrNull(c));
    }

    [Fact]
    public void OverLengthLine_DropsOnlyThatClient()
    {
        int port = StartServer();
        using var good = Hello(port);
        Join(good, TagRoom, Presence);

        using var bad = Hello(port);
        bad.SendLine(new string('A', CipherChatServer.ProtocolLimits.MaxLineChars + 500));
        Assert.Null(ReadOrNull(bad));

        using var other = Hello(port);
        Join(other, TagRoom, Presence, 1);
        Assert.StartsWith("JOINED ", good.ReadLine());
    }

    [Theory]
    [InlineData("\u001b[2J fake log line")]
    [InlineData("FOO bar")]
    [InlineData("join roomAAAAAAAAAAAAAAAAA1 PRESENCE")]          // case sensitive verb
    [InlineData("MSG short PAYLOAD")]                             // bad tag length
    [InlineData("MSG roomAAAAAAAAAAAAAAAAA! PAYLOAD")]            // bad tag charset
    [InlineData("MSG  roomAAAAAAAAAAAAAAAAA1 PAYLOAD")]           // double space
    [InlineData("MSG roomAAAAAAAAAAAAAAAAA1 PAYLOAD ")]           // trailing space
    [InlineData("MSG roomAAAAAAAAAAAAAAAAA1 tooShortPayload")]    // below MinPayloadChars
    [InlineData("MSG roomAAAAAAAAAAAAAAAAA1 a b")]                // extra token
    [InlineData("HELLO 3")]                                       // second HELLO
    [InlineData("HIST roomAAAAAAAAAAAAAAAAA1 0 51")]              // over MaxHistoryReplay
    [InlineData("HIST roomAAAAAAAAAAAAAAAAA1 -1 5")]
    [InlineData("HIST roomAAAAAAAAAAAAAAAAA1 0 0")]
    [InlineData("PING extra")]
    public void NonGrammarLine_DropsClient_AndIsNeverRelayed(string bad)
    {
        int port = StartServer();
        using var watcher = Hello(port);
        Join(watcher, TagRoom, Presence);
        using var c = Hello(port);
        Join(c, TagRoom, Presence, 1);
        watcher.ReadLine(); // JOINED c

        c.SendLine(bad.Replace("PAYLOAD", Payload).Replace("PRESENCE", Presence));
        Assert.Null(ReadOrNull(c));
        // Only the LEFT notice reaches the watcher, never the bad line
        Assert.StartsWith("LEFT ", watcher.ReadLine());
        AssertNothingArrives(watcher);
    }

    [Fact]
    public void Ping_GetsPong()
    {
        int port = StartServer();
        using var c = Hello(port);
        c.SendLine("PING");
        Assert.Equal("PONG", c.ReadLine());
    }

    [Fact]
    public void ChannelLimit_17thJoinGetsErr_AndDuplicateJoinGetsErr()
    {
        int port = StartServer();
        using var c = Hello(port);
        for (int i = 0; i < CipherChatServer.ProtocolLimits.MaxChannelsPerClient; i++)
            Join(c, $"chan{i:D18}", Presence); // 4 + 18 = 22 chars
        c.SendLine($"JOIN extra{new string('Z', 17)} {Presence}");
        Assert.Equal("ERR limit", c.ReadLine());
        c.SendLine($"JOIN chan{0:D18} {Presence}");
        Assert.Equal("ERR alreadyjoined", c.ReadLine());
    }

    private static void AssertNothingArrives(TestClient c)
    {
        c.SetTimeout(300);
        Assert.Throws<IOException>(() => c.ReadLine());
    }

    private static string ReadOrNull(TestClient c)
    {
        try { return c.ReadLine(); }
        catch (IOException) { return null; }
    }

    // Minimal raw-socket client speaking the v3 line protocol
    private sealed class TestClient : IDisposable
    {
        private readonly TcpClient tcp;
        private readonly StreamReader reader;

        public TestClient(int port)
        {
            tcp = new TcpClient();
            tcp.Connect(IPAddress.Loopback, port);
            tcp.ReceiveTimeout = 5000;
            reader = new StreamReader(tcp.GetStream());
        }

        public void SendLine(string line)
        {
            NetworkStream stream = tcp.GetStream();
            byte[] buffer = Encoding.ASCII.GetBytes(line + "\n");
            stream.Write(buffer, 0, buffer.Length);
            stream.Flush();
        }

        public void SetTimeout(int ms) => tcp.ReceiveTimeout = ms;

        public string ReadLine() => reader.ReadLine();

        public void Dispose()
        {
            reader.Dispose();
            tcp.Close();
        }
    }
}
