using System.Net;
using System.Net.Sockets;
using System.Text;
using CipherChatServer;
using Xunit;

namespace CipherChat.Tests;

// Raw-socket tests of the (stub) server: listener, connection caps and ERR version. Pairing arrives in P4.
public class ServerIntegrationTests : IDisposable
{
    private readonly List<ChatServer> servers = new();

    public void Dispose() { foreach (ChatServer s in servers) { s.Stop(); s.Dispose(); } }

    private ChatServer Start(ServerLimits limits = null)
    {
        var s = new ChatServer("localhost", 0, new ChatServerOptions { Limits = limits ?? new ServerLimits() });
        s.Start();
        servers.Add(s);
        return s;
    }

    [Theory]
    [InlineData("HELLO 4")]
    [InlineData("HELLO 3")]
    [InlineData("HELLO 5 abcdef 00112233445566778899aabbccddeeff")]   // v5 is not served yet
    [InlineData("PING")]
    [InlineData("garbage")]
    public void EveryFirstLine_GetsErrVersionAndClose(string first)
    {
        var s = Start();
        using var c = new TestClient(s.Port);
        c.SendLine(first);
        Assert.Equal("ERR version", c.ReadLine());
        Assert.Null(c.ReadLine());
    }

    [Fact]
    public void OverLengthFirstLine_IsClosed()
    {
        var s = Start();
        using var c = new TestClient(s.Port);
        c.SendLine(new string('A', CipherChatServer.ProtocolLimits.MaxLineChars + 10));
        string reply = c.ReadLine();
        Assert.True(reply == null || reply == "ERR version");
        Assert.Null(c.ReadLine());
    }

    [Fact]
    public void ConnectionCaps_TotalAndPerIp()
    {
        var s = Start(new ServerLimits { MaxConnections = 2, MaxConnectionsPerIp = 100 });
        using var a = new TestClient(s.Port);
        using var b = new TestClient(s.Port);
        Wait.For(() => true, "settle", 50);
        using (var third = new TestClient(s.Port))
        {
            Assert.Equal("ERR full", third.ReadLine());
            Assert.Null(third.ReadLine());
        }

        var s2 = Start(new ServerLimits { MaxConnectionsPerIp = 2 });
        using var c1 = new TestClient(s2.Port);
        using var c2 = new TestClient(s2.Port);
        using var c3 = new TestClient(s2.Port);
        Assert.Equal("ERR full", c3.ReadLine());
    }

    [Fact]
    public void ReadTimeout_ClosesSilentConnections()
    {
        var s = Start(new ServerLimits { ReadTimeoutMs = 300 });
        using var c = new TestClient(s.Port);
        Assert.Equal("ERR version", c.ReadLine());
        Assert.Null(c.ReadLine());
    }

    [Fact]
    public void Stop_ClosesAllClients()
    {
        var s = Start();
        using var c = new TestClient(s.Port);
        s.Stop();
        Assert.Null(c.ReadLine());
    }

    [Fact]
    public void ServerAssembly_DoesNotReferenceTheClient()
    {
        var refs = typeof(ChatServer).Assembly.GetReferencedAssemblies().Select(n => n.Name);
        Assert.DoesNotContain("CipherChatClient", refs);
    }

    [Fact]
    public void ServerLogsNothing()
    {
        TextWriter original = Console.Out;
        StringWriter captured = new();
        Console.SetOut(captured);
        try
        {
            var s = Start();
            using var c = new TestClient(s.Port);
            c.SendLine("HELLO 4 secret-looking-text");
            c.ReadLine();
            Thread.Sleep(200);
            Assert.Equal("", captured.ToString());
        }
        finally { Console.SetOut(original); }
    }

    private sealed class TestClient : IDisposable
    {
        private readonly TcpClient tcp;
        private readonly StreamReader reader;

        public TestClient(int port)
        {
            tcp = new TcpClient();
            tcp.Connect(IPAddress.Loopback, port);
            tcp.ReceiveTimeout = 5000;
            reader = new StreamReader(tcp.GetStream(), Encoding.ASCII);
        }

        public void SendLine(string line)
        {
            byte[] buffer = Encoding.ASCII.GetBytes(line + "\n");
            try { tcp.GetStream().Write(buffer, 0, buffer.Length); tcp.GetStream().Flush(); }
            catch (IOException) { }
        }

        public string ReadLine()
        {
            try { return reader.ReadLine(); }
            catch (IOException ex) when (ex.InnerException is SocketException { SocketErrorCode: SocketError.ConnectionReset }) { return null; }
        }

        public void Dispose()
        {
            try { reader.Dispose(); } catch (IOException) { }
            tcp.Close();
        }
    }
}
