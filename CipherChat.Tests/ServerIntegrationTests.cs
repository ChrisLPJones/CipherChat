using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using CipherChatServer;
using Xunit;

namespace CipherChat.Tests;

// Raw-socket tests of the v5 rendezvous server on ephemeral ports. Nothing is stored anywhere; per-IP limits,
// burns and refills use a fake clock, deadlines use small real timeouts.
public class ServerIntegrationTests : IDisposable
{
    private readonly List<ChatServer> servers = new();
    private long fakeNow = 1_800_000_000_000;

    public void Dispose() { foreach (ChatServer s in servers) { s.Stop(); s.Dispose(); } }

    private void Advance(long ms) => Interlocked.Add(ref fakeNow, ms);

    private ChatServer Start(ServerLimits limits = null)
    {
        var s = new ChatServer("localhost", 0, new ChatServerOptions
        {
            Limits = limits ?? Relaxed(),
            Clock = () => Interlocked.Read(ref fakeNow),
        });
        s.Start();
        servers.Add(s);
        return s;
    }

    // Production defaults except for what would get in the way of tests that open many connections.
    private static ServerLimits Relaxed() => new()
    {
        MaxConnectionsPerIp = 100, HellosPerIpPerMinute = 1000, UnproductivePairingsPerIpPerHour = 1000,
    };

    private static string Nonce(char c) => new string(c, 32);
    private static string KeyB64() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
    private static string ConfirmB64() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
    private static string MsgB64(int blocks = 1) => Convert.ToBase64String(RandomNumberGenerator.GetBytes(26 + 256 * blocks + 16));

    private static TestClient Join(ChatServer s, string rid, char nonceChar, out string firstReply)
    {
        var c = new TestClient(s.Port);
        c.SendLine($"HELLO 5 {rid} {Nonce(nonceChar)}");
        firstReply = c.ReadLine();
        return c;
    }

    // Two clients paired on rid; returns (first, second) after both read their PAIRED line.
    private static (TestClient a, TestClient b) Paired(ChatServer s, string rid = "0a0a0a")
    {
        var a = Join(s, rid, 'a', out string w);
        Assert.Equal("WAIT", w);
        var b = Join(s, rid, 'b', out string p2);
        Assert.Equal($"PAIRED 2 {Nonce('a')}", p2);
        Assert.Equal($"PAIRED 1 {Nonce('b')}", a.ReadLine());
        return (a, b);
    }

    // Both complete the handshake lines (KEY and CONFIRM from each side, relayed).
    private static void Handshake(TestClient a, TestClient b)
    {
        string ka = KeyB64(), kb = KeyB64(), ca = ConfirmB64(), cb = ConfirmB64();
        a.SendLine($"KEY {ka}"); Assert.Equal($"KEY {ka}", b.ReadLine());
        b.SendLine($"KEY {kb}"); Assert.Equal($"KEY {kb}", a.ReadLine());
        a.SendLine($"CONFIRM {ca}"); Assert.Equal($"CONFIRM {ca}", b.ReadLine());
        b.SendLine($"CONFIRM {cb}"); Assert.Equal($"CONFIRM {cb}", a.ReadLine());
    }

    private static void Barrier(TestClient c)
    {
        c.SendLine("PING");
        Assert.Equal("PONG", c.ReadLine());
    }

    // ---- version ----

    [Theory]
    [InlineData("HELLO 4")]
    [InlineData("HELLO 4 0a0a0a 00000000000000000000000000000000")]
    [InlineData("HELLO 3")]
    [InlineData("HELLO 5 0A0A0A 00000000000000000000000000000000")]   // uppercase hex is outside the grammar
    [InlineData("HELLO 5 0a0a0a")]
    [InlineData("PING")]
    [InlineData("KEY AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")]
    [InlineData("garbage")]
    public void EveryOtherFirstLine_GetsErrVersionAndClose(string first)
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
        Assert.Null(c.ReadLine());
    }

    // ---- pairing ----

    [Fact]
    public void FirstHelloWaits_SecondPairs_AndNoncesAreExchanged()
    {
        var s = Start();
        var (a, b) = Paired(s);
        using (a) using (b) { Assert.Equal(0, s.WaiterCount); }
    }

    [Fact]
    public void DifferentRids_DoNotPair()
    {
        var s = Start();
        using var a = Join(s, "000001", 'a', out string wa);
        using var b = Join(s, "000002", 'b', out string wb);
        Assert.Equal("WAIT", wa);
        Assert.Equal("WAIT", wb);
        Assert.Equal(2, s.WaiterCount);
    }

    [Fact]
    public void ThirdHello_OnAPairedRid_GetsErrUsed()
    {
        var s = Start();
        var (a, b) = Paired(s);
        using (a) using (b)
        {
            using var c = Join(s, "0a0a0a", 'c', out string reply);
            Assert.Equal("ERR used", reply);
            Assert.Null(c.ReadLine());
            Barrier(a); Barrier(b);   // the pair is unaffected
        }
    }

    [Fact]
    public void RidIsBurnedAfterAPairing_AndExpiresAfterAnHour()
    {
        var s = Start();
        var (a, b) = Paired(s);
        a.Dispose();
        Assert.Equal("GONE", b.ReadLine());
        Assert.Null(b.ReadLine());
        b.Dispose();
        Wait.For(() => s.BurnedCount == 1 && s.ConnectionCount == 0, "pair ended");

        using (var c = Join(s, "0a0a0a", 'c', out string reply))
        {
            Assert.Equal("ERR used", reply);
        }
        Advance(59 * 60_000);
        using (var c = Join(s, "0a0a0a", 'c', out string reply))
            Assert.Equal("ERR used", reply);
        Advance(2 * 60_000);
        using (var c = Join(s, "0a0a0a", 'c', out string reply))
            Assert.Equal("WAIT", reply);          // burn expired
    }

    [Fact]
    public void BurnTable_IsCapped_OldestDroppedFirst()
    {
        var s = Start(new ServerLimits { MaxConnectionsPerIp = 100, HellosPerIpPerMinute = 1000, UnproductivePairingsPerIpPerHour = 1000, MaxBurned = 2 });
        for (int i = 1; i <= 3; i++)
        {
            Advance(1000);
            var (a, b) = Paired(s, $"00000{i}");
            a.Dispose(); b.Dispose();
            Wait.For(() => s.ConnectionCount == 0, "pair ended");
        }
        Assert.Equal(2, s.BurnedCount);
        using var old = Join(s, "000001", 'c', out string r1);
        Assert.Equal("WAIT", r1);                  // the oldest burn was pruned
        using var recent = Join(s, "000003", 'd', out string r3);
        Assert.Equal("ERR used", r3);
    }

    [Fact]
    public void WaiterLeavingUnpaired_FreesTheRid()
    {
        var s = Start();
        var a = Join(s, "0b0b0b", 'a', out string w);
        Assert.Equal("WAIT", w);
        a.Dispose();
        Wait.For(() => s.WaiterCount == 0, "waiter gone");
        Assert.Equal(0, s.BurnedCount);
        using var b = Join(s, "0b0b0b", 'b', out string reply);
        Assert.Equal("WAIT", reply);
    }

    [Fact]
    public void PeerLeaving_GivesGoneAndClose_AtAnyStage()
    {
        var s = Start();
        var (a, b) = Paired(s);
        a.SendLine($"KEY {KeyB64()}");
        Assert.StartsWith("KEY ", b.ReadLine());
        a.Dispose();
        Assert.Equal("GONE", b.ReadLine());
        Assert.Null(b.ReadLine());
        b.Dispose();
    }

    // ---- relay ----

    [Fact]
    public void Relay_IsByteIdentical_AndOnlyToThePeer()
    {
        var s = Start();
        var (a, b) = Paired(s, "0c0c0c");
        var (x, y) = Paired(s, "0d0d0d");
        using (a) using (b) using (x) using (y)
        {
            Handshake(a, b);
            string m1 = MsgB64(1), m2 = MsgB64(24);
            a.SendLine($"MSG {m1}");
            Assert.Equal($"MSG {m1}", b.ReadLine());
            b.SendLine($"MSG {m2}");
            Assert.Equal($"MSG {m2}", a.ReadLine());
            Barrier(x); Barrier(y);    // the other pair saw nothing
        }
    }

    [Fact]
    public void Relay_PreservesOrder()
    {
        var s = Start();
        var (a, b) = Paired(s);
        using (a) using (b)
        {
            Handshake(a, b);
            string[] msgs = Enumerable.Range(0, 20).Select(_ => MsgB64()).ToArray();
            foreach (string m in msgs) a.SendLine($"MSG {m}");
            foreach (string m in msgs) Assert.Equal($"MSG {m}", b.ReadLine());
        }
    }

    // ---- order enforcement ----

    [Theory]
    [InlineData("KEY")]
    [InlineData("CONFIRM")]
    [InlineData("MSG")]
    [InlineData("HELLO")]
    public void WhileAlone_OnlyPingIsAllowed(string verb)
    {
        var s = Start();
        var a = Join(s, "0e0e0e", 'a', out string w);
        using (a)
        {
            Assert.Equal("WAIT", w);
            Barrier(a);
            a.SendLine(verb switch { "KEY" => $"KEY {KeyB64()}", "CONFIRM" => $"CONFIRM {ConfirmB64()}", "MSG" => $"MSG {MsgB64()}", _ => $"HELLO 5 0e0e0e {Nonce('a')}" });
            Assert.Null(a.ReadLine());
        }
    }

    public static IEnumerable<object[]> OrderViolations()
    {
        yield return new object[] { "confirm-first" };
        yield return new object[] { "msg-first" };
        yield return new object[] { "key-twice" };
        yield return new object[] { "msg-before-confirm" };
        yield return new object[] { "confirm-twice" };
        yield return new object[] { "hello-again" };
        yield return new object[] { "grammar" };
        yield return new object[] { "over-length" };
    }

    [Theory]
    [MemberData(nameof(OrderViolations))]
    public void OutOfOrderOrInvalidLines_CloseTheSender_AndTellThePeer(string kind)
    {
        var s = Start();
        var (a, b) = Paired(s);
        using (a) using (b)
        {
            switch (kind)
            {
                case "confirm-first": a.SendLine($"CONFIRM {ConfirmB64()}"); break;
                case "msg-first": a.SendLine($"MSG {MsgB64()}"); break;
                case "key-twice": a.SendLine($"KEY {KeyB64()}"); b.ReadLine(); a.SendLine($"KEY {KeyB64()}"); break;
                case "msg-before-confirm": a.SendLine($"KEY {KeyB64()}"); b.ReadLine(); a.SendLine($"MSG {MsgB64()}"); break;
                case "confirm-twice": a.SendLine($"KEY {KeyB64()}"); b.ReadLine(); a.SendLine($"CONFIRM {ConfirmB64()}"); b.ReadLine(); a.SendLine($"CONFIRM {ConfirmB64()}"); break;
                case "hello-again": a.SendLine($"HELLO 5 0a0a0a {Nonce('a')}"); break;
                case "grammar": a.SendLine("KEY not-base64"); break;
                default: a.SendLine("MSG " + new string('A', CipherChatServer.ProtocolLimits.MaxLineChars + 5)); break;
            }
            Assert.Null(a.ReadLine());
            Assert.Equal("GONE", b.ReadLine());
            Assert.Null(b.ReadLine());
        }
    }

    // ---- rate limits ----

    [Fact]
    public void MsgRate_IsLimitedPerConnection_OverMeansErrRateAndClose()
    {
        var s = Start(new ServerLimits { MaxConnectionsPerIp = 100, HellosPerIpPerMinute = 1000, UnproductivePairingsPerIpPerHour = 1000, MsgBurst = 3, MsgPerSecond = 0.0001 });
        var (a, b) = Paired(s);
        using (a) using (b)
        {
            Handshake(a, b);
            for (int i = 0; i < 3; i++) a.SendLine($"MSG {MsgB64()}");
            a.SendLine($"MSG {MsgB64()}");
            for (int i = 0; i < 3; i++) Assert.StartsWith("MSG ", b.ReadLine());
            Assert.Equal("ERR rate", a.ReadLine());
            Assert.Null(a.ReadLine());
            Assert.Equal("GONE", b.ReadLine());
        }
    }

    [Fact]
    public void PingRate_IsLimited_OverMeansErrRateAndClose()
    {
        var s = Start(new ServerLimits { MaxConnectionsPerIp = 100, HellosPerIpPerMinute = 1000, UnproductivePairingsPerIpPerHour = 1000, PingBurst = 2, PingPerSecond = 0.0001 });
        var a = Join(s, "0f0f0f", 'a', out _);
        using (a)
        {
            Barrier(a); Barrier(a);
            a.SendLine("PING");
            Assert.Equal("ERR rate", a.ReadLine());
            Assert.Null(a.ReadLine());
        }
    }

    [Fact]
    public void HelloRate_PerIp_ErrRate_AndRefill()
    {
        var s = Start(new ServerLimits { MaxConnectionsPerIp = 100, HellosPerIpPerMinute = 2, UnproductivePairingsPerIpPerHour = 1000 });
        using var a = Join(s, "000001", 'a', out string r1);
        using var b = Join(s, "000002", 'b', out string r2);
        Assert.Equal("WAIT", r1); Assert.Equal("WAIT", r2);
        using (var c = Join(s, "000003", 'c', out string r3))
        {
            Assert.Equal("ERR rate", r3);
            Assert.Null(c.ReadLine());
        }
        Advance(60_000);
        using var d = Join(s, "000003", 'd', out string r4);
        Assert.Equal("WAIT", r4);
    }

    [Fact]
    public void UnproductivePairings_PerIp_SixthGetsErrRate_RefillsAfterAnHour()
    {
        var s = Start(new ServerLimits { MaxConnectionsPerIp = 100, HellosPerIpPerMinute = 1000, UnproductivePairingsPerIpPerHour = 5 });
        for (int i = 1; i <= 5; i++)
        {
            var (a, b) = Paired(s, $"1000{i:00}");
            a.Dispose(); b.Dispose();
            Wait.For(() => s.ConnectionCount == 0, "pair ended");
        }
        using (var c = Join(s, "100099", 'c', out string reply))
        {
            Assert.Equal("ERR rate", reply);
            Assert.Null(c.ReadLine());
        }
        Advance(3600_000 / 5 + 1000);   // one token comes back after 12 minutes
        using var d = Join(s, "100099", 'd', out string again);
        Assert.Equal("WAIT", again);
    }

    [Fact]
    public void ProductivePairings_DoNotCountAgainstTheIp()
    {
        var s = Start(new ServerLimits { MaxConnectionsPerIp = 100, HellosPerIpPerMinute = 1000, UnproductivePairingsPerIpPerHour = 1 });
        for (int i = 1; i <= 4; i++)
        {
            var (a, b) = Paired(s, $"2000{i:00}");
            Handshake(a, b);
            a.SendLine($"MSG {MsgB64()}");
            Assert.StartsWith("MSG ", b.ReadLine());
            a.Dispose(); b.Dispose();
            Wait.For(() => s.ConnectionCount == 0, "pair ended");
        }
        using var c = Join(s, "200099", 'c', out string reply);
        Assert.Equal("WAIT", reply);
    }

    // ---- deadlines ----

    [Fact]
    public void HelloDeadline_ClosesSilentConnections()
    {
        var s = Start(new ServerLimits { MaxConnectionsPerIp = 100, HelloDeadlineMs = 300 });
        using var c = new TestClient(s.Port);
        Assert.Equal("ERR timeout", c.ReadLine());
        Assert.Null(c.ReadLine());
    }

    [Fact]
    public void HelloDeadline_DoesNotAffectAWaiter()
    {
        var s = Start(new ServerLimits { MaxConnectionsPerIp = 100, HelloDeadlineMs = 300, HellosPerIpPerMinute = 1000 });
        var a = Join(s, "0b0b0b", 'a', out _);
        using (a)
        {
            Thread.Sleep(700);
            Barrier(a);
        }
    }

    [Fact]
    public void LoneWaiter_HasNoTimeLimit_StaysWaitingPastTheOldTenMinutes_AndKeepaliveHoldsIt()
    {
        var s = Start(new ServerLimits { MaxConnectionsPerIp = 100, HellosPerIpPerMinute = 1000, ReadTimeoutMs = 700, HelloDeadlineMs = 300 });
        var a = Join(s, "0b0b0b", 'a', out string w);
        using (a)
        {
            Assert.Equal("WAIT", w);
            // Longer than the hello deadline and the read timeout, kept alive by PINGs (well within the 4/min refill: the clock is faked).
            for (int i = 0; i < 8; i++)
            {
                Thread.Sleep(250);
                Advance(15_000);                         // 2 minutes of fake time in total on top of the real time
                Barrier(a);
            }
            Advance(11 * 60_000);                       // far past the old 10 minute limit
            Barrier(a);
            Assert.Equal(1, s.WaiterCount);
            // and it can still be paired
            using var b = Join(s, "0b0b0b", 'b', out string p);
            Assert.Equal($"PAIRED 2 {Nonce('a')}", p);
            Assert.Equal($"PAIRED 1 {Nonce('b')}", a.ReadLine());
        }
    }

    [Fact]
    public void DeadWaiter_IsDropped_AndItsSlotAndRidAreFreed()
    {
        // silent but connected: the read timeout ends it
        var s = Start(new ServerLimits { MaxConnectionsPerIp = 100, HellosPerIpPerMinute = 1000, ReadTimeoutMs = 400 });
        var a = Join(s, "0b0b0b", 'a', out _);
        using (a)
        {
            Assert.Equal("ERR timeout", a.ReadLine());
            Assert.Null(a.ReadLine());
        }
        Wait.For(() => s.WaiterCount == 0 && s.ConnectionCount == 0, "slot freed");
        using var b = Join(s, "0b0b0b", 'b', out string reply);
        Assert.Equal("WAIT", reply);

        // vanished without a word: the connection closing frees it at once
        var c = Join(s, "0c0c0c", 'c', out _);
        c.Dispose();
        Wait.For(() => s.WaiterCount == 1, "closed waiter freed");
    }

    [Fact]
    public void ConfirmDeadline_ErrTimeoutToBoth_AndNoDeadlineOnceConfirmed()
    {
        var s = Start(new ServerLimits { MaxConnectionsPerIp = 100, HellosPerIpPerMinute = 1000, UnproductivePairingsPerIpPerHour = 1000, ConfirmDeadlineMs = 400 });
        var (a, b) = Paired(s);
        using (a) using (b)
        {
            a.SendLine($"KEY {KeyB64()}");
            Assert.StartsWith("KEY ", b.ReadLine());
            Assert.Equal("ERR timeout", a.ReadLine());
            Assert.Equal("ERR timeout", b.ReadLine());
            Assert.Null(a.ReadLine());
            Assert.Null(b.ReadLine());
        }

        var (c, d) = Paired(s, "0c0c0c");
        using (c) using (d)
        {
            Handshake(c, d);
            Thread.Sleep(900);
            Barrier(c); Barrier(d);
        }
    }

    [Fact]
    public void ReadTimeout_ClosesIdleConnections()
    {
        var s = Start(new ServerLimits { MaxConnectionsPerIp = 100, HellosPerIpPerMinute = 1000, ReadTimeoutMs = 400 });
        var a = Join(s, "0b0b0b", 'a', out _);
        using (a)
        {
            Assert.Equal("ERR timeout", a.ReadLine());
            Assert.Null(a.ReadLine());
        }
    }

    // ---- caps ----

    [Fact]
    public void ConnectionCaps_TotalAndPerIp()
    {
        var s = Start(new ServerLimits { MaxConnections = 2, MaxConnectionsPerIp = 100, HellosPerIpPerMinute = 1000 });
        using var a = Join(s, "000001", 'a', out _);
        using var b = Join(s, "000002", 'b', out _);
        using (var third = new TestClient(s.Port))
        {
            Assert.Equal("ERR full", third.ReadLine());
            Assert.Null(third.ReadLine());
        }

        var s2 = Start(new ServerLimits { MaxConnectionsPerIp = 2, HellosPerIpPerMinute = 1000 });
        using var c1 = Join(s2, "000001", 'a', out _);
        using var c2 = Join(s2, "000002", 'b', out _);
        using var c3 = new TestClient(s2.Port);
        Assert.Equal("ERR full", c3.ReadLine());
        c1.Dispose();
        Wait.For(() =>
        {
            using var again = new TestClient(s2.Port);
            again.SendLine($"HELLO 5 000009 {Nonce('d')}");
            return again.ReadLine() == "WAIT";
        }, "slot freed");
    }

    [Fact]
    public void WaiterCap_ErrFull()
    {
        var s = Start(new ServerLimits { MaxConnectionsPerIp = 100, HellosPerIpPerMinute = 1000, MaxWaiters = 2 });
        using var a = Join(s, "000001", 'a', out _);
        using var b = Join(s, "000002", 'b', out _);
        using var c = Join(s, "000003", 'c', out string reply);
        Assert.Equal("ERR full", reply);
        using var d = Join(s, "000001", 'd', out string pairs);   // pairing an existing waiter is still allowed
        Assert.Equal($"PAIRED 2 {Nonce('a')}", pairs);
    }

    // ---- misc ----

    [Fact]
    public void Stop_ClosesAllClients()
    {
        var s = Start();
        var (a, b) = Paired(s);
        using (a) using (b)
        {
            s.Stop();
            Assert.Null(a.ReadLine());
            Assert.Null(b.ReadLine());
        }
    }

    [Fact]
    public void ServerAssembly_ReferencesNeitherTheClientNorLibsodium()
    {
        var refs = typeof(ChatServer).Assembly.GetReferencedAssemblies().Select(n => n.Name).ToList();
        Assert.DoesNotContain("CipherChatClient", refs);
        Assert.DoesNotContain(refs, r => r.Contains("sodium", StringComparison.OrdinalIgnoreCase));
        string dir = Path.GetDirectoryName(typeof(ChatServer).Assembly.Location);
        // The server project's own output must carry no native crypto library (the test host output may, via the client).
        string serverBin = Path.GetFullPath(Path.Combine(dir, "..", "..", "..", "..", "CipherChatServer", "bin"));
        if (Directory.Exists(serverBin))
            Assert.Empty(Directory.GetFiles(serverBin, "*sodium*", SearchOption.AllDirectories));
    }

    [Fact]
    public void ServerLogsNothingAboutClients()
    {
        TextWriter original = Console.Out;
        StringWriter captured = new();
        Console.SetOut(captured);
        try
        {
            var s = Start();
            var (a, b) = Paired(s, "7a7b7c");
            string key = KeyB64();
            a.SendLine($"KEY {key}");
            b.ReadLine();
            a.SendLine("garbage line");
            a.ReadLine();
            b.Dispose(); a.Dispose();
            Thread.Sleep(300);
            string log = captured.ToString();
            Assert.DoesNotContain("7a7b7c", log);
            Assert.DoesNotContain(Nonce('a'), log);
            Assert.DoesNotContain(key, log);
            Assert.DoesNotContain("127.0.0.1", log);
            Assert.Equal("", log);
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

        // Null at end of stream (also when the server reset the connection).
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
