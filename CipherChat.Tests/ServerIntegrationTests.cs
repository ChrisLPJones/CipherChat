using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using CipherChatClient;
using CipherChatServer;
using Xunit;

namespace CipherChat.Tests;

// Raw-socket tests of wire protocol v4 against in-process servers on ephemeral ports. Accounts are in memory
// or in a throwaway temp directory; nothing touches real data.
public class ServerIntegrationTests : IDisposable
{
    private readonly List<ChatServer> servers = new();
    private readonly List<TempDir> dirs = new();
    private long fakeNow = 1_800_000_000_000;

    public void Dispose()
    {
        foreach (ChatServer s in servers) { s.Stop(); s.Dispose(); }
        foreach (TempDir d in dirs) d.Dispose();
    }

    private Func<long> Clock => () => Interlocked.Read(ref fakeNow);
    private void Advance(long ms) => Interlocked.Add(ref fakeNow, ms);

    private ChatServer Start(ServerLimits limits = null, string dataDir = null, bool fakeClock = false)
    {
        var opts = new ChatServerOptions
        {
            DataDirectory = dataDir,
            Limits = limits ?? new ServerLimits(),
            Clock = fakeClock ? Clock : (() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()),
        };
        var s = new ChatServer("localhost", 0, opts);
        s.Start();
        servers.Add(s);
        return s;
    }

    private static ServerLimits Relaxed(int msgBurst = 1000) => new()
    {
        PingBurst = 1000, KeyBurst = 1000, UsersBurst = 1000, OfferBurst = 1000, OfferWindowMax = 1000, ReplyBurst = 1000,
        MsgBurst = msgBurst, KnockBurst = 1000, RegistrationsPerIpPerHour = 1000, RegistrationsGlobalPerHour = 1000,
        MaxConnectionsPerIp = 1000, KnockMaxPerSenderPerHour = 1000,
    };

    // ---- helpers speaking the protocol independently of the client library's handshake code ----

    private sealed class Peer : IDisposable
    {
        public readonly IdentityKey Key = IdentityKey.Generate();
        public string Name;
        public TestClient C;
        public void Dispose() { C?.Dispose(); Key.Dispose(); }
    }

    private static byte[] Label(string s) => Encoding.ASCII.GetBytes(s + "\0");
    private static byte[] Lp(string n) => new[] { (byte)n.Length }.Concat(Encoding.ASCII.GetBytes(n)).ToArray();
    private static byte[] RegData(byte[] ch, string u, byte[] pub) => Label("CipherChat-v4/register").Concat(ch).Concat(Lp(u)).Concat(pub).ToArray();
    private static byte[] LoginData(byte[] ch, string u) => Label("CipherChat-v4/login").Concat(ch).Concat(Lp(u)).ToArray();

    private static string Blob(int bytes) => Convert.ToBase64String(RandomNumberGenerator.GetBytes(bytes));

    private static (TestClient c, byte[] challenge) Hello(int port)
    {
        var c = new TestClient(port);
        c.SendLine("HELLO 4");
        string w = c.ReadLine();
        Assert.StartsWith("WELCOME 4 ", w);
        string ch = w["WELCOME 4 ".Length..];
        Assert.Equal(44, ch.Length);
        return (c, Convert.FromBase64String(ch));
    }

    private static Peer Register(int port, string name)
    {
        var p = new Peer { Name = name };
        var (c, ch) = Hello(port);
        p.C = c;
        byte[] sig = p.Key.Sign(RegData(ch, name, p.Key.PublicKey));
        c.SendLine($"REGISTER {name} {Convert.ToBase64String(p.Key.PublicKey)} {Convert.ToBase64String(sig)}");
        Assert.Equal($"READY {name}", c.ReadLine());
        return p;
    }

    private static TestClient LoginAs(int port, Peer p, out string firstReply)
    {
        var (c, ch) = Hello(port);
        c.SendLine($"LOGIN {p.Name} {Convert.ToBase64String(p.Key.Sign(LoginData(ch, p.Name)))}");
        firstReply = c.ReadLine();
        return c;
    }

    private static void Barrier(TestClient c)
    {
        c.SendLine("PING");
        Assert.Equal("PONG", c.ReadLine());
    }

    private static void Eventually(Func<bool> cond)
    {
        for (int i = 0; i < 100; i++) { if (cond()) return; Thread.Sleep(50); }
        Assert.True(cond());
    }

    // ---- handshake and version ----

    [Theory]
    [InlineData("HELLO 3")]
    [InlineData("HELLO 5")]
    [InlineData("JOIN roomAAAAAAAAAAAAAAAAA1 xxxx")]
    [InlineData("garbage")]
    [InlineData("PING")]
    public void WrongFirstLine_GetsErrVersionAndClose(string first)
    {
        var s = Start();
        using var c = new TestClient(s.Port);
        c.SendLine(first);
        Assert.Equal("ERR version", c.ReadLine());
        Assert.Null(c.ReadLine());
    }

    [Fact]
    public void Welcome_ChallengeIsFreshPerConnection()
    {
        var s = Start();
        var (a, ca) = Hello(s.Port);
        var (b, cb) = Hello(s.Port);
        using (a) using (b) Assert.NotEqual(ca, cb);
    }

    [Theory]
    [InlineData("KEY bob")]
    [InlineData("USERS")]
    [InlineData("OFFER bob AAAA")]
    public void CommandBeforeAuth_IsNotAuthAndClose(string cmd)
    {
        var s = Start();
        var (c, _) = Hello(s.Port);
        using (c)
        {
            string line = cmd == "OFFER bob AAAA" ? "OFFER bob " + Blob(156) : cmd;
            c.SendLine(line);
            Assert.Equal("ERR notauth", c.ReadLine());
            Assert.Null(c.ReadLine());
        }
    }

    [Theory]
    [InlineData("hello 4")]
    [InlineData("LOGIN Alice AAAA")]
    [InlineData("KEY")]
    [InlineData("MSG bob short")]
    public void GrammarViolation_ClosesTheConnection(string bad)
    {
        var s = Start();
        var (c, _) = Hello(s.Port);
        using (c)
        {
            c.SendLine(bad);
            Assert.Null(c.ReadLine());
        }
    }

    [Fact]
    public void OverLengthLine_ClosesTheConnection()
    {
        var s = Start();
        var (c, _) = Hello(s.Port);
        using (c)
        {
            c.SendLine("MSG bob " + new string('A', CipherChatServer.ProtocolLimits.MaxLineChars + 10));
            Assert.Null(c.ReadLine());
        }
    }

    [Fact]
    public void Ping_BeforeAndAfterAuth()
    {
        var s = Start();
        var (c, _) = Hello(s.Port);
        using (c) Barrier(c);
    }

    // ---- register / login ----

    [Fact]
    public void Register_ThenLoginOnANewConnection()
    {
        var s = Start();
        using var alice = Register(s.Port, "alice");
        Assert.Equal(1, s.AccountCount);
        alice.C.Dispose();
        using TestClient c = LoginAs(s.Port, alice, out string reply);
        Assert.Equal("READY alice", reply);
        Barrier(c);
    }

    [Fact]
    public void Register_WithBadSignature_IsRejected_AndNothingIsCreated()
    {
        var s = Start();
        using var key = IdentityKey.Generate();
        var (c, ch) = Hello(s.Port);
        using (c)
        {
            byte[] sig = key.Sign(RegData(ch, "mallory", key.PublicKey));
            sig[10] ^= 1;
            c.SendLine($"REGISTER mallory {Convert.ToBase64String(key.PublicKey)} {Convert.ToBase64String(sig)}");
            Assert.Equal("ERR auth", c.ReadLine());
            Assert.Null(c.ReadLine());
        }
        Assert.Equal(0, s.AccountCount);
    }

    [Fact]
    public void Register_WithoutProofOfPossession_OfSomeoneElsesKey_IsRejected()
    {
        // A signature by a different key over the right data does not register the claimed public key.
        var s = Start();
        using var claimed = IdentityKey.Generate();
        using var other = IdentityKey.Generate();
        var (c, ch) = Hello(s.Port);
        using (c)
        {
            byte[] sig = other.Sign(RegData(ch, "mallory", claimed.PublicKey));
            c.SendLine($"REGISTER mallory {Convert.ToBase64String(claimed.PublicKey)} {Convert.ToBase64String(sig)}");
            Assert.Equal("ERR auth", c.ReadLine());
        }
    }

    [Fact]
    public void Register_OffCurveKey_IsRejected()
    {
        var s = Start();
        using var key = IdentityKey.Generate();
        byte[] bad = (byte[])key.PublicKey.Clone();
        bad[64] ^= 1;
        var (c, ch) = Hello(s.Port);
        using (c)
        {
            byte[] sig = key.Sign(RegData(ch, "mallory", bad));
            c.SendLine($"REGISTER mallory {Convert.ToBase64String(bad)} {Convert.ToBase64String(sig)}");
            Assert.Equal("ERR auth", c.ReadLine());
        }
        Assert.Equal(0, s.AccountCount);
    }

    [Fact]
    public void Register_TakenName_KeepsConnectionOpenUpToTheAttemptLimit()
    {
        var s = Start();
        using var alice = Register(s.Port, "alice");
        var (c, ch) = Hello(s.Port);
        using (c)
        {
            using var impostor = IdentityKey.Generate();
            string line = $"REGISTER alice {Convert.ToBase64String(impostor.PublicKey)} {Convert.ToBase64String(impostor.Sign(RegData(ch, "alice", impostor.PublicKey)))}";
            c.SendLine(line);
            Assert.Equal("ERR taken alice", c.ReadLine());
            c.SendLine(line);
            Assert.Equal("ERR taken alice", c.ReadLine());
            c.SendLine(line);
            Assert.Equal("ERR taken alice", c.ReadLine());
            Assert.Null(c.ReadLine());
        }
        Assert.Equal(1, s.AccountCount);
    }

    [Fact]
    public void Register_SameNameSameKey_ActsAsLogin_ButNeedsAValidSignature()
    {
        var s = Start();
        using var alice = Register(s.Port, "alice");
        alice.C.Dispose();
        var (c, ch) = Hello(s.Port);
        using (c)
        {
            c.SendLine($"REGISTER alice {Convert.ToBase64String(alice.Key.PublicKey)} {Convert.ToBase64String(alice.Key.Sign(RegData(ch, "alice", alice.Key.PublicKey)))}");
            Assert.Equal("READY alice", c.ReadLine());
        }
        var (d, ch2) = Hello(s.Port);
        using (d)
        {
            d.SendLine($"REGISTER alice {Convert.ToBase64String(alice.Key.PublicKey)} {Convert.ToBase64String(new byte[64])}");
            Assert.Equal("ERR auth", d.ReadLine());
        }
        Assert.Equal(1, s.AccountCount);
    }

    [Fact]
    public void Login_UnknownUser_BadSignature_AndReplayedChallengeSignature()
    {
        var s = Start();
        using var alice = Register(s.Port, "alice");

        var (c1, ch1) = Hello(s.Port);
        using (c1)
        {
            c1.SendLine($"LOGIN ghost {Convert.ToBase64String(alice.Key.Sign(LoginData(ch1, "ghost")))}");
            Assert.Equal("ERR nouser ghost", c1.ReadLine());
            Assert.Null(c1.ReadLine());
        }

        // A valid login signature captured on one connection is useless on another (new challenge).
        var (c2, ch2) = Hello(s.Port);
        string captured = Convert.ToBase64String(alice.Key.Sign(LoginData(ch2, "alice")));
        c2.Dispose();
        var (c3, _) = Hello(s.Port);
        using (c3)
        {
            c3.SendLine($"LOGIN alice {captured}");
            Assert.Equal("ERR auth", c3.ReadLine());
            Assert.Null(c3.ReadLine());
        }

        using var stranger = IdentityKey.Generate();
        var (c4, ch4) = Hello(s.Port);
        using (c4)
        {
            c4.SendLine($"LOGIN alice {Convert.ToBase64String(stranger.Sign(LoginData(ch4, "alice")))}");
            Assert.Equal("ERR auth", c4.ReadLine());
        }
    }

    [Fact]
    public void RegisterOrLogin_AfterAuth_IsRejected()
    {
        var s = Start();
        using var alice = Register(s.Port, "alice");
        alice.C.SendLine($"LOGIN alice {Convert.ToBase64String(new byte[64])}");
        Assert.Equal("ERR notauth", alice.C.ReadLine());
        Assert.Null(alice.C.ReadLine());
    }

    [Fact]
    public void Takeover_NewLoginReplacesTheOldConnection_AndPeersGetGone()
    {
        var s = Start(Relaxed());
        using var alice = Register(s.Port, "alice");
        using var bob = Register(s.Port, "bob");
        alice.C.SendLine("OFFER bob " + Blob(156));
        Assert.StartsWith("OFFER alice ", bob.C.ReadLine());

        using TestClient alice2 = LoginAs(s.Port, alice, out string reply);
        Assert.Equal("READY alice", reply);
        Assert.Equal("ERR replaced", alice.C.ReadLine());
        Assert.Null(alice.C.ReadLine());
        Assert.Equal("GONE alice", bob.C.ReadLine());
        Barrier(alice2);
    }

    // ---- key lookup ----

    [Fact]
    public void Key_ReturnsTheRegisteredPublicKey_OrNouser()
    {
        var s = Start(Relaxed());
        using var alice = Register(s.Port, "alice");
        using var bob = Register(s.Port, "bob");
        alice.C.SendLine("KEY bob");
        Assert.Equal($"KEY bob {Convert.ToBase64String(bob.Key.PublicKey)}", alice.C.ReadLine());
        alice.C.SendLine("KEY nobody");
        Assert.Equal("ERR nouser nobody", alice.C.ReadLine());
    }

    // ---- connection controls ----

    [Fact]
    public void AuthDeadline_ClosesUnauthenticatedConnections()
    {
        var s = Start(new ServerLimits { AuthDeadlineMs = 300 });
        using var silent = new TestClient(s.Port);
        Assert.Equal("ERR timeout", silent.ReadLine());
        Assert.Null(silent.ReadLine());

        var (hello, _) = Hello(s.Port);
        using (hello)
        {
            Assert.Equal("ERR timeout", hello.ReadLine());
            Assert.Null(hello.ReadLine());
        }
    }

    [Fact]
    public void AuthDeadline_DoesNotAffectAuthenticatedConnections()
    {
        var s = Start(new ServerLimits { AuthDeadlineMs = 300 });
        using var alice = Register(s.Port, "alice");
        Thread.Sleep(700);
        Barrier(alice.C);
    }

    [Fact]
    public void ReadTimeout_ClosesIdleConnections()
    {
        var s = Start(new ServerLimits { ReadTimeoutMs = 400 });
        using var alice = Register(s.Port, "alice");
        Assert.Equal("ERR timeout", alice.C.ReadLine());
        Assert.Null(alice.C.ReadLine());
    }

    [Fact]
    public void ConnectionCaps_TotalAndPerIp()
    {
        var s = Start(new ServerLimits { MaxConnections = 2, MaxConnectionsPerIp = 100 });
        var (a, _) = Hello(s.Port);
        var (b, _) = Hello(s.Port);
        using (var third = new TestClient(s.Port))
        {
            Assert.Equal("ERR full", third.ReadLine());
            Assert.Null(third.ReadLine());
        }
        a.Dispose();
        TestClient again = null;
        Eventually(() => { again?.Dispose(); again = new TestClient(s.Port); again.SendLine("HELLO 4"); return again.ReadLine()?.StartsWith("WELCOME") == true; });
        again.Dispose(); b.Dispose();

        var s2 = Start(new ServerLimits { MaxConnectionsPerIp = 2 });
        var (c1, _) = Hello(s2.Port);
        var (c2, _) = Hello(s2.Port);
        using (var c3 = new TestClient(s2.Port))
        {
            Assert.Equal("ERR full", c3.ReadLine());
        }
        c1.Dispose(); c2.Dispose();
    }

    // ---- registration limits ----

    [Fact]
    public void RegistrationLimits_PerIp_Global_AndAccountCap()
    {
        var s = Start(new ServerLimits { RegistrationsPerIpPerHour = 2, MaxConnectionsPerIp = 100 }, fakeClock: true);
        using var a = Register(s.Port, "a1");
        using var b = Register(s.Port, "a2");
        using var key = IdentityKey.Generate();
        var (c, ch) = Hello(s.Port);
        using (c)
        {
            c.SendLine($"REGISTER a3 {Convert.ToBase64String(key.PublicKey)} {Convert.ToBase64String(key.Sign(RegData(ch, "a3", key.PublicKey)))}");
            Assert.Equal("ERR rate", c.ReadLine());
            Assert.Null(c.ReadLine());
        }
        Assert.Equal(2, s.AccountCount);
        Advance(3600_000);
        using var d = Register(s.Port, "a3"); // the hour passed
        Assert.Equal(3, s.AccountCount);

        var g = Start(new ServerLimits { RegistrationsGlobalPerHour = 2, RegistrationsPerIpPerHour = 100, MaxConnectionsPerIp = 100 });
        using var g1 = Register(g.Port, "g1");
        using var g2 = Register(g.Port, "g2");
        var (c3, ch3) = Hello(g.Port);
        using (c3)
        {
            c3.SendLine($"REGISTER g3 {Convert.ToBase64String(key.PublicKey)} {Convert.ToBase64String(key.Sign(RegData(ch3, "g3", key.PublicKey)))}");
            Assert.Equal("ERR rate", c3.ReadLine());
        }

        var cap = Start(new ServerLimits { MaxAccounts = 1, RegistrationsPerIpPerHour = 100, RegistrationsGlobalPerHour = 100 });
        using var k1 = Register(cap.Port, "k1");
        var (c4, ch4) = Hello(cap.Port);
        using (c4)
        {
            c4.SendLine($"REGISTER k2 {Convert.ToBase64String(key.PublicKey)} {Convert.ToBase64String(key.Sign(RegData(ch4, "k2", key.PublicKey)))}");
            Assert.Equal("ERR limit", c4.ReadLine());
        }
        // existing users can still log in at the cap
        k1.C.Dispose();
        using TestClient again = LoginAs(cap.Port, k1, out string reply);
        Assert.Equal("READY k1", reply);
    }

    // ---- persistence ----

    [Fact]
    public void Accounts_SurviveARestart_AndFilesArePrivate()
    {
        var dir = new TempDir(); dirs.Add(dir);
        string data = Path.Combine(dir.Path, "data");
        Peer alice;
        var s = Start(dataDir: data);
        Assert.True(s.PersistentAccounts);
        alice = Register(s.Port, "alice");
        alice.C.Dispose();
        s.Stop();

        if (!OperatingSystem.IsWindows())
        {
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, File.GetUnixFileMode(data));
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(Path.Combine(data, "accounts.txt")));
        }
        string text = File.ReadAllText(Path.Combine(data, "accounts.txt"));
        Assert.StartsWith("alice " + Convert.ToBase64String(alice.Key.PublicKey) + " ", text);

        var s2 = Start(dataDir: data);
        Assert.Equal(1, s2.AccountCount);
        using TestClient c = LoginAs(s2.Port, alice, out string reply);
        Assert.Equal("READY alice", reply);
        // the name stays taken by the same key
        using var thief = IdentityKey.Generate();
        var (t, ch) = Hello(s2.Port);
        using (t)
        {
            t.SendLine($"REGISTER alice {Convert.ToBase64String(thief.PublicKey)} {Convert.ToBase64String(thief.Sign(RegData(ch, "alice", thief.PublicKey)))}");
            Assert.StartsWith("ERR taken", t.ReadLine());
        }
        alice.Dispose();
    }

    [Fact]
    public void DamagedAccountsFile_StopsTheServerFromStarting()
    {
        var dir = new TempDir(); dirs.Add(dir);
        File.WriteAllText(Path.Combine(dir.Path, "accounts.txt"), "alice notbase64 123\n");
        Assert.Throws<InvalidDataException>(() => new ChatServer("localhost", 0, new ChatServerOptions { DataDirectory = dir.Path }));
        File.WriteAllText(Path.Combine(dir.Path, "accounts.txt"), "Alice " + Blob(65) + " 123\n");
        Assert.Throws<InvalidDataException>(() => new ChatServer("localhost", 0, new ChatServerOptions { DataDirectory = dir.Path }));
    }

    // ---- relay ----

    [Fact]
    public void Relay_IsByteIdentical_WithAuthenticatedFrom_AndOnlyToTheTarget()
    {
        var s = Start(Relaxed());
        using var alice = Register(s.Port, "alice");
        using var bob = Register(s.Port, "bob");
        using var carol = Register(s.Port, "carol");

        string offer = Blob(156), accept = Blob(179), confirm = Blob(50);
        string msg = Blob(26 + 256 * 3 + 16);
        alice.C.SendLine($"OFFER bob {offer}");
        Assert.Equal($"OFFER alice {offer}", bob.C.ReadLine());
        bob.C.SendLine($"ACCEPT alice {accept}");
        Assert.Equal($"ACCEPT bob {accept}", alice.C.ReadLine());
        alice.C.SendLine($"CONFIRM bob {confirm}");
        Assert.Equal($"CONFIRM alice {confirm}", bob.C.ReadLine());
        alice.C.SendLine($"MSG bob {msg}");
        Assert.Equal($"MSG alice {msg}", bob.C.ReadLine());
        bob.C.SendLine($"MSG alice {msg}");
        Assert.Equal($"MSG bob {msg}", alice.C.ReadLine());

        // carol saw nothing and alice has nothing pending beyond what was read
        Barrier(carol.C);
        Barrier(alice.C);
    }

    [Fact]
    public void Relay_ToSelf_IsErrSelf_ToOfflineIsOffline_AndUnauthenticatedNeverRelays()
    {
        var s = Start(Relaxed());
        using var alice = Register(s.Port, "alice");
        alice.C.SendLine("MSG alice " + Blob(26 + 256 + 16));
        Assert.Equal("ERR self", alice.C.ReadLine());
        alice.C.SendLine("OFFER nobody " + Blob(156));
        Assert.Equal("OFFLINE nobody", alice.C.ReadLine());
        alice.C.SendLine("ACCEPT nobody " + Blob(179));
        Assert.Equal("OFFLINE nobody", alice.C.ReadLine());
        alice.C.SendLine("CONFIRM nobody " + Blob(50));
        Assert.Equal("OFFLINE nobody", alice.C.ReadLine());
        alice.C.SendLine("MSG nobody " + Blob(26 + 256 + 16));
        Assert.Equal("OFFLINE nobody", alice.C.ReadLine());

        // An unauthenticated connection cannot inject a line to alice.
        var (c, _) = Hello(s.Port);
        using (c)
        {
            c.SendLine("MSG alice " + Blob(26 + 256 + 16));
            Assert.Equal("ERR notauth", c.ReadLine());
        }
        Barrier(alice.C);
    }

    [Fact]
    public void Gone_IsSentToContactsOnly_OnDisconnect()
    {
        var s = Start(Relaxed());
        using var alice = Register(s.Port, "alice");
        using var bob = Register(s.Port, "bob");
        using var carol = Register(s.Port, "carol");
        alice.C.SendLine("OFFER bob " + Blob(156));
        Assert.StartsWith("OFFER", bob.C.ReadLine());
        alice.C.Dispose();
        Assert.Equal("GONE alice", bob.C.ReadLine());
        Barrier(carol.C); // carol was never a contact: nothing before PONG
        Barrier(bob.C);
    }

    [Fact]
    public void Gone_IsSentWhenTheOtherSideInitiatedToo()
    {
        var s = Start(Relaxed());
        using var alice = Register(s.Port, "alice");
        using var bob = Register(s.Port, "bob");
        alice.C.SendLine("OFFER bob " + Blob(156));
        Assert.StartsWith("OFFER", bob.C.ReadLine());
        bob.C.Dispose();
        Assert.Equal("GONE bob", alice.C.ReadLine());
    }

    // ---- knocks ----

    [Fact]
    public void Knock_OnlineTarget_IsDeliveredAtOnce()
    {
        var s = Start(Relaxed());
        using var alice = Register(s.Port, "alice");
        using var bob = Register(s.Port, "bob");
        string k = Blob(74);
        alice.C.SendLine($"KNOCK bob {k}");
        Assert.Equal($"KNOCK alice {k}", bob.C.ReadLine());
        Assert.Equal(0, s.KnockCount);
    }

    [Fact]
    public void Knock_OfflineTarget_IsStoredDeliveredAfterReadyAndThenGone()
    {
        var s = Start(Relaxed());
        using var alice = Register(s.Port, "alice");
        using var carol = Register(s.Port, "carol");
        using var bob = Register(s.Port, "bob");
        bob.C.Dispose();
        Eventually(() => { alice.C.SendLine("USERS"); return alice.C.ReadLine() == "USERLIST 1 carol"; });

        string k1 = Blob(74), k2 = Blob(74), k3 = Blob(74);
        alice.C.SendLine($"KNOCK bob {k1}");
        alice.C.SendLine($"KNOCK bob {k2}");   // newest per (sender, recipient) wins
        Barrier(alice.C);                       // no OFFLINE or ERR for knocks
        carol.C.SendLine($"KNOCK bob {k3}");
        Barrier(carol.C);
        Assert.Equal(2, s.KnockCount);

        using TestClient bob2 = LoginAs(s.Port, bob, out string ready);
        Assert.Equal("READY bob", ready);
        Assert.Equal($"KNOCK alice {k2}", bob2.ReadLine());
        Assert.Equal($"KNOCK carol {k3}", bob2.ReadLine());
        Barrier(bob2);
        Assert.Equal(0, s.KnockCount);

        bob2.Dispose();
        using TestClient bob3 = LoginAs(s.Port, bob, out ready);
        Assert.Equal("READY bob", ready);
        Barrier(bob3); // nothing delivered twice
    }

    [Fact]
    public void Knock_Expires_AfterTheTtl()
    {
        var s = Start(Relaxed(), fakeClock: true);
        using var alice = Register(s.Port, "alice");
        using var bob = Register(s.Port, "bob");
        bob.C.Dispose();
        Eventually(() => { alice.C.SendLine("USERS"); return alice.C.ReadLine() == "USERLIST 0"; });
        alice.C.SendLine("KNOCK bob " + Blob(74));
        Barrier(alice.C);
        Assert.Equal(1, s.KnockCount);
        Advance(7L * 24 * 3600 * 1000 + 1);
        using TestClient bob2 = LoginAs(s.Port, bob, out string ready);
        Assert.Equal("READY bob", ready);
        Barrier(bob2);
        Assert.Equal(0, s.KnockCount);
    }

    [Fact]
    public void Knock_Caps_PerRecipient_Total_AndPerSender()
    {
        var s = Start(new ServerLimits { KnockMaxPerRecipient = 2, KnockMaxTotal = 3, KnockMaxPerSenderPerHour = 2, KnockBurst = 100,
            RegistrationsPerIpPerHour = 100, RegistrationsGlobalPerHour = 100, MaxConnectionsPerIp = 100, PingBurst = 100 }, fakeClock: true);
        using var target = Register(s.Port, "target");
        using var other = Register(s.Port, "other");
        target.C.Dispose(); other.C.Dispose();
        var senders = Enumerable.Range(1, 4).Select(i => Register(s.Port, "s" + i)).ToList();
        try
        {
            Eventually(() => { senders[0].C.SendLine("USERS"); return senders[0].C.ReadLine() == "USERLIST 3 s2 s3 s4"; });
            senders[0].C.SendLine("KNOCK target " + Blob(74));
            senders[1].C.SendLine("KNOCK target " + Blob(74));
            Barrier(senders[0].C); Barrier(senders[1].C);
            senders[2].C.SendLine("KNOCK target " + Blob(74));            // recipient full
            Assert.Equal("ERR limit target", senders[2].C.ReadLine());
            senders[2].C.SendLine("KNOCK other " + Blob(74));             // total now 3
            Barrier(senders[2].C);
            senders[3].C.SendLine("KNOCK other " + Blob(74));             // total cap
            Assert.Equal("ERR limit other", senders[3].C.ReadLine());
            Assert.Equal(3, s.KnockCount);
        }
        finally { foreach (var p in senders) p.Dispose(); }
    }

    [Fact]
    public void Knock_PerSenderHourlyLimit_ResetsAfterAnHour()
    {
        var s = Start(new ServerLimits { KnockMaxPerSenderPerHour = 2, KnockBurst = 100, PingBurst = 100 }, fakeClock: true);
        using var alice = Register(s.Port, "alice");
        using var bob = Register(s.Port, "bob");
        bob.C.Dispose();
        Eventually(() => { alice.C.SendLine("USERS"); return alice.C.ReadLine() == "USERLIST 0"; });
        alice.C.SendLine("KNOCK bob " + Blob(74));
        Barrier(alice.C);
        alice.C.SendLine("KNOCK bob " + Blob(74));
        Barrier(alice.C);
        alice.C.SendLine("KNOCK bob " + Blob(74));
        Assert.Equal("ERR rate", alice.C.ReadLine());
        Advance(3600_000);
        alice.C.SendLine("KNOCK bob " + Blob(74));
        Barrier(alice.C);
    }

    [Fact]
    public void Knock_ToSelfOrUnknownUser_IsAnError()
    {
        var s = Start(Relaxed());
        using var alice = Register(s.Port, "alice");
        alice.C.SendLine("KNOCK alice " + Blob(74));
        Assert.Equal("ERR self", alice.C.ReadLine());
        alice.C.SendLine("KNOCK ghost " + Blob(74));
        Assert.Equal("ERR nouser ghost", alice.C.ReadLine());
        Assert.Equal(0, s.KnockCount);
    }

    // ---- users list ----

    [Fact]
    public void Users_ListsOtherOnlineUsersSorted_AndNotSelf()
    {
        var s = Start(Relaxed());
        using var carol = Register(s.Port, "carol");
        using var alice = Register(s.Port, "alice");
        using var bob = Register(s.Port, "bob");
        alice.C.SendLine("USERS");
        Assert.Equal("USERLIST 2 bob carol", alice.C.ReadLine());
        bob.C.Dispose();
        Eventually(() => { alice.C.SendLine("USERS"); return alice.C.ReadLine() == "USERLIST 1 carol"; });
        using var solo = new Peer { Name = "x" };
    }

    [Fact]
    public void Users_AloneGivesAnEmptyList_AndIsCappedAt100()
    {
        var s = Start(Relaxed());
        using var first = Register(s.Port, "u000");
        first.C.SendLine("USERS");
        Assert.Equal("USERLIST 0", first.C.ReadLine());
        var peers = new List<Peer>();
        try
        {
            for (int i = 1; i <= 104; i++) peers.Add(Register(s.Port, $"u{i:000}"));
            first.C.SendLine("USERS");
            string line = first.C.ReadLine();
            Assert.StartsWith("USERLIST 100 u001 u002", line);
            Assert.True(ClientFrame.TryParse(line, out var ev));
            Assert.Equal(100, ev.Users.Length);
        }
        finally { foreach (var p in peers) p.Dispose(); }
    }

    // ---- per-verb rate limits ----

    [Fact]
    public void Msg_RateLimit_DropsTheLineAndAnswersErrRate()
    {
        var s = Start(Relaxed(msgBurst: 3));
        using var alice = Register(s.Port, "alice");
        using var bob = Register(s.Port, "bob");
        string m = Blob(26 + 256 + 16);
        for (int i = 0; i < 3; i++) alice.C.SendLine($"MSG bob {m}");
        alice.C.SendLine($"MSG bob {m}");
        Assert.Equal("ERR rate", alice.C.ReadLine());
        for (int i = 0; i < 3; i++) Assert.Equal($"MSG alice {m}", bob.C.ReadLine());
        Barrier(bob.C); // the fourth line was dropped, not relayed
    }

    [Fact]
    public void RateErrorsInARow_CloseTheConnection_AndASuccessResetsTheCount()
    {
        var s = Start(new ServerLimits { PingBurst = 1, PingPerSecond = 0.0001, MaxConsecutiveRateErrors = 3 });
        var (c, _) = Hello(s.Port);
        using (c)
        {
            c.SendLine("PING");
            Assert.Equal("PONG", c.ReadLine());
            c.SendLine("PING");
            Assert.Equal("ERR rate", c.ReadLine());
            c.SendLine("PING");
            Assert.Equal("ERR rate", c.ReadLine());
            c.SendLine("PING");
            Assert.Equal("ERR rate", c.ReadLine());
            Assert.Null(c.ReadLine());
        }
    }

    [Fact]
    public void Offer_RateLimits_BurstAndOutstanding()
    {
        var s = Start(new ServerLimits { OfferWindowMax = 2, OfferBurst = 100, PingBurst = 100,
            RegistrationsPerIpPerHour = 100, RegistrationsGlobalPerHour = 100 });
        using var alice = Register(s.Port, "alice");
        using var bob = Register(s.Port, "bob");
        for (int i = 0; i < 2; i++) alice.C.SendLine("OFFER bob " + Blob(156));
        alice.C.SendLine("OFFER bob " + Blob(156));
        Assert.Equal("ERR rate", alice.C.ReadLine());
        Assert.StartsWith("OFFER alice", bob.C.ReadLine());
        Assert.StartsWith("OFFER alice", bob.C.ReadLine());
        Barrier(bob.C);
    }

    [Fact]
    public void Key_AndUsers_AreRateLimited()
    {
        var s = Start(new ServerLimits { KeyBurst = 2, UsersBurst = 1, PingBurst = 100 });
        using var alice = Register(s.Port, "alice");
        alice.C.SendLine("KEY alice"); alice.C.SendLine("KEY alice"); alice.C.SendLine("KEY alice");
        Assert.StartsWith("KEY alice", alice.C.ReadLine());
        Assert.StartsWith("KEY alice", alice.C.ReadLine());
        Assert.Equal("ERR rate", alice.C.ReadLine());
        alice.C.SendLine("USERS"); alice.C.SendLine("USERS");
        Assert.Equal("USERLIST 0", alice.C.ReadLine());
        Assert.Equal("ERR rate", alice.C.ReadLine());
    }

    // ---- misc ----

    [Fact]
    public void ServerAssembly_DoesNotReferenceTheClientCrypto()
    {
        var refs = typeof(ChatServer).Assembly.GetReferencedAssemblies().Select(n => n.Name);
        Assert.DoesNotContain("CipherChatClient", refs);
    }

    [Fact]
    public void ServerLogsNoUserNamesOrBlobs()
    {
        // Run a full session while capturing console output; the server must print nothing identifying.
        TextWriter original = Console.Out;
        StringWriter captured = new();
        Console.SetOut(captured);
        try
        {
            var s = Start(Relaxed());
            using var alice = Register(s.Port, "zebraname");
            using var bob = Register(s.Port, "yakname");
            string offer = Blob(156);
            alice.C.SendLine($"OFFER yakname {offer}");
            Assert.StartsWith("OFFER", bob.C.ReadLine());
            alice.C.SendLine("garbage line");
            Assert.Null(alice.C.ReadLine());
            bob.C.Dispose();
            Thread.Sleep(200);
            string log = captured.ToString();
            Assert.DoesNotContain("zebraname", log);
            Assert.DoesNotContain("yakname", log);
            Assert.DoesNotContain(offer, log);
            Assert.DoesNotContain("127.0.0.1", log);
        }
        finally { Console.SetOut(original); }
    }

    [Fact]
    public void Stop_ClosesAllClients()
    {
        var s = Start();
        using var alice = Register(s.Port, "alice");
        s.Stop();
        Assert.Null(alice.C.ReadLine());
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
            NetworkStream stream = tcp.GetStream();
            byte[] buffer = Encoding.ASCII.GetBytes(line + "\n");
            try { stream.Write(buffer, 0, buffer.Length); stream.Flush(); }
            catch (IOException) { } // the server may already have closed
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
