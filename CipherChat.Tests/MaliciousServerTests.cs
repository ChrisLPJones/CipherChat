using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using CipherChatClient;
using Xunit;

namespace CipherChat.Tests;

// A scripted TcpListener that speaks just enough v4 to log a ChatSession in, then misbehaves on purpose
// (swapped keys, forged/replayed/reordered lines, fake GONE, floods). It also plays the "peer" using the
// library's own handshake code, so the session under test sees a fully valid counterpart.
public sealed class ScriptedServer : IDisposable
{
    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly ConcurrentDictionary<string, byte[]> keys = new();
    private TcpClient client;
    private StreamWriter writer;
    private readonly object writeLock = new();
    public readonly ConcurrentQueue<string> Received = new();
    public string LoginReply = null;    // null = READY <user>; otherwise sent as is (e.g. "ERR nouser x")
    public Func<string, bool> Intercept; // return true if the line was handled
    public byte[] Challenge = RandomNumberGenerator.GetBytes(32);

    public ScriptedServer() { listener.Start(); Port = ((IPEndPoint)listener.LocalEndpoint).Port; Task.Run(Loop); }
    public int Port { get; }
    public void SetKey(string user, byte[] pub) => keys[user] = pub;

    public void Send(string line)
    {
        lock (writeLock) { writer.Write(line + "\n"); writer.Flush(); }
    }

    private async Task Loop()
    {
        try
        {
            client = await listener.AcceptTcpClientAsync();
            var reader = new StreamReader(client.GetStream(), Encoding.ASCII);
            writer = new StreamWriter(client.GetStream(), new ASCIIEncoding()) { NewLine = "\n" };
            while (true)
            {
                string line = await reader.ReadLineAsync();
                if (line == null) return;
                Received.Enqueue(line);
                if (Intercept != null && Intercept(line)) continue;
                string[] t = line.Split(' ');
                switch (t[0])
                {
                    case "HELLO": Send("WELCOME 4 " + Convert.ToBase64String(Challenge)); break;
                    case "LOGIN":
                    case "REGISTER": Send(LoginReply ?? "READY " + t[1]); break;
                    case "KEY":
                        if (keys.TryGetValue(t[1], out byte[] k)) Send($"KEY {t[1]} {Convert.ToBase64String(k)}");
                        else Send($"ERR nouser {t[1]}");
                        break;
                    case "PING": Send("PONG"); break;
                }
            }
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException or SocketException or NullReferenceException) { }
    }

    public string Wait(Func<string, bool> pred, int ms = 5000)
    {
        DateTime end = DateTime.UtcNow.AddMilliseconds(ms);
        while (DateTime.UtcNow < end)
        {
            string hit = Received.FirstOrDefault(pred);
            if (hit != null) return hit;
            Thread.Sleep(10);
        }
        return null;
    }

    public bool Saw(string prefix) => Received.Any(l => l.StartsWith(prefix));

    public void Dispose() { try { client?.Close(); } catch (Exception) { } listener.Stop(); }
}

public class MaliciousServerTests : IDisposable
{
    private const string Pass = "correct horse";
    private readonly TempDir dir = new();
    private readonly List<IDisposable> toDispose = new();

    public void Dispose() { foreach (IDisposable d in toDispose.AsEnumerable().Reverse()) d.Dispose(); dir.Dispose(); }

    private sealed class Fake : IDisposable
    {
        public string Name;
        public IdentityKey Key = IdentityKey.Generate();
        public SecureChannel Channel;
        public void Dispose() { Channel?.Dispose(); Key.Dispose(); }
    }

    private Fake NewFake(string name) { var f = new Fake { Name = name }; toDispose.Add(f); return f; }

    // Logs "alice" in to the scripted server.
    private async Task<(ChatSession Session, Profile Profile, ScriptedServer Server)> Alice(ChatSessionOptions opts = null, string profileDir = "p")
    {
        var srv = new ScriptedServer();
        toDispose.Add(srv);
        Profile p = new ProfileStore(Path.Combine(dir.Path, profileDir)).Create("alice", "localhost", srv.Port, Pass);
        toDispose.Add(p);
        var s = new ChatSession("localhost", srv.Port, "alice", p, opts);
        toDispose.Add(s);
        await s.ConnectAsync();
        Assert.Equal(AuthResult.Ok, await s.AuthenticateAsync(false));
        return (s, p, srv);
    }

    // Plays bob: answers alice's OFFER with a valid ACCEPT, consumes CONFIRM; returns bob's channel.
    private async Task<SecureChannel> Establish(ChatSession s, Profile alice, ScriptedServer srv, Fake bob)
    {
        srv.SetKey(bob.Name, bob.Key.PublicKey);
        var (chat, err) = await s.StartChatAsync(bob.Name);
        Assert.Null(err);
        string offerLine = srv.Wait(l => l.StartsWith($"OFFER {bob.Name} "));
        Assert.NotNull(offerLine);
        byte[] offer = ClientFrame.DecodeBlob(offerLine.Split(' ')[2]);
        Assert.Equal(HandshakeStatus.Ok, Handshake.Responder.TryReceiveOffer(bob.Key, bob.Name, "alice", alice.Identity.PublicKey, offer, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), new SidCache(), out var resp));
        srv.Send($"ACCEPT {bob.Name} {Convert.ToBase64String(resp.Accept())}");
        string confirmLine = srv.Wait(l => l.StartsWith($"CONFIRM {bob.Name} "));
        Assert.NotNull(confirmLine);
        Assert.Equal(HandshakeStatus.Ok, resp.ProcessConfirm(ClientFrame.DecodeBlob(confirmLine.Split(' ')[2]), out var ch));
        Wait.For(() => chat.Phase == ChatPhase.Active, "alice active");
        bob.Channel = ch;
        return ch;
    }

    private static string Msg(string from, byte[] sealedMsg) => $"MSG {from} {Convert.ToBase64String(sealedMsg)}";

    [Theory]
    [InlineData("ERR nouser alice", AuthResult.UnknownUser)]
    [InlineData("ERR auth", AuthResult.Rejected)]
    [InlineData("ERR taken alice", AuthResult.NameTaken)]
    [InlineData("ERR rate", AuthResult.RateLimited)]
    [InlineData("ERR full", AuthResult.ServerFull)]
    [InlineData("ERR version", AuthResult.VersionMismatch)]
    [InlineData("PONG", AuthResult.Failed)]
    public async Task LoginErrors_AreDistinguished(string reply, AuthResult expected)
    {
        var srv = new ScriptedServer { LoginReply = reply };
        toDispose.Add(srv);
        Profile p = new ProfileStore(Path.Combine(dir.Path, "p")).Create("alice", "localhost", srv.Port, Pass);
        toDispose.Add(p);
        var s = new ChatSession("localhost", srv.Port, "alice", p);
        toDispose.Add(s);
        await s.ConnectAsync();
        Assert.Equal(expected, await s.AuthenticateAsync(false));
    }

    [Fact]
    public async Task ConnectAsync_RejectsAV3ServerAndGarbage()
    {
        var srv = new ScriptedServer();
        toDispose.Add(srv);
        Profile p = new ProfileStore(Path.Combine(dir.Path, "p")).Create("alice", "localhost", srv.Port, Pass);
        toDispose.Add(p);
        srv.Intercept = l => { if (l.StartsWith("HELLO")) { srv.Send("ERR version"); return true; } return false; };
        var s = new ChatSession("localhost", srv.Port, "alice", p);
        toDispose.Add(s);
        var ex = await Assert.ThrowsAsync<IOException>(() => s.ConnectAsync());
        Assert.Contains("upgrade", ex.Message);
    }

    [Fact]
    public async Task SwappedKeyOnLaterContact_BlocksTheChat_AndNoOfferIsSent()
    {
        var (s, p, srv) = await Alice();
        Fake bob = NewFake("bob");
        p.Peers.Pin("bob", bob.Key.PublicKey, 1);            // pinned earlier
        using IdentityKey evil = IdentityKey.Generate();
        srv.SetKey("bob", evil.PublicKey);                   // the server now lies
        var (chat, err) = await s.StartChatAsync("bob");
        Assert.Null(chat);
        Assert.Contains("identity key changed", err);
        Assert.Contains(s.HomeLines, l => l.Contains("WARNING") && l.Contains("/verify bob"));
        Thread.Sleep(200);
        Assert.False(srv.Saw("OFFER"));
        Assert.True(s.GetPeerStatus("bob").KeyChanged);
        Assert.Equal(bob.Key.PublicKey, p.Peers.GetKey("bob")); // pin untouched
    }

    [Fact]
    public async Task ForgedOrReplayedOffers_AreDropped_ValidOneShowsARequest()
    {
        var (s, p, srv) = await Alice();
        Fake bob = NewFake("bob");
        srv.SetKey("bob", bob.Key.PublicKey);
        long now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        using var init = Handshake.Initiator.Create(bob.Key, "bob", "alice", p.Identity.PublicKey, false, now);

        byte[] forged = (byte[])init.Offer.Clone();
        forged[120] ^= 1;
        srv.Send($"OFFER bob {Convert.ToBase64String(forged)}");
        Wait.For(() => s.HomeLines.Any(l => l.Contains("invalid chat request claiming to be from bob")), "warning");
        Assert.Empty(s.Requests);

        // signed by another identity but claiming to be bob
        Fake mallory = NewFake("mallory");
        using var evil = Handshake.Initiator.Create(mallory.Key, "bob", "alice", p.Identity.PublicKey, false, now);
        srv.Send($"OFFER bob {Convert.ToBase64String(evil.Offer)}");
        Thread.Sleep(300);
        Assert.Empty(s.Requests);

        // addressed to someone else
        using var wrongTarget = Handshake.Initiator.Create(bob.Key, "bob", "carol", p.Identity.PublicKey, false, now);
        srv.Send($"OFFER bob {Convert.ToBase64String(wrongTarget.Offer)}");
        Thread.Sleep(300);
        Assert.Empty(s.Requests);

        // the genuine offer works once; a replay of the same offer does not create a second request
        srv.Send($"OFFER bob {Convert.ToBase64String(init.Offer)}");
        Wait.For(() => s.Requests.Count == 1, "valid offer");
        Assert.Null(s.Decline("bob"));
        srv.Send($"OFFER bob {Convert.ToBase64String(init.Offer)}");
        Thread.Sleep(300);
        Assert.Empty(s.Requests);
        Assert.False(srv.Saw("ACCEPT"));          // nothing is sent without consent
    }

    [Fact]
    public async Task StaleOfferTimestamp_IsIgnoredWithAClockHint()
    {
        var (s, p, srv) = await Alice();
        Fake bob = NewFake("bob");
        srv.SetKey("bob", bob.Key.PublicKey);
        long old = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - 11 * 60 * 1000;
        using var init = Handshake.Initiator.Create(bob.Key, "bob", "alice", p.Identity.PublicKey, false, old);
        srv.Send($"OFFER bob {Convert.ToBase64String(init.Offer)}");
        Wait.For(() => s.HomeLines.Any(l => l.Contains("wrong timestamp")), "clock hint");
        Assert.Empty(s.Requests);
    }

    [Fact]
    public async Task ReplayedReorderedDuplicatedAndWithheldMessages_AreHandled()
    {
        var (s, p, srv) = await Alice();
        Fake bob = NewFake("bob");
        SecureChannel bobCh = await Establish(s, p, srv, bob);
        PeerChat chat = s.FindChat("bob");

        byte[] m0 = bobCh.SealText("zero"), m1 = bobCh.SealText("one"), m2 = bobCh.SealText("two"), m3 = bobCh.SealText("three");
        srv.Send(Msg("bob", m0));
        Wait.For(() => Wait.Has(chat, "bob: zero"), "m0");
        srv.Send(Msg("bob", m0));                                  // duplicate
        Wait.For(() => Wait.Has(chat, "replayed or duplicated"), "replay warning");
        srv.Send(Msg("bob", m2));                                  // m1 withheld
        Wait.For(() => Wait.Has(chat, "bob: two") && Wait.Has(chat, "1 message(s) from bob were lost or withheld"), "loss notice");
        srv.Send(Msg("bob", m1));                                  // reordered: late m1 is dropped
        srv.Send(Msg("bob", m3));
        Wait.For(() => Wait.Has(chat, "bob: three"), "m3");
        lock (chat.Messages) Assert.DoesNotContain(chat.Messages, m => m.Contains("bob: one"));

        // injected garbage with the right session id is dropped, state survives
        byte[] junk = (byte[])bobCh.SealText("four").Clone();
        junk[junk.Length - 3] ^= 1;
        srv.Send(Msg("bob", junk));
        byte[] m5 = bobCh.SealText("five");
        srv.Send(Msg("bob", m5));
        Wait.For(() => Wait.Has(chat, "bob: five"), "m5 after junk");
        Assert.Equal(ChatPhase.Active, chat.Phase);
    }

    [Fact]
    public async Task MessagesFromTheWrongUser_OrUnknownSession_AreDropped()
    {
        var (s, p, srv) = await Alice();
        Fake bob = NewFake("bob"), carol = NewFake("carol");
        SecureChannel bobCh = await Establish(s, p, srv, bob);
        PeerChat chat = s.FindChat("bob");
        // the server relays bob's ciphertext as if carol sent it: no chat with carol, and the AAD names differ anyway
        srv.Send(Msg("carol", bobCh.SealText("misattributed")));
        Thread.Sleep(300);
        lock (chat.Messages) Assert.DoesNotContain(chat.Messages, m => m.Contains("misattributed"));
        Assert.Null(s.FindChat("carol"));
    }

    [Fact]
    public async Task FakeGone_EndsTheSessionCleanly()
    {
        var (s, p, srv) = await Alice();
        Fake bob = NewFake("bob");
        await Establish(s, p, srv, bob);
        PeerChat chat = s.FindChat("bob");
        srv.Send("GONE bob");
        Wait.For(() => chat.Phase == ChatPhase.Ended, "ended by GONE");
        Assert.NotNull(s.Send(chat, "anyone there?"));
        Assert.False(s.IsClosed);
    }

    [Fact]
    public async Task UnsolicitedAcceptConfirmAndMsg_AreIgnored()
    {
        var (s, p, srv) = await Alice();
        Fake bob = NewFake("bob");
        srv.SetKey("bob", bob.Key.PublicKey);
        using var other = Handshake.Initiator.Create(bob.Key, "bob", "alice", p.Identity.PublicKey, false, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
        srv.Send($"ACCEPT bob {Convert.ToBase64String(new byte[179])}");
        srv.Send($"CONFIRM bob {Convert.ToBase64String(new byte[50])}");
        srv.Send(Msg("bob", new byte[26 + 256 + 16]));
        Thread.Sleep(300);
        Assert.Empty(s.Chats);
        Assert.Empty(s.HomeLines);

        // A pending offer only accepts the matching, correctly signed ACCEPT (a random one is ignored).
        var (chat, _) = await s.StartChatAsync("bob");
        Assert.Equal(ChatPhase.Offering, chat.Phase);
        srv.Send($"ACCEPT bob {Convert.ToBase64String(RandomNumberGenerator.GetBytes(179))}");
        Thread.Sleep(300);
        Assert.Equal(ChatPhase.Offering, chat.Phase);
        Assert.False(srv.Saw("CONFIRM"));
    }

    [Fact]
    public async Task OfflineAnswer_TurnsTheOfferIntoASignedKnock()
    {
        var (s, p, srv) = await Alice();
        Fake bob = NewFake("bob");
        srv.SetKey("bob", bob.Key.PublicKey);
        srv.Intercept = l => { if (l.StartsWith("OFFER")) { srv.Send("OFFLINE bob"); return false; } return false; };
        var (chat, _) = await s.StartChatAsync("bob");
        string knock = srv.Wait(l => l.StartsWith("KNOCK bob "));
        Assert.NotNull(knock);
        byte[] raw = ClientFrame.DecodeBlob(knock.Split(' ')[2]);
        Assert.Equal(HandshakeStatus.Ok, Handshake.VerifyKnock(raw, "alice", p.Identity.PublicKey, "bob", bob.Key.PublicKey, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), out _));
        Wait.For(() => chat.Phase == ChatPhase.Ended, "offer ended");
    }

    [Fact]
    public async Task ForgedKnock_IsIgnored_ValidKnockIsShown()
    {
        var (s, p, srv) = await Alice();
        Fake bob = NewFake("bob"), mallory = NewFake("mallory");
        srv.SetKey("bob", bob.Key.PublicKey);
        long now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        byte[] forged = Handshake.BuildKnock(mallory.Key, "bob", "alice", p.Identity.PublicKey, now); // signed by the wrong key
        srv.Send($"KNOCK bob {Convert.ToBase64String(forged)}");
        Wait.For(() => s.HomeLines.Any(l => l.Contains("forged knock")), "forged knock warning");
        Assert.DoesNotContain(s.HomeLines, l => l.Contains("tried to reach you"));
        srv.Send($"KNOCK bob {Convert.ToBase64String(Handshake.BuildKnock(bob.Key, "bob", "alice", p.Identity.PublicKey, now))}");
        Wait.For(() => s.HomeLines.Any(l => l.Contains("bob tried to reach you")), "valid knock");
    }

    [Fact]
    public async Task PendingRequestCap_AndNewestOfferPerUserWins()
    {
        var (s, p, srv) = await Alice();
        long now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var fakes = Enumerable.Range(0, ProtocolLimits.MaxPendingRequests + 2).Select(i => NewFake($"u{i:00}")).ToList();
        foreach (Fake f in fakes) srv.SetKey(f.Name, f.Key.PublicKey);
        foreach (Fake f in fakes.Take(ProtocolLimits.MaxPendingRequests))
        {
            using var init = Handshake.Initiator.Create(f.Key, f.Name, "alice", p.Identity.PublicKey, false, now);
            srv.Send($"OFFER {f.Name} {Convert.ToBase64String(init.Offer)}");
        }
        Wait.For(() => s.Requests.Count == ProtocolLimits.MaxPendingRequests, "20 requests");

        Fake extra = fakes[ProtocolLimits.MaxPendingRequests];
        using (var init = Handshake.Initiator.Create(extra.Key, extra.Name, "alice", p.Identity.PublicKey, false, now))
            srv.Send($"OFFER {extra.Name} {Convert.ToBase64String(init.Offer)}");
        Wait.For(() => s.HomeLines.Any(l => l.Contains("Too many pending")), "cap warning");
        Assert.Equal(ProtocolLimits.MaxPendingRequests, s.Requests.Count);
        Assert.DoesNotContain(s.Requests, r => r.User == extra.Name);

        // a second offer from an existing requester replaces the older one instead of adding
        Fake first = fakes[0];
        long ts1 = s.Requests.First(r => r.User == first.Name).ReceivedAtMs;
        Thread.Sleep(5);
        using (var again = Handshake.Initiator.Create(first.Key, first.Name, "alice", p.Identity.PublicKey, false, now + 1))
            srv.Send($"OFFER {first.Name} {Convert.ToBase64String(again.Offer)}");
        Wait.For(() => s.Requests.First(r => r.User == first.Name).ReceivedAtMs > ts1, "replaced");
        Assert.Equal(ProtocolLimits.MaxPendingRequests, s.Requests.Count);
    }

    [Fact]
    public async Task ChatCap_StopsTheSeventeenthChat()
    {
        var (s, p, srv) = await Alice();
        var fakes = Enumerable.Range(0, ProtocolLimits.MaxChats + 1).Select(i => NewFake($"u{i:00}")).ToList();
        foreach (Fake f in fakes) srv.SetKey(f.Name, f.Key.PublicKey);
        foreach (Fake f in fakes.Take(ProtocolLimits.MaxChats))
            Assert.Null((await s.StartChatAsync(f.Name)).Error);
        var (chat, err) = await s.StartChatAsync(fakes[ProtocolLimits.MaxChats].Name);
        Assert.Null(chat);
        Assert.Contains("at most 16", err);
        // ending one frees a slot
        Assert.Null(s.End(s.FindChat(fakes[0].Name)));
        Assert.Null((await s.StartChatAsync(fakes[ProtocolLimits.MaxChats].Name)).Error);
    }

    [Fact]
    public async Task Garbage_OverLengthAndFloods_DoNotBreakTheSession()
    {
        var (s, p, srv) = await Alice();
        string status = null;
        s.Status += t => status = t;
        srv.Send("this is not v4");
        srv.Send("MSG bob short");
        srv.Send("OFFER BOB " + new string('A', 208));
        for (int i = 0; i < 30; i++) srv.Send("ERR rate");
        Wait.For(() => status != null, "status");
        // still alive: a KEY lookup works
        Fake bob = NewFake("bob");
        srv.SetKey("bob", bob.Key.PublicKey);
        var (state, _) = await s.ResolvePeerAsync("bob");
        Assert.Equal(PeerKeyState.FirstContact, state);
        Assert.False(s.IsClosed);
    }

    [Fact]
    public async Task OverLengthLine_StopsTheSession()
    {
        var (s, p, srv) = await Alice();
        bool disconnected = false;
        s.Disconnected += () => disconnected = true;
        srv.Send(new string('A', ProtocolLimits.MaxLineChars + 100));
        Wait.For(() => disconnected, "disconnect");
        Assert.True(s.IsClosed);
    }

    [Fact]
    public async Task KeyReply_WithAnInvalidPoint_IsRejected()
    {
        var (s, p, srv) = await Alice();
        byte[] bad = new byte[65]; bad[0] = 4; bad[64] = 7;
        srv.SetKey("bob", bad);
        var (state, _) = await s.ResolvePeerAsync("bob");
        Assert.Equal(PeerKeyState.Failed, state);
        Assert.False(s.GetPeerStatus("bob").Pinned);
    }

    [Fact]
    public async Task ServerClose_EndsChatsAndRaisesDisconnected()
    {
        var (s, p, srv) = await Alice();
        Fake bob = NewFake("bob");
        await Establish(s, p, srv, bob);
        PeerChat chat = s.FindChat("bob");
        srv.Dispose();
        Wait.For(() => s.IsClosed && chat.Phase == ChatPhase.Ended, "closed");
    }

    [Fact]
    public async Task OwnKeyMaterial_NeverAppearsOnTheWire()
    {
        var (s, p, srv) = await Alice();
        Fake bob = NewFake("bob");
        SecureChannel ch = await Establish(s, p, srv, bob);
        s.Send(s.FindChat("bob"), "a secret message about zebras");
        srv.Wait(l => l.StartsWith("MSG bob "));
        byte[] d = p.Identity.ExportPrivateScalar();
        string dB64 = Convert.ToBase64String(d);
        string all = string.Join("\n", srv.Received);
        Assert.DoesNotContain(dB64, all);
        Assert.DoesNotContain("zebras", all);
        Assert.DoesNotContain(Convert.ToBase64String(Encoding.UTF8.GetBytes("zebras")), all);
        CryptographicOperations.ZeroMemory(d);
    }
}
