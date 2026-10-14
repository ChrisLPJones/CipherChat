using System.Security.Cryptography;
using CipherChatClient;
using CipherChatServer;
using Xunit;

namespace CipherChat.Tests;

public static class Wait
{
    public static void For(Func<bool> cond, string what = "condition", int ms = 8000)
    {
        DateTime end = DateTime.UtcNow.AddMilliseconds(ms);
        while (DateTime.UtcNow < end) { if (cond()) return; Thread.Sleep(20); }
        Assert.True(cond(), "Timed out waiting for " + what);
    }

    // Asserts that cond stays false for a short while (negative checks).
    public static void Never(Func<bool> cond, string what, int ms = 400)
    {
        DateTime end = DateTime.UtcNow.AddMilliseconds(ms);
        while (DateTime.UtcNow < end) { Assert.False(cond(), "Unexpected: " + what); Thread.Sleep(20); }
    }

    public static bool Has(PeerChat c, string text) { lock (c.Messages) return c.Messages.Any(m => m.Contains(text)); }
}

// ChatSession end to end over the real server (ephemeral port, in-memory accounts, throwaway profile dirs).
public class ChatSessionTests : IDisposable
{
    private const string Pass = "correct horse";
    private readonly TempDir dir = new();
    private readonly List<IDisposable> toDispose = new();
    private ChatServer server;

    public void Dispose()
    {
        foreach (IDisposable d in toDispose.AsEnumerable().Reverse()) d.Dispose();
        server?.Stop();
        dir.Dispose();
    }

    private ChatServer Server()
    {
        server = new ChatServer("localhost", 0, new ChatServerOptions
        {
            Limits = new ServerLimits
            {
                RegistrationsPerIpPerHour = 1000, RegistrationsGlobalPerHour = 1000, MaxConnectionsPerIp = 1000,
                KeyBurst = 1000, OfferBurst = 1000, OfferWindowMax = 1000, KnockBurst = 1000, KnockMaxPerSenderPerHour = 1000,
            },
        });
        server.Start();
        return server;
    }

    private sealed class User : IDisposable
    {
        public string Name;
        public Profile Profile;
        public ChatSession Session;
        public void Dispose() { Session?.Dispose(); Profile?.Dispose(); }
    }

    private async Task<User> Join(string name, ChatSessionOptions opts = null)
    {
        ProfileStore store = new(Path.Combine(dir.Path, "p-" + name + server.Port));
        Profile p = store.Create(name, "localhost", server.Port, Pass);
        var u = new User { Name = name, Profile = p };
        u.Session = new ChatSession("localhost", server.Port, name, p, opts);
        toDispose.Add(u);
        await u.Session.ConnectAsync();
        Assert.Equal(AuthResult.Ok, await u.Session.AuthenticateAsync(register: true));
        return u;
    }

    private async Task<(User, User)> Chatting(string a = "alice", string b = "bob")
    {
        Server();
        User ua = await Join(a), ub = await Join(b);
        var (chat, err) = await ua.Session.StartChatAsync(b);
        Assert.Null(err);
        Wait.For(() => ub.Session.Requests.Count == 1, "request");
        Assert.Null(ub.Session.Accept(a).Error);
        Wait.For(() => chat.Phase == ChatPhase.Active && ub.Session.FindChat(a)?.Phase == ChatPhase.Active, "both active");
        return (ua, ub);
    }

    [Fact]
    public async Task Chat_RequestAcceptMessagesBothWaysEndAndGone()
    {
        var (alice, bob) = await Chatting();
        PeerChat ca = alice.Session.FindChat("bob"), cb = bob.Session.FindChat("alice");
        Assert.Null(alice.Session.Send(ca, "hello bob"));
        Wait.For(() => Wait.Has(cb, "alice: hello bob"), "bob receives");
        Assert.Null(bob.Session.Send(cb, "hi alice"));
        Wait.For(() => Wait.Has(ca, "bob: hi alice"), "alice receives");
        Assert.True(Wait.Has(ca, "alice: hello bob")); // local echo

        Assert.Null(alice.Session.End(ca));
        Assert.Equal(ChatPhase.Ended, ca.Phase);
        Wait.For(() => cb.Phase == ChatPhase.Ended && Wait.Has(cb, "alice ended the chat"), "peer end");
        Assert.NotNull(bob.Session.Send(cb, "too late"));
        Assert.NotNull(alice.Session.End(ca));
    }

    [Fact]
    public async Task Disconnect_EndsTheChatViaGone()
    {
        var (alice, bob) = await Chatting();
        PeerChat cb = bob.Session.FindChat("alice");
        alice.Session.Dispose();
        Wait.For(() => cb.Phase == ChatPhase.Ended, "chat ended by GONE");
        Assert.True(Wait.Has(cb, "alice disconnected"));
    }

    [Fact]
    public async Task NothingIsDelivered_BeforeTheRecipientAccepts()
    {
        Server();
        User alice = await Join("alice"), bob = await Join("bob");
        var (chat, _) = await alice.Session.StartChatAsync("bob");
        Wait.For(() => bob.Session.Requests.Count == 1, "request");
        Assert.NotNull(alice.Session.Send(chat, "sneaky"));            // not established yet
        Assert.Equal(ChatPhase.Offering, chat.Phase);
        Wait.Never(() => bob.Session.FindChat("alice") != null, "bob has a chat before accepting");
        Assert.Equal("alice", bob.Session.Requests[0].User);
        Assert.Contains(bob.Session.HomeLines, l => l.Contains("alice wants to chat (unverified key)"));
    }

    [Fact]
    public async Task Decline_IsSilent_AndTheOfferTimesOut()
    {
        Server();
        var opts = new ChatSessionOptions { OfferTimeoutMs = 600 };
        User alice = await Join("alice", opts), bob = await Join("bob");
        var (chat, _) = await alice.Session.StartChatAsync("bob");
        Wait.For(() => bob.Session.Requests.Count == 1, "request");
        Assert.Null(bob.Session.Decline("alice"));
        Assert.Empty(bob.Session.Requests);
        Wait.For(() => chat.Phase == ChatPhase.Ended && Wait.Has(chat, "did not answer"), "offer timeout");
        Assert.NotNull(bob.Session.Accept("alice").Error);
    }

    [Fact]
    public async Task Block_DropsOffersAndKnocks_AndUnblockRestores()
    {
        Server();
        User alice = await Join("alice"), bob = await Join("bob");
        Assert.Null(bob.Session.Block("alice"));
        Assert.True(bob.Session.GetPeerStatus("alice").Blocked);
        var (chat, err) = await alice.Session.StartChatAsync("bob");
        Assert.Null(err);
        Wait.Never(() => bob.Session.Requests.Count > 0 || bob.Session.HomeLines.Count > 0, "blocked offer visible");

        // bob blocked alice: alice cannot be started from bob's side either
        var (c2, err2) = await bob.Session.StartChatAsync("alice");
        Assert.Null(c2);
        Assert.Contains("blocked", err2);

        // knock from a blocked user is dropped: bob goes offline, alice knocks, bob returns
        Assert.Null(bob.Session.Unblock("alice"));
        Assert.NotNull(bob.Session.Unblock("alice"));
        Assert.Null(bob.Session.Block("alice"));
        bob.Session.Dispose();
        Wait.For(() => { var l = alice.Session.ListUsersAsync().Result; return l != null && l.Count == 0; }, "bob offline");
        Wait.For(() => chat.Phase == ChatPhase.Ended, "GONE ends the unanswered offer");
        var (c3, _) = await alice.Session.StartChatAsync("bob");
        Wait.For(() => c3.Phase == ChatPhase.Ended && Wait.Has(c3, "offline"), "knock left");

        var bob2 = new ChatSession("localhost", server.Port, "bob", bob.Profile);
        toDispose.Add(bob2);
        await bob2.ConnectAsync();
        Assert.Equal(AuthResult.Ok, await bob2.AuthenticateAsync(false));
        Wait.Never(() => bob2.HomeLines.Count > 0, "knock from a blocked user shown");

        bob2.Unblock("alice");
        Assert.Null((await alice.Session.StartChatAsync("bob")).Error);
        Wait.For(() => bob2.Requests.Count == 1, "request after unblock");
    }

    [Fact]
    public async Task SimultaneousOffers_ResolveToOneSession()
    {
        Server();
        User alice = await Join("alice"), bob = await Join("bob");
        var t1 = alice.Session.StartChatAsync("bob");
        var t2 = bob.Session.StartChatAsync("alice");
        await Task.WhenAll(t1, t2);
        PeerChat ca = alice.Session.FindChat("bob"), cb = bob.Session.FindChat("alice");
        Wait.For(() => ca.Phase == ChatPhase.Active && cb.Phase == ChatPhase.Active, "one session for both");
        string diag = string.Join(" | ", new[] { alice, bob }.Select(u => u.Name + ": chats=" + string.Join(",", u.Session.Chats.Select(c => c.Peer + ":" + c.Phase)) + " reqs=" + u.Session.Requests.Count + " lines=" + string.Join(";", u.Session.FindChat(u.Name == "alice" ? "bob" : "alice").Messages)));
        Assert.True(alice.Session.Requests.Count == 0 && bob.Session.Requests.Count == 0, diag);
        Assert.Null(alice.Session.Send(ca, "ping"));
        Wait.For(() => Wait.Has(cb, "alice: ping"), "message over the merged session");
        Assert.Null(bob.Session.Send(cb, "pong"));
        Wait.For(() => Wait.Has(ca, "bob: pong"), "reply");
    }

    [Fact]
    public async Task Knock_ToOfflineUser_IsShownAfterTheNextLogin()
    {
        Server();
        User alice = await Join("alice"), bob = await Join("bob");
        bob.Session.Dispose();
        Wait.For(() => { var l = alice.Session.ListUsersAsync().Result; return l != null && l.Count == 0; }, "bob offline");

        var (chat, err) = await alice.Session.StartChatAsync("bob");
        Assert.Null(err);
        Wait.For(() => chat.Phase == ChatPhase.Ended && Wait.Has(chat, "A signed knock was left"), "knock sent");

        var bob2 = new ChatSession("localhost", server.Port, "bob", bob.Profile);
        toDispose.Add(bob2);
        await bob2.ConnectAsync();
        Assert.Equal(AuthResult.Ok, await bob2.AuthenticateAsync(false));
        Wait.For(() => bob2.HomeLines.Any(l => l.Contains("alice tried to reach you") && l.Contains("/chat alice")), "knock shown");
    }

    [Fact]
    public async Task Login_Results_AreDistinguished()
    {
        Server();
        User alice = await Join("alice");

        // unknown user
        ProfileStore store = new(Path.Combine(dir.Path, "other"));
        using Profile p = store.Create("ghost", "localhost", server.Port, Pass);
        using var s1 = new ChatSession("localhost", server.Port, "ghost", p);
        await s1.ConnectAsync();
        Assert.Equal(AuthResult.UnknownUser, await s1.AuthenticateAsync(false));

        // known name, other key
        using Profile p2 = store.Create("alice", "localhost", server.Port, Pass);
        using var s2 = new ChatSession("localhost", server.Port, "alice", p2);
        await s2.ConnectAsync();
        Assert.Equal(AuthResult.Rejected, await s2.AuthenticateAsync(false));

        // register a taken name with another key
        using var s3 = new ChatSession("localhost", server.Port, "alice", p2);
        await s3.ConnectAsync();
        Assert.Equal(AuthResult.NameTaken, await s3.AuthenticateAsync(true));
    }

    [Fact]
    public async Task Users_ListsOthersOnline()
    {
        Server();
        User alice = await Join("alice"), bob = await Join("bob"), carol = await Join("carol");
        IReadOnlyList<string> list = await alice.Session.ListUsersAsync();
        Assert.Equal(new[] { "bob", "carol" }, list);
    }

    [Fact]
    public async Task KeyChange_BlocksChatsUntilVerify_AndSafetyNumbersMatch()
    {
        Server();
        User alice = await Join("alice"), bob = await Join("bob");

        // Both sides compute the same number.
        VerifyInfo va = await alice.Session.BeginVerifyAsync("bob");
        VerifyInfo vb = await bob.Session.BeginVerifyAsync("alice");
        Assert.Null(va.Error);
        Assert.Equal(va.SafetyNumber, vb.SafetyNumber);
        Assert.False(va.KeyChanged);
        Assert.Null(alice.Session.FinishVerify("bob", true));
        Assert.True(alice.Session.GetPeerStatus("bob").Verified);

        // Alice's pin for bob no longer matches what the server serves (simulated key change).
        using IdentityKey other = IdentityKey.Generate();
        alice.Profile.Peers.Pin("bob", other.PublicKey, 1, replace: true);
        Assert.False(alice.Session.GetPeerStatus("bob").Verified);

        var (chat, err) = await alice.Session.StartChatAsync("bob");
        Assert.Null(chat);
        Assert.Contains("identity key changed", err);
        Assert.True(alice.Session.GetPeerStatus("bob").KeyChanged);
        Assert.Contains(alice.Session.HomeLines, l => l.Contains("WARNING") && l.Contains("/verify bob"));
        Wait.Never(() => bob.Session.Requests.Count > 0, "an offer reached bob despite the key change");

        // Answering "no" keeps the block; answering "yes" re-pins and verifies.
        VerifyInfo changed = await alice.Session.BeginVerifyAsync("bob");
        Assert.True(changed.KeyChanged);
        Assert.Equal(va.SafetyNumber, changed.SafetyNumber); // number of bob's real (server) key
        Assert.Contains("stays blocked", alice.Session.FinishVerify("bob", false));
        Assert.NotNull((await alice.Session.StartChatAsync("bob")).Error);

        await alice.Session.BeginVerifyAsync("bob");
        Assert.Null(alice.Session.FinishVerify("bob", true));
        Assert.False(alice.Session.GetPeerStatus("bob").KeyChanged);
        Assert.Null((await alice.Session.StartChatAsync("bob")).Error);
        Wait.For(() => bob.Session.Requests.Count == 1, "offer after verify");
    }

    [Fact]
    public async Task IncomingOffer_FromAChangedKey_IsBlockedWithAWarning()
    {
        Server();
        User alice = await Join("alice"), bob = await Join("bob");
        using IdentityKey other = IdentityKey.Generate();
        bob.Profile.Peers.Pin("alice", other.PublicKey, 1);   // bob pinned a different key for alice
        await alice.Session.StartChatAsync("bob");
        Wait.For(() => bob.Session.HomeLines.Any(l => l.Contains("alice's identity key changed")), "warning");
        Assert.Empty(bob.Session.Requests);
        Assert.NotNull(bob.Session.Accept("alice").Error);
    }

    [Fact]
    public async Task Pinning_FirstContactPins_AndStartChatErrors()
    {
        Server();
        User alice = await Join("alice");
        Assert.False(alice.Session.GetPeerStatus("bob").Pinned);
        var (c0, e0) = await alice.Session.StartChatAsync("nobody");
        Assert.Null(c0);
        Assert.Contains("no user", e0);
        Assert.Contains("yourself", (await alice.Session.StartChatAsync("alice")).Error);
        Assert.Contains("Invalid", (await alice.Session.StartChatAsync("Bad Name")).Error);
        User bob = await Join("bob");
        await alice.Session.StartChatAsync("bob");
        Assert.True(alice.Session.GetPeerStatus("bob").Pinned);
        Assert.False(alice.Session.GetPeerStatus("bob").Verified);
        Assert.Equal(bob.Profile.Identity.PublicKey, alice.Profile.Peers.GetKey("bob"));
    }

    [Fact]
    public async Task ChatCommand_OnAPendingRequest_ActsAsAccept()
    {
        Server();
        User alice = await Join("alice"), bob = await Join("bob");
        await alice.Session.StartChatAsync("bob");
        Wait.For(() => bob.Session.Requests.Count == 1, "request");
        var (chat, err) = await bob.Session.StartChatAsync("alice");
        Assert.Null(err);
        Wait.For(() => chat.Phase == ChatPhase.Active, "active");
        // starting again returns the same chat
        Assert.Same(chat, (await bob.Session.StartChatAsync("alice")).Chat);
    }

    [Fact]
    public async Task LongAndOddMessages_RoundTrip_AndDisplayIsSanitised()
    {
        var (alice, bob) = await Chatting();
        PeerChat ca = alice.Session.FindChat("bob"), cb = bob.Session.FindChat("alice");
        string longText = new('€', CipherChatClient.ProtocolLimits.MaxMessageChars);
        Assert.Null(alice.Session.Send(ca, longText));
        Wait.For(() => Wait.Has(cb, longText), "2000 euro signs");
        Assert.Contains("too long", alice.Session.Send(ca, new string('x', CipherChatClient.ProtocolLimits.MaxMessageChars + 1)));
        Assert.Null(alice.Session.Send(ca, "tricky \u001b[2J‮ text"));
        Wait.For(() => Wait.Has(cb, "alice: tricky [2J text"), "sanitised on receive");
    }

    [Fact]
    public async Task UnreadCounts_SkipTheActiveChat()
    {
        var (alice, bob) = await Chatting();
        PeerChat ca = alice.Session.FindChat("bob"), cb = bob.Session.FindChat("alice");
        bob.Session.Active = cb;
        alice.Session.Send(ca, "one");
        Wait.For(() => Wait.Has(cb, "one"), "msg");
        Assert.Equal(0, cb.Unread);
        bob.Session.Active = null;
        alice.Session.Send(ca, "two");
        Wait.For(() => cb.Unread == 1, "unread");
    }
}
