using CipherChatClient;
using CipherChatServer;
using Xunit;

namespace CipherChat.Tests;

// End-to-end through real ChatSession instances against an in-process server (ephemeral port, no stored data).
public class ChatSessionTests : IDisposable
{
    private readonly ChatServer server = new("localhost", 0);
    private readonly List<ChatSession> sessions = [];

    public ChatSessionTests() { server.Start(); }

    public void Dispose()
    {
        foreach (var s in sessions) s.Dispose();
        server.Stop();
    }

    private async Task<ChatSession> Connect(string user, string loginKey)
    {
        var s = new ChatSession("localhost", server.Port, user, loginKey);
        sessions.Add(s);
        await s.ConnectAsync();
        return s;
    }

    private static bool WaitFor(Func<bool> condition, int ms = 15000)
    {
        var until = DateTime.UtcNow.AddMilliseconds(ms);
        while (DateTime.UtcNow < until)
        {
            if (condition()) return true;
            Thread.Sleep(50);
        }
        return condition();
    }

    private static bool Has(ChannelState ch, string text)
    {
        lock (ch.Messages) return ch.Messages.Contains(text);
    }

    [Fact]
    public async Task Dm_DeliversOnlyToPeerWithSamePairKey_AndStaysOutOfLobby()
    {
        var alice = await Connect("alice", "lobby-key");
        var bob = await Connect("bob", "lobby-key");
        var carol = await Connect("carol", "lobby-key");
        var aLobby = await alice.JoinLobbyAsync();
        var bLobby = await bob.JoinLobbyAsync();
        var cLobby = await carol.JoinLobbyAsync();

        var aDm = await alice.OpenDmAsync("bob", "pair-secret");
        var bDm = await bob.OpenDmAsync("alice", "pair-secret");
        var cDm = await carol.OpenDmAsync("bob", "wrong-pair-key"); // carol guesses wrong

        Assert.Equal(aDm.Tag, bDm.Tag);
        Assert.NotEqual(aDm.Tag, cDm.Tag);
        Assert.True(WaitMembers(aDm, 2));

        Assert.Null(alice.Send(aDm, "secret hello"));
        Assert.True(WaitFor(() => Has(bDm, "alice: secret hello")));
        Assert.False(Has(bLobby, "alice: secret hello"));
        Assert.False(Has(cDm, "alice: secret hello"));
        Assert.False(Has(cLobby, "alice: secret hello"));

        Assert.Null(alice.Send(aLobby, "public hello"));
        Assert.True(WaitFor(() => Has(bLobby, "alice: public hello") && Has(cLobby, "alice: public hello")));
        Assert.False(Has(bDm, "alice: public hello"));
    }

    private static bool WaitMembers(ChannelState ch, int n)
    {
        return WaitFor(() => { lock (ch.Members) return ch.Members.Count == n; });
    }

    [Fact]
    public async Task LoneUserInChannel_GetsEmptyRosterHint()
    {
        var alice = await Connect("alice", "lobby-key");
        var lobby = await alice.JoinLobbyAsync();
        Assert.True(WaitFor(() => { lock (lobby.Messages) return lobby.Messages.Any(m => m.StartsWith("You are alone in general")); }));
    }

    [Fact]
    public async Task JoinAndLeave_AreShownFromPresence()
    {
        var alice = await Connect("alice", "k");
        var aLobby = await alice.JoinLobbyAsync();
        var bob = await Connect("bob", "k");
        await bob.JoinLobbyAsync();
        Assert.True(WaitFor(() => Has(aLobby, "bob joined")));
        bob.Dispose();
        Assert.True(WaitFor(() => Has(aLobby, "bob left")));
    }

    [Fact]
    public async Task ConnectingToNonV3Peer_ReportsProtocolMismatch()
    {
        var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            _ = Task.Run(() => { using var c = listener.AcceptTcpClient(); }); // accepts and closes immediately
            var s = new ChatSession("localhost", ((System.Net.IPEndPoint)listener.LocalEndpoint).Port, "alice", "k");
            sessions.Add(s);
            var ex = await Assert.ThrowsAsync<IOException>(() => s.ConnectAsync());
            Assert.Contains("protocol mismatch", ex.Message);
        }
        finally { listener.Stop(); }
    }

    [Fact]
    public async Task Rooms_AreIsolatedFromEachOtherAndTheLobby()
    {
        var alice = await Connect("alice", "login-key");
        var bob = await Connect("bob", "login-key");
        await alice.JoinLobbyAsync();
        var bLobby = await bob.JoinLobbyAsync();
        var aDev = await alice.JoinRoomAsync("Dev", "dev-key");
        var aOps = await alice.JoinRoomAsync("ops", "ops-key");
        var bDev = await bob.JoinRoomAsync("dev", "dev-key"); // names are case-insensitive
        var bOps = await bob.JoinRoomAsync("ops", "other-key"); // wrong key: different, empty channel

        Assert.Equal("dev", aDev.DisplayName);
        Assert.Equal(aDev.Tag, bDev.Tag);
        Assert.NotEqual(aOps.Tag, bOps.Tag);
        Assert.True(WaitMembers(aDev, 2));

        Assert.Null(alice.Send(aDev, "dev news"));
        Assert.Null(alice.Send(aOps, "ops news"));
        Assert.True(WaitFor(() => Has(bDev, "alice: dev news")));
        Assert.False(Has(bOps, "alice: ops news"));
        Assert.False(Has(bLobby, "alice: dev news"));
        Assert.False(Has(bOps, "alice: dev news"));
        Assert.False(Has(bDev, "alice: ops news"));
    }

    [Fact]
    public async Task JoinRoom_BlankKeyReusesLoginKey()
    {
        var alice = await Connect("alice", "login-key");
        var bob = await Connect("bob", "login-key");
        var aRoom = await alice.JoinRoomAsync("lounge", "");
        var bRoom = await bob.JoinRoomAsync("lounge", null);
        Assert.Equal(aRoom.Tag, bRoom.Tag);
        Assert.True(WaitMembers(aRoom, 2));
    }

    [Fact]
    public async Task JoinRoom_RejectsBadNameAndSameNameWithAnotherKey_AndReturnsExistingForSameKey()
    {
        var alice = await Connect("alice", "login-key");
        var room = await alice.JoinRoomAsync("lounge", "k1");
        Assert.Same(room, await alice.JoinRoomAsync("LOUNGE", "k1"));
        Assert.Single(alice.Channels);
        await Assert.ThrowsAsync<InvalidOperationException>(() => alice.JoinRoomAsync("lounge", "k2"));
        Assert.Throws<InvalidOperationException>(() => { _ = alice.JoinRoomAsync("bad name", "k1"); });
        Assert.Throws<InvalidOperationException>(() => { _ = alice.JoinRoomAsync("dm:bob", "k1"); });
        Assert.Single(alice.Channels);
    }

    [Fact]
    public async Task Leave_StopsDeliveryBothWays_RemovesChannel_AndLobbyCannotBeLeft()
    {
        var alice = await Connect("alice", "k");
        var bob = await Connect("bob", "k");
        var aLobby = await alice.JoinLobbyAsync();
        await bob.JoinLobbyAsync();
        var aRoom = await alice.JoinRoomAsync("lounge", "rk");
        var bRoom = await bob.JoinRoomAsync("lounge", "rk");
        Assert.True(WaitMembers(aRoom, 2));

        Assert.NotNull(alice.Leave(aLobby));
        Assert.Contains(aLobby, alice.Channels);

        Assert.Null(bob.Leave(bRoom));
        Assert.DoesNotContain(bRoom, bob.Channels);
        Assert.True(WaitFor(() => Has(aRoom, "bob left")));
        Assert.NotNull(bob.Leave(bRoom)); // already gone

        Assert.Null(alice.Send(aRoom, "anyone?"));
        Thread.Sleep(500);
        Assert.False(Has(bRoom, "alice: anyone?"));

        // Rejoining works and gives a fresh channel state
        var bAgain = await bob.JoinRoomAsync("lounge", "rk");
        Assert.NotSame(bRoom, bAgain);
        Assert.True(WaitFor(() => Has(aRoom, "bob joined")));
    }

    [Fact]
    public async Task ChannelCap_17thChannelIsRejectedClientSide()
    {
        var alice = await Connect("alice", "k");
        await alice.JoinLobbyAsync();
        for (int i = 1; i < CipherChatClient.ProtocolLimits.MaxChannelsPerClient; i++)
            await alice.JoinRoomAsync("r" + i, "k");
        Assert.Equal(CipherChatClient.ProtocolLimits.MaxChannelsPerClient, alice.Channels.Count);
        await Assert.ThrowsAsync<InvalidOperationException>(() => alice.JoinRoomAsync("one-too-many", "k"));
    }

    [Fact]
    public async Task Unread_CountsOnlyChannelsThatAreNotActive()
    {
        var alice = await Connect("alice", "k");
        var bob = await Connect("bob", "k");
        var aLobby = await alice.JoinLobbyAsync();
        var bLobby = await bob.JoinLobbyAsync();
        var aRoom = await alice.JoinRoomAsync("lounge", "rk");
        var bRoom = await bob.JoinRoomAsync("lounge", "rk");
        Assert.True(WaitMembers(aRoom, 2));

        alice.Active = aLobby;
        Assert.Null(bob.Send(bLobby, "in lobby"));
        Assert.Null(bob.Send(bRoom, "in room 1"));
        Assert.Null(bob.Send(bRoom, "in room 2"));
        Assert.True(WaitFor(() => Has(aRoom, "bob: in room 2") && Has(aLobby, "bob: in lobby")));
        Assert.Equal(0, aLobby.Unread);
        Assert.Equal(2, aRoom.Unread);
    }
}
