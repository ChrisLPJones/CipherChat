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
}
