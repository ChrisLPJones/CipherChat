using System.Security.Cryptography;
using CipherChatClient;
using CipherChatServer;
using Xunit;

namespace CipherChat.Tests;

// ChatSession end to end over the real server (ephemeral port, nothing stored anywhere).
public class ChatSessionTests : IDisposable
{
    private const string Code = "correct horse battery staple";
    private const string OtherCode = "correct horse battery stapl3";
    private readonly List<IDisposable> toDispose = new();
    private ChatServer server;

    public void Dispose()
    {
        foreach (IDisposable d in toDispose.AsEnumerable().Reverse()) d.Dispose();
        server?.Stop();
    }

    private ChatServer Server(ServerLimits limits = null)
    {
        server = new ChatServer("localhost", 0, new ChatServerOptions
        {
            Limits = limits ?? new ServerLimits { MaxConnectionsPerIp = 100, HellosPerIpPerMinute = 1000, UnproductivePairingsPerIpPerHour = 1000 },
        });
        server.Start();
        return server;
    }

    private ChatSession NewSession(string code = Code, string rid = "aabbcc", ChatSessionOptions o = null)
    {
        var s = new ChatSession("localhost", server.Port, code, o ?? new ChatSessionOptions { RidOverride = rid });
        toDispose.Add(s);
        return s;
    }

    private static bool Has(ChatSession s, string text) => s.SnapshotLines().Any(l => l.Contains(text));

    private async Task<(ChatSession a, ChatSession b)> Chatting(string rid = "aabbcc")
    {
        Server();
        ChatSession a = NewSession(rid: rid), b = NewSession(rid: rid);
        await a.StartAsync();
        await b.StartAsync();
        Wait.For(() => a.State == SessionState.Chatting && b.State == SessionState.Chatting, "both chatting");
        return (a, b);
    }

    [Fact]
    public async Task RealPair_WithRealRidDerivation_ChatsBothWays()
    {
        Server();
        var a = NewSession(rid: null, o: new ChatSessionOptions());
        var b = NewSession(rid: null, o: new ChatSessionOptions());
        await Task.WhenAll(a.StartAsync(), b.StartAsync());
        Wait.For(() => a.State == SessionState.Chatting && b.State == SessionState.Chatting, "both chatting");
        Assert.Null(a.Send("hello b"));
        Wait.For(() => Has(b, "Them: hello b"), "b receives");
        Assert.Null(b.Send("hello a"));
        Wait.For(() => Has(a, "Them: hello a"), "a receives");
        Assert.True(Has(a, "You: hello b"));
        Assert.True(Has(a, "The other person proved they know the code"));
    }

    [Fact]
    public async Task Messages_ArriveInOrder_AndLongUnicodeRoundTrips_AndDisplayIsSanitised()
    {
        var (a, b) = await Chatting();
        for (int i = 0; i < 25; i++) Assert.Null(a.Send("m" + i));
        Wait.For(() => Has(b, "Them: m24"), "last message");
        List<string> got = b.SnapshotLines().Where(l => l.StartsWith("Them: m")).ToList();
        Assert.Equal(Enumerable.Range(0, 25).Select(i => "Them: m" + i), got);

        string longText = new('€', CipherChatClient.ProtocolLimits.MaxMessageChars);
        Assert.Null(b.Send(longText));
        Wait.For(() => Has(a, longText), "2000 euro signs");
        Assert.Contains("too long", a.Send(new string('x', CipherChatClient.ProtocolLimits.MaxMessageChars + 1)));

        Assert.Null(a.Send("tricky \u001b[2J‮ text"));
        Wait.For(() => Has(b, "Them: tricky [2J text"), "sanitised");
        Assert.DoesNotContain(b.SnapshotLines(), l => l.Contains('\u001b'));
        Assert.Null(a.Send(""));        // nothing to send
    }

    [Fact]
    public async Task Quit_TellsThePeer_AndBothEnd()
    {
        var (a, b) = await Chatting();
        a.Quit();
        Assert.Equal(EndReason.UserQuit, await a.Completion);
        Assert.Equal(EndReason.PeerLeft, await b.Completion.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.True(Has(b, "The other person left the chat"));
        Assert.False(ChatSession.IsFailure(EndReason.PeerLeft));
        Assert.NotNull(b.Send("too late"));
    }

    [Fact]
    public async Task PeerDisconnect_EndsTheChatViaGone()
    {
        var (a, b) = await Chatting();
        a.Dispose();
        Assert.Equal(EndReason.PeerDisconnected, await b.Completion.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.True(Has(b, "The other person disconnected"));
        Assert.True(ChatSession.IsFailure(EndReason.PeerDisconnected));
    }

    [Fact]
    public async Task DifferentCodes_GiveDifferentRids_AndNeverPair_LookLikeNobodyJoined()
    {
        Server();
        var o = new ChatSessionOptions { AloneTimeoutMs = 1500 };
        var a = NewSession(Code, o: o);
        var b = NewSession(OtherCode, o: new ChatSessionOptions { AloneTimeoutMs = 1500 });
        await Task.WhenAll(a.StartAsync(), b.StartAsync());
        Wait.For(() => a.State == SessionState.Waiting && b.State == SessionState.Waiting, "both waiting");
        Assert.Equal(2, server.WaiterCount);
        Assert.Equal(EndReason.NobodyJoined, await a.Completion.WaitAsync(TimeSpan.FromSeconds(8)));
        Assert.Equal(EndReason.NobodyJoined, await b.Completion.WaitAsync(TimeSpan.FromSeconds(8)));
        Assert.True(Has(a, "Nobody joined with this code"));
        Assert.DoesNotContain(a.SnapshotLines(), l => l.Contains("securely"));
    }

    [Fact]
    public async Task SameRid_DifferentCodes_FailOnBothSides_WithTheSingleSecurityMessage()
    {
        Server();
        var a = NewSession(Code, "aabbcc");
        var b = NewSession(OtherCode, "aabbcc");
        await a.StartAsync();
        await b.StartAsync();
        Assert.Equal(EndReason.SecurityFailure, await a.Completion.WaitAsync(TimeSpan.FromSeconds(8)));
        Assert.Equal(EndReason.SecurityFailure, await b.Completion.WaitAsync(TimeSpan.FromSeconds(8)));
        Assert.True(Has(a, "Could not connect securely"));
        Assert.True(Has(a, "Make up a NEW code"));
        Assert.True(Has(b, "Could not connect securely"));
        Assert.NotNull(a.Send("never delivered"));
        Assert.DoesNotContain(b.SnapshotLines(), l => l.Contains("never delivered"));
    }

    [Fact]
    public async Task ThirdClientWithTheSameCode_IsRejected_AndSoIsALaterRetry()
    {
        var (a, b) = await Chatting();
        var c = NewSession();
        await c.StartAsync();
        Assert.Equal(EndReason.SecurityFailure, await c.Completion.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.True(Has(c, "Make up a NEW code"));
        Assert.Equal(SessionState.Chatting, a.State);     // the pair is unaffected
        Assert.Null(a.Send("still here"));
        Wait.For(() => Has(b, "Them: still here"), "pair still works");

        a.Quit();
        await b.Completion.WaitAsync(TimeSpan.FromSeconds(5));
        var d = NewSession();                              // the rid is burned for an hour
        await d.StartAsync();
        Assert.Equal(EndReason.SecurityFailure, await d.Completion.WaitAsync(TimeSpan.FromSeconds(5)));
    }

    [Fact]
    public async Task ServerBusy_WhenTheServerAnswersErrRate()
    {
        Server(new ServerLimits { MaxConnectionsPerIp = 100, HellosPerIpPerMinute = 1 });
        var a = NewSession(rid: "000001");
        await a.StartAsync();
        Wait.For(() => a.State == SessionState.Waiting, "a waiting");
        var b = NewSession(rid: "000002");
        await b.StartAsync();
        Assert.Equal(EndReason.ServerBusy, await b.Completion.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.True(Has(b, "Server busy"));
    }

    [Fact]
    public async Task CannotConnect_WhenNobodyListens()
    {
        var s = Server();
        int port = s.Port;
        s.Stop();
        var session = new ChatSession("localhost", port, Code, new ChatSessionOptions { RidOverride = "aabbcc" });
        toDispose.Add(session);
        await session.StartAsync();
        Assert.Equal(EndReason.CannotConnect, await session.Completion.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.True(ChatSession.IsFailure(EndReason.CannotConnect));
    }

    [Fact]
    public async Task OldServer_AnswersErrVersion()
    {
        var srv = new ScriptedServer();
        toDispose.Add(srv);
        srv.Intercept = l => { if (l.StartsWith("HELLO")) { srv.Send("ERR version"); return true; } return false; };
        var s = new ChatSession("localhost", srv.Port, Code, new ChatSessionOptions { RidOverride = "aabbcc" });
        toDispose.Add(s);
        await s.StartAsync();
        Assert.Equal(EndReason.VersionMismatch, await s.Completion.WaitAsync(TimeSpan.FromSeconds(5)));
    }

    [Fact]
    public void Constructor_RejectsBadCodes()
    {
        Assert.Throws<ArgumentException>(() => new ChatSession("localhost", 1, "short"));
        Assert.Throws<ArgumentException>(() => new ChatSession("localhost", 1, "Correct Horse Battery Staple"));   // not normalized
        Assert.Throws<ArgumentException>(() => new ChatSession("localhost", 1, "abcdefghijkl"));                   // a straight run
    }

    [Fact]
    public async Task SendBeforeTheChat_IsRefused_AndQuitIsIdempotent()
    {
        Server();
        var a = NewSession();
        Assert.NotNull(a.Send("early"));
        await a.StartAsync();
        Wait.For(() => a.State == SessionState.Waiting, "waiting");
        Assert.NotNull(a.Send("still early"));
        a.Quit(); a.Quit();
        Assert.Equal(EndReason.UserQuit, await a.Completion);
        Wait.For(() => server.WaiterCount == 0, "rid freed after the waiter quit");
    }

    [Fact]
    public async Task Events_AreNeverRaisedUnderTheSessionLock()
    {
        var (a, b) = await Chatting();
        var entered = new ManualResetEventSlim();
        var release = new ManualResetEventSlim();
        a.LineAdded += line => { if (line.Contains("blocker")) { entered.Set(); release.Wait(3000); } };
        b.Send("blocker");
        // a's handler is now stuck; a's own session API must stay responsive.
        Assert.True(entered.Wait(5000));
        var sw = System.Diagnostics.Stopwatch.StartNew();
        Assert.Null(a.Send("while the handler blocks"));
        _ = a.State;
        _ = a.SnapshotLines();
        Assert.True(sw.ElapsedMilliseconds < 1500, "session calls stalled behind a blocked event handler");
        release.Set();
        Wait.For(() => Has(b, "Them: while the handler blocks"), "message went out");

        // A handler may call back into the session without deadlock.
        string reply = null;
        b.LineAdded += line => { if (line == "Them: ping") reply = b.Send("pong"); };
        a.Send("ping");
        Wait.For(() => Has(a, "Them: pong"), "reentrant reply");
        Assert.Null(reply);
    }

    [Fact]
    public void Describe_HasTheMessagesFromThePlan()
    {
        Assert.Equal("Nobody joined with this code within 10 minutes. Check that you both typed exactly the same code.", ChatSession.Describe(EndReason.NobodyJoined));
        Assert.StartsWith("Could not connect securely. Someone else may have used your code, or the connection was tampered with. Make up a NEW code together before trying again.", ChatSession.Describe(EndReason.SecurityFailure));
        Assert.Equal("A message failed verification. The chat was ended for safety.", ChatSession.Describe(EndReason.MessageFailed));
        Assert.True(ChatSession.IsFailure(EndReason.SecurityFailure));
        Assert.False(ChatSession.IsFailure(EndReason.UserQuit));
    }
}
