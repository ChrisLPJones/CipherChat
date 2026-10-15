using System.Security.Cryptography;
using System.Text;
using CipherChatClient;
using Xunit;

namespace CipherChat.Tests;

// A scripted server (ScriptedServer) misbehaves against a ChatSession. It also plays the other user with the
// library's own CPace/SecureChannel, so the session sees a fully valid counterpart whenever the test wants one.
public class MaliciousServerTests : IDisposable
{
    private const string Code = "correct horse battery staple";
    private const string WrongCode = "correct horse battery stapl3";
    private readonly List<IDisposable> toDispose = new();

    public void Dispose() { foreach (IDisposable d in toDispose.AsEnumerable().Reverse()) d.Dispose(); }

    private sealed class Rig
    {
        public ScriptedServer Srv;
        public ChatSession S;
        public CPace Fake;
        public SecureChannel FakeChannel;
        public byte[] ClientNonce;
        public byte[] FakeNonce = RandomNumberGenerator.GetBytes(16);
        public int ClientRole;

        // Sends PAIRED and creates the fake peer's CPace (role = the other one).
        public void Pair(int clientRole, string fakeCode = Code, int? fakeRole = null)
        {
            ClientRole = clientRole;
            Fake = new CPace(fakeRole ?? 3 - clientRole, fakeCode, "aabbcc", FakeNonce, ClientNonce);
            Srv.Send($"PAIRED {clientRole} {Convert.ToHexString(FakeNonce).ToLowerInvariant()}");
        }

        public byte[] ClientKey() => ClientFrame.DecodeBlob(Srv.Wait(l => l.StartsWith("KEY ")).Split(' ')[1]);
        public byte[] ClientConfirm() => ClientFrame.DecodeBlob(Srv.Wait(l => l.StartsWith("CONFIRM ")).Split(' ')[1]);

        // The fake peer's KEY then CONFIRM, answering the client's KEY (a correct, complete handshake when the codes match).
        public void CompleteHandshake()
        {
            byte[] y = Fake.CreateKeyMessage();
            Srv.Send(ClientFrame.Key(y));
            Assert.True(Fake.ReceiveKey(ClientKey()));
            Srv.Send(ClientFrame.Confirm(Fake.CreateConfirm()));
            Assert.True(Fake.VerifyConfirm(ClientConfirm()));
            FakeChannel = Fake.CreateChannel();
        }

        // Same exchange, for fake peers that may legitimately fail (wrong code or role): no assertions on their side.
        public void CompleteHandshakeIgnoringResult()
        {
            Srv.Send(ClientFrame.Key(Fake.CreateKeyMessage()));
            if (!Fake.ReceiveKey(ClientKey())) return;
            Srv.Send(ClientFrame.Confirm(Fake.CreateConfirm()));
        }
    }

    private async Task<Rig> Start(ChatSessionOptions o = null, string code = Code)
    {
        var srv = new ScriptedServer();
        toDispose.Add(srv);
        var s = new ChatSession("localhost", srv.Port, code, o ?? new ChatSessionOptions { RidOverride = "aabbcc" });
        toDispose.Add(s);
        var rig = new Rig { Srv = srv, S = s };
        await s.StartAsync();
        string hello = srv.Wait(l => l.StartsWith("HELLO 5 aabbcc "));
        Assert.NotNull(hello);
        rig.ClientNonce = Convert.FromHexString(hello.Split(' ')[3]);
        return rig;
    }

    private async Task<Rig> Chatting(int clientRole = 1, string handle = null)
    {
        Rig r = await Start(new ChatSessionOptions { RidOverride = "aabbcc", Handle = handle });
        r.Pair(clientRole);
        r.CompleteHandshake();
        Wait.For(() => r.S.State == SessionState.Chatting, "chatting");
        return r;
    }

    private static bool Has(ChatSession s, string text) => s.SnapshotLines().Any(l => l.Contains(text));
    private static string MsgLine(byte[] blob) => ClientFrame.Msg(blob);

    private static void AssertSecurityFailureAndSilence(Rig r)
    {
        Assert.Equal(EndReason.SecurityFailure, r.S.Completion.WaitAsync(TimeSpan.FromSeconds(5)).Result);
        Assert.True(Has(r.S, "Could not connect securely"));
        Thread.Sleep(150);                                         // let lines the client wrote before failing reach the scripted server
        int sent = r.Srv.Received.Count;
        Thread.Sleep(200);
        Assert.Equal(sent, r.Srv.Received.Count);                  // nothing more after the failure
        Assert.False(r.Srv.Saw("MSG"));                            // no message was ever sent
    }

    // ---- the code is the only secret ----

    [Fact]
    public async Task ServerWithTheRightCode_Succeeds_DocumentingThatTheCodeIsTheOnlySecret()
    {
        Rig r = await Chatting();
        Assert.Null(r.S.Send("hello"));
        string line = r.Srv.Wait(l => l.StartsWith("MSG "));
        Assert.Equal("hello", r.FakeChannel.Open(ClientFrame.DecodeBlob(line.Split(' ')[1])).Text);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    public async Task ServerWithAWrongCode_CausesTheGenericFailure_AndNoMessageIsSent(int role)
    {
        Rig r = await Start();
        r.Pair(role, WrongCode);
        r.CompleteHandshakeIgnoringResult();
        AssertSecurityFailureAndSilence(r);
    }

    // ---- handshake abuse ----

    [Fact]
    public async Task BothToldTheSameRole_Fails()
    {
        Rig r = await Start();
        r.Pair(1, Code, fakeRole: 1);
        r.CompleteHandshakeIgnoringResult();
        AssertSecurityFailureAndSilence(r);
    }

    [Fact]
    public async Task ReplayedOwnNonce_IsRejectedImmediately()
    {
        Rig r = await Start();
        r.Srv.Send($"PAIRED 2 {Convert.ToHexString(r.ClientNonce).ToLowerInvariant()}");
        Assert.Equal(EndReason.SecurityFailure, await r.S.Completion.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.False(r.Srv.Saw("KEY"));
    }

    [Fact]
    public async Task ReflectedOwnKey_IsRejected()
    {
        Rig r = await Start();
        r.Pair(1);
        byte[] ownKey = r.ClientKey();
        r.Srv.Send(ClientFrame.Key(ownKey));
        AssertSecurityFailureAndSilence(r);
    }

    [Theory]
    [InlineData("0000000000000000000000000000000000000000000000000000000000000000")]   // the identity element
    [InlineData("2b3c6b8c4f3800e7aef6864025b4ed79bd599117e427c41bd47d93d654b4a51c")]   // draft B.3.11 invalid point
    [InlineData("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")]   // not a canonical encoding
    public async Task IdentityOrInvalidPoints_AreRejected(string hex)
    {
        Rig r = await Start();
        r.Pair(2);
        r.ClientKey();
        r.Srv.Send(ClientFrame.Key(Convert.FromHexString(hex)));
        AssertSecurityFailureAndSilence(r);
    }

    [Fact]
    public async Task ReflectedOwnConfirm_IsRejected()
    {
        Rig r = await Start();
        r.Pair(1);
        r.Srv.Send(ClientFrame.Key(r.Fake.CreateKeyMessage()));
        r.Fake.ReceiveKey(r.ClientKey());
        byte[] own = r.ClientConfirm();
        r.Srv.Send(ClientFrame.Confirm(own));
        AssertSecurityFailureAndSilence(r);
    }

    [Fact]
    public async Task FlippedConfirmByte_IsRejected()
    {
        Rig r = await Start();
        r.Pair(1);
        r.Srv.Send(ClientFrame.Key(r.Fake.CreateKeyMessage()));
        r.Fake.ReceiveKey(r.ClientKey());
        byte[] tag = r.Fake.CreateConfirm();
        tag[10] ^= 1;
        r.Srv.Send(ClientFrame.Confirm(tag));
        AssertSecurityFailureAndSilence(r);
    }

    [Fact]
    public async Task ConfirmBeforeKey_IsRejected()
    {
        Rig r = await Start();
        r.Pair(1);
        r.Srv.Send(ClientFrame.Confirm(RandomNumberGenerator.GetBytes(64)));
        AssertSecurityFailureAndSilence(r);
    }

    [Fact]
    public async Task SecondKey_IsRejected()
    {
        Rig r = await Start();
        r.Pair(1);
        r.Srv.Send(ClientFrame.Key(r.Fake.CreateKeyMessage()));
        r.ClientKey();
        r.Srv.Send(ClientFrame.Key(RandomNumberGenerator.GetBytes(32)));
        AssertSecurityFailureAndSilence(r);
    }

    [Fact]
    public async Task MsgBeforeTheHandshakeFinished_IsRejected()
    {
        Rig r = await Start();
        r.Pair(1);
        r.Srv.Send(ClientFrame.Msg(RandomNumberGenerator.GetBytes(26 + 256 + 16)));
        AssertSecurityFailureAndSilence(r);
    }

    [Theory]
    [InlineData("GONE")]
    [InlineData("ERR timeout")]
    [InlineData("ERR used")]
    [InlineData("WAIT")]
    [InlineData("PAIRED 1 00000000000000000000000000000000")]
    public async Task ControlLinesDuringTheHandshake_AreTheGenericFailure(string line)
    {
        Rig r = await Start();
        r.Pair(1);
        r.ClientKey();
        r.Srv.Send(line);
        AssertSecurityFailureAndSilence(r);
    }

    [Fact]
    public async Task ErrUsedAfterHello_IsTheGenericFailure()
    {
        Rig r = await Start();
        r.Srv.Send("ERR used");
        AssertSecurityFailureAndSilence(r);
    }

    [Theory]
    [InlineData("ERR timeout", EndReason.ConnectionLost)]
    [InlineData("ERR full", EndReason.ServerBusy)]
    [InlineData("ERR rate", EndReason.ServerBusy)]
    [InlineData("ERR version", EndReason.VersionMismatch)]
    [InlineData("KEY AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", EndReason.SecurityFailure)]
    [InlineData("GONE", EndReason.SecurityFailure)]
    public async Task AloneStage_ErrorMapping(string line, EndReason expected)
    {
        Rig r = await Start();
        r.Srv.Send("WAIT");
        Wait.For(() => r.S.State == SessionState.Waiting, "waiting");
        r.Srv.Send(line);
        Assert.Equal(expected, await r.S.Completion.WaitAsync(TimeSpan.FromSeconds(5)));
    }

    // ---- silence, garbage ----

    [Fact]
    public async Task SilentServerWhileAlone_IsDetectedAsDead_ByTheKeepalive_ButQuitStillWorks()
    {
        Rig r = await Start(new ChatSessionOptions { RidOverride = "aabbcc", PingIntervalMs = 150 });
        r.Srv.Intercept = l => l == "PING";            // swallow the PINGs: no PONG ever comes back
        r.Srv.Send("WAIT");
        Wait.For(() => r.S.State == SessionState.Waiting, "waiting");
        Assert.Equal(EndReason.ConnectionLost, await r.S.Completion.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.True(r.Srv.Saw("PING"));
    }

    [Fact]
    public async Task ServerThatAnswersPings_KeepsAWaitingClientWaiting_WithNoClientSideLimit()
    {
        Rig r = await Start(new ChatSessionOptions { RidOverride = "aabbcc", PingIntervalMs = 100 });
        r.Srv.Send("WAIT");
        Wait.For(() => r.S.State == SessionState.Waiting, "waiting");
        Wait.Never(() => r.S.IsEnded, "waiting client gave up", 1500);
        Assert.True(r.Srv.Received.Count(l => l == "PING") >= 5);
        r.S.Quit();
        Assert.Equal(EndReason.UserQuit, await r.S.Completion);
    }

    [Fact]
    public async Task ServerThatGoesSilentAfterPaired_EndsWithTheGenericFailure()
    {
        Rig r = await Start(new ChatSessionOptions { RidOverride = "aabbcc", HandshakeTimeoutMs = 400 });
        r.Pair(2);
        AssertSecurityFailureAndSilence(r);
    }

    [Fact]
    public async Task GarbageAndTruncatedLines_ChangeNothing_AndOverLengthEndsTheSession()
    {
        Rig r = await Start();
        r.Srv.Send("this is not v5");
        r.Srv.Send("PAIRED 1");                         // truncated
        r.Srv.Send("KEY AAAA");
        r.Srv.Send("MSG " + new string('A', 399));
        r.Srv.Send("WAIT");
        Wait.For(() => r.S.State == SessionState.Waiting, "still alive and waiting");
        Assert.True(Has(r.S, "malformed"));

        r.Srv.Send(new string('A', ProtocolLimits.MaxLineChars + 50));
        Assert.Equal(EndReason.SecurityFailure, await r.S.Completion.WaitAsync(TimeSpan.FromSeconds(5)));
    }

    [Fact]
    public async Task ServerClosingMidHandshake_IsTheGenericFailure_AndMidChatIsConnectionLost()
    {
        Rig r = await Start();
        r.Pair(1);
        r.ClientKey();
        r.Srv.Dispose();
        Assert.Equal(EndReason.SecurityFailure, await r.S.Completion.WaitAsync(TimeSpan.FromSeconds(5)));

        Rig c = await Chatting();
        c.Srv.Dispose();
        Assert.Equal(EndReason.ConnectionLost, await c.S.Completion.WaitAsync(TimeSpan.FromSeconds(5)));
    }

    // ---- during the chat ----

    [Fact]
    public async Task ReplayedReorderedWithheldAndFlippedMessages_EndTheChat()
    {
        // replay
        Rig r = await Chatting();
        byte[] m0 = r.FakeChannel.SealText("zero");
        r.Srv.Send(MsgLine(m0));
        Wait.For(() => Has(r.S, "Them: zero"), "m0");
        r.Srv.Send(MsgLine(m0));
        Assert.Equal(EndReason.MessageFailed, await r.S.Completion.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.True(Has(r.S, "A message failed verification. The chat was ended for safety."));

        // reorder (second message first)
        Rig r2 = await Chatting();
        byte[] a = r2.FakeChannel.SealText("a"), b = r2.FakeChannel.SealText("b");
        r2.Srv.Send(MsgLine(b));
        Assert.Equal(EndReason.MessageFailed, await r2.S.Completion.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.False(Has(r2.S, "Them: b"));

        // withheld (gap)
        Rig r3 = await Chatting();
        r3.FakeChannel.SealText("withheld");
        r3.Srv.Send(MsgLine(r3.FakeChannel.SealText("after the gap")));
        Assert.Equal(EndReason.MessageFailed, await r3.S.Completion.WaitAsync(TimeSpan.FromSeconds(5)));

        // flipped byte
        Rig r4 = await Chatting();
        byte[] flipped = r4.FakeChannel.SealText("flip me");
        flipped[40] ^= 1;
        r4.Srv.Send(MsgLine(flipped));
        Assert.Equal(EndReason.MessageFailed, await r4.S.Completion.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.False(Has(r4.S, "flip me"));
    }

    [Fact]
    public async Task KeyOrConfirmDuringTheChat_EndTheChat()
    {
        Rig r = await Chatting();
        r.Srv.Send(ClientFrame.Key(RandomNumberGenerator.GetBytes(32)));
        Assert.Equal(EndReason.MessageFailed, await r.S.Completion.WaitAsync(TimeSpan.FromSeconds(5)));
    }

    [Fact]
    public async Task MessageFromAnotherSession_IsRejected()
    {
        Rig r = await Chatting();
        using var other = new SecureChannel(RandomNumberGenerator.GetBytes(16), RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(32));
        r.Srv.Send(MsgLine(other.SealText("from elsewhere")));
        Assert.Equal(EndReason.MessageFailed, await r.S.Completion.WaitAsync(TimeSpan.FromSeconds(5)));
    }

    [Fact]
    public async Task FakeGone_EndsTheChatCleanly_AndErrIsConnectionLost()
    {
        Rig r = await Chatting();
        r.Srv.Send("GONE");
        Assert.Equal(EndReason.PeerDisconnected, await r.S.Completion.WaitAsync(TimeSpan.FromSeconds(5)));

        Rig e = await Chatting();
        e.Srv.Send("ERR timeout");
        Assert.Equal(EndReason.ConnectionLost, await e.S.Completion.WaitAsync(TimeSpan.FromSeconds(5)));
    }

    [Fact]
    public async Task ValidMessages_ShowSanitised_AndEndOfSessionIsPeerLeft()
    {
        Rig r = await Chatting(clientRole: 2);
        r.Srv.Send(MsgLine(r.FakeChannel.SealText("hi \u001b[31mred‮ there")));
        Wait.For(() => Has(r.S, "Them: hi [31mred there"), "sanitised text");
        Assert.DoesNotContain(r.S.SnapshotLines(), l => l.Contains('\u001b') || l.Contains('‮'));
        r.Srv.Send(MsgLine(r.FakeChannel.SealEnd()));
        Assert.Equal(EndReason.PeerLeft, await r.S.Completion.WaitAsync(TimeSpan.FromSeconds(5)));
    }

    [Fact]
    public async Task Quit_SendsAnAuthenticatedEndOfSession_ThenClosesWithoutSendingMore()
    {
        Rig r = await Chatting();
        r.S.Quit();
        string line = r.Srv.Wait(l => l.StartsWith("MSG "));
        Assert.NotNull(line);
        OpenResult res = r.FakeChannel.Open(ClientFrame.DecodeBlob(line.Split(' ')[1]));
        Assert.Equal(MessageKind.EndOfSession, res.Kind);
        int sent = r.Srv.Received.Count;
        Thread.Sleep(200);
        Assert.Equal(sent, r.Srv.Received.Count);
        Assert.Equal(EndReason.UserQuit, await r.S.Completion);
    }

    // ---- handles (untrusted display names, inside the encrypted session only) ----

    [Fact]
    public async Task OurHandle_IsTheFirstEncryptedMessage_AndNeverOnTheWireInTheClear()
    {
        Rig r = await Chatting(handle: "Anna_Smith");
        string first = r.Srv.Wait(l => l.StartsWith("MSG "));
        OpenResult res = r.FakeChannel.Open(ClientFrame.DecodeBlob(first.Split(' ')[1]));
        Assert.Equal((OpenStatus.Ok, MessageKind.Handle, "Anna_Smith"), (res.Status, res.Kind, res.Text));

        // nothing sent before the session was established mentions the handle in any encoding
        string[] beforeSession = r.Srv.Received.TakeWhile(l => !l.StartsWith("MSG ")).ToArray();
        Assert.All(beforeSession, l => Assert.Contains(l.Split(' ')[0], new[] { "HELLO", "KEY", "CONFIRM", "PING" }));
        r.S.Send("hello");
        r.S.Quit();
        Thread.Sleep(200);
        string all = string.Join("\n", r.Srv.Received);
        foreach (string h in new[] { "Anna_Smith", Convert.ToBase64String(Encoding.ASCII.GetBytes("Anna_Smith")), Convert.ToHexString(Encoding.ASCII.GetBytes("Anna_Smith")) })
            Assert.DoesNotContain(h, all, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Anna", all);
    }

    [Fact]
    public async Task ValidPeerHandle_IsShown_BeforeTheFirstText()
    {
        Rig r = await Chatting(handle: "me");
        r.Srv.Send(MsgLine(r.FakeChannel.SealHandle("Peer.One")));
        r.Srv.Send(MsgLine(r.FakeChannel.SealText("hey")));
        Wait.For(() => Has(r.S, "Peer.One: hey"), "labelled line");
        Assert.True(Has(r.S, "Peer.One is in the chat."));
        r.Srv.Send(MsgLine(r.FakeChannel.SealEnd()));
        Assert.Equal(EndReason.PeerLeft, await r.S.Completion.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.True(Has(r.S, "Peer.One left the chat."));
    }

    [Theory]
    [InlineData("bad!name")]        // '!' is outside [A-Za-z0-9_.-]
    [InlineData("a*b")]             // would look like a status line
    [InlineData("you")]             // would impersonate our own lines
    [InlineData("YOU")]
    [InlineData("me")]              // equal to our own handle
    [InlineData("ME")]
    public async Task InvalidOrDuplicateHandle_FallsBackToTheNeutralLabel_AndTheChatContinues(string handle)
    {
        Rig r = await Chatting(handle: "me");
        r.Srv.Send(MsgLine(r.FakeChannel.SealHandle(handle)));
        r.Srv.Send(MsgLine(r.FakeChannel.SealText("hello")));
        Wait.For(() => Has(r.S, "Them: hello"), "neutral label");
        Assert.DoesNotContain(r.S.SnapshotLines(), l => l.Contains("is in the chat"));
        Assert.Equal(SessionState.Chatting, r.S.State);
    }

    [Fact]
    public async Task RepeatedOrLateHandle_IsIgnored()
    {
        // repeat: the second handle never replaces the first
        Rig r = await Chatting();
        r.Srv.Send(MsgLine(r.FakeChannel.SealHandle("First")));
        r.Srv.Send(MsgLine(r.FakeChannel.SealHandle("Second")));
        r.Srv.Send(MsgLine(r.FakeChannel.SealText("x")));
        Wait.For(() => Has(r.S, "First: x"), "first handle kept");
        Assert.DoesNotContain(r.S.SnapshotLines(), l => l.Contains("Second"));

        // late: a handle after a text message is ignored
        Rig l = await Chatting();
        l.Srv.Send(MsgLine(l.FakeChannel.SealText("before")));
        l.Srv.Send(MsgLine(l.FakeChannel.SealHandle("Late")));
        l.Srv.Send(MsgLine(l.FakeChannel.SealText("after")));
        Wait.For(() => Has(l.S, "Them: after"), "neutral label stays");
        Assert.DoesNotContain(l.S.SnapshotLines(), x => x.Contains("Late"));
    }

    [Fact]
    public async Task OversizedOrMalformedHandleMessage_EndsTheChat()
    {
        Rig r = await Chatting();
        r.Srv.Send(MsgLine(r.FakeChannel.SealForTest(MessageKind.Handle, Encoding.ASCII.GetBytes(new string('a', 21)))));
        Assert.Equal(EndReason.MessageFailed, await r.S.Completion.WaitAsync(TimeSpan.FromSeconds(5)));

        Rig e = await Chatting();
        e.Srv.Send(MsgLine(e.FakeChannel.SealForTest(MessageKind.Handle, Array.Empty<byte>())));
        Assert.Equal(EndReason.MessageFailed, await e.S.Completion.WaitAsync(TimeSpan.FromSeconds(5)));
    }

    [Fact]
    public async Task HandleControlCharacters_NeverReachTheScreen()
    {
        Rig r = await Chatting();
        r.Srv.Send(MsgLine(r.FakeChannel.SealForTest(MessageKind.Handle, Encoding.ASCII.GetBytes("a\u001b[2Jb"))));
        r.Srv.Send(MsgLine(r.FakeChannel.SealText("x")));
        Wait.For(() => Has(r.S, "Them: x"), "neutral label");
        Assert.DoesNotContain(r.S.SnapshotLines(), l => l.Contains('\u001b'));
    }

    // ---- wire hygiene ----

    [Fact]
    public async Task OnlyKnownVerbsAreSent_AndNoCodePlaintextOrKeyMaterialIsOnTheWire()
    {
        Rig r = await Chatting();
        r.S.Send("a secret message about zebras");
        r.Srv.Wait(l => l.StartsWith("MSG "));
        r.S.Quit();
        Thread.Sleep(200);
        string all = string.Join("\n", r.Srv.Received);
        foreach (string line in r.Srv.Received)
            Assert.Contains(line.Split(' ')[0], new[] { "HELLO", "KEY", "CONFIRM", "MSG", "PING" });
        string[] secrets = { Code, Convert.ToBase64String(Encoding.ASCII.GetBytes(Code)), Convert.ToHexString(Encoding.ASCII.GetBytes(Code)),
            "zebras", Convert.ToBase64String(Encoding.UTF8.GetBytes("zebras")), Convert.ToHexString(Encoding.UTF8.GetBytes("zebras")) };
        foreach (string s in secrets) Assert.DoesNotContain(s, all, StringComparison.OrdinalIgnoreCase);
        // the full Argon2id output (of which only 3 bytes become the rid) is never sent
        Assert.DoesNotContain(Hex.S(PairCode.DeriveRidFull(Code)), all, StringComparison.OrdinalIgnoreCase);
        // the HELLO carries only the 6-char rid and the nonce
        string hello = r.Srv.Received.First(l => l.StartsWith("HELLO"));
        Assert.Equal(4, hello.Split(' ').Length);
    }

    [Fact]
    public async Task EachAttempt_UsesAFreshNonceAndKey()
    {
        Rig a = await Start(), b = await Start();
        a.Pair(1); b.Pair(1);
        Assert.NotEqual(a.ClientNonce, b.ClientNonce);
        Assert.NotEqual(a.ClientKey(), b.ClientKey());
    }
}
