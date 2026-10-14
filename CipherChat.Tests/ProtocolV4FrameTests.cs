using System.Security.Cryptography;
using CipherChatClient;
using Xunit;
using S = CipherChatServer.ServerFrame;
using C = CipherChatClient.ClientFrameV4;

namespace CipherChat.Tests;

public class ProtocolV4FrameTests
{
    private static byte[] R(int n) => RandomNumberGenerator.GetBytes(n);
    private static string B(int n) => Convert.ToBase64String(R(n));
    private static readonly string Pub = B(65), Sig = B(64);

    private static string MsgBlob(int blocks) => B(26 + 256 * blocks + 16);

    // ---- client -> server, every verb ----

    [Fact]
    public void ClientFormats_ParseOnServer()
    {
        Assert.True(S.TryParse(C.Hello(), out var c));
        Assert.Equal(CipherChatServer.ClientVerb.Hello, c.Verb);

        byte[] pub = R(65), sig = R(64);
        Assert.True(S.TryParse(C.Register("alice", pub, sig), out c));
        Assert.Equal((CipherChatServer.ClientVerb.Register, "alice", Convert.ToBase64String(pub), Convert.ToBase64String(sig)), (c.Verb, c.User, c.Pub, c.Data));

        Assert.True(S.TryParse(C.Login("a.b_c-1", sig), out c));
        Assert.Equal((CipherChatServer.ClientVerb.Login, "a.b_c-1", Convert.ToBase64String(sig)), (c.Verb, c.User, c.Data));

        Assert.True(S.TryParse(C.Key("bob"), out c));
        Assert.Equal((CipherChatServer.ClientVerb.Key, "bob"), (c.Verb, c.User));

        byte[] offer = R(156), accept = R(179), confirm = R(50), knock = R(74);
        Assert.True(S.TryParse(C.Offer("bob", offer), out c));
        Assert.Equal((CipherChatServer.ClientVerb.Offer, "bob", Convert.ToBase64String(offer)), (c.Verb, c.User, c.Data));
        Assert.True(S.TryParse(C.Accept("bob", accept), out c));
        Assert.Equal(CipherChatServer.ClientVerb.Accept, c.Verb);
        Assert.True(S.TryParse(C.Confirm("bob", confirm), out c));
        Assert.Equal(CipherChatServer.ClientVerb.Confirm, c.Verb);
        Assert.True(S.TryParse(C.Knock("bob", knock), out c));
        Assert.Equal(CipherChatServer.ClientVerb.Knock, c.Verb);
        Assert.True(S.TryParse(C.Users(), out c));
        Assert.Equal(CipherChatServer.ClientVerb.Users, c.Verb);
        Assert.True(S.TryParse(C.Ping(), out c));
        Assert.Equal(CipherChatServer.ClientVerb.Ping, c.Verb);

        for (int k = 1; k <= 24; k++)
        {
            Assert.True(S.TryParse(C.Msg("bob", R(26 + 256 * k + 16)), out c), $"k={k}");
            Assert.Equal(CipherChatServer.ClientVerb.Msg, c.Verb);
        }
    }

    // ---- server -> client, every verb ----

    [Fact]
    public void ServerFormats_ParseOnClient()
    {
        string challenge = B(32);
        Assert.True(C.TryParse(S.Welcome(challenge), out var e));
        Assert.Equal((ServerEventKindV4.Welcome, challenge), (e.Kind, e.Data));

        Assert.True(C.TryParse(S.Ready("alice"), out e));
        Assert.Equal((ServerEventKindV4.Ready, "alice"), (e.Kind, e.User));

        Assert.True(C.TryParse(S.Key("bob", Pub), out e));
        Assert.Equal((ServerEventKindV4.Key, "bob", Pub), (e.Kind, e.User, e.Data));

        foreach (var (verb, bytes, kind) in new[] { ("OFFER", 156, ServerEventKindV4.Offer), ("ACCEPT", 179, ServerEventKindV4.Accept), ("CONFIRM", 50, ServerEventKindV4.Confirm), ("KNOCK", 74, ServerEventKindV4.Knock) })
        {
            string blob = B(bytes);
            Assert.True(C.TryParse(S.Relay(verb, "carol", blob), out e), verb);
            Assert.Equal((kind, "carol", blob), (e.Kind, e.User, e.Data));
        }
        string m = MsgBlob(3);
        Assert.True(C.TryParse(S.Relay("MSG", "carol", m), out e));
        Assert.Equal((ServerEventKindV4.Msg, "carol", m), (e.Kind, e.User, e.Data));

        Assert.True(C.TryParse(S.Offline("dave"), out e));
        Assert.Equal((ServerEventKindV4.Offline, "dave"), (e.Kind, e.User));
        Assert.True(C.TryParse(S.Gone("dave"), out e));
        Assert.Equal(ServerEventKindV4.Gone, e.Kind);
        Assert.True(C.TryParse(S.Pong, out e));
        Assert.Equal(ServerEventKindV4.Pong, e.Kind);

        foreach (string code in S.ErrorCodes)
        {
            Assert.True(C.TryParse(S.Err(code), out e), code);
            Assert.Equal((ServerEventKindV4.Err, code, (string)null), (e.Kind, e.Data, e.User));
            Assert.True(C.TryParse(S.Err(code, "bob"), out e), code);
            Assert.Equal("bob", e.User);
        }
        Assert.Equal(S.ErrorCodes, C.ErrorCodes);
    }

    [Fact]
    public void UserList_RoundTrips_AndEnforcesTheCap()
    {
        Assert.True(C.TryParse(S.UserList(new string[0]), out var e));
        Assert.Empty(e.Users);
        string[] names = { "alice", "bob", "c.d-e_1" };
        Assert.True(C.TryParse(S.UserList(names), out e));
        Assert.Equal(names, e.Users);

        string[] hundred = Enumerable.Range(0, 100).Select(i => "user" + i).ToArray();
        string line = S.UserList(hundred);
        Assert.True(line.Length <= ProtocolLimits.MaxLineCharsV4);
        Assert.True(C.TryParse(line, out e));
        Assert.Equal(100, e.Users.Length);
        string[] many = Enumerable.Range(0, 101).Select(i => "user" + i).ToArray();
        Assert.False(C.TryParse(S.UserList(many), out _));
    }

    [Theory]
    [InlineData("USERLIST")]
    [InlineData("USERLIST 1")]                // count without names
    [InlineData("USERLIST 0 alice")]          // names beyond the count
    [InlineData("USERLIST 2 alice")]
    [InlineData("USERLIST 1 alice bob")]
    [InlineData("USERLIST 01 alice")]         // leading zero
    [InlineData("USERLIST -1")]
    [InlineData("USERLIST x alice")]
    [InlineData("USERLIST 1000 alice")]
    [InlineData("USERLIST 2 alice alice")]    // duplicates
    [InlineData("USERLIST 1 Alice")]
    [InlineData("USERLIST 1 al ice")]
    [InlineData("USERLIST 1  alice")]
    [InlineData("USERLIST 0 ")]
    [InlineData("userlist 0")]
    public void MalformedUserList_IsRejected(string line) => Assert.False(C.TryParse(line, out _));

    // ---- negatives, server side ----

    public static IEnumerable<object[]> BadClientLines()
    {
        string pub = Pub, sig = Sig, offer = B(156), accept = B(179), confirm = B(50), knock = B(74), msg = MsgBlob(1);
        yield return new object[] { "" };
        yield return new object[] { " " };
        yield return new object[] { "FOO bar" };
        yield return new object[] { "hello 4" };
        yield return new object[] { "HELLO" };
        yield return new object[] { "HELLO 3" };
        yield return new object[] { "HELLO 5" };
        yield return new object[] { "HELLO 04" };
        yield return new object[] { "HELLO 4 4" };
        yield return new object[] { "HELLO  4" };
        yield return new object[] { "HELLO 4 " };
        yield return new object[] { " HELLO 4" };
        yield return new object[] { "PING x" };
        yield return new object[] { "PING " };
        yield return new object[] { "USERS 5" };
        yield return new object[] { "USERS all" };
        yield return new object[] { "KEY" };
        yield return new object[] { "KEY Bob" };                  // uppercase user
        yield return new object[] { "KEY bob x" };
        yield return new object[] { "KEY " + new string('a', 21) };
        yield return new object[] { "KEY böb" };
        yield return new object[] { "KEY bob\r" };                // CR inside the token
        yield return new object[] { "KEY b\u001bob" };            // ESC
        yield return new object[] { "KEY bo b" };
        yield return new object[] { "REGISTER alice " + pub };    // missing sig
        yield return new object[] { "REGISTER alice " + sig + " " + sig };   // pub 64 bytes
        yield return new object[] { "REGISTER alice " + pub + " " + pub };   // sig 65 bytes
        yield return new object[] { "REGISTER Alice " + pub + " " + sig };
        yield return new object[] { "REGISTER alice " + pub[..^1] + " " + sig };
        yield return new object[] { "REGISTER alice " + pub + "A " + sig };
        yield return new object[] { "REGISTER alice " + pub + "  " + sig };
        yield return new object[] { "LOGIN alice" };
        yield return new object[] { "LOGIN alice " + pub };
        yield return new object[] { "LOGIN alice " + sig + " extra" };
        yield return new object[] { "LOGIN ALICE " + sig };
        yield return new object[] { "OFFER bob " + offer[..^4] };            // 3 bytes short
        yield return new object[] { "OFFER bob " + offer + "AAAA" };         // 3 bytes long
        yield return new object[] { "OFFER bob " + accept };                 // wrong blob for the verb
        yield return new object[] { "OFFER bob" };
        yield return new object[] { "ACCEPT bob " + offer };
        yield return new object[] { "ACCEPT bob " + accept[..^4] };
        yield return new object[] { "CONFIRM bob " + knock };
        yield return new object[] { "CONFIRM bob " + confirm + "AAAA" };
        yield return new object[] { "KNOCK bob " + confirm };
        yield return new object[] { "KNOCK Bob " + knock };
        yield return new object[] { "MSG bob " + B(10) };                    // too short
        yield return new object[] { "MSG bob " + msg.Substring(0, msg.Length - 4) };   // 3 bytes short: not a block multiple
        yield return new object[] { "MSG bob " + MsgBlob(25) };             // 25 blocks
        yield return new object[] { "MSG bob " + B(26 + 255 + 16) };         // 255-byte body
        yield return new object[] { "MSG bob " + B(26 + 257 + 16) };
        yield return new object[] { "MSG bob " + B(26 + 16) };               // zero blocks
        yield return new object[] { "MSG bob" };
        yield return new object[] { "MSG bob " + msg + " x" };
        yield return new object[] { "MSG bob " + msg.Replace(msg[10], '*') };
        yield return new object[] { "MSG bob " + msg[..10] + "\u001b[2J" + msg[10..] };
        // v3 lines
        yield return new object[] { "JOIN roomAAAAAAAAAAAAAAAAA1 " + B(65) };
        yield return new object[] { "LEAVE roomAAAAAAAAAAAAAAAAA1" };
        yield return new object[] { "HIST roomAAAAAAAAAAAAAAAAA1 0 10" };
        yield return new object[] { "MSG roomAAAAAAAAAAAAAAAAA1 " + MsgBlob(1) };  // 22-char tag is not a user
        yield return new object[] { "MSG bob roomAAAAAAAAAAAAAAAAA1 " + MsgBlob(1) };
    }

    [Theory]
    [MemberData(nameof(BadClientLines))]
    public void Malformed_IsRejectedOnServer(string line) => Assert.False(S.TryParse(line, out _));

    [Fact]
    public void Base64Variants_AreRejected()
    {
        string offer = B(156);
        Assert.False(S.TryParse("OFFER bob =" + offer[1..], out _));            // padding at the start
        string noPad = Pub.TrimEnd('=');
        Assert.False(S.TryParse($"REGISTER alice {noPad} {Sig}", out _));       // padding stripped
        Assert.False(S.TryParse($"REGISTER alice {Pub[..^2]}== {Sig}", out _)); // wrong amount of padding
        Assert.False(S.TryParse($"LOGIN alice {Sig[..^2]}AA", out _));           // 64 bytes need "==" padding
        Assert.False(S.TryParse($"LOGIN alice {Sig[..^3]}=A=", out _));
        string urlSafe = Convert.ToBase64String(new byte[] { 0xFB, 0xFF, 0xBF }.Concat(new byte[61]).ToArray()).Replace('+', '-').Replace('/', '_');
        Assert.DoesNotContain('+', urlSafe);
        Assert.False(S.TryParse($"LOGIN alice {urlSafe}", out _));
        Assert.False(S.TryParse($"LOGIN alice {Sig[..40]} {Sig[40..]}", out _)); // whitespace inside
    }

    [Fact]
    public void NonCanonicalTrailingBits_AreRejectedOnBothSides()
    {
        // 65 bytes -> last char carries 2 data bits; any value with low 2 bits set is non-canonical.
        string good = Convert.ToBase64String(new byte[65]);        // ends "AAA=" style
        string bad = good[..^2] + "B=";                             // 'B' = 1 -> low bits set
        Assert.False(S.TryParse($"REGISTER alice {bad} {Sig}", out _));
        Assert.False(C.TryParse($"KEY bob {bad}", out _));
        Assert.True(C.TryParse($"KEY bob {good}", out _));
        Assert.Null(C.DecodeBlob(bad));
        Assert.NotNull(C.DecodeBlob(good));
    }

    [Fact]
    public void OverLengthLines_AreRejected_AndMaxMsgFits()
    {
        string max = MsgBlob(24);
        Assert.Equal(ProtocolLimits.MaxMsgChars, max.Length);
        string line = C.Msg("a" + new string('b', 19), R(26 + 256 * 24 + 16));
        Assert.Equal("MSG ".Length + 20 + 1 + 8248, line.Length);
        Assert.True(line.Length <= ProtocolLimits.MaxLineCharsV4);
        Assert.True(S.TryParse(line, out _));
        Assert.True(C.TryParse(S.Relay("MSG", new string('b', 20), max), out _));
        Assert.False(S.TryParse(new string('A', ProtocolLimits.MaxLineCharsV4 + 1), out _));
        Assert.False(C.TryParse(new string('A', ProtocolLimits.MaxLineCharsV4 + 1), out _));
        Assert.False(S.TryParse("MSG bob " + new string('A', ProtocolLimits.MaxMsgChars + 4), out _));
        Assert.False(S.TryParse(null, out _));
        Assert.False(C.TryParse(null, out _));
    }

    // ---- negatives, client side ----

    public static IEnumerable<object[]> BadServerLines()
    {
        string pub = Pub, offer = B(156), msg = MsgBlob(1);
        yield return new object[] { "" };
        yield return new object[] { "WELCOME 3 " + B(32) };
        yield return new object[] { "WELCOME 4" };
        yield return new object[] { "WELCOME 4 " + B(31) };
        yield return new object[] { "WELCOME 4 " + B(33) };
        yield return new object[] { "WELCOME 4 5" };                // v3 form
        yield return new object[] { "READY" };
        yield return new object[] { "READY Alice" };
        yield return new object[] { "READY alice bob" };
        yield return new object[] { "KEY bob" };
        yield return new object[] { "KEY bob " + B(64) };
        yield return new object[] { "KEY Bob " + pub };
        yield return new object[] { "OFFER bob " + B(155) };
        yield return new object[] { "OFFER bob " + B(157) };
        yield return new object[] { "OFFER bob " + offer + " extra" };
        yield return new object[] { "ACCEPT bob " + B(178) };
        yield return new object[] { "CONFIRM bob " + B(51) };
        yield return new object[] { "KNOCK bob " + B(73) };
        yield return new object[] { "MSG bob" };
        yield return new object[] { "MSG bob 1 " + msg };           // v3 form with an id
        yield return new object[] { "MSG bob " + msg[..^4] };
        yield return new object[] { "OFFLINE" };
        yield return new object[] { "OFFLINE bob extra" };
        yield return new object[] { "GONE B0B" };
        yield return new object[] { "PONG extra" };
        yield return new object[] { "ERR" };
        yield return new object[] { "ERR Not-Joined" };
        yield return new object[] { "ERR unknowncode" };
        yield return new object[] { "ERR rate Bob" };
        yield return new object[] { "ERR rate bob extra" };
        yield return new object[] { "ERR unsupported" };            // v3 code
        // v3 server lines
        yield return new object[] { "MEMBER roomAAAAAAAAAAAAAAAAA1 1 " + B(65) };
        yield return new object[] { "JOINED roomAAAAAAAAAAAAAAAAA1 1 " + B(65) };
        yield return new object[] { "LEFT roomAAAAAAAAAAAAAAAAA1 1" };
        yield return new object[] { "ACK roomAAAAAAAAAAAAAAAAA1 1" };
        yield return new object[] { "HIST roomAAAAAAAAAAAAAAAAA1 9 " + msg };
        yield return new object[] { "HISTEND roomAAAAAAAAAAAAAAAAA1 9" };
        yield return new object[] { "KEY bob " + pub + "\u001b" };
    }

    [Theory]
    [MemberData(nameof(BadServerLines))]
    public void Malformed_IsRejectedOnClient(string line) => Assert.False(C.TryParse(line, out _));

    [Fact]
    public void ExactLengths_PlusMinusOneByte_AreRejected()
    {
        foreach (int good in new[] { 156, 179, 50, 74 })
        {
            string verb = good switch { 156 => "OFFER", 179 => "ACCEPT", 50 => "CONFIRM", _ => "KNOCK" };
            Assert.True(S.TryParse($"{verb} bob {B(good)}", out _));
            Assert.False(S.TryParse($"{verb} bob {B(good - 1)}", out _));
            Assert.False(S.TryParse($"{verb} bob {B(good + 1)}", out _));
            Assert.True(C.TryParse($"{verb} bob {B(good)}", out _));
            Assert.False(C.TryParse($"{verb} bob {B(good - 1)}", out _));
            Assert.False(C.TryParse($"{verb} bob {B(good + 1)}", out _));
        }
        Assert.True(S.TryParse($"REGISTER a {B(65)} {B(64)}", out _));
        Assert.False(S.TryParse($"REGISTER a {B(64)} {B(64)}", out _));
        Assert.False(S.TryParse($"REGISTER a {B(66)} {B(64)}", out _));
        Assert.False(S.TryParse($"REGISTER a {B(65)} {B(63)}", out _));
        Assert.False(S.TryParse($"REGISTER a {B(65)} {B(65)}", out _));
        Assert.True(S.TryParse($"LOGIN a {B(64)}", out _));
        Assert.False(S.TryParse($"LOGIN a {B(63)}", out _));
        Assert.False(S.TryParse($"LOGIN a {B(65)}", out _));
        for (int k = 1; k <= 24; k++)
        {
            int total = 26 + 256 * k + 16;
            Assert.True(S.TryParse($"MSG bob {B(total)}", out _));
            Assert.False(S.TryParse($"MSG bob {B(total - 1)}", out _));
            Assert.False(S.TryParse($"MSG bob {B(total + 1)}", out _));
        }
    }

    [Fact]
    public void UsernameBoundaries()
    {
        foreach (string ok in new[] { "a", new string('z', 20), "0", "a.b", "a_b", "a-b", "-", "." })
            Assert.True(S.TryParse($"KEY {ok}", out _) && C.TryParse($"READY {ok}", out _), ok);
        foreach (string bad in new[] { new string('z', 21), "A", "aB", "a b", "a:b", "a/b", "a@b", "é", "a\tb" })
            Assert.False(S.TryParse($"KEY {bad}", out _) || C.TryParse($"READY {bad}", out _), bad);
    }

    [Fact]
    public void DecodeBlob_IsStrict()
    {
        byte[] data = R(74);
        string b64 = Convert.ToBase64String(data);
        Assert.Equal(data, C.DecodeBlob(b64));
        Assert.Null(C.DecodeBlob(b64 + "="));
        Assert.Null(C.DecodeBlob(b64[..^1]));
        Assert.Null(C.DecodeBlob("not base64!"));
        Assert.Null(C.DecodeBlob(null));
        Assert.Null(C.DecodeBlob(""));
    }

    [Fact]
    public void ServerAndClientMessageSizes_MatchTheLimitsConstants()
    {
        Assert.Equal(ProtocolLimits.OfferChars, B(156).Length);
        Assert.Equal(ProtocolLimits.AcceptChars, B(179).Length);
        Assert.Equal(ProtocolLimits.ConfirmChars, B(50).Length);
        Assert.Equal(ProtocolLimits.KnockChars, B(74).Length);
        Assert.Equal(ProtocolLimits.PubKeyChars, B(65).Length);
        Assert.Equal(ProtocolLimits.SigChars, B(64).Length);
        Assert.Equal(ProtocolLimits.ChallengeChars, B(32).Length);
        Assert.Equal(ProtocolLimits.MinMsgChars, MsgBlob(1).Length);
        Assert.Equal(ProtocolLimits.MaxMsgChars, MsgBlob(24).Length);
        Assert.True(24 * ProtocolLimits.PadBlock >= 3 + ProtocolLimits.MaxTextBytes);
    }

    [Fact]
    public void RealHandshakeAndChannelOutput_ParsesOnBothSides()
    {
        using IdentityKey a = IdentityKey.Generate();
        using IdentityKey b = IdentityKey.Generate();
        using var init = Handshake.Initiator.Create(a, "alice", "bob", b.PublicKey, false, 1_800_000_000_000);
        Assert.True(S.TryParse(C.Offer("bob", init.Offer), out _));
        Assert.True(C.TryParse(S.Relay("OFFER", "alice", Convert.ToBase64String(init.Offer)), out var ev));
        Assert.Equal(init.Offer, C.DecodeBlob(ev.Data));

        Handshake.Responder.TryReceiveOffer(b, "bob", "alice", a.PublicKey, init.Offer, 1_800_000_000_000, new SidCache(), out var resp);
        byte[] accept = resp.Accept();
        Assert.True(S.TryParse(C.Accept("alice", accept), out _));
        init.ProcessAccept(accept, out var chA, out byte[] confirm);
        Assert.True(S.TryParse(C.Confirm("bob", confirm), out _));
        resp.ProcessConfirm(confirm, out var chB);
        Assert.True(S.TryParse(C.Msg("bob", chA.SealText("")), out _));
        Assert.True(S.TryParse(C.Msg("bob", chA.SealText(new string('x', 6000))), out _));
        Assert.True(S.TryParse(C.Knock("bob", Handshake.BuildKnock(a, "alice", "bob", b.PublicKey, 1)), out _));
        Assert.True(S.TryParse(C.Register("alice", a.PublicKey, a.Sign(new byte[1])), out _));
        Assert.True(S.TryParse(C.Login("alice", a.Sign(new byte[1])), out _));
        chA.Dispose(); chB.Dispose(); resp.Dispose();
    }
}
