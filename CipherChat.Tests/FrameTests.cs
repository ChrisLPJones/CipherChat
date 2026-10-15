using System.Security.Cryptography;
using CipherChatClient;
using Xunit;
using S = CipherChatServer.ServerFrame;
using C = CipherChatClient.ClientFrame;

namespace CipherChat.Tests;

// Wire protocol v5: the closed grammar on both sides, cross-checked against each other.
public class FrameTests
{
    private const string Rid = "0a1b2c";
    private static readonly string Nonce = new string('9', 16) + "abcdef0123456789";
    private static byte[] R(int n) => RandomNumberGenerator.GetBytes(n);
    private static string B(int n) => Convert.ToBase64String(R(n));
    private static string MsgBlob(int blocks) => B(26 + 256 * blocks + 16);

    // ---- every line, both ways ----

    [Fact]
    public void ClientFormats_ParseOnServer()
    {
        Assert.True(S.TryParse(C.Hello(Rid, Nonce), out var c));
        Assert.Equal((CipherChatServer.ClientVerb.Hello, Rid, Nonce), (c.Verb, c.Rid, c.Nonce));

        byte[] key = R(32), tag = R(64);
        Assert.True(S.TryParse(C.Key(key), out c));
        Assert.Equal((CipherChatServer.ClientVerb.Key, Convert.ToBase64String(key)), (c.Verb, c.Data));
        Assert.True(S.TryParse(C.Confirm(tag), out c));
        Assert.Equal((CipherChatServer.ClientVerb.Confirm, Convert.ToBase64String(tag)), (c.Verb, c.Data));
        Assert.True(S.TryParse(C.Ping(), out c));
        Assert.Equal(CipherChatServer.ClientVerb.Ping, c.Verb);
        for (int k = 1; k <= 24; k++)
        {
            byte[] msg = R(26 + 256 * k + 16);
            Assert.True(S.TryParse(C.Msg(msg), out c), $"k={k}");
            Assert.Equal(CipherChatServer.ClientVerb.Msg, c.Verb);
            Assert.Equal(Convert.ToBase64String(msg), c.Data);
        }
    }

    [Fact]
    public void ServerFormats_ParseOnClient()
    {
        Assert.True(C.TryParse(S.Wait, out var e));
        Assert.Equal(ServerEventKind.Wait, e.Kind);
        foreach (int role in new[] { 1, 2 })
        {
            Assert.True(C.TryParse(S.Paired(role, Nonce), out e));
            Assert.Equal((ServerEventKind.Paired, role, Nonce), (e.Kind, e.Role, e.Nonce));
        }
        string k = B(32), t = B(64), m = MsgBlob(3);
        Assert.True(C.TryParse(S.Relay(CipherChatServer.ClientVerb.Key, k), out e));
        Assert.Equal((ServerEventKind.Key, k), (e.Kind, e.Data));
        Assert.True(C.TryParse(S.Relay(CipherChatServer.ClientVerb.Confirm, t), out e));
        Assert.Equal((ServerEventKind.Confirm, t), (e.Kind, e.Data));
        Assert.True(C.TryParse(S.Relay(CipherChatServer.ClientVerb.Msg, m), out e));
        Assert.Equal((ServerEventKind.Msg, m), (e.Kind, e.Data));
        Assert.True(C.TryParse(S.Gone, out e));
        Assert.Equal(ServerEventKind.Gone, e.Kind);
        Assert.True(C.TryParse(S.Pong, out e));
        Assert.Equal(ServerEventKind.Pong, e.Kind);
        foreach (string code in S.ErrorCodes)
        {
            Assert.True(C.TryParse(S.Err(code), out e), code);
            Assert.Equal((ServerEventKind.Err, code), (e.Kind, e.Data));
        }
        Assert.Equal(S.ErrorCodes, C.ErrorCodes);
        Assert.Equal(new[] { "version", "used", "full", "rate", "timeout" }, S.ErrorCodes);
    }

    // ---- exact lengths ----

    [Fact]
    public void ExactLengths_PlusMinusOne_AreRejected()
    {
        Assert.True(S.TryParse($"KEY {B(32)}", out _));
        Assert.False(S.TryParse($"KEY {B(31)}", out _));
        Assert.False(S.TryParse($"KEY {B(33)}", out _));
        Assert.True(C.TryParse($"KEY {B(32)}", out _));
        Assert.False(C.TryParse($"KEY {B(31)}", out _));
        Assert.False(C.TryParse($"KEY {B(33)}", out _));
        Assert.True(S.TryParse($"CONFIRM {B(64)}", out _));
        Assert.False(S.TryParse($"CONFIRM {B(63)}", out _));
        Assert.False(S.TryParse($"CONFIRM {B(65)}", out _));
        Assert.True(C.TryParse($"CONFIRM {B(64)}", out _));
        Assert.False(C.TryParse($"CONFIRM {B(63)}", out _));
        Assert.False(C.TryParse($"CONFIRM {B(65)}", out _));
        for (int k = 1; k <= 24; k++)
        {
            int total = 26 + 256 * k + 16;
            Assert.True(S.TryParse($"MSG {B(total)}", out _));
            Assert.False(S.TryParse($"MSG {B(total - 1)}", out _));
            Assert.False(S.TryParse($"MSG {B(total + 1)}", out _));
            Assert.True(C.TryParse($"MSG {B(total)}", out _));
            Assert.False(C.TryParse($"MSG {B(total - 1)}", out _));
            Assert.False(C.TryParse($"MSG {B(total + 1)}", out _));
        }
        Assert.False(S.TryParse($"MSG {MsgBlob(25)}", out _));
        Assert.False(S.TryParse($"MSG {B(26 + 16)}", out _));   // zero blocks
    }

    [Fact]
    public void Hex_CharsetCaseAndLength()
    {
        Assert.True(S.TryParse($"HELLO 5 {Rid} {Nonce}", out _));
        Assert.False(S.TryParse($"HELLO 5 {Rid[..5]} {Nonce}", out _));
        Assert.False(S.TryParse($"HELLO 5 {Rid}0 {Nonce}", out _));
        Assert.False(S.TryParse($"HELLO 5 {Rid} {Nonce[..31]}", out _));
        Assert.False(S.TryParse($"HELLO 5 {Rid} {Nonce}0", out _));
        Assert.False(S.TryParse($"HELLO 5 0A1B2C {Nonce}", out _));                    // uppercase
        Assert.False(S.TryParse($"HELLO 5 {Rid} {Nonce.ToUpperInvariant()}", out _));
        Assert.False(S.TryParse($"HELLO 5 0a1b2g {Nonce}", out _));                    // not hex
        Assert.False(S.TryParse($"HELLO 5 0a1b2c {Nonce[..31]}z", out _));
        Assert.False(S.TryParse($"HELLO 5 0a1b2c {Nonce[..31]}-", out _));
        Assert.True(C.TryParse($"PAIRED 1 {Nonce}", out _));
        Assert.False(C.TryParse($"PAIRED 1 {Nonce.ToUpperInvariant()}", out _));
        Assert.False(C.TryParse($"PAIRED 1 {Nonce[..31]}", out _));
        Assert.False(C.TryParse($"PAIRED 1 {Nonce}0", out _));
        Assert.False(C.TryParse($"PAIRED 0 {Nonce}", out _));
        Assert.False(C.TryParse($"PAIRED 3 {Nonce}", out _));
        Assert.False(C.TryParse($"PAIRED 01 {Nonce}", out _));
        Assert.False(C.TryParse($"PAIRED {Nonce}", out _));
    }

    [Fact]
    public void NonCanonicalBase64_IsRejectedOnBothSides()
    {
        string good = Convert.ToBase64String(new byte[32]);              // 43 chars + '='
        Assert.True(S.TryParse($"KEY {good}", out _) && C.TryParse($"KEY {good}", out _));
        string trailingBits = good[..^2] + "B=";                         // unused bits set
        Assert.False(S.TryParse($"KEY {trailingBits}", out _));
        Assert.False(C.TryParse($"KEY {trailingBits}", out _));
        Assert.Null(C.DecodeBlob(trailingBits));
        Assert.False(S.TryParse($"KEY {good.TrimEnd('=')}", out _));      // padding stripped
        Assert.False(S.TryParse($"KEY {good[..^1]}==", out _));           // wrong amount of padding
        Assert.False(S.TryParse($"KEY ={good[1..]}", out _));             // padding at the start
        Assert.False(S.TryParse($"KEY {good.Replace('A', '-')}", out _)); // URL-safe alphabet / junk
        Assert.False(S.TryParse($"KEY {good[..20]} {good[20..]}", out _)); // whitespace inside
        string tag = Convert.ToBase64String(new byte[64]);                // ends with "=="
        Assert.True(S.TryParse($"CONFIRM {tag}", out _));
        Assert.False(S.TryParse($"CONFIRM {tag[..^2]}AA", out _));
        Assert.False(S.TryParse($"CONFIRM {tag[..^3]}B==", out _));
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

    // ---- structure ----

    public static IEnumerable<object[]> BadClientLines()
    {
        string key = B(32), tag = B(64), msg = MsgBlob(1);
        yield return new object[] { "" };
        yield return new object[] { " " };
        yield return new object[] { "FOO bar" };
        yield return new object[] { "hello 5 0a1b2c " + new string('a', 32) };       // verb is case sensitive
        yield return new object[] { "HELLO" };
        yield return new object[] { "HELLO 5" };
        yield return new object[] { "HELLO 5 0a1b2c" };
        yield return new object[] { "HELLO 4" };
        yield return new object[] { "HELLO 4 0a1b2c " + new string('a', 32) };       // wrong version
        yield return new object[] { "HELLO 3" };
        yield return new object[] { "HELLO 05 0a1b2c " + new string('a', 32) };
        yield return new object[] { "HELLO 5  0a1b2c " + new string('a', 32) };      // double space
        yield return new object[] { "HELLO 5 0a1b2c " + new string('a', 32) + " " };  // trailing space
        yield return new object[] { " HELLO 5 0a1b2c " + new string('a', 32) };      // leading space
        yield return new object[] { "HELLO 5 0a1b2c " + new string('a', 32) + " x" };
        yield return new object[] { "PING x" };
        yield return new object[] { "PING " };
        yield return new object[] { "KEY" };
        yield return new object[] { "KEY " + key + " x" };
        yield return new object[] { "KEY " + key + "\r" };
        yield return new object[] { "KEY " + key[..10] + "\u001b[2J" + key[10..] };
        yield return new object[] { "CONFIRM" };
        yield return new object[] { "CONFIRM " + key };                              // 32 bytes is not a tag
        yield return new object[] { "MSG" };
        yield return new object[] { "MSG " + tag };
        yield return new object[] { "MSG " + msg + " x" };
        yield return new object[] { "MSG bob " + msg };                              // v4 form with a user name
        yield return new object[] { "WAIT" };                                        // server verbs are not client verbs
        yield return new object[] { "PAIRED 1 " + new string('a', 32) };
        yield return new object[] { "GONE" };
        yield return new object[] { "ERR timeout" };
        // v4 lines
        yield return new object[] { "REGISTER alice " + B(65) + " " + B(64) };
        yield return new object[] { "LOGIN alice " + B(64) };
        yield return new object[] { "KEY bob" };
        yield return new object[] { "OFFER bob " + B(156) };
        yield return new object[] { "ACCEPT bob " + B(179) };
        yield return new object[] { "CONFIRM bob " + B(50) };
        yield return new object[] { "KNOCK bob " + B(74) };
        yield return new object[] { "USERS" };
    }

    [Theory]
    [MemberData(nameof(BadClientLines))]
    public void Malformed_IsRejectedOnServer(string line) => Assert.False(S.TryParse(line, out _));

    public static IEnumerable<object[]> BadServerLines()
    {
        string key = B(32), tag = B(64), msg = MsgBlob(1);
        yield return new object[] { "" };
        yield return new object[] { "wait" };
        yield return new object[] { "WAIT x" };
        yield return new object[] { "WAIT " };
        yield return new object[] { "GONE bob" };
        yield return new object[] { "PONG extra" };
        yield return new object[] { "PAIRED" };
        yield return new object[] { "PAIRED 1" };
        yield return new object[] { "PAIRED 1 2 " + new string('a', 32) };
        yield return new object[] { "KEY" };
        yield return new object[] { "KEY bob " + key };                              // v4 form with a sender
        yield return new object[] { "KEY " + B(33) };
        yield return new object[] { "CONFIRM " + key };
        yield return new object[] { "CONFIRM alice " + tag };
        yield return new object[] { "MSG alice " + msg };
        yield return new object[] { "MSG " + msg[..^4] };
        yield return new object[] { "ERR" };
        yield return new object[] { "ERR Rate" };
        yield return new object[] { "ERR unknowncode" };
        yield return new object[] { "ERR rate bob" };
        yield return new object[] { "ERR nouser bob" };                              // v4 code
        yield return new object[] { "ERR auth" };
        yield return new object[] { "ERR replaced" };
        yield return new object[] { "ERR used extra" };
        // v4 lines
        yield return new object[] { "WELCOME 4 " + B(32) };
        yield return new object[] { "READY alice" };
        yield return new object[] { "OFFLINE bob" };
        yield return new object[] { "GONE bob" };
        yield return new object[] { "USERLIST 0" };
        yield return new object[] { "OFFER bob " + B(156) };
    }

    [Theory]
    [MemberData(nameof(BadServerLines))]
    public void Malformed_IsRejectedOnClient(string line) => Assert.False(C.TryParse(line, out _));

    [Fact]
    public void LineLimits_MaxMsgFits_AndOverLengthIsRejected()
    {
        string max = MsgBlob(24);
        Assert.Equal(ProtocolLimits.MaxMsgChars, max.Length);
        string line = C.Msg(R(26 + 256 * 24 + 16));
        Assert.Equal("MSG ".Length + 8248, line.Length);
        Assert.True(line.Length <= ProtocolLimits.MaxLineChars);
        Assert.True(S.TryParse(line, out _));
        Assert.True(C.TryParse(line, out _));
        Assert.False(S.TryParse(new string('A', ProtocolLimits.MaxLineChars + 1), out _));
        Assert.False(C.TryParse(new string('A', ProtocolLimits.MaxLineChars + 1), out _));
        Assert.False(S.TryParse("MSG " + new string('A', ProtocolLimits.MaxMsgChars + 4), out _));
        Assert.False(S.TryParse(null, out _));
        Assert.False(C.TryParse(null, out _));
    }

    [Fact]
    public void SizeConstants_MatchTheByteLayouts()
    {
        Assert.Equal(ProtocolLimits.KeyChars, B(32).Length);
        Assert.Equal(ProtocolLimits.ConfirmChars, B(64).Length);
        Assert.Equal(ProtocolLimits.MinMsgChars, MsgBlob(1).Length);
        Assert.Equal(ProtocolLimits.MaxMsgChars, MsgBlob(24).Length);
        Assert.Equal(ProtocolLimits.RidChars, Rid.Length);
        Assert.Equal(ProtocolLimits.NonceChars, Nonce.Length);
        Assert.Equal(ProtocolLimits.MaxTextBytes, ProtocolLimits.MaxMessageChars * 3);
        Assert.True(24 * ProtocolLimits.PadBlock >= 3 + ProtocolLimits.MaxTextBytes);
    }

    [Fact]
    public void RealSessionOutput_ParsesOnBothSides()
    {
        byte[] nonceA = R(16), nonceB = R(16);
        using CPace a = new(1, "correct horse battery staple", "69f6e4", nonceA, nonceB);
        using CPace b = new(2, "correct horse battery staple", "69f6e4", nonceB, nonceA);
        byte[] ya = a.CreateKeyMessage(), yb = b.CreateKeyMessage();
        a.ReceiveKey(yb); b.ReceiveKey(ya);
        Assert.True(S.TryParse(C.Hello("69f6e4", Convert.ToHexString(nonceA).ToLowerInvariant()), out _));
        Assert.True(S.TryParse(C.Key(ya), out _));
        Assert.True(S.TryParse(C.Confirm(a.CreateConfirm()), out _));
        using SecureChannel ch = new(new byte[16], R(32), R(32));
        Assert.True(S.TryParse(C.Msg(ch.SealText("")), out _));
        Assert.True(S.TryParse(C.Msg(ch.SealText(new string('x', 6000))), out _));
        Assert.True(C.TryParse(S.Relay(CipherChatServer.ClientVerb.Msg, Convert.ToBase64String(ch.SealText("hi"))), out _));
    }
}
