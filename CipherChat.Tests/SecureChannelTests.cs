using System.Security.Cryptography;
using System.Text;
using CipherChatClient;
using Xunit;

namespace CipherChat.Tests;

public class SecureChannelTests
{
    private static byte[] Seq(int start) => Enumerable.Range(start, 32).Select(i => (byte)i).ToArray();

    // alice -> bob uses ckAB, bob -> alice uses ckBA.
    private static (SecureChannel a, SecureChannel b) Pair()
    {
        byte[] sid = Enumerable.Range(0, 16).Select(i => (byte)(0xA0 + i)).ToArray();
        return (new SecureChannel(sid, Seq(1), Seq(101)),
                new SecureChannel(sid, Seq(101), Seq(1)));
    }

    [Fact]
    public void ChainKeys_FrozenVector()
    {
        byte[] ck = Seq(64);
        string[] mk = { "01156abd78ef59f755f1e6945e5d1e2d7ddd1f1e5fe0a164b2f5fa8ad500bfba", "cc8aa93e9d19721c0c40f310be4d0383b891ee9f4b44bd608370dff83ed74819", "bb8124f922de66d1ca2d1de11076871f812e9e3ebf6672e0c511d5cbb331af09" };
        string[] next = { "f0bdefbbad3cf097dccb03f2c87159f7608e2480543eef7741c8f2e7f226e78f", "6a4d8bf82e78837f7c357918218611c2f51cb4a3c905430893f3dba14cfe3128", "060a465a37bf5c74f63b3030b95d77e55cd168a2256a36a2192aa458121e3d53" };
        for (int i = 0; i < 3; i++)
        {
            Assert.Equal(mk[i], Hex.S(SecureChannel.MessageKey(ck)));
            ck = SecureChannel.NextChainKey(ck);
            Assert.Equal(next[i], Hex.S(ck));
        }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(253)]
    [InlineData(254)]
    [InlineData(6000)]
    public void RoundTrip_AtVariousSizes_PaddedTo256Blocks(int bytes)
    {
        var (a, b) = Pair();
        string text = new('x', bytes);
        byte[] msg = a.SealText(text);
        Assert.Equal(26 + SecureChannel.PaddedLength(bytes) + 16, msg.Length);
        Assert.Equal(0, (msg.Length - 42) % 256);
        int chars = Convert.ToBase64String(msg).Length;
        Assert.InRange(chars, ProtocolLimits.MinMsgChars, ProtocolLimits.MaxMsgChars);
        OpenResult r = b.Open(msg);
        Assert.Equal((OpenStatus.Ok, MessageKind.Text, text), (r.Status, r.Kind, r.Text));
    }

    [Fact]
    public void PaddedSizes_AtTheExtremes_MatchBase64Limits()
    {
        var (a, _) = Pair();
        Assert.Equal(ProtocolLimits.MinMsgChars, Convert.ToBase64String(a.SealText("")).Length);
        Assert.Equal(ProtocolLimits.MaxMsgChars, Convert.ToBase64String(a.SealText(new string('x', 6000))).Length);
    }

    [Fact]
    public void TwoThousandThreeByteChars_FitAndRoundTrip()
    {
        var (a, b) = Pair();
        string text = new('€', ProtocolLimits.MaxMessageChars); // 3 bytes each = 6000
        Assert.Equal(6000, Encoding.UTF8.GetByteCount(text));
        Assert.Equal(text, b.Open(a.SealText(text)).Text);
        Assert.Throws<ArgumentException>(() => a.SealText(new string('x', 6001)));
    }

    [Fact]
    public void EndOfSession_IsAKind()
    {
        var (a, b) = Pair();
        OpenResult r = b.Open(a.SealEnd());
        Assert.Equal((OpenStatus.Ok, MessageKind.EndOfSession, ""), (r.Status, r.Kind, r.Text));
    }

    [Fact]
    public void TamperAnywhere_Fails_AndStateIsUnchanged()
    {
        var (a, b) = Pair();
        byte[] msg = a.SealText("secret");
        for (int i = 0; i < msg.Length; i++)
        {
            byte[] bad = (byte[])msg.Clone();
            bad[i] ^= 0x01;
            OpenResult r = b.Open(bad);
            Assert.NotEqual(OpenStatus.Ok, r.Status);
            Assert.Null(r.Text);
        }
        Assert.Equal(0UL, b.ReceivedCount);
        Assert.Equal("secret", b.Open(msg).Text);
    }

    [Fact]
    public void ForgedFarAheadLine_IsRejected_WithoutDesyncingTheSession()
    {
        var (a, b) = Pair();
        byte[] m0 = a.SealText("zero");
        byte[] m1 = a.SealText("one");
        byte[] forged = (byte[])m1.Clone();
        forged[25] = 50; // claims n = 50
        Assert.Equal(OpenStatus.OutOfOrder, b.Open(forged).Status);
        Assert.Equal("zero", b.Open(m0).Text);
        Assert.Equal("one", b.Open(m1).Text);
    }

    [Fact]
    public void OldVersionByte_IsRejected()
    {
        var (a, b) = Pair();
        byte[] m = a.SealText("hello");
        m[0] = 0x04;
        Assert.Equal(OpenStatus.Malformed, b.Open(m).Status);
        m[0] = 0x05;
        Assert.Equal("hello", b.Open(m).Text);
    }

    [Fact]
    public void HeaderIsAuthenticated_BindsSessionAndNumber()
    {
        // The AAD is the header: a message sealed in another session is never accepted, even under the same chain keys.
        var (a, _) = Pair();
        var other = new SecureChannel(Enumerable.Repeat((byte)7, 16).ToArray(), Seq(101), Seq(1));
        Assert.Equal(OpenStatus.UnknownSession, other.Open(a.SealText("x")).Status);
    }

    [Fact]
    public void Replay_IsDropped()
    {
        var (a, b) = Pair();
        byte[] m = a.SealText("once");
        Assert.Equal(OpenStatus.Ok, b.Open(m).Status);
        Assert.Equal(OpenStatus.Replay, b.Open(m).Status);
        byte[] m1 = a.SealText("two");
        Assert.Equal(OpenStatus.Ok, b.Open(m1).Status);
        Assert.Equal(OpenStatus.Replay, b.Open(m).Status);
    }

    [Fact]
    public void Reorder_Gap_AndWithholding_AreRejected_WithoutStateChange()
    {
        var (a, b) = Pair();
        byte[][] msgs = Enumerable.Range(0, 5).Select(i => a.SealText("m" + i)).ToArray();
        Assert.Equal(OpenStatus.OutOfOrder, b.Open(msgs[1]).Status);   // message 0 withheld or reordered
        Assert.Equal(OpenStatus.OutOfOrder, b.Open(msgs[4]).Status);
        Assert.Equal(0UL, b.ReceivedCount);
        Assert.Equal("m0", b.Open(msgs[0]).Text);
        Assert.Equal("m1", b.Open(msgs[1]).Text);
        Assert.Equal(OpenStatus.OutOfOrder, b.Open(msgs[3]).Status);   // m2 skipped
        Assert.Equal(OpenStatus.Replay, b.Open(msgs[0]).Status);
        Assert.Equal(2UL, b.ReceivedCount);
    }

    [Fact]
    public void SidMismatch_IsUnknownSession_AndMalformedShapesRejected()
    {
        var (a, b) = Pair();
        byte[] m = a.SealText("x");
        byte[] other = (byte[])m.Clone();
        other[2] ^= 1;
        Assert.Equal(OpenStatus.UnknownSession, b.Open(other).Status);
        Assert.Equal(OpenStatus.Malformed, b.Open(m[..^1]).Status);
        Assert.Equal(OpenStatus.Malformed, b.Open(new byte[10]).Status);
        Assert.Equal(OpenStatus.Malformed, b.Open(null).Status);
        byte[] wrongType = (byte[])m.Clone();
        wrongType[1] = 0x11;
        Assert.Equal(OpenStatus.Malformed, b.Open(wrongType).Status);
        byte[] tooBig = new byte[26 + 256 * 25 + 16];
        tooBig[0] = 5; tooBig[1] = 0x10;
        Assert.Equal(OpenStatus.Malformed, b.Open(tooBig).Status);
    }

    // Seals an arbitrary plaintext the way the sender would, to test receiver-side plaintext rules.
    private static byte[] SealRaw(byte[] ckSend, ulong n, byte[] plaintext, byte[] sid)
    {
        byte[] ck = ckSend;
        for (ulong i = 0; i < n; i++) ck = SecureChannel.NextChainKey(ck);
        byte[] header = new byte[26];
        header[0] = 5; header[1] = 0x10;
        sid.CopyTo(header, 2);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(header.AsSpan(18), n);
        byte[] nonce = new byte[12];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(nonce.AsSpan(4), n);
        byte[] aad = header;
        byte[] ct = new byte[plaintext.Length], tag = new byte[16];
        using AesGcm g = new(SecureChannel.MessageKey(ck), 16);
        g.Encrypt(nonce, plaintext, ct, tag, aad);
        return Proto.Concat(header, ct, tag);
    }

    [Fact]
    public void NonZeroPaddingAndBadPlaintextShapes_AreRejected()
    {
        byte[] sid = new byte[16];
        var b = new SecureChannel(sid, Seq(101), Seq(1));
        byte[] pt = new byte[256];
        pt[0] = 1; pt[1] = 0; pt[2] = 2; pt[3] = (byte)'h'; pt[4] = (byte)'i';
        Assert.Equal(OpenStatus.Ok, b.Open(SealRaw(Seq(1), 0, pt, sid)).Status);

        byte[] dirty = (byte[])pt.Clone();
        dirty[200] = 1;
        Assert.Equal(OpenStatus.BadPlaintext, b.Open(SealRaw(Seq(1), 1, dirty, sid)).Status);

        byte[] badLen = (byte[])pt.Clone();
        badLen[1] = 0xFF; badLen[2] = 0xFF;
        Assert.Equal(OpenStatus.BadPlaintext, b.Open(SealRaw(Seq(1), 2, badLen, sid)).Status);

        byte[] badKind = (byte[])pt.Clone();
        badKind[0] = 9;
        Assert.Equal(OpenStatus.BadPlaintext, b.Open(SealRaw(Seq(1), 3, badKind, sid)).Status);

        byte[] endWithText = (byte[])pt.Clone();
        endWithText[0] = 2;
        Assert.Equal(OpenStatus.BadPlaintext, b.Open(SealRaw(Seq(1), 4, endWithText, sid)).Status);

        byte[] notPadded = new byte[300];
        notPadded[0] = 1;
        Assert.Equal(OpenStatus.Malformed, b.Open(SealRaw(Seq(1), 5, notPadded, sid)).Status);

        byte[] overPadded = new byte[512];
        overPadded[0] = 1; overPadded[2] = 2; overPadded[3] = (byte)'h';
        Assert.Equal(OpenStatus.BadPlaintext, b.Open(SealRaw(Seq(1), 5, overPadded, sid)).Status);

        byte[] badUtf8 = (byte[])pt.Clone();
        badUtf8[3] = 0xFF; badUtf8[4] = 0xFE;
        Assert.Equal(OpenStatus.BadPlaintext, b.Open(SealRaw(Seq(1), 6, badUtf8, sid)).Status);
    }

    [Fact]
    public void MessageNumbersAndNonces_NeverRepeat_AndCiphertextsDiffer()
    {
        var (a, _) = Pair();
        HashSet<ulong> ns = new();
        HashSet<string> cts = new();
        for (int i = 0; i < 200; i++)
        {
            byte[] m = a.SealText("same text");
            ulong n = System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(m.AsSpan(18, 8));
            Assert.True(ns.Add(n));
            Assert.Equal((ulong)i, n);
            Assert.True(cts.Add(Convert.ToHexString(m, 26, m.Length - 26)));
        }
    }

    [Fact]
    public void OldChainKeys_AreZeroed_OnSealAndOpen()
    {
        var (a, b) = Pair();
        byte[] oldSend = a.SendChainKeyRef;
        byte[] oldRecv = b.RecvChainKeyRef;
        Assert.Contains(oldSend, x => x != 0);
        byte[] m = a.SealText("x");
        Assert.All(oldSend, x => Assert.Equal(0, x));
        Assert.NotSame(oldSend, a.SendChainKeyRef);
        Assert.Contains(oldRecv, x => x != 0);
        b.Open(m);
        Assert.All(oldRecv, x => Assert.Equal(0, x));

        byte[] live = b.RecvChainKeyRef;
        b.Dispose();
        Assert.All(live, x => Assert.Equal(0, x));
        Assert.Throws<ObjectDisposedException>(() => b.Open(m));
    }

    [Fact]
    public void FailedOpen_LeavesTheChainKeyUntouched()
    {
        var (a, b) = Pair();
        byte[] before = (byte[])b.RecvChainKeyRef.Clone();
        byte[] m = a.SealText("x");
        m[^1] ^= 1;
        b.Open(m);
        Assert.Equal(before, b.RecvChainKeyRef);
    }

    [Fact]
    public void SessionEndsAfterMaxMessages()
    {
        byte[] sid = new byte[16];
        var a = new SecureChannel(sid, Seq(1), Seq(101));
        // Fast-forward by sealing without keeping output would take 100k AES ops (fast enough, ~1 s).
        for (int i = 0; i < SecureChannel.MaxMessages; i++) a.SealEnd();
        Assert.Throws<InvalidOperationException>(() => a.SealText("one too many"));
    }

    [Fact]
    public void Handle_RoundTrips_AsAOneBlockMessage()
    {
        var (a, b) = Pair();
        byte[] m = a.SealHandle("Anna_1.x-y");
        Assert.Equal(26 + 256 + 16, m.Length);
        OpenResult r = b.Open(m);
        Assert.Equal((OpenStatus.Ok, MessageKind.Handle, "Anna_1.x-y"), (r.Status, r.Kind, r.Text));
        Assert.Equal("text after", b.Open(a.SealText("text after")).Text);
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("aaaaaaaaaaaaaaaaaaaaa")]    // 21
    [InlineData("a b")]
    [InlineData("caf\u00e9")]
    public void SealHandle_RejectsBadHandles(string handle)
    {
        var (a, _) = Pair();
        Assert.Throws<ArgumentException>(() => a.SealHandle(handle));
    }

    [Fact]
    public void Handle_StrictParsing_OnTheReceivingSide()
    {
        // oversized (21 bytes), empty, and a handle that is not valid UTF-8 are protocol violations
        var (a, b) = Pair();
        Assert.Equal(OpenStatus.BadPlaintext, b.Open(a.SealForTest(MessageKind.Handle, new byte[21].Select(_ => (byte)'a').ToArray())).Status);
        Assert.Equal(OpenStatus.BadPlaintext, b.Open(a.SealForTest(MessageKind.Handle, Array.Empty<byte>())).Status);
        Assert.Equal(OpenStatus.BadPlaintext, b.Open(a.SealForTest(MessageKind.Handle, new byte[] { 0xFF, 0xFE })).Status);
        // exactly 20 bytes is fine
        Assert.Equal(OpenStatus.Ok, b.Open(a.SealForTest(MessageKind.Handle, new byte[20].Select(_ => (byte)'a').ToArray())).Status);
    }

    [Fact]
    public void Directions_UseDifferentKeys()
    {
        var (a, b) = Pair();
        byte[] fromA = a.SealText("hello");
        // A message sealed by alice cannot be opened by alice's own receive chain.
        Assert.Equal(OpenStatus.AuthFailed, a.Open(fromA).Status);
        Assert.Equal(OpenStatus.Ok, b.Open(fromA).Status);
    }
}
