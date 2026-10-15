using System.Security.Cryptography;
using System.Text;
using CipherChatClient;
using Xunit;

namespace CipherChat.Tests;

// Known-answer tests from draft-irtf-cfrg-cpace-21 (Appendix A and B.3, ristretto255 / SHA-512). These pin down the
// string utilities, the libsodium P/Invoke marshalling and the ISK computation byte for byte; they must pass before
// anything else in the CPace code is trusted. Values are copied from the draft text.
public class CPaceKnownAnswerTests
{

    private const string GenStr = "11435061636552697374726574746f3235350850617373776f72646400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000180b415f696e69746961746f720b425f726573706f6e646572107e4b4791d6a8ef019b936c79fb7f2c57";
    private const string GenHash = "da6d3ddc8802fca9058755ffd3ebde08a9c2c74945901a258482a288b6663af06bf645c93cd1c51512307199c80e84908916d983b34af77205f90851a657ee27";
    private const string GenG = "222b6b195fe84b1652badb6f6a3ae3d24341e7306967f0b8115b40d5698c7e56";
    private const string YaScalar = "da3d23700a9e5699258aef94dc060dfda5ebb61f02a5ea77fad53f4ff0976d08", YbScalar = "d2316b454718c35362d83d69df6320f38578ed5984651435e2949762d900b80d";
    private const string Ya = "d6bac480f2c386c394efc7c47adb9925dcd2630b64f240c50f8d0eec482b9157", Yb = "3ea7e0b19560d7c0b0f5734f63b955286dfa8232b5ebe63324e2d9e7433f7258", KSecret = "80b69a8a76457ab6a4d7f887a4bf6b55a2f80ac19c333f917a05fc9887c8b40f";
    private const string TranscriptIr = "20d6bac480f2c386c394efc7c47adb9925dcd2630b64f240c50f8d0eec482b915703414461203ea7e0b19560d7c0b0f5734f63b955286dfa8232b5ebe63324e2d9e7433f725803414462", LvForIsk = "15435061636552697374726574746f3235355f49534b107e4b4791d6a8ef019b936c79fb7f2c572080b69a8a76457ab6a4d7f887a4bf6b55a2f80ac19c333f917a05fc9887c8b40f20d6bac480f2c386c394efc7c47adb9925dcd2630b64f240c50f8d0eec482b915703414461203ea7e0b19560d7c0b0f5734f63b955286dfa8232b5ebe63324e2d9e7433f725803414462", IskIr = "b69effbf61b51d56401c0f65601abe428de8206feaaf0e32198896dcae7b35cd2b38950a39dfd5d4a79164614c2984f7daa460b588c1e80c3fa2068af7900447";
    private const string SmS = "7cd0e075fa7955ba52c02759a6c90dbbfc10e6d40aea8d283e407d88cf538a05", SmX = "2c3c6b8c4f3800e7aef6864025b4ed79bd599117e427c41bd47d93d654b4a51c", SmOut = "7c13645fe790a468f62c39beb7388e541d8405d1ade69d1778c5fe3e7f6b600e", InvalidY = "2b3c6b8c4f3800e7aef6864025b4ed79bd599117e427c41bd47d93d654b4a51c";

    private static byte[] H(string hex) => Convert.FromHexString(hex);
    private static string S(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();
    private static byte[] Ascii(string s) => Encoding.ASCII.GetBytes(s);

    [Fact]
    public void A12_PrependLen()
    {
        Assert.Equal("00", S(CPace.PrependLen(Array.Empty<byte>())));
        Assert.Equal("0431323334", S(CPace.PrependLen(Ascii("1234"))));
        byte[] r127 = Enumerable.Range(0, 127).Select(i => (byte)i).ToArray();
        byte[] p127 = CPace.PrependLen(r127);
        Assert.Equal(128, p127.Length);
        Assert.Equal(0x7f, p127[0]);
        Assert.Equal(r127, p127[1..]);
        byte[] r128 = Enumerable.Range(0, 128).Select(i => (byte)i).ToArray();
        byte[] p128 = CPace.PrependLen(r128);
        Assert.Equal(130, p128.Length);
        Assert.Equal("8001", S(p128[..2]));
        Assert.Equal(r128, p128[2..]);
    }

    [Fact]
    public void A14_LvCat() =>
        Assert.Equal("043132333401350003363738", S(CPace.LvCat(Ascii("1234"), Ascii("5"), Array.Empty<byte>(), Ascii("678"))));

    [Fact]
    public void A35_TranscriptIr()
    {
        Assert.Equal("03313233065061727479410332333406506172747942", S(CPace.TranscriptIr(Ascii("123"), Ascii("PartyA"), Ascii("234"), Ascii("PartyB"))));
        Assert.Equal("043334353606506172747941043233343506506172747942", S(CPace.TranscriptIr(Ascii("3456"), Ascii("PartyA"), Ascii("2345"), Ascii("PartyB"))));
    }

    private static readonly byte[] Ci = H("0b415f696e69746961746f720b425f726573706f6e646572");
    private static readonly byte[] Sid = H("7e4b4791d6a8ef019b936c79fb7f2c57");

    [Fact]
    public void B31_GeneratorString_Hash_AndGenerator()
    {
        byte[] gs = CPace.GeneratorString(Ascii("CPaceRistretto255"), Ascii("Password"), Ci, Sid, 128);
        Assert.Equal(170, gs.Length);
        Assert.Equal(GenStr, S(gs));
        Assert.Equal(GenHash, S(SHA512.HashData(gs)));
        Assert.Equal(GenG, S(CPace.CalculateGenerator(Ascii("Password"), Ci, Sid)));
    }

    [Fact]
    public void B32_B33_MessagesFromScalars()
    {
        byte[] g = H(GenG);
        Assert.Equal(Ya, S(Sodium.ScalarMult(H(YaScalar), g)));
        Assert.Equal(Yb, S(Sodium.ScalarMult(H(YbScalar), g)));
    }

    [Fact]
    public void B34_SecretPoint_BothWays()
    {
        Assert.Equal(KSecret, S(Sodium.ScalarMult(H(YaScalar), H(Yb))));
        Assert.Equal(KSecret, S(Sodium.ScalarMult(H(YbScalar), H(Ya))));
    }

    [Fact]
    public void B35_Isk_InitiatorResponder()
    {
        byte[] ada = Ascii("ADa"), adb = Ascii("ADb");
        Assert.Equal(TranscriptIr, S(CPace.TranscriptIr(H(Ya), ada, H(Yb), adb)));
        Assert.Equal(LvForIsk, S(Proto.Concat(CPace.LvCat(Ascii("CPaceRistretto255_ISK"), Sid, H(KSecret)), CPace.TranscriptIr(H(Ya), ada, H(Yb), adb))));
        Assert.Equal(IskIr, S(CPace.ComputeIsk(Sid, H(KSecret), H(Ya), ada, H(Yb), adb)));
    }

    [Fact]
    public void B310_ScalarMult_Valid() =>
        Assert.Equal(SmOut, S(Sodium.ScalarMult(H(SmS), H(SmX))));

    [Fact]
    public void B311_InvalidPointAndIdentity_Abort()
    {
        Assert.Null(Sodium.ScalarMult(H(SmS), H(InvalidY)));
        Assert.Null(Sodium.ScalarMult(H(SmS), new byte[32]));
    }

    [Fact]
    public void Sodium_RejectsWrongLengths()
    {
        Assert.Throws<ArgumentException>(() => Sodium.ScalarMult(new byte[31], H(SmX)));
        Assert.Throws<ArgumentException>(() => Sodium.ScalarMult(H(SmS), new byte[33]));
        Assert.Throws<ArgumentException>(() => Sodium.PointFromHash(new byte[63]));
        Assert.Throws<ArgumentException>(() => Sodium.Argon2id(new byte[3], new byte[15], 3, 1024 * 1024));
    }
}

public class CPaceProtocolTests
{
    private const string Code = "correct horse battery staple";
    private const string Rid = "69f6e4";
    private static readonly byte[] NonceA = Enumerable.Range(1, 16).Select(i => (byte)i).ToArray();
    private static readonly byte[] NonceB = Enumerable.Range(101, 16).Select(i => (byte)i).ToArray();

    private static (CPace a, CPace b) Pair(string codeA = Code, string codeB = Code, byte[] peerNonceSeenByB = null)
    {
        CPace a = new(1, codeA, Rid, NonceA, NonceB);
        CPace b = new(2, codeB, Rid, NonceB, peerNonceSeenByB ?? NonceA);
        return (a, b);
    }

    // Runs the whole exchange; returns (aOk, bOk, channels).
    private static (bool, bool, SecureChannel, SecureChannel) Run(CPace a, CPace b)
    {
        byte[] ya = a.CreateKeyMessage(), yb = b.CreateKeyMessage();
        bool ka = a.ReceiveKey(yb), kb = b.ReceiveKey(ya);
        if (!ka || !kb) return (false, false, null, null);
        byte[] ta = a.CreateConfirm(), tb = b.CreateConfirm();
        bool oa = a.VerifyConfirm(tb), ob = b.VerifyConfirm(ta);
        return (oa, ob, oa ? a.CreateChannel() : null, ob ? b.CreateChannel() : null);
    }

    [Fact]
    public void HappyPath_GivesWorkingChannelsInBothDirections()
    {
        var (a, b) = Pair();
        var (oa, ob, cha, chb) = Run(a, b);
        Assert.True(oa && ob);
        Assert.Equal(CPaceState.Confirmed, a.State);
        Assert.Equal("hello", chb.Open(cha.SealText("hello")).Text);
        Assert.Equal("hi", cha.Open(chb.SealText("hi")).Text);
        Assert.Equal(cha.SessionId, chb.SessionId);
    }

    [Fact]
    public void DifferentCodes_FailOnBothSides()
    {
        var (a, b) = Pair(Code, "correct horse battery stapl3");
        byte[] ya = a.CreateKeyMessage(), yb = b.CreateKeyMessage();
        Assert.True(a.ReceiveKey(yb)); Assert.True(b.ReceiveKey(ya));
        byte[] ta = a.CreateConfirm(), tb = b.CreateConfirm();
        Assert.False(a.VerifyConfirm(tb));
        Assert.False(b.VerifyConfirm(ta));
        Assert.Equal(CPaceState.Failed, a.State);
        Assert.Throws<InvalidOperationException>(() => a.CreateChannel());
    }

    [Fact]
    public void DifferentRid_FailsToo()
    {
        CPace a = new(1, Code, "aaaaaa", NonceA, NonceB), b = new(2, Code, "bbbbbb", NonceB, NonceA);
        var (oa, ob, _, _) = Run(a, b);
        Assert.False(oa); Assert.False(ob);
    }

    [Fact]
    public void BothToldRole1_Fails()
    {
        CPace a = new(1, Code, Rid, NonceA, NonceB), b = new(1, Code, Rid, NonceB, NonceA);
        var (oa, ob, _, _) = Run(a, b);
        Assert.False(oa); Assert.False(ob);
    }

    [Fact]
    public void BothToldRole2_Fails()
    {
        CPace a = new(2, Code, Rid, NonceA, NonceB), b = new(2, Code, Rid, NonceB, NonceA);
        var (oa, ob, _, _) = Run(a, b);
        Assert.False(oa); Assert.False(ob);
    }

    [Fact]
    public void ReflectedOwnKey_IsRejected()
    {
        var (a, _) = Pair();
        byte[] ya = a.CreateKeyMessage();
        Assert.False(a.ReceiveKey(ya));
        Assert.Equal(CPaceState.Failed, a.State);
    }

    [Fact]
    public void ReflectedOwnTag_IsRejected()
    {
        var (a, b) = Pair();
        byte[] ya = a.CreateKeyMessage(), yb = b.CreateKeyMessage();
        a.ReceiveKey(yb); b.ReceiveKey(ya);
        Assert.False(a.VerifyConfirm(a.CreateConfirm()));
    }

    [Fact]
    public void EveryByteOfKey_WhenFlipped_BreaksTheHandshake()
    {
        for (int i = 0; i < 32; i++)
        {
            var (a, b) = Pair();
            byte[] ya = a.CreateKeyMessage(), yb = b.CreateKeyMessage();
            byte[] bad = (byte[])yb.Clone();
            bad[i] ^= 0x01;
            bool ka = a.ReceiveKey(bad);
            bool kb = b.ReceiveKey(ya);
            bool ok = ka && kb && a.VerifyConfirm(b.CreateConfirm());
            Assert.False(ok, $"byte {i}");
        }
    }

    [Fact]
    public void EveryByteOfConfirm_WhenFlipped_IsRejected()
    {
        for (int i = 0; i < 64; i++)
        {
            var (a, b) = Pair();
            byte[] ya = a.CreateKeyMessage(), yb = b.CreateKeyMessage();
            a.ReceiveKey(yb); b.ReceiveKey(ya);
            byte[] tb = b.CreateConfirm();
            tb[i] ^= 0x01;
            Assert.False(a.VerifyConfirm(tb), $"byte {i}");
        }
        var (a2, b2) = Pair();
        byte[] y1 = a2.CreateKeyMessage(), y2 = b2.CreateKeyMessage();
        a2.ReceiveKey(y2); b2.ReceiveKey(y1);
        Assert.False(a2.VerifyConfirm(b2.CreateConfirm()[..63]));
    }

    [Fact]
    public void InvalidAndIdentityPoints_AndWrongLengths_AreRejected()
    {
        foreach (byte[] bad in new[] { new byte[32], Convert.FromHexString("2b3c6b8c4f3800e7aef6864025b4ed79bd599117e427c41bd47d93d654b4a51c"), new byte[31], new byte[33], null })
        {
            var (a, _) = Pair();
            a.CreateKeyMessage();
            Assert.False(a.ReceiveKey(bad));
            Assert.Equal(CPaceState.Failed, a.State);
        }
    }

    [Fact]
    public void WrongOrder_IsRejected()
    {
        // second KEY
        var (a, b) = Pair();
        byte[] ya = a.CreateKeyMessage(), yb = b.CreateKeyMessage();
        Assert.True(a.ReceiveKey(yb));
        Assert.False(a.ReceiveKey(yb));

        // CONFIRM before KEY
        var (c, d) = Pair();
        c.CreateKeyMessage(); d.CreateKeyMessage();
        Assert.False(c.VerifyConfirm(new byte[64]));
        Assert.Throws<InvalidOperationException>(() => d.CreateConfirm());

        // receiving a key before our own was created
        var (e, f) = Pair();
        Assert.False(e.ReceiveKey(f.CreateKeyMessage()));

        // channel only after a verified CONFIRM
        var (g, h) = Pair();
        byte[] yg = g.CreateKeyMessage(), yh = h.CreateKeyMessage();
        g.ReceiveKey(yh);
        Assert.Throws<InvalidOperationException>(() => g.CreateChannel());
        _ = yg;
    }

    [Fact]
    public void DifferentSid_BreaksTheHandshake()
    {
        var (a, b) = Pair(peerNonceSeenByB: Enumerable.Repeat((byte)9, 16).ToArray());
        var (oa, ob, _, _) = Run(a, b);
        Assert.False(oa); Assert.False(ob);
    }

    [Fact]
    public void TwoRuns_GiveDifferentKeysAndMessages()
    {
        var (a1, b1) = Pair(); var (a2, b2) = Pair();
        byte[] y1 = a1.CreateKeyMessage(), y2 = a2.CreateKeyMessage();
        Assert.NotEqual(y1, y2);
        b1.CreateKeyMessage(); b2.CreateKeyMessage();
        // same nonces and code, fresh scalars: the channels' first ciphertexts differ
        var (a3, b3) = Pair(); var (a4, b4) = Pair();
        var (_, _, c3, _) = Run(a3, b3); var (_, _, c4, _) = Run(a4, b4);
        Assert.NotEqual(c3.SealText("same"), c4.SealText("same"));
    }

    [Fact]
    public void FixedScalar_GivesAReproducibleKeyMessage()
    {
        byte[] scalar = Convert.FromHexString("da3d23700a9e5699258aef94dc060dfda5ebb61f02a5ea77fad53f4ff0976d08");
        CPace x = new(1, Code, Rid, NonceA, NonceB, scalar), y = new(1, Code, Rid, NonceA, NonceB, scalar);
        Assert.Equal(x.CreateKeyMessage(), y.CreateKeyMessage());
    }

    [Fact]
    public void FrozenVectors_SessionKeysAndTagWrapper()
    {
        byte[] isk = Enumerable.Range(0, 64).Select(i => (byte)i).ToArray();
        byte[] sid = Enumerable.Range(100, 32).Select(i => (byte)i).ToArray();
        CPace.DeriveSession(isk, sid, out var ck12, out var ck21, out var chan);
        Assert.Equal("8ef76bf12b9329a9f2e713057b43c622c3e6716fc51d8c7b52733af05286aa7a", Hex.S(ck12));
        Assert.Equal("b2a77a347784c2f12e14e2fe09d78937180cb6c58b16a647910f81b1d9ceaf57", Hex.S(ck21));
        Assert.Equal("66dd3caa9b88d544c41d05d1e9fb2d51", Hex.S(chan));
        byte[] mk = CPace.ComputeMacKey(sid, isk);
        Assert.Equal("77945fbaf6ca53b22b324da9ac21c1d046edf8d2cd5ebe206a3ab20a534b1790c0f9da961f247fd860a241be355222f31fd56335dd4c57c432af2b104215b44e", Hex.S(mk));
        Assert.Equal("3b6a9ec33d9e5e3d45bfaea9078f869d0e36a6908ba6b62f8b83edbf4477590beeb938e4b54c336080bdf48856c026806d165ccac4271b63186bb538e6875d21",
            Hex.S(CPace.Tag(mk, Enumerable.Repeat((byte)0x11, 32).ToArray(), new byte[] { 1 })));
    }

    [Fact]
    public void Constructor_RejectsBadArguments()
    {
        Assert.Throws<ArgumentException>(() => new CPace(3, Code, Rid, NonceA, NonceB));
        Assert.Throws<ArgumentException>(() => new CPace(1, Code, Rid, new byte[15], NonceB));
        Assert.Throws<ArgumentException>(() => new CPace(1, Code, Rid, NonceA, null));
    }
}
