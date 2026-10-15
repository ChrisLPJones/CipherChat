using System.Security.Cryptography;
using System.Text;

namespace CipherChatClient;

public enum CPaceState { Started, KeySent, KeyReceived, Confirmed, Failed }

// CPace, cipher suite CPACE-RISTR255-SHA512, exactly per draft-irtf-cfrg-cpace-21 (April 2026); the draft's
// Appendix A/B vectors are tested byte for byte. Re-check them if the draft revision is ever changed.
//
// PRS = the normalized code (ASCII), sid = nonce(role 1) || nonce(role 2), CI = lv_cat("CipherChat-v5", rid),
// ADa = 0x01, ADb = 0x02 (implicit from the role), transcript_ir. Key confirmation is draft section 10.4.
// Only the glue is ours; the group operations come from libsodium (Sodium.cs).
internal sealed class CPace : IDisposable
{
    public const string Dsi = "CPaceRistretto255";
    public const int SInBytes = 128;                 // SHA-512 input block size
    public const string AppLabel = "CipherChat-v5";
    public const int NonceBytes = 16;

    private readonly int role;                       // 1 = A (initiator), 2 = B
    private readonly byte[] sid;
    private readonly byte[] ownAd, peerAd;
    private byte[] y;                                // our scalar (zeroed after K is computed)
    private byte[] ownY;
    private byte[] peerY;
    private byte[] isk;
    private byte[] macKey;
    private byte[] ckSend, ckRecv, chanId;

    public CPaceState State { get; private set; } = CPaceState.Started;

    // fixedScalar is a test hook (the draft's vectors use given scalars); production passes null.
    public CPace(int role, string normalizedCode, string rid, byte[] ownNonce, byte[] peerNonce, byte[] fixedScalar = null)
    {
        if (role != 1 && role != 2) throw new ArgumentException("Invalid role.");
        if (ownNonce is not { Length: NonceBytes } || peerNonce is not { Length: NonceBytes }) throw new ArgumentException("Invalid nonce.");
        this.role = role;
        sid = role == 1 ? Proto.Concat(ownNonce, peerNonce) : Proto.Concat(peerNonce, ownNonce);
        ownAd = new[] { (byte)role };
        peerAd = new[] { (byte)(3 - role) };

        byte[] prs = Encoding.ASCII.GetBytes(normalizedCode);
        byte[] ci = LvCat(Encoding.ASCII.GetBytes(AppLabel), Encoding.ASCII.GetBytes(rid));
        byte[] g = CalculateGenerator(prs, ci, sid);
        CryptographicOperations.ZeroMemory(prs);
        y = fixedScalar != null ? (byte[])fixedScalar.Clone() : Sodium.RandomScalar();
        ownY = Sodium.ScalarMult(y, g);
        if (ownY == null) { Fail(); throw new CryptographicException("Key generation failed."); }
    }

    // ---- string utilities (draft Appendix A.1-A.3) ----

    internal static byte[] PrependLen(byte[] data)
    {
        List<byte> r = new();
        int length = data.Length;
        while (true)
        {
            if (length < 128) r.Add((byte)length);
            else r.Add((byte)((length & 0x7f) + 0x80));
            length >>= 7;
            if (length == 0) break;
        }
        r.AddRange(data);
        return r.ToArray();
    }

    internal static byte[] LvCat(params byte[][] args)
    {
        byte[] r = Array.Empty<byte>();
        foreach (byte[] a in args) r = Proto.Concat(r, PrependLen(a));
        return r;
    }

    internal static byte[] GeneratorString(byte[] dsi, byte[] prs, byte[] ci, byte[] sid, int sInBytes)
    {
        int lenZpad = Math.Max(0, sInBytes - 1 - PrependLen(prs).Length - PrependLen(dsi).Length);
        return LvCat(dsi, prs, new byte[lenZpad], ci, sid);
    }

    internal static byte[] CalculateGenerator(byte[] prs, byte[] ci, byte[] sid)
    {
        byte[] genStr = GeneratorString(Encoding.ASCII.GetBytes(Dsi), prs, ci, sid, SInBytes);
        byte[] hash = SHA512.HashData(genStr);
        return Sodium.PointFromHash(hash);
    }

    internal static byte[] TranscriptIr(byte[] ya, byte[] ada, byte[] yb, byte[] adb) =>
        Proto.Concat(LvCat(ya, ada), LvCat(yb, adb));

    internal static byte[] ComputeIsk(byte[] sid, byte[] k, byte[] ya, byte[] ada, byte[] yb, byte[] adb) =>
        SHA512.HashData(Proto.Concat(LvCat(Encoding.ASCII.GetBytes(Dsi + "_ISK"), sid, k), TranscriptIr(ya, ada, yb, adb)));

    internal static byte[] ComputeMacKey(byte[] sid, byte[] isk) =>
        SHA512.HashData(Proto.Concat(Encoding.ASCII.GetBytes("CPaceMac"), sid, isk));

    // Our key-confirmation tag over the message we sent: HMAC-SHA-512(mac_key, lv_cat(Y, AD)).
    internal static byte[] Tag(byte[] macKey, byte[] y, byte[] ad) => HMACSHA512.HashData(macKey, LvCat(y, ad));

    // okm = HKDF-SHA256(ikm = ISK, salt = sid, info = "CipherChat-v5/session\0", 80) = ck12 || ck21 || chanId(16)
    internal static void DeriveSession(byte[] isk, byte[] sid, out byte[] ck12, out byte[] ck21, out byte[] chanId)
    {
        byte[] okm = HKDF.DeriveKey(HashAlgorithmName.SHA256, isk, 80, sid, Proto.Label("CipherChat-v5/session"));
        ck12 = okm[0..32]; ck21 = okm[32..64]; chanId = okm[64..80];
        CryptographicOperations.ZeroMemory(okm);
    }

    // ---- protocol steps ----

    // Our message Y (32 bytes): send it as KEY.
    public byte[] CreateKeyMessage()
    {
        if (State != CPaceState.Started) { Fail(); throw new InvalidOperationException("Key already created."); }
        State = CPaceState.KeySent;
        return (byte[])ownY.Clone();
    }

    // Processes the peer's Y. False = abort (wrong order, wrong length, our own Y reflected, invalid or identity point).
    public bool ReceiveKey(byte[] peer)
    {
        if (State != CPaceState.KeySent || peer is not { Length: Sodium.PointBytes }) return Fail();
        if (CryptographicOperations.FixedTimeEquals(peer, ownY)) return Fail();   // reflection
        byte[] k = Sodium.ScalarMult(y, peer);
        if (k == null) return Fail();                                             // invalid encoding or identity
        byte[] ya = role == 1 ? ownY : peer, yb = role == 1 ? peer : ownY;
        isk = ComputeIsk(sid, k, ya, new byte[] { 1 }, yb, new byte[] { 2 });
        CryptographicOperations.ZeroMemory(k);                                    // K is never exposed
        CryptographicOperations.ZeroMemory(y);
        y = null;
        macKey = ComputeMacKey(sid, isk);
        peerY = (byte[])peer.Clone();
        DeriveSession(isk, sid, out byte[] ck12, out byte[] ck21, out chanId);
        ckSend = role == 1 ? ck12 : ck21;
        ckRecv = role == 1 ? ck21 : ck12;
        CryptographicOperations.ZeroMemory(isk);
        isk = null;
        State = CPaceState.KeyReceived;
        return true;
    }

    // Our CONFIRM tag (64 bytes); only after the peer's key was processed.
    public byte[] CreateConfirm()
    {
        if (State != CPaceState.KeyReceived) { Fail(); throw new InvalidOperationException("Not ready to confirm."); }
        return Tag(macKey, ownY, ownAd);
    }

    // Verifies the peer's CONFIRM tag in constant time. False = abort.
    public bool VerifyConfirm(byte[] tag)
    {
        if (State != CPaceState.KeyReceived || tag is not { Length: 64 }) return Fail();
        if (!CryptographicOperations.FixedTimeEquals(tag, Tag(macKey, peerY, peerAd))) return Fail();
        CryptographicOperations.ZeroMemory(macKey);
        macKey = null;
        State = CPaceState.Confirmed;
        return true;
    }

    // The established session; ownership of the chain keys passes to the channel. Only after a verified CONFIRM.
    public SecureChannel CreateChannel()
    {
        if (State != CPaceState.Confirmed || ckSend == null) throw new InvalidOperationException("The handshake is not complete.");
        SecureChannel ch = new(chanId, ckSend, ckRecv);
        ckSend = ckRecv = null;
        return ch;
    }

    private bool Fail()
    {
        State = CPaceState.Failed;
        Wipe();
        return false;
    }

    private void Wipe()
    {
        foreach (byte[] b in new[] { y, isk, macKey, ckSend, ckRecv }) if (b != null) CryptographicOperations.ZeroMemory(b);
        y = isk = macKey = ckSend = ckRecv = null;
    }

    public void Dispose() => Wipe();
}
