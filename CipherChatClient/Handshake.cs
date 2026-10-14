using System.Security.Cryptography;

namespace CipherChatClient;

public enum HandshakeStatus
{
    Ok, Malformed, SelfChat, BadPeerKey, BadSignature, Stale, Replayed, BadEphemeral, Reflection, BadMac, UnknownSession, BadState,
}

// Remembers recently seen session ids (20 minutes) so a replayed OFFER is not shown twice.
// Only ids of OFFERs whose signature verified are added, so forged lines cannot fill it.
public sealed class SidCache
{
    public const long WindowMs = 20 * 60 * 1000;
    public const int MaxEntries = 4096;
    private readonly Dictionary<string, long> seen = new();

    // False when the sid was already seen (or the cache is full of fresh entries).
    public bool TryAdd(byte[] sid, long nowMs)
    {
        lock (seen)
        {
            foreach (string k in seen.Where(kv => nowMs - kv.Value > WindowMs).Select(kv => kv.Key).ToList()) seen.Remove(k);
            string key = Convert.ToHexString(sid);
            if (seen.ContainsKey(key) || seen.Count >= MaxEntries) return false;
            seen[key] = nowMs;
            return true;
        }
    }
}

// Signed-ephemeral ECDH handshake (SIGMA style): OFFER (A->B), ACCEPT (B->A), CONFIRM (A->B).
// See agent-reports/architecture-e2e-redesign.md for the byte layouts. Pure functions on byte arrays; no networking.
public static class Handshake
{
    public const byte Version = 0x04;
    public const byte TypeOffer = 0x01, TypeAccept = 0x02, TypeConfirm = 0x03, TypeKnock = 0x05;
    public const int OfferBytes = 156, AcceptBytes = 179, ConfirmBytes = 50, KnockBytes = 74;
    public const long MaxSkewMs = 10 * 60 * 1000;
    public const long KnockMaxAgeMs = 8L * 24 * 3600 * 1000;
    private const int OfferHeader = 27;          // ver type flags sid(16) ts(8)
    private const int OfferEphemeralEnd = 92;    // + eA(65)

    internal static byte[] OfferSignedData(string a, string b, byte[] ikA, byte[] ikB, byte[] offerPrefix92) =>
        Proto.Concat(Proto.Label("CipherChat-v4/offer"), Proto.Lp(a), Proto.Lp(b), ikA, ikB, offerPrefix92);

    internal static byte[] Th1(string a, string b, byte[] ikA, byte[] ikB, byte[] offer) =>
        SHA256.HashData(Proto.Concat(Proto.Label("CipherChat-v4/th1"), Proto.Lp(a), Proto.Lp(b), ikA, ikB, offer));

    internal static byte[] AcceptSignedData(byte[] th1, byte[] sid, byte[] eB) =>
        Proto.Concat(Proto.Label("CipherChat-v4/accept"), th1, sid, eB);

    internal static byte[] Th2(byte[] th1, byte[] sid, byte[] eB, byte[] sigB) =>
        SHA256.HashData(Proto.Concat(Proto.Label("CipherChat-v4/th2"), th1, new[] { Version, TypeAccept }, sid, eB, sigB));

    // okm = HKDF-SHA256(ss, salt = th2, info = "CipherChat-v4/session", 128) = ck_AB | ck_BA | kc_A | kc_B
    internal static void DeriveKeys(byte[] sharedSecret, byte[] th2, out byte[] ckAB, out byte[] ckBA, out byte[] kcA, out byte[] kcB)
    {
        byte[] okm = HKDF.DeriveKey(HashAlgorithmName.SHA256, sharedSecret, 128, th2, Proto.Label("CipherChat-v4/session"));
        ckAB = okm[0..32]; ckBA = okm[32..64]; kcA = okm[64..96]; kcB = okm[96..128];
        CryptographicOperations.ZeroMemory(okm);
    }

    internal static byte[] Confirm(string who, byte[] kc, byte[] th2) =>
        HMACSHA256.HashData(kc, Proto.Concat(Proto.Label("CipherChat-v4/confirm-" + who), th2));

    private static bool TryDeriveSecret(ECDiffieHellman mine, byte[] theirPoint, out byte[] secret)
    {
        secret = null;
        if (!IdentityKey.TryDecodePoint(theirPoint, out ECParameters p)) return false;
        try
        {
            using ECDiffieHellman other = ECDiffieHellman.Create(p);
            secret = mine.DeriveRawSecretAgreement(other.PublicKey);
            return secret.Length == 32;
        }
        catch (CryptographicException) { return false; }
        catch (ArgumentException) { return false; }
    }

    private static (ECDiffieHellman key, byte[] pub) NewEphemeral()
    {
        ECDiffieHellman e = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        return (e, IdentityKey.EncodePublic(e.ExportParameters(false)));
    }

    private static bool NamesOk(string a, string b) => Proto.IsUserName(a) && Proto.IsUserName(b);

    // ---- Offline knock: ver | type=0x05 | ts(8) | sig(64) ----

    public static byte[] BuildKnock(IdentityKey me, string meName, string peerName, byte[] peerPub, long tsMs)
    {
        if (!NamesOk(meName, peerName) || meName == peerName || !IdentityKey.IsValidPublicKey(peerPub)) throw new ArgumentException("Invalid knock parameters.");
        byte[] prefix = Proto.Concat(new[] { Version, TypeKnock }, Proto.U64(tsMs));
        byte[] sig = me.Sign(Proto.Concat(Proto.Label("CipherChat-v4/knock"), Proto.Lp(meName), Proto.Lp(peerName), me.PublicKey, peerPub, Proto.U64(tsMs)));
        return Proto.Concat(prefix, sig);
    }

    // senderPub is the sender's pinned key; myPub is the recipient's own key.
    public static HandshakeStatus VerifyKnock(byte[] knock, string senderName, byte[] senderPub, string myName, byte[] myPub, long nowMs, out long tsMs)
    {
        tsMs = 0;
        if (knock == null || knock.Length != KnockBytes || knock[0] != Version || knock[1] != TypeKnock) return HandshakeStatus.Malformed;
        if (!NamesOk(senderName, myName) || senderName == myName) return HandshakeStatus.SelfChat;
        if (!IdentityKey.IsValidPublicKey(senderPub) || !IdentityKey.IsValidPublicKey(myPub)) return HandshakeStatus.BadPeerKey;
        long ts = System.Buffers.Binary.BinaryPrimitives.ReadInt64BigEndian(knock.AsSpan(2, 8));
        byte[] data = Proto.Concat(Proto.Label("CipherChat-v4/knock"), Proto.Lp(senderName), Proto.Lp(myName), senderPub, myPub, Proto.U64(ts));
        if (!IdentityKey.Verify(senderPub, data, knock.AsSpan(10, 64))) return HandshakeStatus.BadSignature;
        if (ts > nowMs + MaxSkewMs || nowMs - ts > KnockMaxAgeMs) return HandshakeStatus.Stale;
        tsMs = ts;
        return HandshakeStatus.Ok;
    }

    // ---- Initiator (A) ----

    public sealed class Initiator : IDisposable
    {
        private readonly IdentityKey me;
        private readonly string meName, peerName;
        private readonly byte[] peerPub;
        private ECDiffieHellman eph;
        private bool done;

        public byte[] Offer { get; private set; }
        public byte[] Sid { get; private set; }
        public bool Rekey { get; }

        private Initiator(IdentityKey me, string meName, string peerName, byte[] peerPub, bool rekey)
        {
            this.me = me; this.meName = meName; this.peerName = peerName; this.peerPub = peerPub; Rekey = rekey;
        }

        public static Initiator Create(IdentityKey me, string meName, string peerName, byte[] peerPub, bool rekey, long nowMs)
        {
            if (!NamesOk(meName, peerName) || meName == peerName) throw new ArgumentException("Invalid user names.");
            if (!IdentityKey.IsValidPublicKey(peerPub)) throw new ArgumentException("Invalid peer key.");
            Initiator i = new(me, meName, peerName, (byte[])peerPub.Clone(), rekey);
            (i.eph, byte[] eA) = NewEphemeral();
            i.Sid = RandomNumberGenerator.GetBytes(16);
            byte[] prefix = Proto.Concat(new[] { Version, TypeOffer, (byte)(rekey ? 1 : 0) }, i.Sid, Proto.U64(nowMs), eA);
            byte[] sig = me.Sign(OfferSignedData(meName, peerName, me.PublicKey, peerPub, prefix));
            i.Offer = Proto.Concat(prefix, sig);
            return i;
        }

        // On Ok: channel is the established session and confirm is the CONFIRM message to send.
        // On any failure the pending offer stays usable (a forged ACCEPT cannot cancel it).
        public HandshakeStatus ProcessAccept(byte[] accept, out SecureChannel channel, out byte[] confirm)
        {
            channel = null; confirm = null;
            if (done) return HandshakeStatus.BadState;
            if (accept == null || accept.Length != AcceptBytes || accept[0] != Version || accept[1] != TypeAccept) return HandshakeStatus.Malformed;
            if (!CryptographicOperations.FixedTimeEquals(accept.AsSpan(2, 16), Sid)) return HandshakeStatus.UnknownSession;
            byte[] eB = accept[18..83];
            byte[] sigB = accept[83..147];
            byte[] macB = accept[147..179];
            byte[] eA = Offer[27..92];
            if (!IdentityKey.TryDecodePoint(eB, out _) ) return HandshakeStatus.BadEphemeral;
            if (CryptographicOperations.FixedTimeEquals(eA, eB)) return HandshakeStatus.Reflection;

            byte[] th1 = Th1(meName, peerName, me.PublicKey, peerPub, Offer);
            if (!IdentityKey.Verify(peerPub, AcceptSignedData(th1, Sid, eB), sigB)) return HandshakeStatus.BadSignature;
            if (!TryDeriveSecret(eph, eB, out byte[] ss)) return HandshakeStatus.BadEphemeral;
            byte[] th2 = Th2(th1, Sid, eB, sigB);
            DeriveKeys(ss, th2, out byte[] ckAB, out byte[] ckBA, out byte[] kcA, out byte[] kcB);
            CryptographicOperations.ZeroMemory(ss);
            try
            {
                if (!CryptographicOperations.FixedTimeEquals(Confirm("B", kcB, th2), macB))
                {
                    CryptographicOperations.ZeroMemory(ckAB); CryptographicOperations.ZeroMemory(ckBA);
                    return HandshakeStatus.BadMac;
                }
                confirm = Proto.Concat(new[] { Version, TypeConfirm }, Sid, Confirm("A", kcA, th2));
                channel = new SecureChannel(Sid, meName, peerName, ckAB, ckBA);
                done = true;
                eph.Dispose();
                return HandshakeStatus.Ok;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(kcA);
                CryptographicOperations.ZeroMemory(kcB);
            }
        }

        public void Dispose() { eph?.Dispose(); }
    }

    // ---- Responder (B) ----

    public sealed class Responder : IDisposable
    {
        private readonly IdentityKey me;
        private readonly string meName, peerName;
        private readonly byte[] peerPub, offer, sid, eA;
        private byte[] ckAB, ckBA, kcA, th2;
        private bool accepted, done;

        public byte[] Sid => sid;
        public bool Rekey { get; private init; }
        public long OfferTimestampMs { get; private init; }

        private Responder(IdentityKey me, string meName, string peerName, byte[] peerPub, byte[] offer)
        {
            this.me = me; this.meName = meName; this.peerName = peerName; this.peerPub = peerPub; this.offer = offer;
            sid = offer[3..19]; eA = offer[27..92];
        }

        // Validates an incoming OFFER. peerPub is the pinned key of the sender. Nothing is sent back here.
        public static HandshakeStatus TryReceiveOffer(IdentityKey me, string meName, string peerName, byte[] peerPub, byte[] offer, long nowMs, SidCache seen, out Responder responder)
        {
            responder = null;
            if (offer == null || offer.Length != OfferBytes || offer[0] != Version || offer[1] != TypeOffer || (offer[2] & 0xFE) != 0) return HandshakeStatus.Malformed;
            if (!NamesOk(meName, peerName) || meName == peerName) return HandshakeStatus.SelfChat;
            if (!IdentityKey.IsValidPublicKey(peerPub)) return HandshakeStatus.BadPeerKey;
            byte[] prefix = offer[..OfferEphemeralEnd];
            if (!IdentityKey.Verify(peerPub, OfferSignedData(peerName, meName, peerPub, me.PublicKey, prefix), offer.AsSpan(OfferEphemeralEnd, 64)))
                return HandshakeStatus.BadSignature;
            long ts = System.Buffers.Binary.BinaryPrimitives.ReadInt64BigEndian(offer.AsSpan(19, 8));
            if (Math.Abs(nowMs - ts) > MaxSkewMs) return HandshakeStatus.Stale;
            if (!IdentityKey.TryDecodePoint(offer.AsSpan(27, 65), out ECParameters ep)) return HandshakeStatus.BadEphemeral;
            try { using ECDiffieHellman probe = ECDiffieHellman.Create(ep); }
            catch (CryptographicException) { return HandshakeStatus.BadEphemeral; }
            if (!seen.TryAdd(offer[3..19], nowMs)) return HandshakeStatus.Replayed;
            responder = new Responder(me, meName, peerName, (byte[])peerPub.Clone(), (byte[])offer.Clone())
            {
                Rekey = (offer[2] & 1) != 0,
                OfferTimestampMs = ts,
            };
            return HandshakeStatus.Ok;
        }

        // Builds the ACCEPT message (call once, after the user accepted).
        public byte[] Accept()
        {
            if (accepted) throw new InvalidOperationException("Already accepted.");
            accepted = true;
            (ECDiffieHellman eph, byte[] eB) = NewEphemeral();
            using (eph)
            {
                if (CryptographicOperations.FixedTimeEquals(eA, eB)) throw new CryptographicException("Ephemeral key collision.");
                byte[] ikA = peerPub, ikB = me.PublicKey;
                byte[] th1 = Th1(peerName, meName, ikA, ikB, offer);
                byte[] sigB = me.Sign(AcceptSignedData(th1, sid, eB));
                th2 = Th2(th1, sid, eB, sigB);
                if (!TryDeriveSecret(eph, eA, out byte[] ss)) throw new CryptographicException("Key agreement failed.");
                DeriveKeys(ss, th2, out ckAB, out ckBA, out kcA, out byte[] kcB);
                CryptographicOperations.ZeroMemory(ss);
                byte[] macB = Confirm("B", kcB, th2);
                CryptographicOperations.ZeroMemory(kcB);
                return Proto.Concat(new[] { Version, TypeAccept }, sid, eB, sigB, macB);
            }
        }

        // Activates the session only after macA verifies.
        public HandshakeStatus ProcessConfirm(byte[] confirm, out SecureChannel channel)
        {
            channel = null;
            if (!accepted || done) return HandshakeStatus.BadState;
            if (confirm == null || confirm.Length != ConfirmBytes || confirm[0] != Version || confirm[1] != TypeConfirm) return HandshakeStatus.Malformed;
            if (!CryptographicOperations.FixedTimeEquals(confirm.AsSpan(2, 16), sid)) return HandshakeStatus.UnknownSession;
            if (!CryptographicOperations.FixedTimeEquals(confirm.AsSpan(18, 32), Confirm("A", kcA, th2))) return HandshakeStatus.BadMac;
            channel = new SecureChannel(sid, meName, peerName, ckBA, ckAB); // B sends on ck_BA, receives on ck_AB
            ckAB = ckBA = null;
            done = true;
            CryptographicOperations.ZeroMemory(kcA);
            return HandshakeStatus.Ok;
        }

        public void Dispose()
        {
            if (ckAB != null) CryptographicOperations.ZeroMemory(ckAB);
            if (ckBA != null) CryptographicOperations.ZeroMemory(ckBA);
            if (kcA != null) CryptographicOperations.ZeroMemory(kcA);
        }
    }
}
