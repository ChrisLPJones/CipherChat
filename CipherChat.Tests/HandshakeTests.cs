using System.Security.Cryptography;
using CipherChatClient;
using Xunit;

namespace CipherChat.Tests;

public class HandshakeTests : IDisposable
{
    private const long Now = 1_800_000_000_000;
    private readonly IdentityKey alice = IdentityKey.Generate();
    private readonly IdentityKey bob = IdentityKey.Generate();
    private readonly IdentityKey mallory = IdentityKey.Generate();

    public void Dispose() { alice.Dispose(); bob.Dispose(); mallory.Dispose(); }

    private Handshake.Initiator NewOffer(bool rekey = false, long now = Now) =>
        Handshake.Initiator.Create(alice, "alice", "bob", bob.PublicKey, rekey, now);

    private HandshakeStatus Receive(byte[] offer, out Handshake.Responder r, long now = Now, SidCache cache = null) =>
        Handshake.Responder.TryReceiveOffer(bob, "bob", "alice", alice.PublicKey, offer, now, cache ?? new SidCache(), out r);

    [Fact]
    public void Sizes_MatchThePlan()
    {
        using var init = NewOffer();
        Assert.Equal(156, init.Offer.Length);
        Assert.Equal(ProtocolLimits.OfferChars, Convert.ToBase64String(init.Offer).Length);
        Assert.Equal(HandshakeStatus.Ok, Receive(init.Offer, out var resp));
        byte[] accept = resp.Accept();
        Assert.Equal(179, accept.Length);
        Assert.Equal(ProtocolLimits.AcceptChars, Convert.ToBase64String(accept).Length);
        Assert.Equal(HandshakeStatus.Ok, init.ProcessAccept(accept, out var chA, out byte[] confirm));
        Assert.Equal(50, confirm.Length);
        Assert.Equal(ProtocolLimits.ConfirmChars, Convert.ToBase64String(confirm).Length);
        byte[] knock = Handshake.BuildKnock(alice, "alice", "bob", bob.PublicKey, Now);
        Assert.Equal(74, knock.Length);
        Assert.Equal(ProtocolLimits.KnockChars, Convert.ToBase64String(knock).Length);
        Assert.Equal(HandshakeStatus.Ok, resp.ProcessConfirm(confirm, out var chB));
        chA.Dispose(); chB.Dispose(); resp.Dispose();
    }

    [Fact]
    public void HappyPath_BothDirectionsWork_AndSidsMatch()
    {
        using var init = NewOffer();
        Assert.Equal(HandshakeStatus.Ok, Receive(init.Offer, out var resp));
        Assert.False(resp.Rekey);
        Assert.Equal(Now, resp.OfferTimestampMs);
        Assert.Equal(init.Sid, resp.Sid);
        Assert.Equal(HandshakeStatus.Ok, init.ProcessAccept(resp.Accept(), out var chA, out byte[] confirm));
        Assert.Equal(HandshakeStatus.Ok, resp.ProcessConfirm(confirm, out var chB));
        Assert.Equal("hi bob", chB.Open(chA.SealText("hi bob")).Text);
        Assert.Equal("hi alice", chA.Open(chB.SealText("hi alice")).Text);
        chA.Dispose(); chB.Dispose(); resp.Dispose();
    }

    [Fact]
    public void RekeyFlag_IsCarried_AndReservedBitsRejected()
    {
        using var init = NewOffer(rekey: true);
        Assert.Equal(HandshakeStatus.Ok, Receive(init.Offer, out var resp));
        Assert.True(resp.Rekey);

        // A correctly signed OFFER with a reserved flag bit set is still rejected.
        byte[] prefix = init.Offer[..92];
        prefix[2] = 0x02;
        byte[] sig = alice.Sign(Handshake.OfferSignedData("alice", "bob", alice.PublicKey, bob.PublicKey, prefix));
        Assert.Equal(HandshakeStatus.Malformed, Receive(prefix.Concat(sig).ToArray(), out _));
    }

    [Fact]
    public void EveryByteOfOffer_WhenFlipped_IsRejected()
    {
        using var init = NewOffer();
        for (int i = 0; i < init.Offer.Length; i++)
        {
            byte[] bad = (byte[])init.Offer.Clone();
            bad[i] ^= 0x01;
            Assert.NotEqual(HandshakeStatus.Ok, Receive(bad, out var r));
            Assert.Null(r);
        }
        Assert.Equal(HandshakeStatus.Malformed, Receive(init.Offer[..155], out _));
        Assert.Equal(HandshakeStatus.Malformed, Receive(init.Offer.Concat(new byte[] { 0 }).ToArray(), out _));
    }

    [Fact]
    public void EveryByteOfAccept_WhenFlipped_IsRejected_AndOfferStaysUsable()
    {
        using var init = NewOffer();
        Receive(init.Offer, out var resp);
        byte[] accept = resp.Accept();
        for (int i = 0; i < accept.Length; i++)
        {
            byte[] bad = (byte[])accept.Clone();
            bad[i] ^= 0x01;
            Assert.NotEqual(HandshakeStatus.Ok, init.ProcessAccept(bad, out var ch, out var c));
            Assert.Null(ch);
            Assert.Null(c);
        }
        Assert.Equal(HandshakeStatus.Ok, init.ProcessAccept(accept, out var good, out _));
        good.Dispose(); resp.Dispose();
    }

    [Fact]
    public void EveryByteOfConfirm_WhenFlipped_IsRejected_AndResponderStaysPending()
    {
        using var init = NewOffer();
        Receive(init.Offer, out var resp);
        init.ProcessAccept(resp.Accept(), out var chA, out byte[] confirm);
        for (int i = 0; i < confirm.Length; i++)
        {
            byte[] bad = (byte[])confirm.Clone();
            bad[i] ^= 0x01;
            Assert.NotEqual(HandshakeStatus.Ok, resp.ProcessConfirm(bad, out var ch));
            Assert.Null(ch);
        }
        Assert.Equal(HandshakeStatus.Ok, resp.ProcessConfirm(confirm, out var chB));
        Assert.Equal(HandshakeStatus.BadState, resp.ProcessConfirm(confirm, out _));
        chA.Dispose(); chB.Dispose(); resp.Dispose();
    }

    [Fact]
    public void WrongPinnedIdentityKey_IsRejectedOnBothSides()
    {
        using var init = NewOffer();
        // Responder believes the sender is mallory's key.
        Assert.Equal(HandshakeStatus.BadSignature, Handshake.Responder.TryReceiveOffer(bob, "bob", "alice", mallory.PublicKey, init.Offer, Now, new SidCache(), out _));
        // Responder is really someone else (offer addressed to bob's key, received by mallory).
        Assert.Equal(HandshakeStatus.BadSignature, Handshake.Responder.TryReceiveOffer(mallory, "bob", "alice", alice.PublicKey, init.Offer, Now, new SidCache(), out _));

        // Initiator pinned a wrong key for bob: the ACCEPT signature does not verify.
        using var init2 = Handshake.Initiator.Create(alice, "alice", "bob", mallory.PublicKey, false, Now);
        Handshake.Responder.TryReceiveOffer(bob, "bob", "alice", alice.PublicKey, init2.Offer, Now, new SidCache(), out var resp);
        Assert.Null(resp); // bob's key is not the one alice signed for

        // Mallory forges an ACCEPT signed with her own key while alice pinned bob.
        using var init3 = NewOffer();
        using ECDiffieHellman e = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        byte[] eB = IdentityKey.EncodePublic(e.ExportParameters(false));
        byte[] th1 = Handshake.Th1("alice", "bob", alice.PublicKey, bob.PublicKey, init3.Offer);
        byte[] sigM = mallory.Sign(Handshake.AcceptSignedData(th1, init3.Sid, eB));
        byte[] forged = new byte[] { 4, 2 }.Concat(init3.Sid).Concat(eB).Concat(sigM).Concat(new byte[32]).ToArray();
        Assert.Equal(HandshakeStatus.BadSignature, init3.ProcessAccept(forged, out _, out _));
    }

    [Fact]
    public void SwappedNames_AreRejected()
    {
        using var init = NewOffer();
        Assert.Equal(HandshakeStatus.BadSignature, Handshake.Responder.TryReceiveOffer(bob, "alice", "bob", alice.PublicKey, init.Offer, Now, new SidCache(), out _));
        Assert.Equal(HandshakeStatus.SelfChat, Handshake.Responder.TryReceiveOffer(bob, "bob", "bob", alice.PublicKey, init.Offer, Now, new SidCache(), out _));
        Assert.Throws<ArgumentException>(() => Handshake.Initiator.Create(alice, "alice", "alice", bob.PublicKey, false, Now));
        Assert.Throws<ArgumentException>(() => Handshake.Initiator.Create(alice, "Alice", "bob", bob.PublicKey, false, Now));
    }

    [Fact]
    public void ReusedSid_IsRejected()
    {
        using var init = NewOffer();
        SidCache cache = new();
        Assert.Equal(HandshakeStatus.Ok, Receive(init.Offer, out _, Now, cache));
        Assert.Equal(HandshakeStatus.Replayed, Receive(init.Offer, out _, Now + 1000, cache));
        // after the 20 minute window the entry expires from the cache (but the timestamp is stale by then)
        Assert.Equal(HandshakeStatus.Stale, Receive(init.Offer, out _, Now + SidCache.WindowMs + 1, cache));
    }

    [Fact]
    public void ForgedOffers_DoNotFillTheSidCache()
    {
        using var init = NewOffer();
        SidCache cache = new();
        byte[] bad = (byte[])init.Offer.Clone();
        bad[100] ^= 1; // eA changed: signature fails
        Assert.NotEqual(HandshakeStatus.Ok, Receive(bad, out _, Now, cache));
        Assert.Equal(HandshakeStatus.Ok, Receive(init.Offer, out _, Now, cache));
    }

    [Fact]
    public void StaleOrFutureTimestamp_IsRejected_ButTenMinutesIsAccepted()
    {
        const long TenMin = 10 * 60 * 1000;
        using var init = NewOffer();
        Assert.Equal(HandshakeStatus.Ok, Receive(init.Offer, out _, Now + TenMin));
        Assert.Equal(HandshakeStatus.Stale, Receive(init.Offer, out _, Now + TenMin + 1));
        using var init2 = NewOffer();
        Assert.Equal(HandshakeStatus.Ok, Receive(init2.Offer, out _, Now - TenMin));
        Assert.Equal(HandshakeStatus.Stale, Receive(init2.Offer, out _, Now - TenMin - 1));
    }

    private byte[] SignedOfferWithEphemeral(byte[] eA)
    {
        byte[] prefix = new byte[] { 4, 1, 0 }.Concat(RandomNumberGenerator.GetBytes(16)).Concat(Proto.U64(Now)).Concat(eA).ToArray();
        byte[] sig = alice.Sign(Handshake.OfferSignedData("alice", "bob", alice.PublicKey, bob.PublicKey, prefix));
        return prefix.Concat(sig).ToArray();
    }

    [Fact]
    public void OffCurveAndIdentityPointEphemerals_AreRejected_InOffer()
    {
        using var good = NewOffer();
        byte[] offCurve = (byte[])good.Offer[27..92].Clone();
        offCurve[64] ^= 1;
        Assert.Equal(HandshakeStatus.BadEphemeral, Receive(SignedOfferWithEphemeral(offCurve), out _));
        byte[] identity = new byte[65];
        identity[0] = 4;
        Assert.Equal(HandshakeStatus.BadEphemeral, Receive(SignedOfferWithEphemeral(identity), out _));
        Assert.Equal(HandshakeStatus.Ok, Receive(SignedOfferWithEphemeral(good.Offer[27..92]), out _));
    }

    // Builds an ACCEPT that is correctly signed by bob but carries the given ephemeral key and MAC.
    private byte[] SignedAccept(Handshake.Initiator init, byte[] eB, byte[] macB)
    {
        byte[] th1 = Handshake.Th1("alice", "bob", alice.PublicKey, bob.PublicKey, init.Offer);
        byte[] sigB = bob.Sign(Handshake.AcceptSignedData(th1, init.Sid, eB));
        return new byte[] { 4, 2 }.Concat(init.Sid).Concat(eB).Concat(sigB).Concat(macB).ToArray();
    }

    [Fact]
    public void BadEphemeralAndReflectionAndMac_InAccept_AreRejected()
    {
        using var init = NewOffer();
        byte[] eA = init.Offer[27..92];
        byte[] junkMac = RandomNumberGenerator.GetBytes(32);

        byte[] offCurve = (byte[])eA.Clone();
        offCurve[64] ^= 1;
        Assert.Equal(HandshakeStatus.BadEphemeral, init.ProcessAccept(SignedAccept(init, offCurve, junkMac), out _, out _));
        byte[] identity = new byte[65];
        identity[0] = 4;
        Assert.Equal(HandshakeStatus.BadEphemeral, init.ProcessAccept(SignedAccept(init, identity, junkMac), out _, out _));
        Assert.Equal(HandshakeStatus.Reflection, init.ProcessAccept(SignedAccept(init, eA, junkMac), out _, out _));

        using ECDiffieHellman other = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        byte[] eB = IdentityKey.EncodePublic(other.ExportParameters(false));
        Assert.Equal(HandshakeStatus.BadMac, init.ProcessAccept(SignedAccept(init, eB, junkMac), out var ch, out _));
        Assert.Null(ch);
    }

    [Fact]
    public void WrongMacA_IsRejectedByResponder()
    {
        using var init = NewOffer();
        Receive(init.Offer, out var resp);
        init.ProcessAccept(resp.Accept(), out var chA, out byte[] confirm);
        byte[] bad = confirm[..18].Concat(RandomNumberGenerator.GetBytes(32)).ToArray();
        Assert.Equal(HandshakeStatus.BadMac, resp.ProcessConfirm(bad, out _));
        chA.Dispose(); resp.Dispose();
    }

    [Fact]
    public void AcceptForUnknownSid_IsRejected()
    {
        using var init = NewOffer();
        using var other = NewOffer();
        Receive(other.Offer, out var resp);
        Assert.Equal(HandshakeStatus.UnknownSession, init.ProcessAccept(resp.Accept(), out _, out _));
        Assert.Equal(HandshakeStatus.UnknownSession, resp.ProcessConfirm(new byte[] { 4, 3 }.Concat(new byte[16]).Concat(new byte[32]).ToArray(), out _));
    }

    [Fact]
    public void AcceptBeforeAcceptCall_ConfirmIsBadState_AndAcceptOnlyOnce()
    {
        using var init = NewOffer();
        Receive(init.Offer, out var resp);
        Assert.Equal(HandshakeStatus.BadState, resp.ProcessConfirm(new byte[50], out _));
        resp.Accept();
        Assert.Throws<InvalidOperationException>(() => resp.Accept());
    }

    [Fact]
    public void InvalidPeerPublicKey_IsRejected()
    {
        using var init = NewOffer();
        byte[] bad = (byte[])alice.PublicKey.Clone();
        bad[64] ^= 1;
        Assert.Equal(HandshakeStatus.BadPeerKey, Handshake.Responder.TryReceiveOffer(bob, "bob", "alice", bad, init.Offer, Now, new SidCache(), out _));
        Assert.Throws<ArgumentException>(() => Handshake.Initiator.Create(alice, "alice", "bob", bad, false, Now));
    }

    [Fact]
    public void KeysFromDifferentHandshakes_AreDifferent_AndSessionsDoNotInteroperate()
    {
        (SecureChannel a1, SecureChannel b1) = Establish();
        (SecureChannel a2, SecureChannel b2) = Establish();
        Assert.NotEqual(a1.SessionId, a2.SessionId);
        Assert.Equal(OpenStatus.UnknownSession, b2.Open(a1.SealText("x")).Status);
        foreach (var c in new[] { a1, b1, a2, b2 }) c.Dispose();
    }

    private (SecureChannel, SecureChannel) Establish()
    {
        using var init = NewOffer();
        Receive(init.Offer, out var resp);
        init.ProcessAccept(resp.Accept(), out var chA, out byte[] confirm);
        resp.ProcessConfirm(confirm, out var chB);
        return (chA, chB);
    }

    [Fact]
    public void Knock_VerifiesAndRejectsTamperWrongKeyAndStale()
    {
        byte[] knock = Handshake.BuildKnock(alice, "alice", "bob", bob.PublicKey, Now);
        Assert.Equal(HandshakeStatus.Ok, Handshake.VerifyKnock(knock, "alice", alice.PublicKey, "bob", bob.PublicKey, Now + 1000, out long ts));
        Assert.Equal(Now, ts);
        for (int i = 0; i < knock.Length; i++)
        {
            byte[] bad = (byte[])knock.Clone();
            bad[i] ^= 1;
            Assert.NotEqual(HandshakeStatus.Ok, Handshake.VerifyKnock(bad, "alice", alice.PublicKey, "bob", bob.PublicKey, Now, out _));
        }
        Assert.Equal(HandshakeStatus.BadSignature, Handshake.VerifyKnock(knock, "alice", mallory.PublicKey, "bob", bob.PublicKey, Now, out _));
        Assert.Equal(HandshakeStatus.BadSignature, Handshake.VerifyKnock(knock, "carol", alice.PublicKey, "bob", bob.PublicKey, Now, out _));
        Assert.Equal(HandshakeStatus.BadSignature, Handshake.VerifyKnock(knock, "alice", alice.PublicKey, "bob", mallory.PublicKey, Now, out _));
        Assert.Equal(HandshakeStatus.Stale, Handshake.VerifyKnock(knock, "alice", alice.PublicKey, "bob", bob.PublicKey, Now + Handshake.KnockMaxAgeMs + 1, out _));
        Assert.Equal(HandshakeStatus.Stale, Handshake.VerifyKnock(knock, "alice", alice.PublicKey, "bob", bob.PublicKey, Now - Handshake.MaxSkewMs - 1, out _));
    }

    [Fact]
    public void KeySchedule_FrozenVector()
    {
        byte[] ss = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
        byte[] th2 = Enumerable.Range(32, 32).Select(i => (byte)i).ToArray();
        Handshake.DeriveKeys(ss, th2, out var ckAB, out var ckBA, out var kcA, out var kcB);
        Assert.Equal("76c41c9001c3251502dff2c92346827211c0dc4b891629bdfed24bfe228d489f", Hex.S(ckAB));
        Assert.Equal("7ecf5052141c308242abc1d63841b679ddc54abaa1b0c870bb3ad0b317bd85ff", Hex.S(ckBA));
        Assert.Equal("465d7591294fd4f1a3d464919480792c2140d32c3cb139157aca4e72e980f428", Hex.S(kcA));
        Assert.Equal("6bfa70cb2d292d4b7306c6f2f67ba2f6180ec85e9c91f29da1b805bba1967c74", Hex.S(kcB));
        Assert.Equal("4bf91bf543a9a5f85b5e6c4da25765ff98ea141636b69c3251009e0fd40b5247", Hex.S(Handshake.Confirm("B", kcB, th2)));
    }
}
