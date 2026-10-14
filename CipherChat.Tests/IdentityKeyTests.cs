using System.Security.Cryptography;
using System.Text;
using CipherChatClient;
using Xunit;

namespace CipherChat.Tests;

public static class Hex
{
    public static byte[] B(string h) => Convert.FromHexString(h);
    public static string S(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();
}

public class PrimitiveKnownAnswerTests
{
    [Fact]
    public void Hkdf_Rfc5869_TestCase1()
    {
        byte[] ikm = Enumerable.Repeat((byte)0x0b, 22).ToArray();
        byte[] salt = Hex.B("000102030405060708090a0b0c");
        byte[] info = Hex.B("f0f1f2f3f4f5f6f7f8f9");
        byte[] okm = HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, 42, salt, info);
        Assert.Equal("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865", Hex.S(okm));
    }

    [Fact]
    public void HmacSha256_Rfc4231_TestCase2()
    {
        byte[] mac = HMACSHA256.HashData(Encoding.ASCII.GetBytes("Jefe"), Encoding.ASCII.GetBytes("what do ya want for nothing?"));
        Assert.Equal("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", Hex.S(mac));
    }

    [Fact]
    public void EcdsaP256Sha256_Rfc6979_A25_Sample_VerifiesAsP1363()
    {
        byte[] pub = Hex.B("04" + "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6"
                               + "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299");
        byte[] sig = Hex.B("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716"
                         + "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8");
        byte[] msg = Encoding.ASCII.GetBytes("sample");
        Assert.True(IdentityKey.Verify(pub, msg, sig));
        sig[63] ^= 1;
        Assert.False(IdentityKey.Verify(pub, msg, sig));
    }
}

public class IdentityKeyTests
{
    [Fact]
    public void PublicKey_Is65ByteUncompressed_AndSignaturesAre64Bytes()
    {
        using IdentityKey k = IdentityKey.Generate();
        Assert.Equal(65, k.PublicKey.Length);
        Assert.Equal(0x04, k.PublicKey[0]);
        byte[] sig = k.Sign(new byte[] { 1, 2, 3 });
        Assert.Equal(64, sig.Length);
        Assert.True(IdentityKey.Verify(k.PublicKey, new byte[] { 1, 2, 3 }, sig));
        Assert.False(IdentityKey.Verify(k.PublicKey, new byte[] { 1, 2, 4 }, sig));
        Assert.False(IdentityKey.Verify(k.PublicKey, new byte[] { 1, 2, 3 }, sig[..63]));
    }

    [Fact]
    public void OffCurveAndMalformedPublicKeys_AreRejected()
    {
        using IdentityKey k = IdentityKey.Generate();
        byte[] offCurve = (byte[])k.PublicKey.Clone();
        offCurve[64] ^= 1;
        Assert.False(IdentityKey.IsValidPublicKey(offCurve));
        Assert.False(IdentityKey.Verify(offCurve, new byte[1], k.Sign(new byte[1])));
        byte[] identityPoint = new byte[65];
        identityPoint[0] = 0x04;
        Assert.False(IdentityKey.IsValidPublicKey(identityPoint));
        byte[] wrongPrefix = (byte[])k.PublicKey.Clone();
        wrongPrefix[0] = 0x02;
        Assert.False(IdentityKey.IsValidPublicKey(wrongPrefix));
        Assert.False(IdentityKey.IsValidPublicKey(k.PublicKey[..64]));
        Assert.True(IdentityKey.IsValidPublicKey(k.PublicKey));
    }

    [Fact]
    public void EncryptedExport_RoundTrips_AndWrongPassphraseThrows()
    {
        using IdentityKey k = IdentityKey.Generate();
        byte[] blob = k.ExportEncrypted("correct horse");
        using IdentityKey back = IdentityKey.LoadEncrypted(blob, "correct horse");
        Assert.Equal(k.PublicKey, back.PublicKey);
        Assert.Throws<CryptographicException>(() => IdentityKey.LoadEncrypted(blob, "wrong passphrase"));
        byte[] d = k.ExportPrivateScalar();
        Assert.Equal(32, d.Length);
        // The key file must not contain the private scalar in the clear.
        Assert.DoesNotContain(true, Enumerable.Range(0, blob.Length - 31).Select(i => blob.AsSpan(i, 32).SequenceEqual(d)));
    }

    [Fact]
    public void LoadEncrypted_RejectsNonP256Key()
    {
        using ECDsa p384 = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        byte[] blob = p384.ExportEncryptedPkcs8PrivateKey("passphrase1".AsSpan(),
            new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 10_000));
        Assert.Throws<CryptographicException>(() => IdentityKey.LoadEncrypted(blob, "passphrase1"));
    }
}
