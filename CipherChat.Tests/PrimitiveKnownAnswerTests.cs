using System.Security.Cryptography;
using System.Text;
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
}
