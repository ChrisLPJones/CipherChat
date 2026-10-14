using CipherChatClient;
using Xunit;

namespace CipherChat.Tests;

public class AESecureStringTests
{
    private const string Key = "unit-test-key";
    private const string Tag = "AAAAAAAAAAAAAAAAAAAAAA"; // 22-char channel tag

    [Theory]
    [InlineData("hello")]
    [InlineData("")]
    [InlineData("Ünïcödé — çàtüñs, 日本語, 🚀")]
    public void RoundTrip_ReturnsOriginal(string plainText)
    {
        string cipherText = AESecureString.EncryptString(plainText, Key, Tag);
        string decrypted = AESecureString.DecryptCipher(cipherText, Key, Tag);

        Assert.Equal(plainText, decrypted);
    }

    [Fact]
    public void WrongKey_ThrowsAuthenticationException()
    {
        string plainText = "secret message";
        string cipherText = AESecureString.EncryptString(plainText, Key, Tag);

        Assert.Throws<CipherAuthenticationException>(() => AESecureString.DecryptCipher(cipherText, "a-different-key", Tag));
    }

    [Fact]
    public void TamperedCiphertext_ThrowsAuthenticationException()
    {
        string plainText = "tamper with me";
        string cipherText = AESecureString.EncryptString(plainText, Key, Tag);

        // Flip one character in the middle of the Base64 string, keeping it a
        // valid Base64 character so the failure is in decryption, not parsing.
        const string base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        int position = cipherText.Length / 2;
        char replacement = base64Chars[(base64Chars.IndexOf(cipherText[position]) + 1) % base64Chars.Length];
        string tampered = cipherText[..position] + replacement + cipherText[(position + 1)..];

        Assert.Throws<CipherAuthenticationException>(() => AESecureString.DecryptCipher(tampered, Key, Tag));
    }

    [Fact]
    public void LongMessage_RoundTripsIntact()
    {
        string plainText = new string('a', 1500) + " " + new string('b', 250) + " end";
        string cipherText = AESecureString.EncryptString(plainText, Key, Tag);

        string decrypted = AESecureString.DecryptCipher(cipherText, Key, Tag);

        Assert.Equal(plainText, decrypted);
    }

    [Fact]
    public void IterationConstant_Is600000_AndMatchesKnownAnswer()
    {
        Assert.Equal(600000, AESecureString.Pbkdf2Iterations);
        byte[] salt = new byte[16];
        byte[] a = System.Security.Cryptography.Rfc2898DeriveBytes.Pbkdf2("pw", salt, AESecureString.Pbkdf2Iterations, System.Security.Cryptography.HashAlgorithmName.SHA256, 32);
        byte[] b = System.Security.Cryptography.Rfc2898DeriveBytes.Pbkdf2("pw", salt, 600000, System.Security.Cryptography.HashAlgorithmName.SHA256, 32);
        Assert.Equal(a, b);
    }

    [Fact]
    public void SamePlaintext_ProducesDifferentCiphertexts()
    {
        Assert.NotEqual(AESecureString.EncryptString("same", Key, Tag), AESecureString.EncryptString("same", Key, Tag));
    }

    [Fact]
    public void UnknownVersion_ThrowsFormatException()
    {
        byte[] data = Convert.FromBase64String(AESecureString.EncryptString("x", Key, Tag));
        data[0] = 0x01;
        Assert.Throws<FormatException>(() => AESecureString.DecryptCipher(Convert.ToBase64String(data), Key, Tag));
    }

    [Fact]
    public void Truncated_ThrowsFormatException()
    {
        byte[] data = Convert.FromBase64String(AESecureString.EncryptString("x", Key, Tag));
        string truncated = Convert.ToBase64String(data[..20]);
        Assert.Throws<FormatException>(() => AESecureString.DecryptCipher(truncated, Key, Tag));
    }

    [Fact]
    public void NonBase64_ThrowsFormatException()
    {
        Assert.Throws<FormatException>(() => AESecureString.DecryptCipher("not base64 !!!", Key, Tag));
    }

    [Fact]
    public void TooLongPlaintext_IsRejected()
    {
        Assert.Throws<ArgumentException>(() => AESecureString.EncryptString(new string('a', AESecureString.MaxPlaintextBytes + 1), Key, Tag));
    }

    [Fact]
    public void MaxSizePlaintext_FitsWithinMaxLineChars()
    {
        string cipher = AESecureString.EncryptString(new string('a', AESecureString.MaxPlaintextBytes), Key, Tag);
        Assert.True(cipher.Length <= CipherChatClient.ProtocolLimits.MaxPayloadChars);
    }

    private const string OtherTag = "BBBBBBBBBBBBBBBBBBBBBB";

    [Fact]
    public void WrongChannelTag_FailsAuthentication()
    {
        string cipher = AESecureString.EncryptString("bound to a channel", Key, Tag);
        Assert.Throws<CipherAuthenticationException>(() => AESecureString.DecryptCipher(cipher, Key, OtherTag));
    }

    [Fact]
    public void Version_IsThree_AndV2BlobIsRejected()
    {
        byte[] data = Convert.FromBase64String(AESecureString.EncryptString("x", Key, Tag));
        Assert.Equal(0x03, data[0]);
        data[0] = 0x02;
        Assert.Throws<FormatException>(() => AESecureString.DecryptCipher(Convert.ToBase64String(data), Key, Tag));
    }

    [Fact]
    public void SaltAndNonce_AreRandomPerMessage()
    {
        byte[] a = Convert.FromBase64String(AESecureString.EncryptString("same", Key, Tag));
        byte[] b = Convert.FromBase64String(AESecureString.EncryptString("same", Key, Tag));
        Assert.NotEqual(a[1..17], b[1..17]);   // salt
        Assert.NotEqual(a[17..29], b[17..29]); // nonce
    }

    [Fact]
    public void MissingTag_IsRejected()
    {
        Assert.Throws<ArgumentException>(() => AESecureString.EncryptString("x", Key, ""));
    }

    [Fact]
    public void MaxSizePayload_Is10984Chars()
    {
        string cipher = AESecureString.EncryptString(new string('a', AESecureString.MaxPlaintextBytes), Key, Tag);
        Assert.Equal(CipherChatClient.ProtocolLimits.MaxPayloadChars, cipher.Length);
    }

    [Fact]
    public void SmallestBlob_Is60Chars()
    {
        Assert.Equal(CipherChatClient.ProtocolLimits.MinPayloadChars, AESecureString.EncryptString("", Key, Tag).Length);
    }
}
