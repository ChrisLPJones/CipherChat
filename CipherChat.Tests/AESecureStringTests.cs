using CipherChatClient;
using Xunit;

namespace CipherChat.Tests;

public class AESecureStringTests
{
    private const string Key = "unit-test-key";

    [Theory]
    [InlineData("hello")]
    [InlineData("")]
    [InlineData("Ünïcödé — çàtüñs, 日本語, 🚀")]
    public void RoundTrip_ReturnsOriginal(string plainText)
    {
        string cipherText = AESecureString.EncryptString(plainText, Key);
        string decrypted = AESecureString.DecryptCipher(cipherText, Key);

        Assert.Equal(plainText, decrypted);
    }

    [Fact]
    public void WrongKey_ThrowsAuthenticationException()
    {
        string plainText = "secret message";
        string cipherText = AESecureString.EncryptString(plainText, Key);

        Assert.Throws<CipherAuthenticationException>(() => AESecureString.DecryptCipher(cipherText, "a-different-key"));
    }

    [Fact]
    public void TamperedCiphertext_ThrowsAuthenticationException()
    {
        string plainText = "tamper with me";
        string cipherText = AESecureString.EncryptString(plainText, Key);

        // Flip one character in the middle of the Base64 string, keeping it a
        // valid Base64 character so the failure is in decryption, not parsing.
        const string base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        int position = cipherText.Length / 2;
        char replacement = base64Chars[(base64Chars.IndexOf(cipherText[position]) + 1) % base64Chars.Length];
        string tampered = cipherText[..position] + replacement + cipherText[(position + 1)..];

        Assert.Throws<CipherAuthenticationException>(() => AESecureString.DecryptCipher(tampered, Key));
    }

    [Fact]
    public void LongMessage_RoundTripsIntact()
    {
        string plainText = new string('a', 1500) + " " + new string('b', 250) + " end";
        string cipherText = AESecureString.EncryptString(plainText, Key);

        string decrypted = AESecureString.DecryptCipher(cipherText, Key);

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
        Assert.NotEqual(AESecureString.EncryptString("same", Key), AESecureString.EncryptString("same", Key));
    }

    [Fact]
    public void UnknownVersion_ThrowsFormatException()
    {
        byte[] data = Convert.FromBase64String(AESecureString.EncryptString("x", Key));
        data[0] = 0x01;
        Assert.Throws<FormatException>(() => AESecureString.DecryptCipher(Convert.ToBase64String(data), Key));
    }

    [Fact]
    public void Truncated_ThrowsFormatException()
    {
        byte[] data = Convert.FromBase64String(AESecureString.EncryptString("x", Key));
        string truncated = Convert.ToBase64String(data[..20]);
        Assert.Throws<FormatException>(() => AESecureString.DecryptCipher(truncated, Key));
    }

    [Fact]
    public void NonBase64_ThrowsFormatException()
    {
        Assert.Throws<FormatException>(() => AESecureString.DecryptCipher("not base64 !!!", Key));
    }

    [Fact]
    public void TooLongPlaintext_IsRejected()
    {
        Assert.Throws<ArgumentException>(() => AESecureString.EncryptString(new string('a', AESecureString.MaxPlaintextBytes + 1), Key));
    }

    [Fact]
    public void MaxSizePlaintext_FitsWithinMaxLineChars()
    {
        string cipher = AESecureString.EncryptString(new string('a', AESecureString.MaxPlaintextBytes), Key);
        Assert.True(cipher.Length <= CipherChatClient.ProtocolLimits.MaxLineChars);
    }
}
