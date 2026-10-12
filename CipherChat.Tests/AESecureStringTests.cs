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
    public void WrongKey_DoesNotReturnOriginal()
    {
        string plainText = "secret message";
        string cipherText = AESecureString.EncryptString(plainText, Key);

        string decrypted = AESecureString.DecryptCipher(cipherText, "a-different-key");

        Assert.NotEqual(plainText, decrypted);
    }

    [Fact]
    public void TamperedCiphertext_DoesNotReturnOriginal()
    {
        string plainText = "tamper with me";
        string cipherText = AESecureString.EncryptString(plainText, Key);

        // Flip one character in the middle of the Base64 string, keeping it a
        // valid Base64 character so the failure is in decryption, not parsing.
        const string base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        int position = cipherText.Length / 2;
        char replacement = base64Chars[(base64Chars.IndexOf(cipherText[position]) + 1) % base64Chars.Length];
        string tampered = cipherText[..position] + replacement + cipherText[(position + 1)..];

        string decrypted = AESecureString.DecryptCipher(tampered, Key);

        Assert.NotEqual(plainText, decrypted);
    }

    [Fact]
    public void LongMessage_RoundTripsIntact()
    {
        string plainText = new string('a', 1500) + " " + new string('b', 250) + " end";
        string cipherText = AESecureString.EncryptString(plainText, Key);

        string decrypted = AESecureString.DecryptCipher(cipherText, Key);

        Assert.Equal(plainText, decrypted);
    }
}
