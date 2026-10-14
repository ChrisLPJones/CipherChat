using System.Reflection;
using CipherChatClient;
using Xunit;

namespace CipherChat.Tests;

public class MessageRulesTests
{
    private const string Tag = "AAAAAAAAAAAAAAAAAAAAAA";

    [Theory]
    [InlineData("alice", true)]
    [InlineData("A_b.c-9", true)]
    [InlineData("", false)]
    [InlineData("aaaaaaaaaaaaaaaaaaaaa", false)] // 21 chars
    [InlineData("aaaaaaaaaaaaaaaaaaaa", true)]    // 20 chars
    [InlineData("a b", false)]
    [InlineData("a:b", false)]
    [InlineData("josé", false)]
    [InlineData("a\u001bb", false)]
    public void ValidateUsername(string name, bool valid)
    {
        Assert.Equal(valid, MessageRules.ValidateUsername(name) == null);
    }

    [Theory]
    [InlineData("lounge", true)]
    [InlineData("Dev_Team.1-x", true)]
    [InlineData("", false)]
    [InlineData("a b", false)]
    [InlineData("dm:bob", false)]
    [InlineData("a|b", false)]
    [InlineData("café", false)]
    [InlineData("a\u001bb", false)]
    [InlineData("12345678901234567890123456789012", true)]   // 32 chars
    [InlineData("123456789012345678901234567890123", false)] // 33 chars
    public void ValidateRoomName(string name, bool valid)
    {
        Assert.Equal(valid, MessageRules.ValidateRoomName(name) == null);
    }

    [Fact]
    public void Sanitizer_StripsControlChars_KeepsUnicode()
    {
        Assert.Equal("[31mred", MessageRules.SanitizeForDisplay("\u001b[31mred\u0007\r\n"));
        Assert.DoesNotContain('\u001b', MessageRules.SanitizeForDisplay("a\u001b[2Jb"));
        Assert.Equal("Ünï 日本語 🚀", MessageRules.SanitizeForDisplay("Ünï 日本語 🚀"));
    }

    [Theory]
    [InlineData("a\u202Eb")]
    [InlineData("a\u202Ab")]
    [InlineData("a\u2066b")]
    [InlineData("a\u2069b")]
    [InlineData("a\u2028b")]
    [InlineData("a\u2029b")]
    [InlineData("a\u200Bb")]
    [InlineData("a\u200Db")]
    [InlineData("a\uFEFFb")]
    public void Sanitizer_StripsFormatAndSeparatorChars(string input)
    {
        Assert.Equal("ab", MessageRules.SanitizeForDisplay(input));
    }

    [Fact]
    public void TryDecrypt_ClassifiesResults()
    {
        string cipher = AESecureString.EncryptString("hi", "k1", Tag);
        Assert.Equal(DecryptStatus.Ok, MessageRules.TryDecrypt(cipher, "k1", Tag, out string plain));
        Assert.Equal("hi", plain);
        Assert.Equal(DecryptStatus.WrongKey, MessageRules.TryDecrypt(cipher, "k2", Tag, out _));
        Assert.Equal(DecryptStatus.Malformed, MessageRules.TryDecrypt("???", "k1", Tag, out _));
    }

    [Fact]
    public void ProtocolLimits_ClientAndServerCopiesMatch()
    {
        var client = typeof(CipherChatClient.ProtocolLimits);
        var server = typeof(CipherChatServer.ProtocolLimits);
        var fields = client.GetFields(BindingFlags.Public | BindingFlags.Static).Where(f => f.IsLiteral).ToList();
        Assert.NotEmpty(fields);
        foreach (var f in fields)
        {
            var other = server.GetField(f.Name, BindingFlags.Public | BindingFlags.Static);
            Assert.NotNull(other);
            Assert.Equal(f.GetRawConstantValue(), other.GetRawConstantValue());
        }
        Assert.Equal(fields.Count, server.GetFields(BindingFlags.Public | BindingFlags.Static).Count(f => f.IsLiteral));
    }
}
