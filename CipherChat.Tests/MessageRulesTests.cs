using System.Reflection;
using CipherChatClient;
using Xunit;

namespace CipherChat.Tests;

public class MessageRulesTests
{
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

    [Fact]
    public void Sanitizer_StripsControlChars_KeepsUnicode()
    {
        Assert.Equal("[31mred", MessageRules.SanitizeForDisplay("\u001b[31mred\u0007\r\n"));
        Assert.DoesNotContain('\u001b', MessageRules.SanitizeForDisplay("a\u001b[2Jb"));
        Assert.Equal("Ünï 日本語 🚀", MessageRules.SanitizeForDisplay("Ünï 日本語 🚀"));
    }

    [Fact]
    public void TryDecrypt_ClassifiesResults()
    {
        string cipher = AESecureString.EncryptString("hi", "k1");
        Assert.Equal(DecryptStatus.Ok, MessageRules.TryDecrypt(cipher, "k1", out string plain));
        Assert.Equal("hi", plain);
        Assert.Equal(DecryptStatus.WrongKey, MessageRules.TryDecrypt(cipher, "k2", out _));
        Assert.Equal(DecryptStatus.Malformed, MessageRules.TryDecrypt("???", "k1", out _));
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
