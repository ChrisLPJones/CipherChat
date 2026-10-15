using System.Reflection;
using CipherChatClient;
using Xunit;

namespace CipherChat.Tests;

public class MessageRulesTests
{
    [Theory]
    [InlineData("a", true)]
    [InlineData("Anna", true)]
    [InlineData("A_b.c-9", true)]
    [InlineData("aaaaaaaaaaaaaaaaaaaa", true)]     // 20
    [InlineData("aaaaaaaaaaaaaaaaaaaaa", false)]   // 21
    [InlineData("", false)]
    [InlineData(null, false)]
    [InlineData("a b", false)]
    [InlineData(" a", false)]
    [InlineData("a:b", false)]
    [InlineData("a*b", false)]
    [InlineData("jos\u00e9", false)]
    [InlineData("a\u001bb", false)]
    [InlineData("a\u202eb", false)]
    [InlineData("you", false)]
    [InlineData("YOU", false)]
    [InlineData("You", false)]
    [InlineData("young", true)]
    [InlineData("them", true)]
    public void ValidateHandle(string handle, bool valid)
    {
        Assert.Equal(valid, MessageRules.ValidateHandle(handle) == null);
        if (!valid) Assert.False(string.IsNullOrEmpty(MessageRules.ValidateHandle(handle)));   // always a plain message
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
