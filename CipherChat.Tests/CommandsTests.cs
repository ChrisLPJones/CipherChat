using CipherChatClient;
using Xunit;

namespace CipherChat.Tests;

public class CommandsTests
{
    [Theory]
    [InlineData("hello", CommandKind.Message, "hello")]
    [InlineData("hello /quit", CommandKind.Message, "hello /quit")]
    [InlineData("//not a command", CommandKind.Message, "/not a command")]
    [InlineData("//", CommandKind.Message, "/")]
    [InlineData("/quit", CommandKind.Quit, "")]
    [InlineData("/QUIT", CommandKind.Quit, "")]
    [InlineData("/quit  ", CommandKind.Quit, "")]
    [InlineData("/nope", CommandKind.Unknown, "nope")]
    [InlineData("/chat bob", CommandKind.Unknown, "chat bob")]   // v4 commands are gone
    [InlineData("/", CommandKind.Unknown, "")]
    public void Parse(string input, CommandKind kind, string arg)
    {
        var c = Commands.Parse(input);
        Assert.Equal((kind, arg), (c.Kind, c.Arg));
    }

    [Fact]
    public void EmptyAndNull_AreEmptyMessages()
    {
        Assert.Equal((CommandKind.Message, ""), (Commands.Parse("").Kind, Commands.Parse(null).Arg));
    }
}

public class CodeEntryTests
{
    private const string Good = "correct horse battery staple";

    [Fact]
    public void MatchingGoodEntries_AreAccepted_AndNormalized()
    {
        Assert.Null(PairCode.CheckEntry("  Correct  HORSE battery staple ", Good, out string n));
        Assert.Equal(Good, n);
    }

    [Fact]
    public void Mismatch_IsReportedInPlainWords()
    {
        string p = PairCode.CheckEntry(Good, "correct horse battery stapl3", out _);
        Assert.Contains("do not match", p);
    }

    [Theory]
    [InlineData("short", "too short")]
    [InlineData("aaaaaaaaaaaaaaaa", "repetitive")]
    [InlineData("abcdefghijkl", "straight run")]
    [InlineData("café au lait noir", "plain keyboard")]
    public void WeakCodes_AreExplainedBeforeAnyMismatch(string code, string fragment)
    {
        string p = PairCode.CheckEntry(code, "something else entirely", out _);
        Assert.Contains(fragment, p, StringComparison.OrdinalIgnoreCase);
    }
}
