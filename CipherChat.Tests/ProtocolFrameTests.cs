using CipherChatClient;
using Xunit;

namespace CipherChat.Tests;

public class CommandsTests
{
    [Theory]
    [InlineData("hello", CommandKind.Message, "hello")]
    [InlineData("//not a command", CommandKind.Message, "/not a command")]
    [InlineData("/dm bob", CommandKind.Dm, "bob")]
    [InlineData("/DM  bob ", CommandKind.Dm, "bob")]
    [InlineData("/switch 2", CommandKind.Switch, "2")]
    [InlineData("/users", CommandKind.Users, "")]
    [InlineData("/help", CommandKind.Help, "")]
    [InlineData("/quit", CommandKind.Quit, "")]
    [InlineData("/join lounge", CommandKind.Join, "lounge")]
    [InlineData("/join", CommandKind.Join, "")]
    [InlineData("/JOIN  Lounge ", CommandKind.Join, "Lounge")]
    [InlineData("/leave", CommandKind.Leave, "")]
    [InlineData("/leave lounge", CommandKind.Leave, "lounge")]
    [InlineData("/nope", CommandKind.Unknown, "nope")]
    public void Parse(string input, CommandKind kind, string arg)
    {
        var c = Commands.Parse(input);
        Assert.Equal((kind, arg), (c.Kind, c.Arg));
    }
}
