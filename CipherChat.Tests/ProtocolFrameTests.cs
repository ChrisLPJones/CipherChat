using CipherChatClient;
using Xunit;

namespace CipherChat.Tests;

public class CommandsTests
{
    [Theory]
    [InlineData("hello", CommandKind.Message, "hello")]
    [InlineData("hello /chat bob", CommandKind.Message, "hello /chat bob")]
    [InlineData("//not a command", CommandKind.Message, "/not a command")]
    [InlineData("//", CommandKind.Message, "/")]
    [InlineData("/chat bob", CommandKind.Chat, "bob")]
    [InlineData("/CHAT  Bob ", CommandKind.Chat, "Bob")]
    [InlineData("/chat", CommandKind.Chat, "")]
    [InlineData("/accept", CommandKind.Accept, "")]
    [InlineData("/accept alice", CommandKind.Accept, "alice")]
    [InlineData("/decline alice", CommandKind.Decline, "alice")]
    [InlineData("/block alice", CommandKind.Block, "alice")]
    [InlineData("/unblock alice", CommandKind.Unblock, "alice")]
    [InlineData("/verify", CommandKind.Verify, "")]
    [InlineData("/verify alice", CommandKind.Verify, "alice")]
    [InlineData("/end", CommandKind.End, "")]
    [InlineData("/users", CommandKind.Users, "")]
    [InlineData("/chats", CommandKind.Chats, "")]
    [InlineData("/switch 2", CommandKind.Switch, "2")]
    [InlineData("/switch home", CommandKind.Switch, "home")]
    [InlineData("/help", CommandKind.Help, "")]
    [InlineData("/quit", CommandKind.Quit, "")]
    [InlineData("/nope", CommandKind.Unknown, "nope")]
    [InlineData("/join lounge", CommandKind.Unknown, "join")]   // v3 commands are gone
    [InlineData("/dm bob", CommandKind.Unknown, "dm")]
    [InlineData("/history", CommandKind.Unknown, "history")]
    [InlineData("/", CommandKind.Unknown, "")]
    public void Parse(string input, CommandKind kind, string arg)
    {
        var c = Commands.Parse(input);
        Assert.Equal((kind, arg), (c.Kind, c.Arg));
    }

    [Fact]
    public void EmptyInput_IsAnEmptyMessage()
    {
        Assert.Equal((CommandKind.Message, ""), (Commands.Parse("").Kind, Commands.Parse(null).Arg));
    }
}
