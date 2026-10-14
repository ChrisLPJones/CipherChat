using CipherChatClient;
using Xunit;

namespace CipherChat.Tests;

public class ChannelIdTests
{
    [Fact]
    public void Tag_IsDeterministic_22UrlSafeChars()
    {
        string a = ChannelId.DeriveRoomTag("general", "k");
        Assert.Equal(a, ChannelId.DeriveRoomTag("general", "k"));
        Assert.Equal(CipherChatClient.ProtocolLimits.TagChars, a.Length);
        Assert.True(ClientFrame.IsTag(a));
    }

    [Fact]
    public void Tag_DiffersByKeyNameAndKind_AndRoomNameIsCaseInsensitive()
    {
        string room = ChannelId.DeriveRoomTag("general", "k");
        Assert.NotEqual(room, ChannelId.DeriveRoomTag("general", "other-key"));
        Assert.NotEqual(room, ChannelId.DeriveRoomTag("lounge", "k"));
        Assert.NotEqual(room, ChannelId.DeriveDmTag("general", "x", "k"));
        Assert.Equal(room, ChannelId.DeriveRoomTag("GENERAL", "k"));
    }

    [Fact]
    public void DmName_IsSymmetricAndCaseInsensitive()
    {
        Assert.Equal(ChannelId.DmName("alice", "Bob"), ChannelId.DmName("BOB", "alice"));
        Assert.Equal(ChannelId.DeriveDmTag("alice", "bob", "pair"), ChannelId.DeriveDmTag("Bob", "ALICE", "pair"));
        Assert.NotEqual(ChannelId.DeriveDmTag("alice", "bob", "pair"), ChannelId.DeriveDmTag("alice", "carol", "pair"));
    }

    [Fact]
    public void Tag_IsNotTheMessageKey()
    {
        // The tag salt is a domain string, never a per-message random salt: deriving with an
        // all-zero 16-byte salt (what a message key could use) must not equal the tag.
        string tag = ChannelId.DeriveRoomTag("general", "k");
        byte[] other = System.Security.Cryptography.Rfc2898DeriveBytes.Pbkdf2("k", new byte[16], 600_000, System.Security.Cryptography.HashAlgorithmName.SHA256, 16);
        Assert.NotEqual(Convert.ToBase64String(other).TrimEnd('='), tag);
    }
}

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
