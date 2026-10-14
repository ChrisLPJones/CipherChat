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

public class FrameTests
{
    private const string Tag = "roomAAAAAAAAAAAAAAAAA1";
    private static readonly string Blob = AESecureString.EncryptString("x", "k", Tag);

    [Fact]
    public void ClientFormats_ParseOnServer()
    {
        Assert.True(CipherChatServer.ServerFrame.TryParse(ClientFrame.Hello(), out var hello));
        Assert.Equal(CipherChatServer.ClientVerb.Hello, hello.Verb);

        Assert.True(CipherChatServer.ServerFrame.TryParse(ClientFrame.Join(Tag, Blob), out var join));
        Assert.Equal((CipherChatServer.ClientVerb.Join, Tag, Blob), (join.Verb, join.Tag, join.Data));

        Assert.True(CipherChatServer.ServerFrame.TryParse(ClientFrame.Msg(Tag, Blob), out var msg));
        Assert.Equal(Blob, msg.Data);

        Assert.True(CipherChatServer.ServerFrame.TryParse(ClientFrame.Leave(Tag), out var leave));
        Assert.Equal(Tag, leave.Tag);

        Assert.True(CipherChatServer.ServerFrame.TryParse(ClientFrame.Hist(Tag, 7, 50), out var hist));
        Assert.Equal((7L, 50), (hist.AfterId, hist.Max));

        Assert.True(CipherChatServer.ServerFrame.TryParse(ClientFrame.Ping(), out var ping));
        Assert.Equal(CipherChatServer.ClientVerb.Ping, ping.Verb);
    }

    [Fact]
    public void ServerFormats_ParseOnClient()
    {
        Assert.True(ClientFrame.TryParse(CipherChatServer.ServerFrame.Welcome(5), out var w));
        Assert.Equal((ServerEventKind.Welcome, 5), (w.Kind, w.Mid));

        Assert.True(ClientFrame.TryParse(CipherChatServer.ServerFrame.Member(Tag, 3, Blob), out var m));
        Assert.Equal((ServerEventKind.Member, 3, Blob), (m.Kind, m.Mid, m.Data));

        Assert.True(ClientFrame.TryParse(CipherChatServer.ServerFrame.Joined(Tag, 4, Blob), out var j));
        Assert.Equal(ServerEventKind.Joined, j.Kind);

        Assert.True(ClientFrame.TryParse(CipherChatServer.ServerFrame.Left(Tag, 4), out var l));
        Assert.Equal((ServerEventKind.Left, 4), (l.Kind, l.Mid));

        Assert.True(ClientFrame.TryParse(CipherChatServer.ServerFrame.Msg(Tag, 12, Blob), out var msg));
        Assert.Equal((ServerEventKind.Msg, 12L, Blob), (msg.Kind, msg.Id, msg.Data));

        Assert.True(ClientFrame.TryParse(CipherChatServer.ServerFrame.Ack(Tag, 12), out var ack));
        Assert.Equal(ServerEventKind.Ack, ack.Kind);

        Assert.True(ClientFrame.TryParse($"HIST {Tag} 9 {Blob}", out var hist));
        Assert.Equal(ServerEventKind.Hist, hist.Kind);

        Assert.True(ClientFrame.TryParse(CipherChatServer.ServerFrame.HistEnd(Tag, 40), out var he));
        Assert.Equal((ServerEventKind.HistEnd, 40L), (he.Kind, he.Id));

        Assert.True(ClientFrame.TryParse(CipherChatServer.ServerFrame.Pong, out var p));
        Assert.Equal(ServerEventKind.Pong, p.Kind);

        Assert.True(ClientFrame.TryParse(CipherChatServer.ServerFrame.Err("notjoined"), out var e));
        Assert.Equal("notjoined", e.Data);
    }

    [Theory]
    [InlineData("")]
    [InlineData("MSG")]
    [InlineData("FOO bar")]
    [InlineData("msg roomAAAAAAAAAAAAAAAAA1 PAYLOAD")]
    [InlineData("MSG roomAAAAAAAAAAAAAAAAA1  PAYLOAD")]
    [InlineData("MSG roomAAAAAAAAAAAAAAAAA PAYLOAD")]        // 21-char tag
    [InlineData("MSG roomAAAAAAAAAAAAAAAAA1x PAYLOAD")]      // 23-char tag
    [InlineData("MSG roomAAAAAAAAAAAAAAAAA+ PAYLOAD")]       // '+' is not Base64Url
    [InlineData("MSG roomAAAAAAAAAAAAAAAAA1 PAY\u001b[2J")]
    [InlineData("MSG roomAAAAAAAAAAAAAAAAA1 short")]
    [InlineData("HIST roomAAAAAAAAAAAAAAAAA1 0 51")]
    [InlineData("HIST roomAAAAAAAAAAAAAAAAA1 0 0")]
    [InlineData("HIST roomAAAAAAAAAAAAAAAAA1 x 5")]
    [InlineData("JOIN roomAAAAAAAAAAAAAAAAA1")]
    [InlineData("LEAVE roomAAAAAAAAAAAAAAAAA1 extra")]
    [InlineData("HELLO 2")]
    [InlineData("PING x")]
    public void Malformed_IsRejectedOnServer(string line)
    {
        Assert.False(CipherChatServer.ServerFrame.TryParse(line.Replace("PAYLOAD", Blob), out _));
    }

    [Theory]
    [InlineData("")]
    [InlineData("WELCOME 2 1")]
    [InlineData("WELCOME 3")]
    [InlineData("LEFT roomAAAAAAAAAAAAAAAAA1 x")]
    [InlineData("ACK roomAAAAAAAAAAAAAAAAA1 -1")]
    [InlineData("ERR Not-Joined")]
    [InlineData("PONG extra")]
    [InlineData("MSG roomAAAAAAAAAAAAAAAAA1 1")]
    public void Malformed_IsRejectedOnClient(string line)
    {
        Assert.False(ClientFrame.TryParse(line, out _));
    }

    [Fact]
    public void OverLengthLine_IsRejectedOnBothSides()
    {
        string line = "MSG " + Tag + " " + new string('A', CipherChatClient.ProtocolLimits.MaxPayloadChars + 1);
        Assert.False(CipherChatServer.ServerFrame.TryParse(line, out _));
        Assert.False(ClientFrame.TryParse("MSG " + Tag + " 1 " + new string('A', CipherChatClient.ProtocolLimits.MaxPayloadChars + 1), out _));
    }

    [Fact]
    public void MaxPayloadMsg_FitsInLineLimit_BothDirections()
    {
        string max = new string('A', CipherChatClient.ProtocolLimits.MaxPayloadChars);
        string c2s = ClientFrame.Msg(Tag, max);
        string s2c = CipherChatServer.ServerFrame.Msg(Tag, 999_999_999_999_999_999, max);
        Assert.True(c2s.Length <= CipherChatClient.ProtocolLimits.MaxLineChars);
        Assert.True(s2c.Length <= CipherChatClient.ProtocolLimits.MaxLineChars);
        Assert.True(CipherChatServer.ServerFrame.TryParse(c2s, out _));
        Assert.True(ClientFrame.TryParse(s2c, out _));
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
    [InlineData("/nope", CommandKind.Unknown, "nope")]
    public void Parse(string input, CommandKind kind, string arg)
    {
        var c = Commands.Parse(input);
        Assert.Equal((kind, arg), (c.Kind, c.Arg));
    }
}
