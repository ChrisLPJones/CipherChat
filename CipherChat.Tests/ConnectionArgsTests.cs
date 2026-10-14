using CipherChatClient;
using Xunit;

namespace CipherChat.Tests;

public class ConnectionArgsTests
{
    [Fact]
    public void NoArgs_UsesDefaults()
    {
        Assert.True(ConnectionArgs.TryParse([], out string host, out int port, out string error));
        Assert.Equal("localhost", host);
        Assert.Equal(3000, port);
        Assert.Null(error);
    }

    [Fact]
    public void HostOnly_UsesDefaultPort()
    {
        Assert.True(ConnectionArgs.TryParse(["chat.example.com"], out string host, out int port, out _));
        Assert.Equal("chat.example.com", host);
        Assert.Equal(3000, port);
    }

    [Fact]
    public void HostAndPort()
    {
        Assert.True(ConnectionArgs.TryParse(["192.168.1.5", "4000"], out string host, out int port, out _));
        Assert.Equal("192.168.1.5", host);
        Assert.Equal(4000, port);
    }

    [Theory]
    [InlineData("abc")]
    [InlineData("")]
    [InlineData("30.5")]
    [InlineData("-1")]
    [InlineData("99999999999")]
    public void BadPort_Fails(string p)
    {
        Assert.False(ConnectionArgs.TryParse(["localhost", p], out _, out _, out string error));
        Assert.NotNull(error);
    }

    [Theory]
    [InlineData("0")]
    [InlineData("65536")]
    public void PortOutOfRange_Fails(string p)
    {
        Assert.False(ConnectionArgs.TryParse(["localhost", p], out _, out _, out string error));
        Assert.Contains("1 and 65535", error);
    }

    [Theory]
    [InlineData("1")]
    [InlineData("65535")]
    public void PortBoundaries_Ok(string p)
    {
        Assert.True(ConnectionArgs.TryParse(["localhost", p], out _, out int port, out _));
        Assert.Equal(int.Parse(p), port);
    }

    [Fact]
    public void TooManyArgs_Fails()
    {
        Assert.False(ConnectionArgs.TryParse(["localhost", "3000", "extra"], out _, out _, out string error));
        Assert.NotNull(error);
    }

    [Fact]
    public void EmptyHost_Fails()
    {
        Assert.False(ConnectionArgs.TryParse([" "], out _, out _, out _));
    }
}
