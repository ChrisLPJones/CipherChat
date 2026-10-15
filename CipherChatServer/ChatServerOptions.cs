namespace CipherChatServer;

// Server limits. The defaults are the production values; tests lower them.
// (Being rebuilt for protocol v5: pairing limits arrive with the new server.)
public sealed class ServerLimits
{
    public int MaxConnections { get; init; } = 200;
    public int MaxConnectionsPerIp { get; init; } = 4;
    public int ReadTimeoutMs { get; init; } = 90_000;
}

public sealed class ChatServerOptions
{
    public ServerLimits Limits { get; init; } = new();

    // Unix milliseconds; tests inject a fake clock.
    public Func<long> Clock { get; init; } = () => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
}
