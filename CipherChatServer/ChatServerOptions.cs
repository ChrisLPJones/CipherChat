namespace CipherChatServer;

// Server limits. The defaults are the production values; tests lower them.
public sealed class ServerLimits
{
    public int MaxConnections { get; init; } = 200;
    public int MaxConnectionsPerIp { get; init; } = 4;
    public int MaxWaiters { get; init; } = 100;

    // Deadlines (real time)
    public int HelloDeadlineMs { get; init; } = 10_000;        // from connect to a valid HELLO
    public int AloneTimeoutMs { get; init; } = 10 * 60_000;    // waiting alone
    public int ConfirmDeadlineMs { get; init; } = 30_000;      // both CONFIRMs after PAIRED
    public int ReadTimeoutMs { get; init; } = 90_000;          // no line at all (clients PING every 30 s)

    // Pairing and abuse controls (clock-based, so tests use a fake clock)
    public long BurnMs { get; init; } = 60L * 60_000;          // a rid is burned this long after one pairing
    public int MaxBurned { get; init; } = 10_000;
    public int HellosPerIpPerMinute { get; init; } = 10;
    public int UnproductivePairingsPerIpPerHour { get; init; } = 5;

    // Token buckets per connection
    public int MsgBurst { get; init; } = 30;
    public double MsgPerSecond { get; init; } = 10;
    public int PingBurst { get; init; } = 4;
    public double PingPerSecond { get; init; } = 4 / 60.0;
}

public sealed class ChatServerOptions
{
    public ServerLimits Limits { get; init; } = new();

    // Unix milliseconds; tests inject a fake clock for burns and per-IP limits.
    public Func<long> Clock { get; init; } = () => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
}
