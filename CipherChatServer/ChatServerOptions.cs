namespace CipherChatServer;

// Server limits. The defaults are the production values; tests lower them.
public sealed class ServerLimits
{
    public int MaxConnections { get; init; } = 500;
    public int MaxConnectionsPerIp { get; init; } = 8;
    public int AuthDeadlineMs { get; init; } = 10_000;     // from connect to a successful REGISTER/LOGIN
    public int ReadTimeoutMs { get; init; } = 90_000;      // no line at all for this long -> ERR timeout
    public int MaxAccounts { get; init; } = 10_000;
    public int RegistrationsPerIpPerHour { get; init; } = 3;
    public int RegistrationsGlobalPerHour { get; init; } = 30;
    public int MaxAuthAttempts { get; init; } = 3;         // ERR taken keeps the connection open this many times
    public int MaxConsecutiveRateErrors { get; init; } = 20;

    // Token buckets per connection: (burst, refill per second)
    public int MsgBurst { get; init; } = 30;
    public double MsgPerSecond { get; init; } = 10;
    public int OfferBurst { get; init; } = 10;
    public double OfferPerSecond { get; init; } = 10 / 60.0;
    public int OfferWindowMax { get; init; } = 5;          // offers per 2 minutes (the handshake timeout)
    public int KeyBurst { get; init; } = 30;
    public double KeyPerSecond { get; init; } = 30 / 60.0;
    public int KnockBurst { get; init; } = 10;
    public double KnockPerSecond { get; init; } = 10 / 3600.0;
    public int PingBurst { get; init; } = 4;
    public double PingPerSecond { get; init; } = 4 / 60.0;
    public int UsersBurst { get; init; } = 6;
    public double UsersPerSecond { get; init; } = 6 / 60.0;
    public int ReplyBurst { get; init; } = 20;             // ACCEPT and CONFIRM share this bucket
    public double ReplyPerSecond { get; init; } = 20 / 60.0;

    // Offline knocks (memory only)
    public int KnockMaxPerRecipient { get; init; } = 20;
    public int KnockMaxTotal { get; init; } = 10_000;
    public int KnockMaxPerSenderPerHour { get; init; } = 10;
    public long KnockTtlMs { get; init; } = 7L * 24 * 3600 * 1000;
}

public sealed class ChatServerOptions
{
    // Directory for accounts.txt (created 0700 if missing); null keeps accounts in memory only (tests and dev).
    public string DataDirectory { get; init; }

    public ServerLimits Limits { get; init; } = new();

    // Unix milliseconds; tests inject a fake clock for rate limits and knock expiry.
    public Func<long> Clock { get; init; } = () => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
}
