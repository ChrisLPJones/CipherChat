namespace CipherChatServer;

// Optional server settings. History is opt-in: with HistoryDirectory = null nothing is written to disk.
public sealed class ChatServerOptions
{
    public const int DefaultMaxPerChannel = 1000;

    // Directory for the history files (created if missing); null disables history.
    public string HistoryDirectory { get; init; }

    // Records kept per channel (older ones are trimmed away).
    public int MaxPerChannel { get; init; } = DefaultMaxPerChannel;
}
