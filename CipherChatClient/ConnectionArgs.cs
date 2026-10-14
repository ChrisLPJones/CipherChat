namespace CipherChatClient;

// Command-line parsing for the client's optional "host port" arguments (same format and defaults as the server).
public static class ConnectionArgs
{
    public const string DefaultHost = "localhost";
    public const int DefaultPort = 3000;
    public const string Usage = "Usage: CipherChatClient [host [port]]  (defaults: localhost 3000; port 1-65535)";

    // Returns true and the target on success; otherwise false with the reason in error.
    public static bool TryParse(string[] args, out string host, out int port, out string error)
    {
        host = DefaultHost;
        port = DefaultPort;
        error = null;
        args ??= [];

        if (args.Length > 2)
        {
            error = "Too many arguments.";
            return false;
        }
        if (args.Length >= 1)
        {
            if (string.IsNullOrWhiteSpace(args[0]))
            {
                error = "The host must not be empty.";
                return false;
            }
            host = args[0].Trim();
        }
        if (args.Length == 2)
        {
            if (!int.TryParse(args[1], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out int p))
            {
                error = $"Invalid port '{args[1]}': not a number.";
                return false;
            }
            if (p < 1 || p > 65535)
            {
                error = $"Invalid port {p}: must be between 1 and 65535.";
                return false;
            }
            port = p;
        }
        return true;
    }
}
