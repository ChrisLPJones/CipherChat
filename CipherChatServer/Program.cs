namespace CipherChatServer;

class Program
{
    static int Main(string[] args)
    {
        // Default: loopback on port 3000; optionally "host port [dataDir]" from the command line
        string host = "localhost";
        int port = 3000;
        if (args.Length >= 1) host = args[0];
        if (args.Length >= 2 && (!int.TryParse(args[1], out port) || port < 0 || port > 65535))
        {
            Console.Error.WriteLine("Usage: CipherChatServer [host] [port 0-65535] [dataDir]");
            return 1;
        }
        // Optional third argument: data directory for accounts.txt (without it accounts are kept in memory only)
        string dataDir = args.Length >= 3 ? args[2] : null;

        ChatServer server;
        try
        {
            server = new(host, port, new ChatServerOptions { DataDirectory = dataDir });
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or FormatException or InvalidDataException)
        {
            Console.Error.WriteLine($"Cannot start the server: {ex.GetType().Name}. Check the host address and the data directory.");
            return 1;
        }

        server.Start();
        Console.WriteLine("Server started (protocol v4).");
        Console.WriteLine(dataDir == null
            ? "WARNING: no data directory given; accounts are kept in memory only and names can be re-claimed after a restart."
            : "Accounts are stored in the data directory.");

        // Keep the process alive while the server accepts and manages clients
        server.Stopped.Wait();
        return 0;
    }
}
