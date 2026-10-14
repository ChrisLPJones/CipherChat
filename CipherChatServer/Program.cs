namespace CipherChatServer;

class Program
{
    static void Main(string[] args)
    {
        // Default: loopback on port 3000; optionally "host port" from the command line
        string host = "localhost";
        int port = 3000;
        if (args.Length >= 1) host = args[0];
        if (args.Length >= 2) port = int.Parse(args[1]);
        // Optional third argument: history directory (opt-in; without it nothing is stored)
        string historyDir = args.Length >= 3 ? args[2] : null;

        ChatServer server;
        try
        {
            server = new(host, port, new ChatServerOptions { HistoryDirectory = historyDir });
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            Console.Error.WriteLine($"Cannot use the history directory: {ex.Message}");
            return;
        }

        // Step 1: Start the server to listen for incoming client connections
        server.Start();
        Console.Clear();
        Console.WriteLine("Server started...");
        Console.WriteLine(historyDir == null
            ? "History: off (pass a directory as third argument to keep encrypted history)\n"
            : $"History: on, up to {ChatServerOptions.DefaultMaxPerChannel} messages per channel in {historyDir}\n");

        // Step 2: Keep the process alive while the server accepts and manages clients
        server.Stopped.Wait();
    }
}
