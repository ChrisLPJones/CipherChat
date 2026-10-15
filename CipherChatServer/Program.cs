namespace CipherChatServer;

class Program
{
    static int Main(string[] args)
    {
        // Default: loopback on port 3000; optionally "host port" from the command line
        string host = "localhost";
        int port = 3000;
        if (args.Length > 2 || (args.Length >= 2 && (!int.TryParse(args[1], out port) || port < 0 || port > 65535)))
        {
            Console.Error.WriteLine("Usage: CipherChatServer [host] [port 0-65535]");
            return 1;
        }
        if (args.Length >= 1) host = args[0];

        ChatServer server;
        try { server = new(host, port); }
        catch (Exception ex) when (ex is ArgumentException or FormatException or System.Net.Sockets.SocketException)
        {
            Console.Error.WriteLine($"Cannot start the server: {ex.GetType().Name}. Check the host address.");
            return 1;
        }

        try { server.Start(); }
        catch (System.Net.Sockets.SocketException ex)
        {
            Console.Error.WriteLine($"Cannot listen on that address and port: {ex.SocketErrorCode}.");
            return 1;
        }
        Console.WriteLine("Server started (protocol v5).");
        server.Stopped.Wait();
        return 0;
    }
}
