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

        ChatServer server = new(host, port);

        // Step 1: Start the server to listen for incoming client connections
        server.Start();
        Console.Clear();
        Console.WriteLine("Server started...\n");

        // Step 2: Keep the process alive while the server accepts and manages clients
        server.Stopped.Wait();
    }
}
