namespace CipherChatClient;

// The v4 console UI is task T7. Until then this entry point only validates the arguments.
class Program
{
    static int Main(string[] args)
    {
        if (!ConnectionArgs.TryParse(args, out string host, out int port, out string argError))
        {
            Console.Error.WriteLine(argError);
            Console.Error.WriteLine(ConnectionArgs.Usage);
            return 1;
        }
        Console.Error.WriteLine($"CipherChat client (protocol v4) for {host}:{port}: the console UI is not implemented yet.");
        return 1;
    }
}
