using System.Net;
using System.Net.Sockets;
using System.Text;

namespace CipherChatServer;

// TCP chat server: accepts newline-delimited Base64 lines, tracks the
// encrypted usernames of connected clients and broadcasts messages to all
// other connected clients. Behavior is identical to the original Program.cs
// logic; it is extracted here so it can be started on an ephemeral port in tests.
public class ChatServer : IDisposable
{
    // List to store all connected clients for broadcasting messages
    private readonly List<TcpClient> clients = [];

    // List to store encrypted usernames of connected clients
    private readonly List<string> clientsConnected = [];

    private readonly TcpListener listener;
    private readonly TaskCompletionSource<bool> stopped = new();
    private Task acceptTask;
    private int stopRequested;

    // The port the listener is actually bound to (useful when started on port 0)
    public int Port { get; private set; }

    // Completes when Stop() has finished shutting the server down
    public Task Stopped => stopped.Task;

    public ChatServer(string host, int port)
    {
        IPAddress address = host == "localhost" ? IPAddress.Loopback : IPAddress.Parse(host);
        listener = new(address, port);
    }

    // Starts the TCP server listening and begins accepting client connections
    public void Start()
    {
        listener.Start();
        Port = ((IPEndPoint)listener.LocalEndpoint).Port;
        acceptTask = Task.Run(AcceptLoop);
    }

    // Stops accepting connections, closes all clients and waits for handlers to finish
    public void Stop()
    {
        if (Interlocked.Exchange(ref stopRequested, 1) == 1) return;

        listener.Stop();

        lock (clients)
        {
            foreach (var client in clients)
            {
                client.Close();
            }
        }

        acceptTask?.Wait();
        stopped.TrySetResult(true);
    }

    public void Dispose()
    {
        Stop();
    }

    // Accepts new client connections in a loop and assigns each to a handler
    private void AcceptLoop()
    {
        while (true)
        {
            TcpClient client;
            try
            {
                client = listener.AcceptTcpClient();
            }
            catch (Exception)
            {
                // Listener was stopped
                break;
            }

            // Safely add the client to the list of connected clients
            lock (clients)
            {
                clients.Add(client);
            }

            // Handle the connected client in a separate asynchronous task
            _ = Task.Run(() => HandleClient(client));
        }
    }

    // Manages communication with a single connected client
    private void HandleClient(TcpClient client)
    {
        string encryptedUserName = "";

        try
        {
            NetworkStream stream = client.GetStream();
            StreamReader reader = new(stream);

            // Step 1: Read the encrypted username (one newline-delimited line) from the connected client
            string userNameLine = ProtocolLimits.ReadBoundedLine(reader, ProtocolLimits.MaxLineChars);
            if (userNameLine == null) return;
            encryptedUserName = userNameLine.Trim();
            if (!IsValidLine(encryptedUserName)) return; // drop and close

            // Step 2: Add the client's encrypted username to the connected users list
            lock (clientsConnected)
            {
                clientsConnected.Add(encryptedUserName);
            }

            // Step 3: Send a list of currently connected users to the newly connected client
            SendConnectedUsersList(client);

            // Step 4: Broadcast a notification to all clients about the new connection
            BroadcastMessage(client, encryptedUserName);

            // Step 5: Continuously listen for and process messages from this client
            while (client.Connected)
            {
                try
                {
                    // Read one newline-delimited message at a time
                    string line = ProtocolLimits.ReadBoundedLine(reader, ProtocolLimits.MaxLineChars);

                    // Exit the loop if the client disconnects (no data received)
                    if (line == null) break;

                    // Drop and disconnect clients sending anything that is not a plausible Base64 line
                    line = line.Trim();
                    if (!IsValidLine(line)) break;

                    // Broadcast the received message to all other clients
                    BroadcastMessage(client, line);
                }
                catch (IOException)
                {
                    // Handle client disconnection gracefully
                    break;
                }
            }
        }
        catch (InvalidDataException)
        {
            // Over-length line: close this client only
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error handling client: {ex.Message}");
        }
        finally
        {
            // Clean up resources and remove the client from the server's lists
            lock (clients)
            {
                clients.Remove(client);
            }
            lock (clientsConnected)
            {
                clientsConnected.Remove(encryptedUserName);
            }
            client.Close();
        }
    }

    // A relayable line is Base64 only, within the protocol length bounds (also prevents log injection)
    private static bool IsValidLine(string line)
    {
        if (line.Length < ProtocolLimits.MinLineChars || line.Length > ProtocolLimits.MaxLineChars) return false;
        foreach (char c in line)
        {
            bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                      || c == '+' || c == '/' || c == '=';
            if (!ok) return false;
        }
        return true;
    }

    // Sends the list of all currently connected users to a newly connected client
    private void SendConnectedUsersList(TcpClient client)
    {
        NetworkStream stream = client.GetStream();

        lock (clientsConnected)
        {
            foreach (var encryptedUser in clientsConnected)
            {
                try
                {
                    // Send each encrypted username as a separate line
                    byte[] buffer = Encoding.ASCII.GetBytes(encryptedUser + "\n");
                    Console.WriteLine(encryptedUser); // Log the sent usernames
                    stream.Write(buffer, 0, buffer.Length);
                }
                catch (IOException ex)
                {
                    Console.WriteLine($"Error sending connected users: {ex.Message}");
                }
            }
        }
    }

    // Broadcasts a message to all connected clients except the sender
    private void BroadcastMessage(TcpClient sender, string encryptedMessage)
    {
        // Append a newline so every server-to-client unit is exactly one line
        byte[] buffer = Encoding.ASCII.GetBytes(encryptedMessage + "\n");

        lock (clients)
        {
            foreach (var client in clients)
            {
                // Skip sending the message back to the sender
                if (client != sender)
                {
                    try
                    {
                        Console.WriteLine(encryptedMessage); // Log the broadcasted message
                        client.GetStream().Write(buffer, 0, buffer.Length);
                    }
                    catch (IOException)
                    {
                        // Ignore errors for disconnected clients
                    }
                }
            }
        }
    }
}
