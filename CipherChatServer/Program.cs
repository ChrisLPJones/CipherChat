using System.Net;
using System.Net.Sockets;
using System.Text;

namespace CipherChatServer;

class Program
{
    // List to store all connected clients for broadcasting messages
    private static readonly List<TcpClient> clients = [];

    // List to store encrypted usernames of connected clients
    private static readonly List<string> clientsConnected = [];

    static void Main()
    {
        // Initialize a TCP listener to accept connections on port 3000
        TcpListener listener = new(IPAddress.Loopback, 3000);

        // Step 1: Start the server to listen for incoming client connections
        StartServer(listener);

        // Step 2: Continuously accept and manage new clients
        AddClients(listener);
    }

    // Starts the TCP server and begins listening for client connections
    private static void StartServer(TcpListener listener)
    {
        listener.Start();
        Console.WriteLine("Server started...\n");
    }

    // Accepts new client connections in an infinite loop and assigns each to a handler
    private static void AddClients(TcpListener listener)
    {
        while (true)
        {
            TcpClient client = listener.AcceptTcpClient();

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
    private static void HandleClient(TcpClient client)
    {
        string encryptedUserName = "";

        try
        {
            NetworkStream stream = client.GetStream();

            // Step 1: Read the encrypted username from the connected client
            byte[] userNameBuffer = new byte[1024];
            int userNameBytesRead = stream.Read(userNameBuffer, 0, userNameBuffer.Length);
            encryptedUserName = Encoding.ASCII.GetString(userNameBuffer, 0, userNameBytesRead).Trim();

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
                    byte[] buffer = new byte[1024];
                    int bytesRead = stream.Read(buffer, 0, buffer.Length);

                    // Exit the loop if the client disconnects (no data received)
                    if (bytesRead == 0) break;

                    // Broadcast the received message to all other clients
                    BroadcastMessage(client, Encoding.ASCII.GetString(buffer, 0, bytesRead));
                }
                catch (IOException)
                {
                    // Handle client disconnection gracefully
                    break;
                }
            }
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

    // Sends the list of all currently connected users to a newly connected client
    private static void SendConnectedUsersList(TcpClient client)
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
    private static void BroadcastMessage(TcpClient sender, string encryptedMessage)
    {
        
        byte[] buffer = Encoding.ASCII.GetBytes(encryptedMessage);

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
