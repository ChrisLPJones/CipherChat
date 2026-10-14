using System.Net.Sockets;
using System.Net;
using System.Text;
using System.Security;

namespace CipherChatClient;

class Program
{
    // List to store messages received from the chat server
    private static readonly List<string> messages = [];

    // TCP client for establishing and maintaining a connection to the server
    private static readonly TcpClient client = new();
    private static NetworkStream stream;

    // Variables for managing user input, username and encryption key
    private static string currentInput = "";
    private static string userName;
    private static int currentCursorPosition = 0;
    private static string encryptionKey;

    static async Task Main()
    {
        // Handle cleanup on application exit
        Console.CancelKeyPress += HandleExit;
        AppDomain.CurrentDomain.ProcessExit += (sender, e) => OnProcessExit();

        // Step 1: Gather the user's username and encryption key
        //GetUserName();
        GetLogin();

        // Step 2: Connect to the chat server
        await ConnectToServer();

        // Step 3: Begin receiving messages asynchronously
        _ = Task.Run(() => ReceiveMessages());

        // Step 4: Main loop to handle user input and send messages
        while (client.Connected)
        {
            string input = GetUserInput();
            if (input.Length > ProtocolLimits.MaxMessageChars)
            {
                AddSystemMessage($"Message too long (max {ProtocolLimits.MaxMessageChars} characters).");
                continue;
            }
            SendMessage($"{userName}: {input}");
        }
    }

    // Prompt the user for their username and encryption key
    private static void GetLogin(){
        
        Console.Clear();
        
        // Validate the username against the protocol rules, re-prompting with the reason
        string problem = null;
        while (true)
        {
            Console.Write("Enter username: ");
            string candidate = Console.ReadLine() ?? "";
            Console.Clear();
            problem = MessageRules.ValidateUsername(candidate);
            if (problem == null)
            {
                userName = candidate;
                break;
            }
            Console.SetCursorPosition(0, 1);
            Console.WriteLine(problem);
            Console.SetCursorPosition(0, 0);
        }

        // Check if empty Encryption key
        while(string.IsNullOrWhiteSpace(encryptionKey)){
            Console.Write("Enter encryption key: ");
            encryptionKey = GetPassword();
            Console.Clear();
            if(encryptionKey.Length > 0){
                break;
            }
            Console.SetCursorPosition(0,1);
            Console.WriteLine("The encryption key is required to proceed.");
            Console.SetCursorPosition(0, 0);
        }
    }

    // Securely collect the encryption key while hiding input from display
    private static string GetPassword()
    {
        string encryptionKey = string.Empty;
        ConsoleKeyInfo keyInfo;
        do
        {
            keyInfo = Console.ReadKey(intercept: true);

            if (keyInfo.Key == ConsoleKey.Backspace && encryptionKey.Length > 0)
            {
                encryptionKey = encryptionKey.Remove(encryptionKey.Length - 1, 1);
                Console.Write("\b \b");
            }

            if (!char.IsControl(keyInfo.KeyChar))
            {
                encryptionKey += keyInfo.KeyChar;
                Console.Write("*");
            }
        } while (keyInfo.Key != ConsoleKey.Enter);

        return encryptionKey;
    }

    // Establish a connection to the server and notify clients with an encrypted message
    private static async Task ConnectToServer()
    {
        try
        {
            await client.ConnectAsync(IPAddress.Loopback, 3000);
            stream = client.GetStream();

            string cipherText = AESecureString.EncryptString($"{userName} is Connected", encryptionKey);
            byte[] userConnectedCipherBytes = Encoding.ASCII.GetBytes(cipherText + "\n");
            await stream.WriteAsync(userConnectedCipherBytes);

            Console.WriteLine("Connected to the server...");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to connect to server: {ex.Message}");
        }
    }

    // Continuously receive and decrypt messages from the server
    private static async Task ReceiveMessages()
    {
        StreamReader reader = new(stream);
        int wrongKeyCount = 0;

        while (client.Connected)
        {
            try
            {
                // Read one newline-delimited message at a time (bounded length)
                string line = await ProtocolLimits.ReadBoundedLineAsync(reader, ProtocolLimits.MaxLineChars);

                // Exit the loop if the server closes the connection
                if (line == null) break;

                switch (MessageRules.TryDecrypt(line.Trim(), encryptionKey, out string plainText))
                {
                    case DecryptStatus.Ok:
                        AddSystemMessage(MessageRules.SanitizeForDisplay(plainText));
                        break;
                    case DecryptStatus.WrongKey:
                        // Show on the first failure and then every 10th; never disconnect
                        if (wrongKeyCount++ % 10 == 0)
                            AddSystemMessage("Could not decrypt a message: the shared key is probably wrong (or the sender uses an older version).");
                        break;
                    default:
                        AddSystemMessage("Malformed message ignored.");
                        break;
                }
            }
            catch (InvalidDataException)
            {
                AddSystemMessage("Received an over-length line from the server; stopping.");
                break;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error receiving message: {ex.Message}");
                break;
            }
        }
    }

    // Adds a line to the message list and redraws, so it is not wiped by the next redraw
    private static void AddSystemMessage(string text)
    {
        lock (messages)
        {
            messages.Add(text);
            DisplayMessages();
            DisplayInputLine();
        }
    }

    // Encrypt and send a message to the server
    private static void SendMessage(string message)
    {
        if (!string.IsNullOrWhiteSpace(message))
        {
            try
            {
                string cipherText = AESecureString.EncryptString(message, encryptionKey);
                byte[] buffer = Encoding.ASCII.GetBytes(cipherText + "\n");
                stream?.WriteAsync(buffer, 0, buffer.Length);

                lock (messages)
                {
                    messages.Add(message);
                }

                currentInput = "";
                currentCursorPosition = 0;

                DisplayMessages();
                DisplayInputLine();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error sending message: {ex.Message}");
            }
        }
    }

    // Update the console to display the input line for user messages
    private static void DisplayInputLine()
    {
        Console.SetCursorPosition(0, Console.WindowHeight - 1);
        Console.Write("Enter Message: " + currentInput.PadRight(Console.WindowWidth - "Enter Message: ".Length - 1));
        Console.SetCursorPosition("Enter Message: ".Length + currentCursorPosition, Console.WindowHeight - 1);
    }

    // Clear the console and display the most recent chat messages
    private static void DisplayMessages()
    {
        Console.Clear();

        int maxMessagesToShow = Console.WindowHeight - 2;

        lock (messages)
        {
            var recentMessages = messages.Skip(Math.Max(0, messages.Count - maxMessagesToShow)).ToList();
            for (int i = 0; i < recentMessages.Count; i++)
            {
                Console.SetCursorPosition(0, i);
                Console.WriteLine(recentMessages[i].PadRight(Console.WindowWidth));
            }
        }
    }

    // Capture and process user input for sending messages
    private static string GetUserInput()
    {
        DisplayInputLine();
        currentInput = "";

        while (true)
        {
            ConsoleKeyInfo keyInfo = Console.ReadKey(intercept: true);

            if (keyInfo.Key == ConsoleKey.Enter && currentInput != "")
                return currentInput;

            switch (keyInfo.Key)
            {
                case ConsoleKey.Escape:
                    Environment.Exit(0);
                    break;

                case ConsoleKey.Backspace:
                    if (currentCursorPosition > 0)
                    {
                        currentInput = currentInput.Remove(currentCursorPosition - 1, 1);
                        currentCursorPosition--;
                    }
                    break;

                case ConsoleKey.Delete:
                    if (currentCursorPosition < currentInput.Length)
                    {
                        currentInput = currentInput.Remove(currentCursorPosition, 1);
                    }
                    break;

                case ConsoleKey.Home:
                    currentCursorPosition = 0;
                    break;

                case ConsoleKey.End:
                    currentCursorPosition = currentInput.Length;
                    break;

                case ConsoleKey.LeftArrow:
                    if (currentCursorPosition > 0) currentCursorPosition--;
                    break;

                case ConsoleKey.RightArrow:
                    if (currentCursorPosition < currentInput.Length) currentCursorPosition++;
                    break;

                default:
                    if (!char.IsControl(keyInfo.KeyChar) && currentInput.Length < ProtocolLimits.MaxMessageChars)
                    {
                        currentInput = currentInput.Insert(currentCursorPosition, keyInfo.KeyChar.ToString());
                        currentCursorPosition++;
                    }
                    break;
            }

            DisplayInputLine();
        }
    }

    // Handles cleanup tasks when the application exits
    private static void HandleExit(object sender, ConsoleCancelEventArgs e)
    {
        e.Cancel = true; // Prevent abrupt termination
        OnProcessExit();
        Environment.Exit(0);
    }

    // Notify the server of disconnection and release resources
    private static void OnProcessExit()
    {
        if (client.Connected)
        {
            SendMessage($"{userName} has Disconnected");
            client.Close();
        }
        
        Console.Clear();
    }
}
