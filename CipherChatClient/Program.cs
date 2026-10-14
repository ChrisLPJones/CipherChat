using System.Net.Sockets;
using System.Text;

namespace CipherChatClient;

class Program
{
    private static ChatSession session;
    private static ChannelState active;
    private static readonly object ui = new();
    private static bool suspendRedraw;

    // Variables for managing user input, username and encryption key
    private static string currentInput = "";
    private static string userName;
    private static int currentCursorPosition = 0;
    private static string encryptionKey;
    private static string serverHost = ConnectionArgs.DefaultHost;
    private static int serverPort = ConnectionArgs.DefaultPort;

    static async Task<int> Main(string[] args)
    {
        // Validate "host port" arguments before any prompt
        if (!ConnectionArgs.TryParse(args, out serverHost, out serverPort, out string argError))
        {
            Console.Error.WriteLine(argError);
            Console.Error.WriteLine(ConnectionArgs.Usage);
            return 1;
        }

        // Handle cleanup on application exit
        Console.CancelKeyPress += HandleExit;
        AppDomain.CurrentDomain.ProcessExit += (sender, e) => OnProcessExit();

        // Step 1: Gather the user's username and encryption key
        GetLogin();

        // Step 2: Connect (HELLO/WELCOME) and join the lobby channel
        session = new ChatSession(serverHost, serverPort, userName, encryptionKey);
        session.LineAdded += OnLineAdded;
        session.Status += text => ShowStatus(text);
        session.Disconnected += () => ShowStatus("Connection closed by the server. Press Esc to quit.");
        try
        {
            await session.ConnectAsync();
            active = await session.JoinLobbyAsync();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to connect to {serverHost}:{serverPort}: {ex.Message}");
            return 1;
        }
        Redraw();

        // Step 3: Main loop to handle user input, commands and messages
        while (true)
        {
            string input = GetUserInput();
            ParsedCommand cmd = Commands.Parse(input);
            switch (cmd.Kind)
            {
                case CommandKind.Message:
                    if (cmd.Arg.Length > ProtocolLimits.MaxMessageChars)
                    {
                        ShowStatus($"Message too long (max {ProtocolLimits.MaxMessageChars} characters).");
                        break;
                    }
                    if (string.IsNullOrWhiteSpace(cmd.Arg)) break;
                    string error = session.Send(active, cmd.Arg);
                    if (error != null) ShowStatus(error);
                    break;
                case CommandKind.Dm:
                    await OpenDm(cmd.Arg);
                    break;
                case CommandKind.Switch:
                    SwitchTo(cmd.Arg);
                    break;
                case CommandKind.Users:
                    ShowUsers();
                    break;
                case CommandKind.Help:
                    ShowStatus("Commands: /dm <user> (private chat; both type the same pair key), /switch <name|n> (or PgUp/PgDn), /users, /help, /quit. Start a message with // to send a literal /. Esc quits.");
                    break;
                case CommandKind.Quit:
                    Environment.Exit(0);
                    break;
                case CommandKind.Join:
                case CommandKind.Leave:
                case CommandKind.History:
                    ShowStatus("That command is not available yet.");
                    break;
                default:
                    ShowStatus($"Unknown command '/{cmd.Arg}'. Type /help.");
                    break;
            }
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

    // /dm <user>: prompt for the pair key (masked) and open the private channel
    private static async Task OpenDm(string peer)
    {
        string problem = MessageRules.ValidateUsername(peer);
        if (problem != null) { ShowStatus(problem); return; }
        if (string.Equals(peer, userName, StringComparison.OrdinalIgnoreCase))
        {
            ShowStatus("You cannot start a private chat with yourself.");
            return;
        }

        string pairKey;
        lock (ui)
        {
            suspendRedraw = true;
            string prompt = $"Pair key with {peer} (agreed out of band; blank cancels): ";
            Console.SetCursorPosition(0, Console.WindowHeight - 1);
            Console.Write(prompt.PadRight(Math.Max(prompt.Length, Console.WindowWidth - 1)));
            Console.SetCursorPosition(prompt.Length, Console.WindowHeight - 1);
            pairKey = GetPassword();
            suspendRedraw = false;
        }
        if (pairKey.Length == 0) { ShowStatus("Private chat cancelled."); return; }

        ShowStatus($"Opening private chat with {peer}...");
        try
        {
            ChannelState dm = await session.OpenDmAsync(peer, pairKey);
            Activate(dm);
            session.AddLocal(dm, $"Private chat with {peer}. It only works if {peer} also ran /dm {userName} with the same pair key.");
        }
        catch (Exception ex)
        {
            ShowStatus($"Could not open the private chat: {ex.Message}");
        }
    }

    private static void SwitchTo(string arg)
    {
        var list = session.Channels;
        ChannelState target = int.TryParse(arg, out int n) && n >= 1 && n <= list.Count
            ? list[n - 1]
            : list.FirstOrDefault(c => string.Equals(c.DisplayName, arg, StringComparison.OrdinalIgnoreCase));
        if (target == null) { ShowStatus("No such channel. Channels: " + ChannelList()); return; }
        Activate(target);
    }

    private static string ChannelList() =>
        string.Join(", ", session.Channels.Select((c, i) => $"{i + 1}:{c.DisplayName}"));

    private static void CycleChannel(int delta)
    {
        var list = session.Channels;
        if (list.Count < 2) return;
        int i = list.ToList().IndexOf(active);
        Activate(list[((i + delta) % list.Count + list.Count) % list.Count]);
    }

    private static void Activate(ChannelState ch)
    {
        lock (ui)
        {
            active = ch;
            lock (ch.Messages) ch.Unread = 0;
        }
        Redraw();
    }

    private static void ShowUsers()
    {
        string[] names;
        lock (active.Members) names = active.Members.Values.OrderBy(n => n, StringComparer.OrdinalIgnoreCase).ToArray();
        ShowStatus($"In {active.DisplayName}: {string.Join(", ", names)}");
    }

    // A status/system line in the active channel (never sent anywhere)
    private static void ShowStatus(string text)
    {
        ChannelState ch = active;
        if (ch == null) { Console.WriteLine(text); return; }
        session.AddLocal(ch, MessageRules.SanitizeForDisplay(text));
    }

    private static void OnLineAdded(ChannelState ch, string text)
    {
        Redraw();
    }

    private static void Redraw()
    {
        lock (ui)
        {
            if (suspendRedraw || active == null) return;
            DisplayMessages();
            DisplayInputLine();
        }
    }

    // Update the console to display the input line for user messages
    private static void DisplayInputLine()
    {
        const string prompt = "Enter Message: ";
        Console.SetCursorPosition(0, Console.WindowHeight - 1);
        Console.Write(prompt + currentInput.PadRight(Math.Max(0, Console.WindowWidth - prompt.Length - 1)));
        Console.SetCursorPosition(prompt.Length + currentCursorPosition, Console.WindowHeight - 1);
    }

    // Clear the console and display the header and the most recent messages of the active channel
    private static void DisplayMessages()
    {
        Console.Clear();
        int width = Math.Max(10, Console.WindowWidth - 1);

        var parts = new List<string>();
        foreach (ChannelState c in session.Channels)
        {
            string label = c == active ? $"[{c.DisplayName}]" : c.DisplayName;
            if (c != active && c.Unread > 0) label += $"({c.Unread})";
            parts.Add(label);
        }
        Console.SetCursorPosition(0, 0);
        Console.Write(Truncate(string.Join(" ", parts), width));

        int maxMessagesToShow = Console.WindowHeight - 3;
        List<string> recent;
        lock (active.Messages)
        {
            recent = active.Messages.Skip(Math.Max(0, active.Messages.Count - maxMessagesToShow)).ToList();
        }
        for (int i = 0; i < recent.Count; i++)
        {
            Console.SetCursorPosition(0, i + 1);
            Console.Write(Truncate(recent[i], width));
        }
    }

    private static string Truncate(string text, int width) => text.Length <= width ? text : text[..width];

    // Capture and process user input for sending messages
    private static string GetUserInput()
    {
        lock (ui) { currentInput = ""; currentCursorPosition = 0; DisplayInputLine(); }

        while (true)
        {
            ConsoleKeyInfo keyInfo = Console.ReadKey(intercept: true);

            lock (ui)
            {
                if (keyInfo.Key == ConsoleKey.Enter && currentInput != "")
                {
                    string result = currentInput;
                    currentInput = "";
                    currentCursorPosition = 0;
                    return result;
                }

                switch (keyInfo.Key)
                {
                    case ConsoleKey.Escape:
                        Environment.Exit(0);
                        break;

                    case ConsoleKey.PageUp:
                        CycleChannel(-1);
                        break;

                    case ConsoleKey.PageDown:
                        CycleChannel(1);
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
    }

    // Handles cleanup tasks when the application exits
    private static void HandleExit(object sender, ConsoleCancelEventArgs e)
    {
        e.Cancel = true; // Prevent abrupt termination
        Environment.Exit(0);
    }

    // Close the connection (the server announces the departure to channel members) and clear the screen
    private static void OnProcessExit()
    {
        session?.Dispose();
        Console.Clear();
    }
}
