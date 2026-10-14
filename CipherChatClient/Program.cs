using System.Text;

namespace CipherChatClient;

class Program
{
    private static ChatSession session;
    private static Profile profile;
    private static PeerChat active;          // null = the home tab
    private static readonly object ui = new();
    private static bool suspendRedraw;

    private static string currentInput = "";
    private static int currentCursorPosition = 0;
    private static string userName;
    private static string serverHost = ConnectionArgs.DefaultHost;
    private static int serverPort = ConnectionArgs.DefaultPort;

    static async Task<int> Main(string[] args)
    {
        if (!ConnectionArgs.TryParse(args, out serverHost, out serverPort, out string argError))
        {
            Console.Error.WriteLine(argError);
            Console.Error.WriteLine(ConnectionArgs.Usage);
            return 1;
        }

        Console.CancelKeyPress += HandleExit;
        AppDomain.CurrentDomain.ProcessExit += (sender, e) => OnProcessExit();

        if (!await Login()) return 1;

        session.Active = active;
        Redraw();
        StartResizeWatcher();
        ShowStatus("Welcome. /users shows who is online, /chat <name> starts a chat, /help lists the commands.");

        while (true)
        {
            string input = GetUserInput();
            ParsedCommand cmd = Commands.Parse(input);
            try { await Run(cmd); }
            catch (Exception ex) when (ex is IOException or ObjectDisposedException)
            {
                ShowStatus("Not connected. Press Esc to quit and start the client again.");
            }
        }
    }

    private static async Task Run(ParsedCommand cmd)
    {
        switch (cmd.Kind)
        {
            case CommandKind.Message:
                if (cmd.Arg.Length > ProtocolLimits.MaxMessageChars)
                {
                    ShowStatus($"Message too long (max {ProtocolLimits.MaxMessageChars} characters).");
                    break;
                }
                if (string.IsNullOrWhiteSpace(cmd.Arg)) break;
                if (active == null) { ShowStatus("This is the home tab. Start a chat with /chat <name> first."); break; }
                string error = session.Send(active, cmd.Arg);
                if (error != null) ShowStatus(error);
                break;

            case CommandKind.Chat:
                if (cmd.Arg.Length == 0) { ShowStatus("Usage: /chat <user>"); break; }
                ShowStatus($"Looking up {MessageRules.Canonicalize(cmd.Arg)}...");
                var (chat, chatError) = await session.StartChatAsync(cmd.Arg);
                if (chatError != null) ShowStatus(chatError); else Activate(chat);
                break;

            case CommandKind.Accept:
                var (accepted, acceptError) = session.Accept(cmd.Arg.Length == 0 ? null : cmd.Arg);
                if (acceptError != null) ShowStatus(acceptError); else Activate(accepted);
                break;

            case CommandKind.Decline:
                string declineError = session.Decline(cmd.Arg.Length == 0 ? null : cmd.Arg);
                ShowStatus(declineError ?? "Request declined (the sender is not told).");
                break;

            case CommandKind.Block:
                if (cmd.Arg.Length == 0) { ShowStatus("Usage: /block <user>"); break; }
                string blockError = session.Block(cmd.Arg);
                ShowStatus(blockError ?? $"Blocked {MessageRules.Canonicalize(cmd.Arg)}: their requests and knocks are dropped silently. /unblock to undo.");
                Redraw();
                break;

            case CommandKind.Unblock:
                if (cmd.Arg.Length == 0) { ShowStatus("Usage: /unblock <user>"); break; }
                string unblockError = session.Unblock(cmd.Arg);
                ShowStatus(unblockError ?? $"Unblocked {MessageRules.Canonicalize(cmd.Arg)}.");
                break;

            case CommandKind.Verify:
                await Verify(cmd.Arg);
                break;

            case CommandKind.End:
                if (active == null) { ShowStatus("Nothing to end on the home tab."); break; }
                string endError = session.End(active);
                if (endError != null) ShowStatus(endError);
                Redraw();
                break;

            case CommandKind.Users:
                IReadOnlyList<string> users = await session.ListUsersAsync();
                if (users == null) ShowStatus("No answer from the server.");
                else ShowStatus(users.Count == 0 ? "Nobody else is online." : "Online: " + string.Join(", ", users));
                break;

            case CommandKind.Chats:
                ShowChats();
                break;

            case CommandKind.Switch:
                SwitchTo(cmd.Arg);
                break;

            case CommandKind.Help:
                ShowStatus("/chat <user> start a chat | /accept [user], /decline [user] answer a request | /block <user>, /unblock <user> | /verify [user] compare safety numbers | /end end this chat | /users who is online | /chats list chats and requests | /switch <user|n|home> (or PgUp/PgDn) | /quit (or Esc). Start a message with // to send a literal /.");
                break;

            case CommandKind.Quit:
                Environment.Exit(0);
                break;

            default:
                ShowStatus($"Unknown command '/{cmd.Arg}'. Type /help.");
                break;
        }
    }

    // ---- login ----

    private static async Task<bool> Login()
    {
        Console.Clear();
        ProfileStore store = new();
        while (true)
        {
            Console.Write("Username: ");
            string candidate = Console.ReadLine() ?? "";
            string problem = MessageRules.ValidateUsername(candidate);
            if (problem == null) { userName = MessageRules.Canonicalize(candidate); break; }
            Console.WriteLine(problem);
        }

        bool created = false;
        bool exists = store.Exists(userName, serverHost, serverPort);
        if (!exists)
        {
            Console.Write($"No identity for {userName} on {serverHost}:{serverPort} yet. Create a new one? (y/n) ");
            if (!ReadYesNo()) return false;
            string pass;
            while (true)
            {
                Console.Write($"New passphrase for your identity key (at least {ProfileStore.MinPassphraseLength} characters): ");
                pass = GetPassword();
                if (pass.Length < ProfileStore.MinPassphraseLength) { Console.WriteLine($"The passphrase must be at least {ProfileStore.MinPassphraseLength} characters."); continue; }
                Console.Write("Repeat the passphrase: ");
                if (GetPassword() == pass) break;
                Console.WriteLine("The passphrases do not match.");
            }
            Console.WriteLine("Creating the identity key...");
            profile = store.Create(userName, serverHost, serverPort, pass);
            created = true;
        }
        else
        {
            for (int attempt = 1; ; attempt++)
            {
                Console.Write("Passphrase: ");
                string pass = GetPassword();
                try { profile = store.Unlock(userName, serverHost, serverPort, pass); break; }
                catch (ProfileException ex) when (ex.Error == ProfileError.WrongPassphrase && attempt < 3) { Console.WriteLine("Wrong passphrase, try again."); }
                catch (ProfileException ex) { Console.Error.WriteLine(ex.Message); return false; }
            }
        }

        bool register = created;
        while (true)
        {
            session = new ChatSession(serverHost, serverPort, userName, profile);
            try
            {
                await session.ConnectAsync();
                AuthResult result = await session.AuthenticateAsync(register);
                switch (result)
                {
                    case AuthResult.Ok:
                        session.LineAdded += (c, t) => Redraw();
                        session.RequestReceived += r => Redraw();
                        session.ChatStateChanged += c => Redraw();
                        session.Status += text => ShowStatus(text);
                        session.Disconnected += () => ShowStatus("Connection closed by the server. Press Esc to quit.");
                        return true;
                    case AuthResult.NameTaken:
                        Console.WriteLine($"The name '{userName}' is already taken on this server by another identity. Start again with a different username.");
                        if (created) { profile.Dispose(); profile = null; store.Delete(userName, serverHost, serverPort); }
                        return false;
                    case AuthResult.UnknownUser:
                        Console.Write($"The server does not know the identity '{userName}'. Register this name now with your existing key? (y/n) ");
                        session.Dispose();
                        if (!ReadYesNo()) return false;
                        register = true;
                        continue;
                    case AuthResult.Rejected:
                        Console.WriteLine($"The server rejected the login: '{userName}' belongs to a different identity key (not the one in your profile).");
                        return false;
                    case AuthResult.RateLimited:
                        Console.WriteLine("The server refused (too many attempts or registrations right now). Try again later.");
                        return false;
                    case AuthResult.ServerFull:
                        Console.WriteLine("The server is full. Try again later.");
                        return false;
                    case AuthResult.VersionMismatch:
                        Console.WriteLine("The server does not speak protocol v4: upgrade server and clients together.");
                        return false;
                    default:
                        Console.WriteLine("Login failed (unexpected reply from the server).");
                        return false;
                }
            }
            catch (Exception ex) when (ex is IOException or System.Net.Sockets.SocketException)
            {
                Console.WriteLine($"Failed to connect to {serverHost}:{serverPort}: {ex.Message}");
                return false;
            }
        }
    }

    private static bool ReadYesNo()
    {
        while (true)
        {
            ConsoleKeyInfo k = Console.ReadKey(intercept: true);
            char c = char.ToLowerInvariant(k.KeyChar);
            if (c == 'y') { Console.WriteLine("y"); return true; }
            if (c == 'n' || k.Key == ConsoleKey.Escape) { Console.WriteLine("n"); return false; }
        }
    }

    // Securely collect a passphrase while hiding input from display
    private static string GetPassword()
    {
        StringBuilder sb = new();
        ConsoleKeyInfo keyInfo;
        do
        {
            keyInfo = Console.ReadKey(intercept: true);
            if (keyInfo.Key == ConsoleKey.Backspace && sb.Length > 0)
            {
                sb.Length--;
                Console.Write("\b \b");
            }
            else if (!char.IsControl(keyInfo.KeyChar))
            {
                sb.Append(keyInfo.KeyChar);
                Console.Write("*");
            }
        } while (keyInfo.Key != ConsoleKey.Enter);
        Console.WriteLine();
        return sb.ToString();
    }

    // ---- verification ----

    private static async Task Verify(string arg)
    {
        string user = arg.Length > 0 ? MessageRules.Canonicalize(arg) : active?.Peer;
        if (user == null) { ShowStatus("Usage: /verify <user> (or run it inside a chat)."); return; }
        ShowStatus($"Fetching {user}'s key...");
        VerifyInfo info = await session.BeginVerifyAsync(user);
        if (info.Error != null) { ShowStatus(info.Error); return; }
        if (info.KeyChanged) ShowStatus($"WARNING: {user}'s identity key is NOT the one you pinned earlier. Only continue if the numbers below match what {user} sees.");
        else if (info.AlreadyVerified) ShowStatus($"{user} is already verified; the number is shown again.");
        foreach (string line in info.SafetyNumber.Split('\n')) ShowStatus("  " + line);
        char answer = PromptKey($"Does {user} see the same number? (y/n) ");
        string result = session.FinishVerify(user, answer == 'y');
        ShowStatus(result ?? (info.KeyChanged ? $"{user}'s new key is now trusted and verified." : $"{user} is now marked verified."));
        Redraw();
    }

    // ---- prompts on the bottom line ----

    // Single-key prompt. Redraws are suspended while it is open, but the ui lock is NOT held during the
    // blocking key read, so the session's events (Redraw) are never stalled behind the user.
    private static char PromptKey(string prompt)
    {
        BeginPrompt(prompt);
        try
        {
            while (true)
            {
                ConsoleKeyInfo k = Console.ReadKey(intercept: true);
                char c = char.ToLowerInvariant(k.KeyChar);
                if (c == 'y' || c == 'n') return c;
                if (k.Key == ConsoleKey.Escape) return 'n';
            }
        }
        finally { lock (ui) suspendRedraw = false; }
    }

    private static void BeginPrompt(string prompt)
    {
        lock (ui)
        {
            suspendRedraw = true;
            Console.SetCursorPosition(0, Console.WindowHeight - 1);
            Console.Write(prompt.PadRight(Math.Max(prompt.Length, Console.WindowWidth - 1)));
            Console.SetCursorPosition(Math.Min(prompt.Length, Console.WindowWidth - 1), Console.WindowHeight - 1);
        }
    }

    // ---- tabs ----

    private static void ShowChats()
    {
        var list = session.Chats.Where(c => c.Phase != ChatPhase.Ended).ToList();
        var reqs = session.Requests;
        ShowStatus(list.Count == 0 ? "No active chats." : "Chats: " + string.Join(", ", list.Select((c, i) => $"{i + 1}:{c.Peer}{(c.Phase == ChatPhase.Active ? "" : " (waiting)")}")));
        ShowStatus(reqs.Count == 0 ? "No pending requests." : "Requests: " + string.Join(", ", reqs.Select(r => r.User + (r.Verified ? "" : "?"))) + " (/accept <user> or /decline <user>)");
    }

    private static List<PeerChat> Tabs() => session.Chats.Where(c => c.Phase != ChatPhase.Ended || c == active).OrderBy(c => c.Peer, StringComparer.Ordinal).ToList();

    private static void SwitchTo(string arg)
    {
        if (arg.Length == 0 || arg.Equals("home", StringComparison.OrdinalIgnoreCase)) { Activate(null); return; }
        var tabs = Tabs();
        PeerChat target = int.TryParse(arg, out int n) && n >= 1 && n <= tabs.Count
            ? tabs[n - 1]
            : tabs.FirstOrDefault(c => c.Peer == MessageRules.Canonicalize(arg));
        if (target == null) { ShowStatus("No such chat. /chats lists them."); return; }
        Activate(target);
    }

    private static void CycleTab(int delta)
    {
        var tabs = new List<PeerChat> { null };
        tabs.AddRange(Tabs());
        int i = tabs.IndexOf(active);
        Activate(tabs[((i + delta) % tabs.Count + tabs.Count) % tabs.Count]);
    }

    private static void Activate(PeerChat chat)
    {
        lock (ui)
        {
            active = chat;
            session.Active = chat;
            if (chat != null) lock (chat.Messages) chat.Unread = 0;
        }
        Redraw();
    }

    // A status/system line in the active tab (never sent anywhere)
    private static void ShowStatus(string text) => session.AddLocal(active, MessageRules.SanitizeForDisplay(text));

    private static string TabLabel(PeerChat c)
    {
        PeerStatus st = session.GetPeerStatus(c.Peer);
        string marker = st.KeyChanged ? "!" : st.Verified ? "" : "?";
        string label = c.Peer + marker + (c.Phase == ChatPhase.Ended ? "[ended]" : c.Phase != ChatPhase.Active ? "[...]" : "");
        if (c != active && c.Unread > 0) label += $"({c.Unread})";
        return c == active ? $"[{label}]" : label;
    }

    // ---- drawing ----

    private static void Redraw()
    {
        lock (ui)
        {
            if (suspendRedraw || session == null) return;
            DisplayMessages();
            DisplayInputLine();
        }
    }

    private static void DisplayInputLine()
    {
        const string prompt = "Enter Message: ";
        Console.SetCursorPosition(0, Console.WindowHeight - 1);
        Console.Write(prompt + currentInput.PadRight(Math.Max(0, Console.WindowWidth - prompt.Length - 1)));
        Console.SetCursorPosition(Math.Min(prompt.Length + currentCursorPosition, Console.WindowWidth - 1), Console.WindowHeight - 1);
    }

    private static void DisplayMessages()
    {
        Console.Clear();
        int width = Math.Max(10, Console.WindowWidth - 1);

        var parts = new List<string> { active == null ? "[home]" : "home" };
        int pending = session.Requests.Count;
        if (pending > 0 && active != null) parts[0] = $"home({pending})";
        parts.AddRange(Tabs().Select(TabLabel));
        Console.SetCursorPosition(0, 0);
        Console.Write(Truncate(string.Join(" ", parts), width));

        int maxRows = Math.Max(1, Console.WindowHeight - 3);
        List<string> rows = new();
        foreach (string line in session.SnapshotLines(active).TakeLast(maxRows))
            rows.AddRange(Wrap(MessageRules.SanitizeForDisplay(line), width));
        foreach (var (row, i) in rows.TakeLast(maxRows).Select((r, i) => (r, i)))
        {
            Console.SetCursorPosition(0, i + 1);
            Console.Write(row);
        }
    }

    // Wraps a line to the terminal width (long warnings must stay readable, not be cut off).
    private static IEnumerable<string> Wrap(string text, int width)
    {
        if (text.Length <= width) { yield return text; yield break; }
        while (text.Length > width)
        {
            int cut = text.LastIndexOf(' ', width - 1, width);
            if (cut <= 0) cut = width;
            yield return text[..cut];
            text = text[cut..].TrimStart(' ');
        }
        if (text.Length > 0) yield return text;
    }

    private static string Truncate(string text, int width) => text.Length <= width ? text : text[..width];

    private static void StartResizeWatcher()
    {
        _ = Task.Run(async () =>
        {
            int w = Console.WindowWidth, h = Console.WindowHeight;
            while (true)
            {
                await Task.Delay(300);
                try
                {
                    if (Console.WindowWidth != w || Console.WindowHeight != h)
                    {
                        w = Console.WindowWidth; h = Console.WindowHeight;
                        Redraw();
                    }
                }
                catch (IOException) { }
            }
        });
    }

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
                        CycleTab(-1);
                        break;
                    case ConsoleKey.PageDown:
                        CycleTab(1);
                        break;
                    case ConsoleKey.Backspace:
                        if (currentCursorPosition > 0)
                        {
                            currentInput = currentInput.Remove(currentCursorPosition - 1, 1);
                            currentCursorPosition--;
                        }
                        break;
                    case ConsoleKey.Delete:
                        if (currentCursorPosition < currentInput.Length) currentInput = currentInput.Remove(currentCursorPosition, 1);
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

    private static void HandleExit(object sender, ConsoleCancelEventArgs e)
    {
        e.Cancel = true;
        Environment.Exit(0);
    }

    // Closes the connection (the server tells the peers) and zeroes the keys, then clears the screen.
    private static void OnProcessExit()
    {
        session?.Dispose();
        profile?.Dispose();
        Console.Clear();
    }
}
