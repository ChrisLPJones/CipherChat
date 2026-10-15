using System.Text;

namespace CipherChatClient;

class Program
{
    private static ChatSession session;
    private static readonly object ui = new();   // guards the input line and drawing only; never held while calling the session
    private static string currentInput = "";
    private static int cursor;

    static async Task<int> Main(string[] args)
    {
        if (!ConnectionArgs.TryParse(args, out string host, out int port, out string argError))
        {
            Console.Error.WriteLine(argError);
            Console.Error.WriteLine(ConnectionArgs.Usage);
            return 1;
        }
        Console.CancelKeyPress += (s, e) => { e.Cancel = true; session?.Quit(); };

        string code = PromptCode();
        if (code == null) return 0;

        session = new ChatSession(host, port, code);
        session.LineAdded += _ => Redraw();
        session.StateChanged += _ => Redraw();
        Console.Clear();
        Redraw();
        _ = Task.Run(WatchResize);
        await session.StartAsync();

        // Key loop: poll so that the loop also ends when the session ends without a key press.
        while (!session.IsEnded)
        {
            if (!Console.KeyAvailable) { await Task.Delay(30); continue; }
            string line = HandleKey(Console.ReadKey(intercept: true));
            if (line == null) continue;
            switch (Commands.Parse(line).Kind)
            {
                case CommandKind.Quit: session.Quit(); break;
                case CommandKind.Unknown: session.ShowStatus("Unknown command. The only command is /quit (start a message with // to send a literal /)."); break;
                default:
                    string text = Commands.Parse(line).Arg;
                    string error = session.Send(text);
                    if (error != null) session.ShowStatus(error);
                    break;
            }
        }

        EndReason reason = await session.Completion;
        Redraw();
        lock (ui) { Console.SetCursorPosition(0, Console.WindowHeight - 1); Console.Write("Press any key to exit".PadRight(Math.Max(21, Console.WindowWidth - 1))); }
        Console.ReadKey(intercept: true);
        Console.Clear();
        return ChatSession.IsFailure(reason) ? 1 : 0;
    }

    // ---- code entry ----

    private static string PromptCode()
    {
        Console.Clear();
        Console.WriteLine("CipherChat - private chat for two people");
        Console.WriteLine();
        Console.WriteLine("Make up 4 or more random words together (not a quote, a name or a song line).");
        Console.WriteLine("Anyone who guesses the code can read the chat.");
        while (true)
        {
            Console.WriteLine();
            string first = ReadMasked("Code you agreed on (hidden): ");
            if (first == null) return null;
            string problem = PairCode.Validate(PairCode.Normalize(first));
            if (problem != null) { Console.WriteLine(problem); continue; }
            string second = ReadMasked("Type it again: ");
            if (second == null) return null;
            problem = PairCode.CheckEntry(first, second, out string normalized);
            if (problem == null) return normalized;
            Console.WriteLine(problem);
        }
    }

    // Reads a line without echoing it (shows '*'). Returns null if Esc is pressed.
    private static string ReadMasked(string prompt)
    {
        Console.Write(prompt);
        StringBuilder sb = new();
        while (true)
        {
            ConsoleKeyInfo k = Console.ReadKey(intercept: true);
            if (k.Key == ConsoleKey.Enter) { Console.WriteLine(); return sb.ToString(); }
            if (k.Key == ConsoleKey.Escape) { Console.WriteLine(); return null; }
            if (k.Key == ConsoleKey.Backspace) { if (sb.Length > 0) { sb.Length--; Console.Write("\b \b"); } continue; }
            if (!char.IsControl(k.KeyChar) && sb.Length < ProtocolLimits.MaxCodeChars + 20) { sb.Append(k.KeyChar); Console.Write('*'); }
        }
    }

    // ---- input line ----

    // Returns a completed line (Enter) or null. Esc ends the chat through the session, outside the ui lock.
    private static string HandleKey(ConsoleKeyInfo k)
    {
        string done = null;
        bool quit = false;
        lock (ui)
        {
            switch (k.Key)
            {
                case ConsoleKey.Enter: if (currentInput.Length > 0) { done = currentInput; currentInput = ""; cursor = 0; } break;
                case ConsoleKey.Escape: quit = true; break;
                case ConsoleKey.Backspace: if (cursor > 0) { currentInput = currentInput.Remove(cursor - 1, 1); cursor--; } break;
                case ConsoleKey.Delete: if (cursor < currentInput.Length) currentInput = currentInput.Remove(cursor, 1); break;
                case ConsoleKey.Home: cursor = 0; break;
                case ConsoleKey.End: cursor = currentInput.Length; break;
                case ConsoleKey.LeftArrow: if (cursor > 0) cursor--; break;
                case ConsoleKey.RightArrow: if (cursor < currentInput.Length) cursor++; break;
                default:
                    if (!char.IsControl(k.KeyChar) && currentInput.Length < ProtocolLimits.MaxMessageChars)
                    {
                        currentInput = currentInput.Insert(cursor, k.KeyChar.ToString());
                        cursor++;
                    }
                    break;
            }
        }
        if (quit) { session.Quit(); return null; }
        Redraw();
        return done;
    }

    // ---- drawing ----

    // Takes its data from the session first, then draws under the ui lock (so the session is never called with it held).
    private static void Redraw()
    {
        if (session == null) return;
        List<string> lines = session.SnapshotLines();
        SessionState state = session.State;
        lock (ui)
        {
            try
            {
                Console.Clear();
                int width = Math.Max(10, Console.WindowWidth - 1);
                Console.SetCursorPosition(0, 0);
                Console.Write(Truncate("CipherChat | end-to-end encrypted | /quit or Esc to leave" + (state == SessionState.Chatting ? " | connected" : ""), width));

                int maxRows = Math.Max(1, Console.WindowHeight - 3);
                List<string> rows = new();
                foreach (string line in lines.TakeLast(maxRows))
                    rows.AddRange(Wrap(MessageRules.SanitizeForDisplay(line), width));
                foreach (var (row, i) in rows.TakeLast(maxRows).Select((r, i) => (r, i)))
                {
                    Console.SetCursorPosition(0, i + 1);
                    Console.Write(row);
                }
                const string prompt = "Enter Message: ";
                Console.SetCursorPosition(0, Console.WindowHeight - 1);
                Console.Write(prompt + Truncate(currentInput, Math.Max(0, width - prompt.Length)).PadRight(Math.Max(0, width - prompt.Length)));
                Console.SetCursorPosition(Math.Min(prompt.Length + cursor, width), Console.WindowHeight - 1);
            }
            catch (IOException) { }
            catch (ArgumentOutOfRangeException) { }   // the terminal was resized mid-draw; the watcher redraws
        }
    }

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

    // A terminal resize raises no key event; poll the size and redraw when it changes.
    private static async Task WatchResize()
    {
        int w = Console.WindowWidth, h = Console.WindowHeight;
        while (session == null || !session.IsEnded)
        {
            await Task.Delay(300);
            try
            {
                if (Console.WindowWidth != w || Console.WindowHeight != h) { w = Console.WindowWidth; h = Console.WindowHeight; Redraw(); }
            }
            catch (IOException) { }
        }
    }
}
