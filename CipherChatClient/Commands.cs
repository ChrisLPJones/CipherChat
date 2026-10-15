namespace CipherChatClient;

public enum CommandKind { Message, Quit, Unknown }

public sealed record ParsedCommand(CommandKind Kind, string Arg);

// The only slash command is /quit. "//" sends a literal message starting with "/".
public static class Commands
{
    public static ParsedCommand Parse(string input)
    {
        if (string.IsNullOrEmpty(input) || input[0] != '/') return new ParsedCommand(CommandKind.Message, input ?? "");
        if (input.StartsWith("//")) return new ParsedCommand(CommandKind.Message, input[1..]);
        string name = input[1..].Trim().ToLowerInvariant();
        return name == "quit" ? new ParsedCommand(CommandKind.Quit, "") : new ParsedCommand(CommandKind.Unknown, name);
    }
}
