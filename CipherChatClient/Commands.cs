namespace CipherChatClient;

public enum CommandKind { Message, Join, Leave, Dm, Switch, Users, History, Help, Quit, Unknown }

public sealed record ParsedCommand(CommandKind Kind, string Arg);

// Slash-command parser. Input starting with "/" is a command; "//" sends a literal message starting with "/".
public static class Commands
{
    public static ParsedCommand Parse(string input)
    {
        if (string.IsNullOrEmpty(input) || input[0] != '/')
            return new ParsedCommand(CommandKind.Message, input ?? "");
        if (input.StartsWith("//"))
            return new ParsedCommand(CommandKind.Message, input[1..]);

        string body = input[1..].Trim();
        int space = body.IndexOf(' ');
        string name = (space < 0 ? body : body[..space]).ToLowerInvariant();
        string arg = space < 0 ? "" : body[(space + 1)..].Trim();

        return name switch
        {
            "join" => new ParsedCommand(CommandKind.Join, arg),
            "leave" => new ParsedCommand(CommandKind.Leave, arg),
            "dm" => new ParsedCommand(CommandKind.Dm, arg),
            "switch" => new ParsedCommand(CommandKind.Switch, arg),
            "users" => new ParsedCommand(CommandKind.Users, arg),
            "history" => new ParsedCommand(CommandKind.History, arg),
            "help" => new ParsedCommand(CommandKind.Help, arg),
            "quit" => new ParsedCommand(CommandKind.Quit, arg),
            _ => new ParsedCommand(CommandKind.Unknown, name),
        };
    }
}
