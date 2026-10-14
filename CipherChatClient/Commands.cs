namespace CipherChatClient;

public enum CommandKind { Message, Chat, Accept, Decline, Block, Unblock, Verify, End, Users, Chats, Switch, Help, Quit, Unknown }

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
            "chat" => new ParsedCommand(CommandKind.Chat, arg),
            "accept" => new ParsedCommand(CommandKind.Accept, arg),
            "decline" => new ParsedCommand(CommandKind.Decline, arg),
            "block" => new ParsedCommand(CommandKind.Block, arg),
            "unblock" => new ParsedCommand(CommandKind.Unblock, arg),
            "verify" => new ParsedCommand(CommandKind.Verify, arg),
            "end" => new ParsedCommand(CommandKind.End, arg),
            "users" => new ParsedCommand(CommandKind.Users, arg),
            "chats" => new ParsedCommand(CommandKind.Chats, arg),
            "switch" => new ParsedCommand(CommandKind.Switch, arg),
            "help" => new ParsedCommand(CommandKind.Help, arg),
            "quit" => new ParsedCommand(CommandKind.Quit, arg),
            _ => new ParsedCommand(CommandKind.Unknown, name),
        };
    }
}
