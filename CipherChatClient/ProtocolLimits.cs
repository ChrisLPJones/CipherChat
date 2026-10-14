using System.Text;

namespace CipherChatClient;

// Protocol limits. DUPLICATED on purpose in CipherChatClient and CipherChatServer
// (a shared linked file would cause CS0433 in the test project); a test asserts
// both copies are equal. Change both together.
public static class ProtocolLimits
{
    public const int MinUsernameLength = 1;
    public const int MaxUsernameLength = 20;
    public const int MaxMessageChars = 2000;
    public const int MaxPlaintextBytes = 8192;
    // Wire v3. Base64 of 1 + 16 + 12 + 8192 + 16 = 8237 bytes is 10984 chars (payload).
    // Longest line: "MSG " + tag(22) + " " + payload(10984) = 11011; the server-to-client
    // forms add a numeric id (HIST/MSG <tag> <id> <payload>) and stay below 11100.
    public const int MaxLineChars = 11100;
    public const int TagChars = 22;
    public const int MaxPayloadChars = 10984;
    // Base64 of the smallest valid blob (1 + 16 + 12 + 0 + 16 = 45 bytes) is 60 chars
    public const int MinPayloadChars = 60;
    // Presence = encrypted username (at most 20 bytes): Base64 of 65 bytes is 88 chars
    public const int MaxPresenceChars = 128;
    public const int MaxRoomNameLength = 32;
    public const int MaxChannelsPerClient = 16;
    public const int MaxHistoryReplay = 50;

    // Reads one newline-delimited line, never buffering more than maxChars characters.
    // Returns null at end of stream; throws InvalidDataException when the line is too long.
    public static string ReadBoundedLine(TextReader reader, int maxChars)
    {
        StringBuilder sb = new();
        while (true)
        {
            int c = reader.Read();
            if (c < 0) return sb.Length == 0 ? null : sb.ToString();
            if (c == '\n') return sb.ToString();
            if (c == '\r') continue;
            if (sb.Length >= maxChars) throw new InvalidDataException("Line exceeds the maximum length.");
            sb.Append((char)c);
        }
    }

    public static async Task<string> ReadBoundedLineAsync(TextReader reader, int maxChars)
    {
        StringBuilder sb = new();
        char[] one = new char[1];
        while (true)
        {
            int n = await reader.ReadAsync(one, 0, 1);
            if (n <= 0) return sb.Length == 0 ? null : sb.ToString();
            char c = one[0];
            if (c == '\n') return sb.ToString();
            if (c == '\r') continue;
            if (sb.Length >= maxChars) throw new InvalidDataException("Line exceeds the maximum length.");
            sb.Append(c);
        }
    }
}
