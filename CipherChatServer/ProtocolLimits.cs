using System.Text;

namespace CipherChatServer;

// Protocol limits. DUPLICATED on purpose in CipherChatClient and CipherChatServer
// (a shared linked file would cause CS0433 in the test project); a test asserts
// both copies are equal. Change both together.
public static class ProtocolLimits
{
    public const int MinUsernameLength = 1;
    public const int MaxUsernameLength = 20;
    public const int MaxMessageChars = 2000;
    public const int MaxPlaintextBytes = 8192;
    // Base64 of 1 + 16 + 12 + 8192 + 16 = 8237 bytes is 10984 chars
    public const int MaxLineChars = 11000;
    public const int MinLineChars = 60;

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
