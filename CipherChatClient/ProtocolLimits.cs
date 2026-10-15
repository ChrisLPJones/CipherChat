using System.Text;

namespace CipherChatClient;

// Protocol limits. DUPLICATED on purpose in CipherChatClient and CipherChatServer
// (a shared linked file would cause CS0433 in the test project); a test asserts
// both copies are equal. Change both together.
public static class ProtocolLimits
{
    // Wire protocol v5 (paired-code chat).
    public const int MaxMessageChars = 2000;
    public const int MaxTextBytes = 6000;   // 2000 characters of up to 3 UTF-8 bytes
    public const int PadBlock = 256;
    // Longest line: "MSG " + 8248 = 8252; the limit leaves some room and bounds every read.
    public const int MaxLineChars = 8300;
    public const int RidChars = 6;          // 3 bytes as lowercase hex
    public const int NonceChars = 32;       // 16 bytes as lowercase hex
    public const int KeyChars = 44;         // Base64 of 32 bytes
    public const int ConfirmChars = 88;     // Base64 of 64 bytes
    public const int MinMsgChars = 400;     // Base64 of 298 bytes (1 padded block)
    public const int MaxMsgChars = 8248;    // Base64 of 6186 bytes (24 padded blocks)
    public const int MinCodeChars = 12;
    public const int MaxCodeChars = 100;

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
