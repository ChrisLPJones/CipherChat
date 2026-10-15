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
    // Wire v4 (end-to-end redesign). The v3 constants above are removed together with the v3 code
    // (tasks T4/T6); MaxLineChars then replaces MaxLineChars.
    // Longest v4 line: "MSG " + 20 + " " + 8248 = 8273.
    public const int MaxLineChars = 8400;
    public const int PubKeyChars = 88;      // Base64 of 65 bytes
    public const int SigChars = 88;         // Base64 of 64 bytes
    public const int ChallengeChars = 44;   // Base64 of 32 bytes
    public const int OfferChars = 208;      // Base64 of 156 bytes
    public const int AcceptChars = 240;     // Base64 of 179 bytes
    public const int ConfirmChars = 68;     // Base64 of 50 bytes
    public const int KnockChars = 100;      // Base64 of 74 bytes
    public const int MinMsgChars = 400;     // Base64 of 298 bytes (1 padded block)
    public const int MaxMsgChars = 8248;    // Base64 of 6186 bytes (24 padded blocks)
    public const int MaxTextBytes = 6000;
    public const int PadBlock = 256;
    public const int MaxChats = 16;
    public const int MaxPendingRequests = 20;
    public const int MaxUserListEntries = 100;
    public const int MinCodeChars = 12;     // v5
    public const int MaxCodeChars = 100;    // v5

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
