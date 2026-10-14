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

    // Wire v4 (end-to-end redesign). The v3 constants above are removed together with the v3 code
    // (tasks T4/T6); MaxLineCharsV4 then replaces MaxLineChars.
    // Longest v4 line: "MSG " + 20 + " " + 8248 = 8273.
    public const int MaxLineCharsV4 = 8400;
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
