namespace CipherChatClient;

public enum ServerEventKind { Wait, Paired, Key, Confirm, Msg, Gone, Pong, Err }

// One validated server-to-client line (wire protocol v5).
public sealed class ServerEvent
{
    public ServerEventKind Kind { get; init; }
    public int Role { get; init; }         // PAIRED: 1 or 2
    public string Nonce { get; init; }     // PAIRED: the peer's nonce, 32 lowercase hex chars
    public string Data { get; init; }      // KEY/CONFIRM/MSG: Base64; ERR: the error code
}

// Wire grammar v5, client side (the server has its own copy in ServerFrame.cs; tests cross-check them).
public static class ClientFrame
{
    public const int Version = 5;
    public static readonly string[] ErrorCodes = { "version", "used", "full", "rate", "timeout" };

    // Client-to-server lines (without the trailing newline).
    public static string Hello(string ridHex, string nonceHex) => $"HELLO {Version} {ridHex} {nonceHex}";
    public static string Key(byte[] key) => $"KEY {Convert.ToBase64String(key)}";
    public static string Confirm(byte[] tag) => $"CONFIRM {Convert.ToBase64String(tag)}";
    public static string Msg(byte[] blob) => $"MSG {Convert.ToBase64String(blob)}";
    public static string Ping() => "PING";

    // Returns false for any line outside the grammar.
    public static bool TryParse(string line, out ServerEvent ev)
    {
        ev = null;
        if (line == null || line.Length == 0 || line.Length > ProtocolLimits.MaxLineChars) return false;
        string[] t = line.Split(' ');
        foreach (string token in t) if (token.Length == 0) return false;

        switch (t[0])
        {
            case "WAIT":
            case "GONE":
            case "PONG":
                if (t.Length != 1) return false;
                ev = new ServerEvent { Kind = t[0] == "WAIT" ? ServerEventKind.Wait : t[0] == "GONE" ? ServerEventKind.Gone : ServerEventKind.Pong };
                return true;
            case "PAIRED":
                if (t.Length != 3 || (t[1] != "1" && t[1] != "2") || !IsHex(t[2], ProtocolLimits.NonceChars)) return false;
                ev = new ServerEvent { Kind = ServerEventKind.Paired, Role = t[1][0] - '0', Nonce = t[2] };
                return true;
            case "KEY":
                if (t.Length != 2 || !IsBase64Bytes(t[1], 32)) return false;
                ev = new ServerEvent { Kind = ServerEventKind.Key, Data = t[1] };
                return true;
            case "CONFIRM":
                if (t.Length != 2 || !IsBase64Bytes(t[1], 64)) return false;
                ev = new ServerEvent { Kind = ServerEventKind.Confirm, Data = t[1] };
                return true;
            case "MSG":
                if (t.Length != 2 || !IsMsgBlob(t[1])) return false;
                ev = new ServerEvent { Kind = ServerEventKind.Msg, Data = t[1] };
                return true;
            case "ERR":
                if (t.Length != 2 || Array.IndexOf(ErrorCodes, t[1]) < 0) return false;
                ev = new ServerEvent { Kind = ServerEventKind.Err, Data = t[1] };
                return true;
            default:
                return false;
        }
    }

    public static bool IsHex(string s, int chars)
    {
        if (s == null || s.Length != chars) return false;
        foreach (char c in s)
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
        return true;
    }

    public static bool IsBase64Bytes(string s, int bytes) => TryBase64ByteLength(s, out int n) && n == bytes;

    public static bool IsMsgBlob(string s)
    {
        if (s == null || s.Length < ProtocolLimits.MinMsgChars || s.Length > ProtocolLimits.MaxMsgChars) return false;
        if (!TryBase64ByteLength(s, out int n)) return false;
        int body = n - 26 - 16;
        return body >= ProtocolLimits.PadBlock && body % ProtocolLimits.PadBlock == 0 && body / ProtocolLimits.PadBlock <= 24;
    }

    // Charset, length multiple of 4, padding only at the end and with zero unused bits (canonical).
    public static bool TryBase64ByteLength(string s, out int bytes)
    {
        bytes = 0;
        if (s == null || s.Length == 0 || s.Length % 4 != 0) return false;
        int pad = 0;
        if (s[^1] == '=') pad = s.Length >= 2 && s[^2] == '=' ? 2 : 1;
        int end = s.Length - pad;
        for (int i = 0; i < end; i++)
        {
            int v = Value(s[i]);
            if (v < 0) return false;
            if (i == end - 1 && pad == 1 && (v & 0x03) != 0) return false;
            if (i == end - 1 && pad == 2 && (v & 0x0F) != 0) return false;
        }
        bytes = s.Length / 4 * 3 - pad;
        return true;
    }

    private static int Value(char c)
    {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    }

    // Strict decode: returns null unless the text is canonical Base64 (re-encoding gives the same text).
    public static byte[] DecodeBlob(string b64)
    {
        if (!TryBase64ByteLength(b64, out _)) return null;
        try
        {
            byte[] b = Convert.FromBase64String(b64);
            return Convert.ToBase64String(b) == b64 ? b : null;
        }
        catch (FormatException) { return null; }
    }
}
