namespace CipherChatClient;

public enum ServerEventKind { Welcome, Ready, Key, Offer, Accept, Confirm, Msg, Knock, Offline, Gone, Pong, Err, UserList }

// One validated server-to-client line (wire protocol v4).
public sealed class ServerEvent
{
    public ServerEventKind Kind { get; init; }
    public string User { get; init; }          // READY/KEY/OFFLINE/GONE user, relay sender, ERR user
    public string Data { get; init; }          // challenge, key, blob (Base64) or error code
    public string[] Users { get; init; }       // USERLIST
}

// Wire grammar v4, client side (the server has its own copy in ServerFrameV4.cs; tests cross-check them).
//
public static class ClientFrame
{
    public const int Version = 4;
    public static readonly string[] ErrorCodes =
        { "version", "auth", "taken", "nouser", "self", "rate", "full", "limit", "replaced", "timeout", "notauth" };

    // Client-to-server lines (without the trailing newline).
    public static string Hello() => $"HELLO {Version}";
    public static string Register(string user, byte[] pub, byte[] sig) => $"REGISTER {user} {Convert.ToBase64String(pub)} {Convert.ToBase64String(sig)}";
    public static string Login(string user, byte[] sig) => $"LOGIN {user} {Convert.ToBase64String(sig)}";
    public static string Key(string user) => $"KEY {user}";
    public static string Offer(string to, byte[] blob) => $"OFFER {to} {Convert.ToBase64String(blob)}";
    public static string Accept(string to, byte[] blob) => $"ACCEPT {to} {Convert.ToBase64String(blob)}";
    public static string Confirm(string to, byte[] blob) => $"CONFIRM {to} {Convert.ToBase64String(blob)}";
    public static string Msg(string to, byte[] blob) => $"MSG {to} {Convert.ToBase64String(blob)}";
    public static string Knock(string to, byte[] blob) => $"KNOCK {to} {Convert.ToBase64String(blob)}";
    public static string Users() => "USERS";
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
            case "WELCOME":
                if (t.Length != 3 || t[1] != "4" || !IsBase64Bytes(t[2], 32)) return false;
                ev = new ServerEvent { Kind = ServerEventKind.Welcome, Data = t[2] };
                return true;
            case "READY":
            case "OFFLINE":
            case "GONE":
                if (t.Length != 2 || !IsUser(t[1])) return false;
                ev = new ServerEvent { Kind = t[0] == "READY" ? ServerEventKind.Ready : t[0] == "OFFLINE" ? ServerEventKind.Offline : ServerEventKind.Gone, User = t[1] };
                return true;
            case "KEY":
                if (t.Length != 3 || !IsUser(t[1]) || !IsBase64Bytes(t[2], 65)) return false;
                ev = new ServerEvent { Kind = ServerEventKind.Key, User = t[1], Data = t[2] };
                return true;
            case "OFFER": return Relay(t, ServerEventKind.Offer, 156, out ev);
            case "ACCEPT": return Relay(t, ServerEventKind.Accept, 179, out ev);
            case "CONFIRM": return Relay(t, ServerEventKind.Confirm, 50, out ev);
            case "KNOCK": return Relay(t, ServerEventKind.Knock, 74, out ev);
            case "MSG":
                if (t.Length != 3 || !IsUser(t[1]) || !IsMsgBlob(t[2])) return false;
                ev = new ServerEvent { Kind = ServerEventKind.Msg, User = t[1], Data = t[2] };
                return true;
            case "PONG":
                if (t.Length != 1) return false;
                ev = new ServerEvent { Kind = ServerEventKind.Pong };
                return true;
            case "ERR":
                if ((t.Length != 2 && t.Length != 3) || Array.IndexOf(ErrorCodes, t[1]) < 0) return false;
                if (t.Length == 3 && !IsUser(t[2])) return false;
                ev = new ServerEvent { Kind = ServerEventKind.Err, Data = t[1], User = t.Length == 3 ? t[2] : null };
                return true;
            case "USERLIST":
                return ParseUserList(t, out ev);
            default:
                return false;
        }
    }

    private static bool ParseUserList(string[] t, out ServerEvent ev)
    {
        ev = null;
        if (t.Length < 2) return false;
        string c = t[1];
        if (c.Length < 1 || c.Length > 3 || (c.Length > 1 && c[0] == '0')) return false;
        foreach (char ch in c) if (ch < '0' || ch > '9') return false;
        int n = int.Parse(c, System.Globalization.CultureInfo.InvariantCulture);
        if (n > ProtocolLimits.MaxUserListEntries || t.Length != 2 + n) return false;
        string[] names = new string[n];
        HashSet<string> seen = new();
        for (int i = 0; i < n; i++)
        {
            if (!IsUser(t[2 + i]) || !seen.Add(t[2 + i])) return false;
            names[i] = t[2 + i];
        }
        ev = new ServerEvent { Kind = ServerEventKind.UserList, Users = names };
        return true;
    }

    private static bool Relay(string[] t, ServerEventKind kind, int bytes, out ServerEvent ev)
    {
        ev = null;
        if (t.Length != 3 || !IsUser(t[1]) || !IsBase64Bytes(t[2], bytes)) return false;
        ev = new ServerEvent { Kind = kind, User = t[1], Data = t[2] };
        return true;
    }

    public static bool IsUser(string s) => Proto.IsUserName(s);

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
