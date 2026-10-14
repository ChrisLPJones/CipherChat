using System.Globalization;

namespace CipherChatClient;

public enum ServerEventKind { Welcome, Member, Joined, Left, Msg, Ack, Hist, HistEnd, Pong, Err }

// One validated server-to-client line (wire protocol v3).
public sealed class ServerEvent
{
    public ServerEventKind Kind { get; init; }
    public string Tag { get; init; }
    public int Mid { get; init; }
    public long Id { get; init; }       // message id (MSG/ACK/HIST) or head id (HISTEND)
    public string Data { get; init; }   // payload or presence (Base64) or error code
}

// Wire grammar, client side (the server has its own copy in ServerFrame.cs; tests cross-check them).
public static class ClientFrame
{
    public const int Version = 3;

    // Client-to-server lines (without the trailing newline).
    public static string Hello() => $"HELLO {Version}";
    public static string Join(string tag, string presence) => $"JOIN {tag} {presence}";
    public static string Leave(string tag) => $"LEAVE {tag}";
    public static string Msg(string tag, string payload) => $"MSG {tag} {payload}";
    public static string Hist(string tag, long afterId, int max) => $"HIST {tag} {afterId} {max}";
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
                if (t.Length != 3 || t[1] != "3" || !TryMid(t[2], out int wm)) return false;
                ev = new ServerEvent { Kind = ServerEventKind.Welcome, Mid = wm };
                return true;
            case "MEMBER":
            case "JOINED":
                if (t.Length != 4 || !IsTag(t[1]) || !TryMid(t[2], out int mm)) return false;
                if (!IsBase64(t[3], ProtocolLimits.MinPayloadChars, ProtocolLimits.MaxPresenceChars)) return false;
                ev = new ServerEvent { Kind = t[0] == "MEMBER" ? ServerEventKind.Member : ServerEventKind.Joined, Tag = t[1], Mid = mm, Data = t[3] };
                return true;
            case "LEFT":
                if (t.Length != 3 || !IsTag(t[1]) || !TryMid(t[2], out int lm)) return false;
                ev = new ServerEvent { Kind = ServerEventKind.Left, Tag = t[1], Mid = lm };
                return true;
            case "MSG":
            case "HIST":
                if (t.Length != 4 || !IsTag(t[1]) || !TryNumber(t[2], out long id)) return false;
                if (!IsBase64(t[3], ProtocolLimits.MinPayloadChars, ProtocolLimits.MaxPayloadChars)) return false;
                ev = new ServerEvent { Kind = t[0] == "MSG" ? ServerEventKind.Msg : ServerEventKind.Hist, Tag = t[1], Id = id, Data = t[3] };
                return true;
            case "ACK":
            case "HISTEND":
                if (t.Length != 3 || !IsTag(t[1]) || !TryNumber(t[2], out long n)) return false;
                ev = new ServerEvent { Kind = t[0] == "ACK" ? ServerEventKind.Ack : ServerEventKind.HistEnd, Tag = t[1], Id = n };
                return true;
            case "PONG":
                if (t.Length != 1) return false;
                ev = new ServerEvent { Kind = ServerEventKind.Pong };
                return true;
            case "ERR":
                if (t.Length != 2 || !IsErrCode(t[1])) return false;
                ev = new ServerEvent { Kind = ServerEventKind.Err, Data = t[1] };
                return true;
            default:
                return false;
        }
    }

    public static bool IsTag(string s)
    {
        if (s == null || s.Length != ProtocolLimits.TagChars) return false;
        foreach (char c in s)
        {
            bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-';
            if (!ok) return false;
        }
        return true;
    }

    public static bool IsBase64(string s, int min, int max)
    {
        if (s == null || s.Length < min || s.Length > max) return false;
        int end = s.Length;
        while (end > 0 && s[end - 1] == '=') end--;
        if (s.Length - end > 2) return false;
        for (int i = 0; i < end; i++)
        {
            char c = s[i];
            bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/';
            if (!ok) return false;
        }
        return true;
    }

    private static bool TryNumber(string s, out long value)
    {
        value = 0;
        if (s.Length < 1 || s.Length > 18) return false;
        foreach (char c in s) if (c < '0' || c > '9') return false;
        return long.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture, out value);
    }

    private static bool TryMid(string s, out int mid)
    {
        mid = 0;
        if (s.Length < 1 || s.Length > 9) return false;
        foreach (char c in s) if (c < '0' || c > '9') return false;
        return int.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture, out mid);
    }

    private static bool IsErrCode(string s)
    {
        if (s.Length < 1 || s.Length > 32) return false;
        foreach (char c in s) if (c < 'a' || c > 'z') return false;
        return true;
    }
}
