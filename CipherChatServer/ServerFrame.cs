using System.Globalization;

namespace CipherChatServer;

public enum ClientVerb { Hello, Join, Leave, Msg, Hist, Ping }

// One validated client-to-server line (wire protocol v3).
public sealed class ClientCommand
{
    public ClientVerb Verb { get; init; }
    public string Tag { get; init; }
    public string Data { get; init; }   // presence (JOIN) or payload (MSG), Base64, opaque to the server
    public long AfterId { get; init; }
    public int Max { get; init; }
}

// Wire grammar, server side. Single-space separated ASCII tokens; every token is checked
// against a closed grammar before the server uses it. The server never decodes Base64
// tokens: it only checks charset and length. The client has its own copy (ClientFrame.cs).
public static class ServerFrame
{
    public const int Version = 3;
    public const string HelloLine = "HELLO 3";

    // Returns false for any line outside the grammar (caller closes the connection).
    public static bool TryParse(string line, out ClientCommand cmd)
    {
        cmd = null;
        if (line == null || line.Length == 0 || line.Length > ProtocolLimits.MaxLineChars) return false;
        string[] t = line.Split(' ');
        foreach (string token in t)
            if (token.Length == 0) return false; // leading, trailing or double space

        switch (t[0])
        {
            case "HELLO":
                if (t.Length != 2 || t[1] != "3") return false;
                cmd = new ClientCommand { Verb = ClientVerb.Hello };
                return true;
            case "PING":
                if (t.Length != 1) return false;
                cmd = new ClientCommand { Verb = ClientVerb.Ping };
                return true;
            case "LEAVE":
                if (t.Length != 2 || !IsTag(t[1])) return false;
                cmd = new ClientCommand { Verb = ClientVerb.Leave, Tag = t[1] };
                return true;
            case "JOIN":
                if (t.Length != 3 || !IsTag(t[1])) return false;
                if (!IsBase64(t[2], ProtocolLimits.MinPayloadChars, ProtocolLimits.MaxPresenceChars)) return false;
                cmd = new ClientCommand { Verb = ClientVerb.Join, Tag = t[1], Data = t[2] };
                return true;
            case "MSG":
                if (t.Length != 3 || !IsTag(t[1])) return false;
                if (!IsBase64(t[2], ProtocolLimits.MinPayloadChars, ProtocolLimits.MaxPayloadChars)) return false;
                cmd = new ClientCommand { Verb = ClientVerb.Msg, Tag = t[1], Data = t[2] };
                return true;
            case "HIST":
                if (t.Length != 4 || !IsTag(t[1])) return false;
                if (!TryParseId(t[2], out long after)) return false;
                if (!TryParseId(t[3], out long max) || max < 1 || max > ProtocolLimits.MaxHistoryReplay) return false;
                cmd = new ClientCommand { Verb = ClientVerb.Hist, Tag = t[1], AfterId = after, Max = (int)max };
                return true;
            default:
                return false;
        }
    }

    // Opaque channel id: exactly TagChars characters of [A-Za-z0-9_-] (Base64Url without padding).
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

    // Base64 charset, '=' only as 1-2 trailing padding characters, length within bounds.
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

    // Non-negative decimal number of 1-18 digits.
    public static bool TryParseId(string s, out long value)
    {
        value = 0;
        if (s == null || s.Length < 1 || s.Length > 18) return false;
        foreach (char c in s) if (c < '0' || c > '9') return false;
        return long.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture, out value);
    }

    // Server-to-client lines (without the trailing newline).
    public static string Welcome(int mid) => $"WELCOME {Version} {mid}";
    public static string Member(string tag, int mid, string presence) => $"MEMBER {tag} {mid} {presence}";
    public static string Joined(string tag, int mid, string presence) => $"JOINED {tag} {mid} {presence}";
    public static string Left(string tag, int mid) => $"LEFT {tag} {mid}";
    public static string Msg(string tag, long id, string payload) => $"MSG {tag} {id} {payload}";
    public static string Ack(string tag, long id) => $"ACK {tag} {id}";
    public static string HistEnd(string tag, long headId) => $"HISTEND {tag} {headId}";
    public const string Pong = "PONG";
    public static string Err(string code) => $"ERR {code}";
}
