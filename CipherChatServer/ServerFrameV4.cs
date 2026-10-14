namespace CipherChatServer;

public enum ClientVerbV4 { Hello, Register, Login, Key, Offer, Accept, Confirm, Msg, Knock, Users, Ping }

// One validated client-to-server line (wire protocol v4).
public sealed class ClientCommandV4
{
    public ClientVerbV4 Verb { get; init; }
    public string User { get; init; }   // REGISTER/LOGIN: the account name; others: the target user
    public string Pub { get; init; }    // REGISTER: Base64 identity key (opaque here)
    public string Data { get; init; }   // LOGIN/REGISTER: signature; OFFER/ACCEPT/CONFIRM/MSG/KNOCK: blob (Base64, opaque)
}

// Wire grammar v4, server side. Single-space separated ASCII tokens, closed grammar. The server never decodes
// Base64: it checks charset, canonical padding, exact lengths (or the padded-block structure for MSG) only.
// The client has its own copy (ClientFrameV4.cs); tests cross-check them. Replaces ServerFrame (v3) in task T4.
public static class ServerFrameV4
{
    public const int Version = 4;
    public const string HelloLine = "HELLO 4";
    public static readonly string[] ErrorCodes =
        { "version", "auth", "taken", "nouser", "self", "rate", "full", "limit", "replaced", "timeout", "notauth" };

    public static bool TryParse(string line, out ClientCommandV4 cmd)
    {
        cmd = null;
        if (line == null || line.Length == 0 || line.Length > ProtocolLimits.MaxLineCharsV4) return false;
        string[] t = line.Split(' ');
        foreach (string token in t) if (token.Length == 0) return false;

        switch (t[0])
        {
            case "HELLO":
                if (t.Length != 2 || t[1] != "4") return false;
                cmd = new ClientCommandV4 { Verb = ClientVerbV4.Hello };
                return true;
            case "PING":
                if (t.Length != 1) return false;
                cmd = new ClientCommandV4 { Verb = ClientVerbV4.Ping };
                return true;
            case "USERS":
                if (t.Length != 1) return false;
                cmd = new ClientCommandV4 { Verb = ClientVerbV4.Users };
                return true;
            case "REGISTER":
                if (t.Length != 4 || !IsUser(t[1]) || !IsBase64Bytes(t[2], 65) || !IsBase64Bytes(t[3], 64)) return false;
                cmd = new ClientCommandV4 { Verb = ClientVerbV4.Register, User = t[1], Pub = t[2], Data = t[3] };
                return true;
            case "LOGIN":
                if (t.Length != 3 || !IsUser(t[1]) || !IsBase64Bytes(t[2], 64)) return false;
                cmd = new ClientCommandV4 { Verb = ClientVerbV4.Login, User = t[1], Data = t[2] };
                return true;
            case "KEY":
                if (t.Length != 2 || !IsUser(t[1])) return false;
                cmd = new ClientCommandV4 { Verb = ClientVerbV4.Key, User = t[1] };
                return true;
            case "OFFER": return Blob(t, ClientVerbV4.Offer, 156, out cmd);
            case "ACCEPT": return Blob(t, ClientVerbV4.Accept, 179, out cmd);
            case "CONFIRM": return Blob(t, ClientVerbV4.Confirm, 50, out cmd);
            case "KNOCK": return Blob(t, ClientVerbV4.Knock, 74, out cmd);
            case "MSG":
                if (t.Length != 3 || !IsUser(t[1]) || !IsMsgBlob(t[2])) return false;
                cmd = new ClientCommandV4 { Verb = ClientVerbV4.Msg, User = t[1], Data = t[2] };
                return true;
            default:
                return false;
        }
    }

    private static bool Blob(string[] t, ClientVerbV4 verb, int bytes, out ClientCommandV4 cmd)
    {
        cmd = null;
        if (t.Length != 3 || !IsUser(t[1]) || !IsBase64Bytes(t[2], bytes)) return false;
        cmd = new ClientCommandV4 { Verb = verb, User = t[1], Data = t[2] };
        return true;
    }

    // Lowercase user name: 1-20 chars of [a-z0-9_.-].
    public static bool IsUser(string s)
    {
        if (s == null || s.Length < ProtocolLimits.MinUsernameLength || s.Length > ProtocolLimits.MaxUsernameLength) return false;
        foreach (char c in s)
        {
            bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-';
            if (!ok) return false;
        }
        return true;
    }

    // Canonical standard Base64 (with padding) of exactly 'bytes' bytes.
    public static bool IsBase64Bytes(string s, int bytes) => TryBase64ByteLength(s, out int n) && n == bytes;

    // MSG blob: 26-byte header + 256*k ciphertext (k = 1..24) + 16-byte tag.
    public static bool IsMsgBlob(string s)
    {
        if (s == null || s.Length < ProtocolLimits.MinMsgChars || s.Length > ProtocolLimits.MaxMsgChars) return false;
        if (!TryBase64ByteLength(s, out int n)) return false;
        int body = n - 26 - 16;
        return body >= ProtocolLimits.PadBlock && body % ProtocolLimits.PadBlock == 0 && body / ProtocolLimits.PadBlock <= 24;
    }

    // Charset, length multiple of 4, padding only at the end and with zero unused bits (canonical).
    // Returns the decoded byte count without decoding.
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

    // Server-to-client lines (without the trailing newline).
    public static string Welcome(string challengeB64) => $"WELCOME {Version} {challengeB64}";
    public static string Ready(string user) => $"READY {user}";
    public static string Key(string user, string pubB64) => $"KEY {user} {pubB64}";
    public static string Relay(string verb, string from, string blob) => $"{verb} {from} {blob}";
    public static string Offline(string user) => $"OFFLINE {user}";
    public static string Gone(string user) => $"GONE {user}";
    public const string Pong = "PONG";
    public static string Err(string code, string user = null) => user == null ? $"ERR {code}" : $"ERR {code} {user}";
    public static string UserList(IReadOnlyCollection<string> names) =>
        names.Count == 0 ? "USERLIST 0" : $"USERLIST {names.Count} {string.Join(' ', names)}";
}
