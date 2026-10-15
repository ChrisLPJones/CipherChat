namespace CipherChatServer;

public enum ClientVerb { Hello, Key, Confirm, Msg, Ping }

// One validated client-to-server line (wire protocol v5).
public sealed class ClientCommand
{
    public ClientVerb Verb { get; init; }
    public string Rid { get; init; }     // HELLO: 6 lowercase hex chars
    public string Nonce { get; init; }   // HELLO: 32 lowercase hex chars
    public string Data { get; init; }    // KEY/CONFIRM/MSG: Base64, opaque to the server
}

// Wire grammar v5, server side. Single-space separated ASCII tokens, closed grammar. The server never decodes
// Base64: it checks charset, canonical padding, exact lengths (or the padded-block structure for MSG) only.
// The client has its own copy (ClientFrame.cs); tests cross-check them.
public static class ServerFrame
{
    public const int Version = 5;
    public static readonly string[] ErrorCodes = { "version", "used", "full", "rate", "timeout" };

    public static bool TryParse(string line, out ClientCommand cmd)
    {
        cmd = null;
        if (line == null || line.Length == 0 || line.Length > ProtocolLimits.MaxLineChars) return false;
        string[] t = line.Split(' ');
        foreach (string token in t) if (token.Length == 0) return false;

        switch (t[0])
        {
            case "HELLO":
                if (t.Length != 4 || t[1] != "5" || !IsHex(t[2], ProtocolLimits.RidChars) || !IsHex(t[3], ProtocolLimits.NonceChars)) return false;
                cmd = new ClientCommand { Verb = ClientVerb.Hello, Rid = t[2], Nonce = t[3] };
                return true;
            case "PING":
                if (t.Length != 1) return false;
                cmd = new ClientCommand { Verb = ClientVerb.Ping };
                return true;
            case "KEY":
                if (t.Length != 2 || !IsBase64Bytes(t[1], 32)) return false;
                cmd = new ClientCommand { Verb = ClientVerb.Key, Data = t[1] };
                return true;
            case "CONFIRM":
                if (t.Length != 2 || !IsBase64Bytes(t[1], 64)) return false;
                cmd = new ClientCommand { Verb = ClientVerb.Confirm, Data = t[1] };
                return true;
            case "MSG":
                if (t.Length != 2 || !IsMsgBlob(t[1])) return false;
                cmd = new ClientCommand { Verb = ClientVerb.Msg, Data = t[1] };
                return true;
            default:
                return false;
        }
    }

    // Exactly 'chars' lowercase hexadecimal characters.
    public static bool IsHex(string s, int chars)
    {
        if (s == null || s.Length != chars) return false;
        foreach (char c in s)
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
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
    public const string Wait = "WAIT";
    public const string Gone = "GONE";
    public const string Pong = "PONG";
    public static string Paired(int role, string peerNonceHex) => $"PAIRED {role} {peerNonceHex}";
    public static string Relay(ClientVerb verb, string blob) =>
        $"{(verb == ClientVerb.Key ? "KEY" : verb == ClientVerb.Confirm ? "CONFIRM" : "MSG")} {blob}";
    public static string Err(string code) => $"ERR {code}";
}
