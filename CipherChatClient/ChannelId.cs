using System.Security.Cryptography;

namespace CipherChatClient;

// Channel naming and keyed tag derivation. A channel is (tag, key); room, DM and lobby are the same thing.
// The tag is a capability: PBKDF2-SHA256(key, salt = "cipherchat-channel-v1|<kind>|<name>", 600k, 16 bytes),
// Base64Url without padding (22 chars). The salt domain string differs from the random 16-byte per-message
// salts used for message keys, so the tag does not reveal or shortcut a message key. A wrong key yields a
// different (empty) channel. The server can run an offline guess against a tag, no cheaper than against a ciphertext.
public static class ChannelId
{
    public const string LobbyName = "general";
    private const string Domain = "cipherchat-channel-v1";
    private const int TagBytes = 16;

    // Room names are compared case-insensitively.
    public static string NormalizeRoomName(string room) => room.ToLowerInvariant();

    // Sorted, case-insensitive pair "a|b" (symmetric). '|' cannot occur in usernames.
    public static string DmName(string userA, string userB)
    {
        string a = userA.ToLowerInvariant();
        string b = userB.ToLowerInvariant();
        return string.CompareOrdinal(a, b) <= 0 ? $"{a}|{b}" : $"{b}|{a}";
    }

    public static string DeriveRoomTag(string room, string key) =>
        Derive($"{Domain}|room|{NormalizeRoomName(room)}", key);

    public static string DeriveDmTag(string userA, string userB, string key) =>
        Derive($"{Domain}|dm|{DmName(userA, userB)}", key);

    private static string Derive(string saltText, string key)
    {
        byte[] salt = System.Text.Encoding.UTF8.GetBytes(saltText);
        byte[] raw = Rfc2898DeriveBytes.Pbkdf2(key, salt, AESecureString.Pbkdf2Iterations, HashAlgorithmName.SHA256, TagBytes);
        string tag = Convert.ToBase64String(raw).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        CryptographicOperations.ZeroMemory(raw);
        return tag;
    }
}
