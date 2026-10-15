using System.Security.Cryptography;
using System.Text;

namespace CipherChatClient;

// The shared code: normalization, the quality rules the client enforces, and the rendezvous id.
public static class PairCode
{
    public const int MinChars = ProtocolLimits.MinCodeChars;
    public const int MaxChars = ProtocolLimits.MaxCodeChars;
    public const int MinDistinct = 6;
    public const int MinDigitsOnly = 20;

    // Argon2id parameters are fixed constants (not libsodium's "moderate" helpers, which may change).
    public const ulong RidOps = 3;
    public const long RidMemBytes = 256L * 1024 * 1024;
    public const int RidBytes = 3;                       // truncated to 24 bits on purpose (see the architecture report)

    private static readonly string[] Runs =
    {
        "abcdefghijklmnopqrstuvwxyz", "012345678901234567890123456789", "qwertyuiop", "asdfghjkl", "zxcvbnm", "qwertyuiopasdfghjklzxcvbnm",
    };

    // trim, collapse whitespace runs to one space, ASCII A-Z to lower case. Anything else is left for Validate.
    public static string Normalize(string code)
    {
        if (code == null) return "";
        StringBuilder sb = new();
        bool space = false;
        foreach (char c in code)
        {
            if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f') { space = sb.Length > 0; continue; }
            if (space) { sb.Append(' '); space = false; }
            sb.Append(c >= 'A' && c <= 'Z' ? (char)(c + 32) : c);
        }
        return sb.ToString();
    }

    // Returns null when the normalized code is acceptable, otherwise the specific rule it breaks.
    public static string Validate(string normalized)
    {
        if (string.IsNullOrEmpty(normalized)) return "Please type a code.";
        foreach (char c in normalized)
            if (c < 0x20 || c > 0x7E) return "Use only plain keyboard characters (letters, digits, punctuation and spaces; no accents or emoji).";
        if (normalized.Length > MaxChars) return $"The code is too long (at most {MaxChars} characters).";
        if (normalized.Length < MinChars) return $"The code is too short (at least {MinChars} characters). Make up 4 or more random words together.";
        if (normalized.Distinct().Count() < MinDistinct) return $"The code is too repetitive (at least {MinDistinct} different characters).";
        string compact = normalized.Replace(" ", "");
        if (compact.Length > 0 && compact.All(c => c == compact[0])) return "The code is just one repeated character.";
        foreach (string run in Runs)
        {
            string rev = new(run.Reverse().ToArray());
            if (run.Contains(compact) || rev.Contains(compact)) return "The code is a straight run of keys (like abcdef, 123456 or qwerty).";
        }
        if (compact.All(char.IsAsciiDigit) && compact.Length < MinDigitsOnly)
            return $"A code of only digits needs at least {MinDigitsOnly} digits (dates and phone numbers are easy to guess).";
        return null;
    }

    // rid = first 3 bytes of Argon2id(code, salt = first 16 bytes of SHA-256("CipherChat-v5/rid" || 0x00)), as 6 lowercase hex chars.
    public static string DeriveRid(string normalized)
    {
        byte[] salt = SHA256.HashData(Proto.Label("CipherChat-v5/rid"))[..Sodium.PwhashSaltBytes];
        byte[] pw = Encoding.ASCII.GetBytes(normalized);
        byte[] full = Sodium.Argon2id(pw, salt, RidOps, (nuint)RidMemBytes);
        CryptographicOperations.ZeroMemory(pw);
        string rid = Convert.ToHexString(full, 0, RidBytes).ToLowerInvariant();
        CryptographicOperations.ZeroMemory(full);
        return rid;
    }

    internal static byte[] DeriveRidFull(string normalized)
    {
        byte[] salt = SHA256.HashData(Proto.Label("CipherChat-v5/rid"))[..Sodium.PwhashSaltBytes];
        return Sodium.Argon2id(Encoding.ASCII.GetBytes(normalized), salt, RidOps, (nuint)RidMemBytes);
    }
}
