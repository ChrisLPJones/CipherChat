using System.Globalization;
using System.Text;

namespace CipherChatClient;

// Client-side rules that are independent of the Console UI so they can be unit tested.
public static class MessageRules
{
    // User names are canonical lowercase on the wire; the client lowercases what the user types.
    // Only ASCII A-Z are lowercased (no culture or Unicode case folding, so look-alike characters stay invalid).
    public static string Canonicalize(string name)
    {
        if (name == null) return null;
        return string.Create(name.Trim().Length, name.Trim(), (span, src) =>
        {
            for (int i = 0; i < src.Length; i++) span[i] = src[i] >= 'A' && src[i] <= 'Z' ? (char)(src[i] + 32) : src[i];
        });
    }

    // Returns null when valid, otherwise the reason it is rejected (the name is checked in its canonical form).
    public static string ValidateUsername(string name)
    {
        name = Canonicalize(name);
        if (string.IsNullOrEmpty(name) || name.Length < ProtocolLimits.MinUsernameLength)
            return "A username is required to proceed.";
        if (name.Length > ProtocolLimits.MaxUsernameLength)
            return $"The username must be at most {ProtocolLimits.MaxUsernameLength} characters.";
        foreach (char c in name)
        {
            bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                      || c == '_' || c == '.' || c == '-';
            if (!ok)
                return "The username may only contain letters, digits, '_', '.' and '-' (no spaces or colons).";
        }
        return null;
    }

    // Removes control, format (bidi overrides, zero-width), line and paragraph separator characters (including ESC) so decrypted text cannot inject terminal escapes.
    public static string SanitizeForDisplay(string text)
    {
        if (text == null) return "";
        StringBuilder sb = new(text.Length);
        foreach (char c in text)
        {
            if (char.IsControl(c)) continue;
            UnicodeCategory cat = char.GetUnicodeCategory(c);
            if (cat == UnicodeCategory.Format || cat == UnicodeCategory.LineSeparator || cat == UnicodeCategory.ParagraphSeparator) continue;
            sb.Append(c);
        }
        return sb.ToString();
    }
}
