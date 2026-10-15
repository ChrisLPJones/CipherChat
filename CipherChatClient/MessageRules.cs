using System.Globalization;
using System.Text;

namespace CipherChatClient;

// Client-side rules that are independent of the Console UI so they can be unit tested.
public static class MessageRules
{
    public const string NeutralPeerLabel = "Them";

    // Returns null when valid, otherwise the reason in plain words. A handle is a display name, not an identity:
    // 1-20 characters from [A-Za-z0-9_.-]; "you" is reserved because own lines are shown as "You:".
    public static string ValidateHandle(string handle)
    {
        if (string.IsNullOrEmpty(handle)) return "Please enter a handle.";
        if (handle.Length > ProtocolLimits.MaxHandleChars) return $"The handle may have at most {ProtocolLimits.MaxHandleChars} characters.";
        foreach (char c in handle)
        {
            bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-';
            if (!ok) return "Use only letters, digits, '_', '.' and '-' in the handle (no spaces).";
        }
        if (handle.Equals("you", StringComparison.OrdinalIgnoreCase)) return "That handle is reserved. Please choose another.";
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
