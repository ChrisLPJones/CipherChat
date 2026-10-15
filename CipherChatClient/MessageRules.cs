using System.Globalization;
using System.Text;

namespace CipherChatClient;

// Client-side rules that are independent of the Console UI so they can be unit tested.
public static class MessageRules
{
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
