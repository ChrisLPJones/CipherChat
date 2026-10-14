using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace CipherChatClient;

public enum DecryptStatus { Ok, WrongKey, Malformed }

// Client-side rules that are independent of the Console UI so they can be unit tested.
public static class MessageRules
{
    // Returns null when valid, otherwise the reason it is rejected.
    public static string ValidateUsername(string name)
    {
        if (string.IsNullOrEmpty(name) || name.Length < ProtocolLimits.MinUsernameLength)
            return "A username is required to proceed.";
        if (name.Length > ProtocolLimits.MaxUsernameLength)
            return $"The username must be at most {ProtocolLimits.MaxUsernameLength} characters.";
        foreach (char c in name)
        {
            bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
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

    // Decrypts one received line and classifies the outcome.
    public static DecryptStatus TryDecrypt(string line, string key, out string plainText)
    {
        plainText = null;
        try
        {
            plainText = AESecureString.DecryptCipher(line, key);
            return DecryptStatus.Ok;
        }
        catch (CipherAuthenticationException)
        {
            return DecryptStatus.WrongKey;
        }
        catch (FormatException)
        {
            return DecryptStatus.Malformed;
        }
    }
}
