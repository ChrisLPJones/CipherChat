using System.Security.Cryptography;

namespace CipherChatClient;

// Safety number shown to both users so they can compare it out of band.
// fp_X = SHA-256("CipherChat-v4/fp" || lp(user) || IK_X)
// s = SHA-512("CipherChat-v4/safety" || min(fp_A, fp_B) || max(fp_A, fp_B))
// 12 groups of 5 digits; group i = uint40(s[5i..5i+5]) mod 100000.
public static class SafetyNumber
{
    public static byte[] Fingerprint(string user, byte[] identityPublicKey) =>
        SHA256.HashData(Proto.Concat(Proto.Label("CipherChat-v4/fp"), Proto.Lp(user), identityPublicKey));

    public static string[] Groups(string userA, byte[] pubA, string userB, byte[] pubB)
    {
        byte[] fa = Fingerprint(userA, pubA);
        byte[] fb = Fingerprint(userB, pubB);
        bool aFirst = fa.AsSpan().SequenceCompareTo(fb) <= 0;
        byte[] s = SHA512.HashData(Proto.Concat(Proto.Label("CipherChat-v4/safety"), aFirst ? fa : fb, aFirst ? fb : fa));
        string[] groups = new string[12];
        for (int i = 0; i < 12; i++)
        {
            ulong v = 0;
            for (int j = 0; j < 5; j++) v = (v << 8) | s[5 * i + j];
            groups[i] = (v % 100000UL).ToString("D5");
        }
        return groups;
    }

    // Two lines of six groups, e.g. "12345 12345 ...\n12345 ...". Identical for both users.
    public static string Compute(string userA, byte[] pubA, string userB, byte[] pubB)
    {
        string[] g = Groups(userA, pubA, userB, pubB);
        return string.Join(' ', g, 0, 6) + "\n" + string.Join(' ', g, 6, 6);
    }
}
