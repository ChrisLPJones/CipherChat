using System.Security.Cryptography;
using System.Text;

namespace CipherChatServer;

// Verifies REGISTER/LOGIN signatures with the BCL only (public keys only; the server never holds a private key).
// Public keys are 65-byte uncompressed P-256 points; signatures are IEEE P1363 (r || s, 64 bytes).
public static class AuthVerifier
{
    public const int PublicKeyBytes = 65;
    public const int SignatureBytes = 64;
    public const int ChallengeBytes = 32;

    // True when pub is a 0x04-prefixed point that lies on P-256 (import rejects off-curve points).
    public static bool IsValidPublicKey(byte[] pub)
    {
        if (!TryCreate(pub, out ECDsa e)) return false;
        e.Dispose();
        return true;
    }

    // "CipherChat-v4/register\0" || challenge || lp(user) || pub
    public static byte[] RegisterData(byte[] challenge, string user, byte[] pub) =>
        Concat(Label("CipherChat-v4/register"), challenge, Lp(user), pub);

    // "CipherChat-v4/login\0" || challenge || lp(user)
    public static byte[] LoginData(byte[] challenge, string user) =>
        Concat(Label("CipherChat-v4/login"), challenge, Lp(user));

    public static bool Verify(byte[] pub, byte[] data, byte[] signature)
    {
        if (signature == null || signature.Length != SignatureBytes) return false;
        if (!TryCreate(pub, out ECDsa e)) return false;
        using (e)
        {
            try { return e.VerifyData(data, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation); }
            catch (CryptographicException) { return false; }
        }
    }

    private static bool TryCreate(byte[] pub, out ECDsa ecdsa)
    {
        ecdsa = null;
        if (pub == null || pub.Length != PublicKeyBytes || pub[0] != 0x04) return false;
        try
        {
            ecdsa = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = pub[1..33], Y = pub[33..65] },
            });
            return true;
        }
        catch (CryptographicException) { return false; }
        catch (ArgumentException) { return false; }
    }

    private static byte[] Label(string s) { byte[] b = new byte[s.Length + 1]; Encoding.ASCII.GetBytes(s, 0, s.Length, b, 0); return b; }

    private static byte[] Lp(string name)
    {
        byte[] b = new byte[1 + name.Length];
        b[0] = (byte)name.Length;
        Encoding.ASCII.GetBytes(name, 0, name.Length, b, 1);
        return b;
    }

    private static byte[] Concat(params byte[][] parts)
    {
        byte[] r = new byte[parts.Sum(p => p.Length)];
        int o = 0;
        foreach (byte[] p in parts) { p.CopyTo(r, o); o += p.Length; }
        return r;
    }
}
