using System.Security.Cryptography;
using System.Text;

namespace CipherChatClient;

// Long-term identity: ECDSA P-256 / SHA-256, signatures in IEEE P1363 form (r || s, 64 bytes).
// Public keys travel as 65-byte uncompressed SEC1 points (0x04 || X || Y). Only BCL primitives.
public sealed class IdentityKey : IDisposable
{
    public const int PublicKeyBytes = 65;
    public const int SignatureBytes = 64;
    public const int Pbkdf2Iterations = 600_000;

    private readonly ECDsa key;
    private bool disposed;

    public byte[] PublicKey { get; }

    private IdentityKey(ECDsa key)
    {
        this.key = key;
        PublicKey = EncodePublic(key.ExportParameters(false));
    }

    public static IdentityKey Generate() => new(ECDsa.Create(ECCurve.NamedCurves.nistP256));

    // Loads an encrypted PKCS#8 key (PBES2, PBKDF2-SHA256, AES-256-CBC). Throws CryptographicException
    // for a wrong passphrase or a damaged / non-P-256 file.
    public static IdentityKey LoadEncrypted(byte[] encryptedPkcs8, string passphrase)
    {
        ECDsa ecdsa = ECDsa.Create();
        try
        {
            ecdsa.ImportEncryptedPkcs8PrivateKey(passphrase.AsSpan(), encryptedPkcs8, out _);
            ECParameters p = ecdsa.ExportParameters(true);
            try
            {
                if (p.Curve.Oid?.Value != "1.2.840.10045.3.1.7" && p.Curve.Oid?.FriendlyName != "nistP256")
                    throw new CryptographicException("The identity key is not an ECDSA P-256 key.");
            }
            finally { if (p.D != null) CryptographicOperations.ZeroMemory(p.D); }
            return new IdentityKey(ecdsa);
        }
        catch
        {
            ecdsa.Dispose();
            throw;
        }
    }

    // Encrypted PKCS#8: PBES2 with PBKDF2-SHA256 (600,000 iterations) and AES-256-CBC.
    public byte[] ExportEncrypted(string passphrase)
    {
        ThrowIfDisposed();
        PbeParameters pbe = new(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, Pbkdf2Iterations);
        return key.ExportEncryptedPkcs8PrivateKey(passphrase.AsSpan(), pbe);
    }

    public byte[] Sign(ReadOnlySpan<byte> data)
    {
        ThrowIfDisposed();
        return key.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

    // The private scalar d (32 bytes, big-endian). The caller must zero it after use.
    public byte[] ExportPrivateScalar()
    {
        ThrowIfDisposed();
        ECParameters p = key.ExportParameters(true);
        try
        {
            byte[] d = new byte[32];
            if (p.D.Length > 32) throw new CryptographicException("Unexpected private key size.");
            p.D.CopyTo(d, 32 - p.D.Length);
            return d;
        }
        finally { CryptographicOperations.ZeroMemory(p.D); }
    }

    // True when pub is a 65-byte uncompressed point that lies on P-256 (import rejects off-curve points).
    public static bool IsValidPublicKey(ReadOnlySpan<byte> pub) => TryCreateVerifier(pub, out ECDsa e) && Dispose(e);

    public static bool Verify(ReadOnlySpan<byte> pub, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        if (signature.Length != SignatureBytes) return false;
        if (!TryCreateVerifier(pub, out ECDsa e)) return false;
        using (e)
        {
            try { return e.VerifyData(data, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation); }
            catch (CryptographicException) { return false; }
        }
    }

    internal static bool TryDecodePoint(ReadOnlySpan<byte> pub, out ECParameters parameters)
    {
        parameters = default;
        if (pub.Length != PublicKeyBytes || pub[0] != 0x04) return false;
        parameters = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = pub.Slice(1, 32).ToArray(), Y = pub.Slice(33, 32).ToArray() },
        };
        return true;
    }

    internal static byte[] EncodePublic(ECParameters p)
    {
        byte[] pub = new byte[PublicKeyBytes];
        pub[0] = 0x04;
        p.Q.X.CopyTo(pub, 1 + 32 - p.Q.X.Length);
        p.Q.Y.CopyTo(pub, 33 + 32 - p.Q.Y.Length);
        return pub;
    }

    private static bool TryCreateVerifier(ReadOnlySpan<byte> pub, out ECDsa ecdsa)
    {
        ecdsa = null;
        if (!TryDecodePoint(pub, out ECParameters p)) return false;
        try
        {
            ecdsa = ECDsa.Create(p);
            return true;
        }
        catch (CryptographicException) { return false; }
        catch (ArgumentException) { return false; }
    }

    private static bool Dispose(IDisposable d) { d.Dispose(); return true; }

    private void ThrowIfDisposed() { if (disposed) throw new ObjectDisposedException(nameof(IdentityKey)); }

    public void Dispose()
    {
        disposed = true;
        key.Dispose();
    }
}

// Byte-building helpers shared by the handshake, channel, safety number and profile code.
internal static class Proto
{
    // ASCII label followed by one 0x00 byte (domain separation).
    public static byte[] Label(string s)
    {
        byte[] b = new byte[s.Length + 1];
        Encoding.ASCII.GetBytes(s, 0, s.Length, b, 0);
        return b;
    }

    // 1-byte length followed by the ASCII bytes (user names are at most 20 characters).
    public static byte[] Lp(string name)
    {
        if (name == null || name.Length == 0 || name.Length > 255) throw new ArgumentException("Invalid name.");
        byte[] b = new byte[1 + name.Length];
        b[0] = (byte)name.Length;
        Encoding.ASCII.GetBytes(name, 0, name.Length, b, 1);
        return b;
    }

    public static byte[] Concat(params byte[][] parts)
    {
        int len = 0;
        foreach (byte[] p in parts) len += p.Length;
        byte[] r = new byte[len];
        int o = 0;
        foreach (byte[] p in parts) { p.CopyTo(r, o); o += p.Length; }
        return r;
    }

    public static byte[] U64(long v)
    {
        byte[] b = new byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(b, v);
        return b;
    }

    public static byte[] U64(ulong v)
    {
        byte[] b = new byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(b, v);
        return b;
    }

    // Canonical lowercase user name: 1-20 chars of [a-z0-9_.-].
    public static bool IsUserName(string s)
    {
        if (s == null || s.Length < ProtocolLimits.MinUsernameLength || s.Length > ProtocolLimits.MaxUsernameLength) return false;
        foreach (char c in s)
        {
            bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-';
            if (!ok) return false;
        }
        return true;
    }
}
