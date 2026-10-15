using System.Runtime.InteropServices;

namespace CipherChatClient;

// Thin P/Invoke wrapper around the five libsodium functions we use (NuGet "libsodium" 1.0.22, ISC licence).
// All group arithmetic (ristretto255), scalar sampling and Argon2id come from libsodium; we only check
// array lengths before every call and treat every non-zero return code as a failure.
internal static class Sodium
{
    public const int PointBytes = 32;       // crypto_core_ristretto255_BYTES
    public const int ScalarBytes = 32;      // crypto_core_ristretto255_SCALARBYTES
    public const int HashBytes = 64;        // crypto_core_ristretto255_HASHBYTES
    public const int PwhashSaltBytes = 16;  // crypto_pwhash_SALTBYTES
    public const int PwhashAlgArgon2id13 = 2;

    private const string Lib = "libsodium";

    [DllImport(Lib)] private static extern int sodium_init();
    [DllImport(Lib)] private static extern int crypto_core_ristretto255_from_hash(byte[] p, byte[] r);
    [DllImport(Lib)] private static extern void crypto_core_ristretto255_scalar_random(byte[] r);
    [DllImport(Lib)] private static extern int crypto_scalarmult_ristretto255(byte[] q, byte[] n, byte[] p);
    [DllImport(Lib)]
    private static extern int crypto_pwhash(byte[] output, ulong outlen, byte[] passwd, ulong passwdlen, byte[] salt,
        ulong opslimit, nuint memlimit, int alg);

    private static readonly object initLock = new();
    private static bool initialized;

    // Must succeed before anything else is used; throws if the native library is missing or cannot start.
    public static void Init()
    {
        lock (initLock)
        {
            if (initialized) return;
            int rc;
            try { rc = sodium_init(); }
            catch (Exception ex) when (ex is DllNotFoundException or BadImageFormatException or EntryPointNotFoundException)
            {
                throw new CryptographicUnavailableException("The libsodium library could not be loaded on this platform.", ex);
            }
            if (rc < 0) throw new CryptographicUnavailableException("libsodium failed to initialise.", null);
            initialized = true;
        }
    }

    // Maps 64 uniform bytes to a ristretto255 point (the element-derivation step of the CPace generator).
    public static byte[] PointFromHash(byte[] hash64)
    {
        Init();
        Require(hash64, HashBytes);
        byte[] p = new byte[PointBytes];
        if (crypto_core_ristretto255_from_hash(p, hash64) != 0) throw new System.Security.Cryptography.CryptographicException("Point derivation failed.");
        return p;
    }

    public static byte[] RandomScalar()
    {
        Init();
        byte[] s = new byte[ScalarBytes];
        crypto_core_ristretto255_scalar_random(s);
        return s;
    }

    // q = n * p. Returns null when libsodium rejects the input (invalid encoding, or the result is the identity).
    public static byte[] ScalarMult(byte[] scalar, byte[] point)
    {
        Init();
        Require(scalar, ScalarBytes);
        Require(point, PointBytes);
        byte[] q = new byte[PointBytes];
        return crypto_scalarmult_ristretto255(q, scalar, point) == 0 ? q : null;
    }

    // Argon2id (ARGON2ID13), 32-byte output. Throws InsufficientMemoryException when the memory cannot be allocated.
    public static byte[] Argon2id(byte[] password, byte[] salt16, ulong opslimit, nuint memlimit)
    {
        Init();
        Require(salt16, PwhashSaltBytes);
        byte[] output = new byte[32];
        if (crypto_pwhash(output, (ulong)output.Length, password, (ulong)password.Length, salt16, opslimit, memlimit, PwhashAlgArgon2id13) != 0)
            throw new InsufficientMemoryException("Not enough memory to derive the rendezvous id (about 256 MiB are needed).");
        return output;
    }

    private static void Require(byte[] a, int length)
    {
        if (a == null || a.Length != length) throw new ArgumentException($"Expected {length} bytes.");
    }
}

public sealed class CryptographicUnavailableException : Exception
{
    public CryptographicUnavailableException(string message, Exception inner) : base(message, inner) { }
}
