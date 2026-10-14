using System;
using System.Security.Cryptography;
using System.Text;

namespace CipherChatClient
{
    // Thrown when the authentication tag does not match: wrong key or tampered data.
    public class CipherAuthenticationException : CryptographicException
    {
        public CipherAuthenticationException(string message, Exception inner) : base(message, inner) { }
    }

    public class AESecureString
    {
        public const int Pbkdf2Iterations = 600_000;
        public const int MaxPlaintextBytes = ProtocolLimits.MaxPlaintextBytes;

        private const byte Version = 0x03;
        private const int SaltSize = 16;
        private const int NonceSize = 12;
        private const int TagSize = 16;
        private const int HeaderSize = 1 + SaltSize + NonceSize;

        // Wire format (Base64 of): version(1)=0x03 | salt(16) | nonce(12) | ciphertext | tag(16)
        // Additional authenticated data = version byte || ASCII bytes of the channel tag, so a
        // blob only decrypts in the channel it was produced for (the server cannot move it).
        // Salt and nonce are random per call (messages and presence blobs alike).
        public static string EncryptString(string plainText, string key, string channelTag)
        {
            byte[] aad = BuildAad(channelTag);
            byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);
            if (plainTextBytes.Length > MaxPlaintextBytes)
                throw new ArgumentException($"Plaintext exceeds {MaxPlaintextBytes} bytes.", nameof(plainText));

            byte[] result = new byte[HeaderSize + plainTextBytes.Length + TagSize];
            result[0] = Version;
            Span<byte> salt = result.AsSpan(1, SaltSize);
            Span<byte> nonce = result.AsSpan(1 + SaltSize, NonceSize);
            RandomNumberGenerator.Fill(salt);
            RandomNumberGenerator.Fill(nonce);

            byte[] aesKey = Rfc2898DeriveBytes.Pbkdf2(key, salt.ToArray(), Pbkdf2Iterations, HashAlgorithmName.SHA256, 32);
            try
            {
                using AesGcm gcm = new(aesKey, TagSize);
                gcm.Encrypt(nonce, plainTextBytes,
                    result.AsSpan(HeaderSize, plainTextBytes.Length),
                    result.AsSpan(HeaderSize + plainTextBytes.Length, TagSize),
                    aad);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(aesKey);
            }

            return Convert.ToBase64String(result);
        }

        // Throws FormatException (bad Base64, too short, unknown version) or
        // CipherAuthenticationException (wrong key or tampered data).
        public static string DecryptCipher(string cipherText, string key, string channelTag)
        {
            byte[] aad = BuildAad(channelTag);
            byte[] data = Convert.FromBase64String(cipherText); // FormatException on bad Base64
            if (data.Length < HeaderSize + TagSize)
                throw new FormatException("Ciphertext is too short.");
            if (data[0] != Version)
                throw new FormatException("Unknown ciphertext version.");

            // Shape checks above run before the expensive KDF.
            byte[] salt = data.AsSpan(1, SaltSize).ToArray();
            int cipherLength = data.Length - HeaderSize - TagSize;
            byte[] aesKey = Rfc2898DeriveBytes.Pbkdf2(key, salt, Pbkdf2Iterations, HashAlgorithmName.SHA256, 32);
            byte[] plain = new byte[cipherLength];
            try
            {
                using AesGcm gcm = new(aesKey, TagSize);
                gcm.Decrypt(data.AsSpan(1 + SaltSize, NonceSize),
                    data.AsSpan(HeaderSize, cipherLength),
                    data.AsSpan(HeaderSize + cipherLength, TagSize),
                    plain,
                    aad);
            }
            catch (AuthenticationTagMismatchException ex)
            {
                throw new CipherAuthenticationException("Authentication failed: wrong key or corrupted data.", ex);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(aesKey);
            }

            try
            {
                return new UTF8Encoding(false, true).GetString(plain);
            }
            catch (DecoderFallbackException ex)
            {
                throw new FormatException("Decrypted data is not valid UTF-8.", ex);
            }
        }

        private static byte[] BuildAad(string channelTag)
        {
            if (string.IsNullOrEmpty(channelTag))
                throw new ArgumentException("A channel tag is required.", nameof(channelTag));
            byte[] tag = Encoding.ASCII.GetBytes(channelTag);
            byte[] aad = new byte[1 + tag.Length];
            aad[0] = Version;
            tag.CopyTo(aad, 1);
            return aad;
        }
    }
}
