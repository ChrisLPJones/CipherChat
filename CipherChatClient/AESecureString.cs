using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CipherChatClient
{
    public class AESecureString
    {
        public static string EncryptString(string plainText, string key)
        {
            // Convert the plain text message into a byte array
            byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);

            // Generate a random 16-byte salt for this encryption
            byte[] salt = new byte[16];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt); // Fill the salt with random bytes
            }

            // Derive a 256-bit AES key from the passphrase and salt using PBKDF2 with 1000 iterations and SHA256
            using Rfc2898DeriveBytes rfc = new(key, salt, 1000, HashAlgorithmName.SHA256);
            byte[] saltedKeyBytes = rfc.GetBytes(32); // Generate a 256-bit key

            // Create an AES encryption object with the derived key
            using Aes aes = Aes.Create();
            aes.KeySize = 256;
            aes.GenerateIV(); // Generate a random IV for encryption
            aes.Key = saltedKeyBytes;

            // Encrypt the plaintext bytes using the AES encryptor
            using ICryptoTransform encrypt = aes.CreateEncryptor();
            byte[] cipherTextBytes = encrypt.TransformFinalBlock(plainTextBytes, 0, plainTextBytes.Length);

            // Combine salt, IV, and ciphertext into a single array for easy transport/storage
            byte[] result = new byte[salt.Length + aes.IV.Length + cipherTextBytes.Length];
            Array.Copy(salt, 0, result, 0, salt.Length); // Copy salt to the beginning of result
            Array.Copy(aes.IV, 0, result, salt.Length, aes.IV.Length); // Followed by IV
            Array.Copy(cipherTextBytes, 0, result, salt.Length + aes.IV.Length, cipherTextBytes.Length); // And finally ciphertext

            // Convert the combined byte array to a Base64 string for easy transmission
            return Convert.ToBase64String(result);
        }

        public static string DecryptCipher(string cipherText, string key)
        {
            // Decode the Base64 encoded string back to a byte array
            byte[] cipherBytes = Convert.FromBase64String(cipherText);

            // Extract the salt from the beginning of the byte array
            byte[] salt = new byte[16];
            Array.Copy(cipherBytes, 0, salt, 0, salt.Length);

            // Derive the AES key using the passphrase and extracted salt with PBKDF2
            using Rfc2898DeriveBytes rfc = new(key, salt, 1000, HashAlgorithmName.SHA256);
            byte[] saltedKeyBytes = rfc.GetBytes(32); // Regenerate the 256-bit key

            // Create an AES decryption object with the derived key
            using Aes aes = Aes.Create();
            aes.KeySize = 256;
            aes.Key = saltedKeyBytes;

            // Extract the IV from the cipher bytes after the salt
            byte[] iv = new byte[aes.BlockSize / 8];
            Array.Copy(cipherBytes, salt.Length, iv, 0, iv.Length);
            aes.IV = iv;

            // Extract the actual encrypted data (ciphertext) following the salt and IV
            byte[] actualCipherBytes = new byte[cipherBytes.Length - iv.Length - salt.Length];
            Array.Copy(cipherBytes, salt.Length + iv.Length, actualCipherBytes, 0, actualCipherBytes.Length);

            // Decrypt the ciphertext using the AES decryptor
            using ICryptoTransform decrypt = aes.CreateDecryptor();
            try
            {
                byte[] plainTextBytes = decrypt.TransformFinalBlock(actualCipherBytes, 0, actualCipherBytes.Length);
                string plainText = Encoding.UTF8.GetString(plainTextBytes); // Convert decrypted bytes back to string
                return plainText;
            }
            catch (CryptographicException)
            {
                // Catch any errors that occur during decryption (e.g., wrong key or corrupt data)
                return string.Empty; // Return an empty string if decryption fails
            }
        }
    }
}
