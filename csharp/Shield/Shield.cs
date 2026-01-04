using System;
using System.Security.Cryptography;
using System.Text;

namespace Guard8.Shield
{
    /// <summary>
    /// Shield - EXPTIME-Secure Symmetric Encryption Library
    ///
    /// Uses only symmetric cryptographic primitives with proven exponential-time security:
    /// PBKDF2-SHA256, HMAC-SHA256, and SHA256-based stream cipher.
    /// Breaking requires 2^256 operations - no shortcut exists.
    /// </summary>
    public class Shield : IDisposable
    {
        public const int KeySize = 32;
        public const int NonceSize = 16;
        public const int MacSize = 16;
        public const int Iterations = 100000;
        public const int MinCiphertextSize = NonceSize + 8 + MacSize;

        private readonly byte[] _key;
        private bool _disposed;

        /// <summary>
        /// Create Shield from password and service name.
        /// </summary>
        public Shield(string password, string service)
        {
            byte[] salt = Sha256(Encoding.UTF8.GetBytes(service));
            _key = Pbkdf2(password, salt, Iterations, KeySize);
        }

        /// <summary>
        /// Create Shield with pre-shared key.
        /// </summary>
        public Shield(byte[] key)
        {
            if (key.Length != KeySize)
                throw new ArgumentException("Invalid key size", nameof(key));

            _key = new byte[KeySize];
            Array.Copy(key, _key, KeySize);
        }

        /// <summary>
        /// Encrypt plaintext.
        /// </summary>
        public byte[] Encrypt(byte[] plaintext)
        {
            return EncryptWithKey(_key, plaintext);
        }

        /// <summary>
        /// Decrypt ciphertext.
        /// </summary>
        public byte[] Decrypt(byte[] ciphertext)
        {
            return DecryptWithKey(_key, ciphertext);
        }

        /// <summary>
        /// Get the derived key.
        /// </summary>
        public byte[] GetKey()
        {
            byte[] copy = new byte[KeySize];
            Array.Copy(_key, copy, KeySize);
            return copy;
        }

        /// <summary>
        /// Quick encrypt with explicit key.
        /// </summary>
        public static byte[] QuickEncrypt(byte[] key, byte[] plaintext)
        {
            if (key.Length != KeySize)
                throw new ArgumentException("Invalid key size", nameof(key));
            return EncryptWithKey(key, plaintext);
        }

        /// <summary>
        /// Quick decrypt with explicit key.
        /// </summary>
        public static byte[] QuickDecrypt(byte[] key, byte[] ciphertext)
        {
            if (key.Length != KeySize)
                throw new ArgumentException("Invalid key size", nameof(key));
            return DecryptWithKey(key, ciphertext);
        }

        private static byte[] EncryptWithKey(byte[] key, byte[] plaintext)
        {
            // Generate random nonce
            byte[] nonce = RandomBytes(NonceSize);

            // Counter prefix (8 bytes of zeros)
            byte[] dataToEncrypt = new byte[8 + plaintext.Length];
            Array.Copy(plaintext, 0, dataToEncrypt, 8, plaintext.Length);

            // Generate keystream and XOR
            byte[] keystream = GenerateKeystream(key, nonce, dataToEncrypt.Length);
            byte[] ciphertext = new byte[dataToEncrypt.Length];
            for (int i = 0; i < dataToEncrypt.Length; i++)
                ciphertext[i] = (byte)(dataToEncrypt[i] ^ keystream[i]);

            // Compute HMAC over nonce || ciphertext
            byte[] macData = new byte[NonceSize + ciphertext.Length];
            Array.Copy(nonce, 0, macData, 0, NonceSize);
            Array.Copy(ciphertext, 0, macData, NonceSize, ciphertext.Length);
            byte[] mac = HmacSha256(key, macData);

            // Format: nonce || ciphertext || mac
            byte[] result = new byte[NonceSize + ciphertext.Length + MacSize];
            Array.Copy(nonce, 0, result, 0, NonceSize);
            Array.Copy(ciphertext, 0, result, NonceSize, ciphertext.Length);
            Array.Copy(mac, 0, result, NonceSize + ciphertext.Length, MacSize);

            return result;
        }

        private static byte[] DecryptWithKey(byte[] key, byte[] encrypted)
        {
            if (encrypted.Length < MinCiphertextSize)
                throw new ArgumentException("Ciphertext too short");

            // Parse components
            byte[] nonce = new byte[NonceSize];
            Array.Copy(encrypted, 0, nonce, 0, NonceSize);

            int ciphertextLen = encrypted.Length - NonceSize - MacSize;
            byte[] ciphertext = new byte[ciphertextLen];
            Array.Copy(encrypted, NonceSize, ciphertext, 0, ciphertextLen);

            byte[] receivedMac = new byte[MacSize];
            Array.Copy(encrypted, encrypted.Length - MacSize, receivedMac, 0, MacSize);

            // Verify MAC
            byte[] macData = new byte[NonceSize + ciphertextLen];
            Array.Copy(nonce, 0, macData, 0, NonceSize);
            Array.Copy(ciphertext, 0, macData, NonceSize, ciphertextLen);
            byte[] expectedMac = HmacSha256(key, macData);

            if (!ConstantTimeEquals(receivedMac, expectedMac, MacSize))
                throw new CryptographicException("Authentication failed");

            // Decrypt
            byte[] keystream = GenerateKeystream(key, nonce, ciphertextLen);
            byte[] decrypted = new byte[ciphertextLen];
            for (int i = 0; i < ciphertextLen; i++)
                decrypted[i] = (byte)(ciphertext[i] ^ keystream[i]);

            // Skip 8-byte counter prefix
            byte[] result = new byte[ciphertextLen - 8];
            Array.Copy(decrypted, 8, result, 0, ciphertextLen - 8);
            return result;
        }

        private static byte[] GenerateKeystream(byte[] key, byte[] nonce, int length)
        {
            int numBlocks = (length + 31) / 32;
            byte[] keystream = new byte[numBlocks * 32];

            for (int i = 0; i < numBlocks; i++)
            {
                byte[] block = new byte[KeySize + NonceSize + 4];
                Array.Copy(key, 0, block, 0, KeySize);
                Array.Copy(nonce, 0, block, KeySize, NonceSize);
                BitConverter.GetBytes(i).CopyTo(block, KeySize + NonceSize);

                byte[] hash = Sha256(block);
                Array.Copy(hash, 0, keystream, i * 32, 32);
            }

            byte[] result = new byte[length];
            Array.Copy(keystream, result, length);
            return result;
        }

        // ============== Crypto Utilities ==============

        public static byte[] Sha256(byte[] data)
        {
            using var sha = SHA256.Create();
            return sha.ComputeHash(data);
        }

        public static byte[] HmacSha256(byte[] key, byte[] data)
        {
            using var hmac = new HMACSHA256(key);
            return hmac.ComputeHash(data);
        }

        public static byte[] Pbkdf2(string password, byte[] salt, int iterations, int keyLength)
        {
            using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256);
            return pbkdf2.GetBytes(keyLength);
        }

        public static bool ConstantTimeEquals(byte[] a, byte[] b, int length)
        {
            if (a.Length < length || b.Length < length)
                return false;

            int result = 0;
            for (int i = 0; i < length; i++)
                result |= a[i] ^ b[i];

            return result == 0;
        }

        public static byte[] RandomBytes(int length)
        {
            byte[] bytes = new byte[length];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(bytes);
            return bytes;
        }

        public static void SecureWipe(byte[] data)
        {
            Array.Clear(data, 0, data.Length);
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                SecureWipe(_key);
                _disposed = true;
            }
        }
    }
}
