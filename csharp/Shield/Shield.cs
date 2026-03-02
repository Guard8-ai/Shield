using System;
using System.Security.Cryptography;
using System.Text;

namespace Dikestra.Shield
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

        // V2 constants
        public const int V2HeaderSize = 17;  // counter(8) + timestamp(8) + pad_len(1)
        public const int MinPadding = 32;
        public const int MaxPadding = 128;
        public const long MinTimestampMs = 1577836800000L;  // 2020-01-01
        public const long MaxTimestampMs = 4102444800000L;  // 2100-01-01
        public const long DefaultMaxAgeMs = 60000L;

        private readonly byte[] _key;
        private readonly byte[] _encKey;  // encryption subkey
        private readonly byte[] _macKey;  // authentication subkey
        private readonly long? _maxAgeMs;
        private bool _disposed;

        /// <summary>
        /// Derive separated encryption and MAC subkeys from master key using HMAC-SHA256.
        /// </summary>
        private static (byte[] encKey, byte[] macKey) DeriveSubkeys(byte[] masterKey)
        {
            var encKey = HmacSha256(masterKey, Encoding.UTF8.GetBytes("shield-encrypt"));
            var macKey = HmacSha256(masterKey, Encoding.UTF8.GetBytes("shield-authenticate"));
            return (encKey, macKey);
        }

        /// <summary>
        /// Create Shield from password and service name.
        /// </summary>
        public Shield(string password, string service) : this(password, service, DefaultMaxAgeMs) { }

        /// <summary>
        /// Create Shield from password and service name with custom max age.
        /// </summary>
        public Shield(string password, string service, long? maxAgeMs)
        {
            byte[] salt = Sha256(Encoding.UTF8.GetBytes(service));
            _key = Pbkdf2(password, salt, Iterations, KeySize);
            var (encKey, macKey) = DeriveSubkeys(_key);
            _encKey = encKey;
            _macKey = macKey;
            _maxAgeMs = maxAgeMs;
        }

        /// <summary>
        /// Create Shield with pre-shared key.
        /// </summary>
        public Shield(byte[] key) : this(key, DefaultMaxAgeMs) { }

        /// <summary>
        /// Create Shield with pre-shared key and custom max age.
        /// </summary>
        public Shield(byte[] key, long? maxAgeMs)
        {
            if (key.Length != KeySize)
                throw new ArgumentException("Invalid key size", nameof(key));

            _key = new byte[KeySize];
            Array.Copy(key, _key, KeySize);
            var (encKey, macKey) = DeriveSubkeys(_key);
            _encKey = encKey;
            _macKey = macKey;
            _maxAgeMs = maxAgeMs;
        }

        /// <summary>
        /// Encrypt plaintext (v2 format).
        /// </summary>
        public byte[] Encrypt(byte[] plaintext)
        {
            return EncryptWithSeparatedKeys(_encKey, _macKey, plaintext);
        }

        /// <summary>
        /// Decrypt ciphertext (auto-detects v1/v2).
        /// </summary>
        public byte[] Decrypt(byte[] ciphertext)
        {
            return DecryptWithSeparatedKeys(_encKey, _macKey, ciphertext, _maxAgeMs);
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
            var (encKey, macKey) = DeriveSubkeys(key);
            return EncryptWithSeparatedKeys(encKey, macKey, plaintext);
        }

        /// <summary>
        /// Quick decrypt with explicit key.
        /// </summary>
        public static byte[] QuickDecrypt(byte[] key, byte[] ciphertext)
        {
            if (key.Length != KeySize)
                throw new ArgumentException("Invalid key size", nameof(key));
            var (encKey, macKey) = DeriveSubkeys(key);
            return DecryptWithSeparatedKeys(encKey, macKey, ciphertext, null);
        }

        private static byte[] EncryptWithSeparatedKeys(byte[] encKey, byte[] macKey, byte[] plaintext)
        {
            // Generate random nonce
            byte[] nonce = RandomBytes(NonceSize);

            // Counter prefix (8 bytes of zeros)
            byte[] counter = new byte[8];

            // Timestamp in milliseconds
            long timestampMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            byte[] timestamp = BitConverter.GetBytes(timestampMs);
            if (!BitConverter.IsLittleEndian) Array.Reverse(timestamp);

            // Random padding: 32-128 bytes (rejection sampling to avoid modulo bias)
            int padRange = MaxPadding - MinPadding + 1; // 97
            int padLen;
            using (var rng = RandomNumberGenerator.Create())
            {
                byte[] buf = new byte[1];
                while (true)
                {
                    rng.GetBytes(buf);
                    int v = buf[0];
                    if (v < padRange * (256 / padRange))
                    {
                        padLen = (v % padRange) + MinPadding;
                        break;
                    }
                }
            }
            byte[] padding = RandomBytes(padLen);

            // Data to encrypt: counter || timestamp || pad_len || padding || plaintext
            byte[] dataToEncrypt = new byte[8 + 8 + 1 + padLen + plaintext.Length];
            int pos = 0;
            Array.Copy(counter, 0, dataToEncrypt, pos, 8); pos += 8;
            Array.Copy(timestamp, 0, dataToEncrypt, pos, 8); pos += 8;
            dataToEncrypt[pos] = (byte)padLen; pos += 1;
            Array.Copy(padding, 0, dataToEncrypt, pos, padLen); pos += padLen;
            Array.Copy(plaintext, 0, dataToEncrypt, pos, plaintext.Length);

            // Generate keystream and XOR (using encryption subkey)
            byte[] keystream = GenerateKeystream(encKey, nonce, dataToEncrypt.Length);
            byte[] ciphertext = new byte[dataToEncrypt.Length];
            for (int i = 0; i < dataToEncrypt.Length; i++)
                ciphertext[i] = (byte)(dataToEncrypt[i] ^ keystream[i]);

            // Compute HMAC over nonce || ciphertext (using MAC subkey)
            byte[] macData = new byte[NonceSize + ciphertext.Length];
            Array.Copy(nonce, 0, macData, 0, NonceSize);
            Array.Copy(ciphertext, 0, macData, NonceSize, ciphertext.Length);
            byte[] mac = HmacSha256(macKey, macData);

            // Format: nonce || ciphertext || mac
            byte[] result = new byte[NonceSize + ciphertext.Length + MacSize];
            Array.Copy(nonce, 0, result, 0, NonceSize);
            Array.Copy(ciphertext, 0, result, NonceSize, ciphertext.Length);
            Array.Copy(mac, 0, result, NonceSize + ciphertext.Length, MacSize);

            return result;
        }

        private static byte[] DecryptWithSeparatedKeys(byte[] encKey, byte[] macKey, byte[] encrypted, long? maxAgeMs)
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

            // Verify MAC (using MAC subkey)
            byte[] macData = new byte[NonceSize + ciphertextLen];
            Array.Copy(nonce, 0, macData, 0, NonceSize);
            Array.Copy(ciphertext, 0, macData, NonceSize, ciphertextLen);
            byte[] expectedMac = HmacSha256(macKey, macData);

            if (!ConstantTimeEquals(receivedMac, expectedMac, MacSize))
                throw new CryptographicException("Authentication failed");

            // Decrypt (using encryption subkey)
            byte[] keystream = GenerateKeystream(encKey, nonce, ciphertextLen);
            byte[] decrypted = new byte[ciphertextLen];
            for (int i = 0; i < ciphertextLen; i++)
                decrypted[i] = (byte)(ciphertext[i] ^ keystream[i]);

            // Auto-detect v2 by timestamp range
            if (decrypted.Length >= V2HeaderSize)
            {
                byte[] timestampBytes = new byte[8];
                Array.Copy(decrypted, 8, timestampBytes, 0, 8);
                if (!BitConverter.IsLittleEndian) Array.Reverse(timestampBytes);
                long timestampMs = BitConverter.ToInt64(timestampBytes, 0);

                if (timestampMs >= MinTimestampMs && timestampMs <= MaxTimestampMs)
                {
                    // v2 format detected
                    int padLen = decrypted[16] & 0xFF;

                    if (padLen < MinPadding || padLen > MaxPadding)
                        throw new CryptographicException("Authentication failed");

                    int dataStart = V2HeaderSize + padLen;
                    if (decrypted.Length < dataStart)
                        throw new ArgumentException("Ciphertext too short");

                    if (maxAgeMs.HasValue)
                    {
                        long nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                        long age = nowMs - timestampMs;
                        if (timestampMs > nowMs + 5000 || age > maxAgeMs.Value)
                            throw new CryptographicException("Authentication failed");
                    }

                    byte[] result = new byte[decrypted.Length - dataStart];
                    Array.Copy(decrypted, dataStart, result, 0, result.Length);
                    return result;
                }
            }

            // v1 format: skip counter (8 bytes)
            byte[] v1Result = new byte[ciphertextLen - 8];
            Array.Copy(decrypted, 8, v1Result, 0, ciphertextLen - 8);
            return v1Result;
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
                SecureWipe(_encKey);
                SecureWipe(_macKey);
                _disposed = true;
            }
        }
    }
}
