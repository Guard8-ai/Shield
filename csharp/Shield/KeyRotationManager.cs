using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

namespace Guard8.Shield
{
    /// <summary>
    /// KeyRotationManager - Version-based key management.
    ///
    /// Supports seamless key rotation without breaking existing encrypted data.
    /// Each ciphertext is tagged with the key version used.
    ///
    /// Ciphertext format: version(4) || nonce(16) || ciphertext || mac(16)
    /// </summary>
    public class KeyRotationManager : IDisposable
    {
        private const int NonceSize = 16;
        private const int MacSize = 16;
        private const int MinCiphertextSize = 4 + NonceSize + MacSize;

        private readonly Dictionary<int, byte[]> _keys = new();
        private int _currentVersion;
        private bool _disposed;

        /// <summary>
        /// Create with initial key.
        /// </summary>
        public KeyRotationManager(byte[] key, int version = 1)
        {
            if (key.Length != 32)
                throw new ArgumentException("Key must be 32 bytes", nameof(key));

            var keyCopy = new byte[32];
            Array.Copy(key, keyCopy, 32);
            _keys[version] = keyCopy;
            _currentVersion = version;
        }

        /// <summary>
        /// Get current key version.
        /// </summary>
        public int CurrentVersion => _currentVersion;

        /// <summary>
        /// Get all available versions.
        /// </summary>
        public IEnumerable<int> Versions => _keys.Keys.OrderBy(v => v);

        /// <summary>
        /// Add historical key for decryption.
        /// </summary>
        public void AddKey(byte[] key, int version)
        {
            if (_keys.ContainsKey(version))
                throw new ArgumentException($"Version {version} already exists");

            var keyCopy = new byte[32];
            Array.Copy(key, keyCopy, 32);
            _keys[version] = keyCopy;
        }

        /// <summary>
        /// Rotate to new key.
        /// </summary>
        public int Rotate(byte[] newKey, int? newVersion = null)
        {
            int version = newVersion ?? _currentVersion + 1;
            if (version <= _currentVersion)
                throw new ArgumentException("New version must be greater than current");

            var keyCopy = new byte[32];
            Array.Copy(newKey, keyCopy, 32);
            _keys[version] = keyCopy;
            _currentVersion = version;
            return version;
        }

        /// <summary>
        /// Encrypt with current key (includes version tag).
        /// </summary>
        public byte[] Encrypt(byte[] plaintext)
        {
            byte[] key = _keys[_currentVersion];
            byte[] nonce = Shield.RandomBytes(NonceSize);

            // Generate keystream and encrypt
            byte[] keystream = GenerateKeystream(key, nonce, plaintext.Length);
            byte[] ciphertext = new byte[plaintext.Length];
            for (int i = 0; i < plaintext.Length; i++)
                ciphertext[i] = (byte)(plaintext[i] ^ keystream[i]);

            // Version bytes
            byte[] versionBytes = BitConverter.GetBytes(_currentVersion);

            // HMAC authenticate (includes version)
            byte[] macData = new byte[4 + NonceSize + ciphertext.Length];
            Array.Copy(versionBytes, 0, macData, 0, 4);
            Array.Copy(nonce, 0, macData, 4, NonceSize);
            Array.Copy(ciphertext, 0, macData, 4 + NonceSize, ciphertext.Length);
            byte[] mac = Shield.HmacSha256(key, macData);

            // Result: version || nonce || ciphertext || mac
            byte[] result = new byte[4 + NonceSize + ciphertext.Length + MacSize];
            Array.Copy(versionBytes, 0, result, 0, 4);
            Array.Copy(nonce, 0, result, 4, NonceSize);
            Array.Copy(ciphertext, 0, result, 4 + NonceSize, ciphertext.Length);
            Array.Copy(mac, 0, result, result.Length - MacSize, MacSize);

            return result;
        }

        /// <summary>
        /// Decrypt with appropriate key version.
        /// </summary>
        public byte[] Decrypt(byte[] encrypted)
        {
            if (encrypted.Length < MinCiphertextSize)
                throw new ArgumentException("Ciphertext too short");

            // Parse version
            int version = BitConverter.ToInt32(encrypted, 0);
            byte[] nonce = new byte[NonceSize];
            Array.Copy(encrypted, 4, nonce, 0, NonceSize);

            int ciphertextLen = encrypted.Length - 4 - NonceSize - MacSize;
            byte[] ciphertext = new byte[ciphertextLen];
            Array.Copy(encrypted, 4 + NonceSize, ciphertext, 0, ciphertextLen);

            byte[] receivedMac = new byte[MacSize];
            Array.Copy(encrypted, encrypted.Length - MacSize, receivedMac, 0, MacSize);

            if (!_keys.TryGetValue(version, out byte[] key))
                throw new ArgumentException($"Unknown key version: {version}");

            // Verify MAC
            byte[] macData = new byte[encrypted.Length - MacSize];
            Array.Copy(encrypted, 0, macData, 0, macData.Length);
            byte[] expectedMac = Shield.HmacSha256(key, macData);

            if (!Shield.ConstantTimeEquals(receivedMac, expectedMac, MacSize))
                throw new CryptographicException("Authentication failed");

            // Decrypt
            byte[] keystream = GenerateKeystream(key, nonce, ciphertextLen);
            byte[] plaintext = new byte[ciphertextLen];
            for (int i = 0; i < ciphertextLen; i++)
                plaintext[i] = (byte)(ciphertext[i] ^ keystream[i]);

            return plaintext;
        }

        /// <summary>
        /// Re-encrypt data with current key.
        /// </summary>
        public byte[] ReEncrypt(byte[] encrypted)
        {
            byte[] plaintext = Decrypt(encrypted);
            return Encrypt(plaintext);
        }

        /// <summary>
        /// Remove old keys, keeping only recent versions.
        /// </summary>
        public List<int> PruneOldKeys(int keepVersions = 2)
        {
            if (keepVersions < 1)
                throw new ArgumentException("Must keep at least 1 version");

            var versions = _keys.Keys.OrderByDescending(v => v).ToList();
            var toKeep = new HashSet<int>(versions.Take(keepVersions)) { _currentVersion };

            var pruned = new List<int>();
            foreach (var v in _keys.Keys.ToList())
            {
                if (!toKeep.Contains(v))
                {
                    Shield.SecureWipe(_keys[v]);
                    _keys.Remove(v);
                    pruned.Add(v);
                }
            }

            return pruned;
        }

        private static byte[] GenerateKeystream(byte[] key, byte[] nonce, int length)
        {
            int numBlocks = (length + 31) / 32;
            byte[] keystream = new byte[numBlocks * 32];

            for (int i = 0; i < numBlocks; i++)
            {
                byte[] block = new byte[32 + NonceSize + 4];
                Array.Copy(key, 0, block, 0, 32);
                Array.Copy(nonce, 0, block, 32, NonceSize);
                BitConverter.GetBytes(i).CopyTo(block, 32 + NonceSize);

                byte[] hash = Shield.Sha256(block);
                Array.Copy(hash, 0, keystream, i * 32, 32);
            }

            byte[] result = new byte[length];
            Array.Copy(keystream, result, length);
            return result;
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                foreach (var key in _keys.Values)
                    Shield.SecureWipe(key);
                _disposed = true;
            }
        }
    }
}
