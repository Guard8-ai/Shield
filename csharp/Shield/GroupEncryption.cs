using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Guard8.Shield
{
    /// <summary>
    /// GroupEncryption - Multi-recipient encryption.
    ///
    /// Encrypt once for multiple recipients, each can decrypt with their own key.
    /// Uses a group key for message encryption, then encrypts the group key
    /// separately for each member.
    /// </summary>
    public class GroupEncryption : IDisposable
    {
        private const int NonceSize = 16;
        private const int MacSize = 16;

        private byte[] _groupKey;
        private readonly Dictionary<string, byte[]> _members = new();
        private bool _disposed;

        /// <summary>
        /// Create group encryption with generated group key.
        /// </summary>
        public GroupEncryption()
        {
            _groupKey = Shield.RandomBytes(32);
        }

        /// <summary>
        /// Create group encryption with specified group key.
        /// </summary>
        public GroupEncryption(byte[] groupKey)
        {
            if (groupKey.Length != 32)
                throw new ArgumentException("Group key must be 32 bytes", nameof(groupKey));

            _groupKey = new byte[32];
            Array.Copy(groupKey, _groupKey, 32);
        }

        /// <summary>
        /// Add a member to the group.
        /// </summary>
        public void AddMember(string memberId, byte[] sharedKey)
        {
            if (sharedKey.Length != 32)
                throw new ArgumentException("Shared key must be 32 bytes", nameof(sharedKey));

            var keyCopy = new byte[32];
            Array.Copy(sharedKey, keyCopy, 32);
            _members[memberId] = keyCopy;
        }

        /// <summary>
        /// Remove a member from the group.
        /// </summary>
        public bool RemoveMember(string memberId)
        {
            return _members.Remove(memberId);
        }

        /// <summary>
        /// Get list of member IDs.
        /// </summary>
        public IEnumerable<string> Members => _members.Keys;

        /// <summary>
        /// Encrypt for all group members.
        /// </summary>
        public Dictionary<string, object> Encrypt(byte[] plaintext)
        {
            // Encrypt message with group key
            byte[] ciphertext = EncryptBlock(_groupKey, plaintext);

            // Encrypt group key for each member
            var encryptedKeys = new Dictionary<string, string>();
            foreach (var (memberId, memberKey) in _members)
            {
                byte[] encKey = EncryptBlock(memberKey, _groupKey);
                encryptedKeys[memberId] = Convert.ToBase64String(encKey);
            }

            return new Dictionary<string, object>
            {
                ["version"] = 1,
                ["ciphertext"] = Convert.ToBase64String(ciphertext),
                ["keys"] = encryptedKeys
            };
        }

        /// <summary>
        /// Decrypt as a group member.
        /// </summary>
        public static byte[] Decrypt(Dictionary<string, object> encrypted, string memberId, byte[] memberKey)
        {
            if (!encrypted.TryGetValue("keys", out var keysObj) ||
                keysObj is not Dictionary<string, string> keys ||
                !keys.TryGetValue(memberId, out var encryptedKeyB64))
            {
                return null;
            }

            // Decrypt group key
            byte[] encryptedGroupKey = Convert.FromBase64String(encryptedKeyB64);
            byte[] groupKey = DecryptBlock(memberKey, encryptedGroupKey);
            if (groupKey == null)
                return null;

            // Decrypt message
            byte[] ciphertext = Convert.FromBase64String((string)encrypted["ciphertext"]);
            return DecryptBlock(groupKey, ciphertext);
        }

        /// <summary>
        /// Rotate the group key.
        /// </summary>
        public byte[] RotateKey()
        {
            byte[] oldKey = _groupKey;
            _groupKey = Shield.RandomBytes(32);
            return oldKey;
        }

        // ============== Helper Methods ==============

        private static byte[] EncryptBlock(byte[] key, byte[] data)
        {
            byte[] nonce = Shield.RandomBytes(NonceSize);
            byte[] keystream = GenerateKeystream(key, nonce, data.Length);
            byte[] ciphertext = new byte[data.Length];
            for (int i = 0; i < data.Length; i++)
                ciphertext[i] = (byte)(data[i] ^ keystream[i]);

            byte[] macData = new byte[NonceSize + ciphertext.Length];
            Array.Copy(nonce, 0, macData, 0, NonceSize);
            Array.Copy(ciphertext, 0, macData, NonceSize, ciphertext.Length);
            byte[] mac = Shield.HmacSha256(key, macData);

            byte[] result = new byte[NonceSize + ciphertext.Length + MacSize];
            Array.Copy(nonce, 0, result, 0, NonceSize);
            Array.Copy(ciphertext, 0, result, NonceSize, ciphertext.Length);
            Array.Copy(mac, 0, result, NonceSize + ciphertext.Length, MacSize);

            return result;
        }

        private static byte[] DecryptBlock(byte[] key, byte[] encrypted)
        {
            if (encrypted.Length < NonceSize + MacSize)
                return null;

            byte[] nonce = new byte[NonceSize];
            Array.Copy(encrypted, 0, nonce, 0, NonceSize);

            int ciphertextLen = encrypted.Length - NonceSize - MacSize;
            byte[] ciphertext = new byte[ciphertextLen];
            Array.Copy(encrypted, NonceSize, ciphertext, 0, ciphertextLen);

            byte[] receivedMac = new byte[MacSize];
            Array.Copy(encrypted, encrypted.Length - MacSize, receivedMac, 0, MacSize);

            byte[] macData = new byte[NonceSize + ciphertextLen];
            Array.Copy(nonce, 0, macData, 0, NonceSize);
            Array.Copy(ciphertext, 0, macData, NonceSize, ciphertextLen);
            byte[] expectedMac = Shield.HmacSha256(key, macData);

            if (!Shield.ConstantTimeEquals(receivedMac, expectedMac, MacSize))
                return null;

            byte[] keystream = GenerateKeystream(key, nonce, ciphertextLen);
            byte[] decrypted = new byte[ciphertextLen];
            for (int i = 0; i < ciphertextLen; i++)
                decrypted[i] = (byte)(ciphertext[i] ^ keystream[i]);

            return decrypted;
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
                Shield.SecureWipe(_groupKey);
                foreach (var key in _members.Values)
                    Shield.SecureWipe(key);
                _disposed = true;
            }
        }
    }
}
