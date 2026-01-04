using System;
using System.Security.Cryptography;
using System.Text;

namespace Guard8.Shield
{
    /// <summary>
    /// RatchetSession provides forward secrecy through key ratcheting.
    /// </summary>
    public class RatchetSession : IDisposable
    {
        private byte[] _sendKey;
        private byte[] _recvKey;
        private ulong _sendCounter;
        private ulong _recvCounter;
        private readonly bool _isInitiator;
        private bool _disposed;

        public RatchetSession(byte[] rootKey, bool isInitiator)
        {
            if (rootKey.Length != Shield.KeySize)
                throw new ArgumentException("Invalid key size", nameof(rootKey));

            _isInitiator = isInitiator;
            _sendCounter = 0;
            _recvCounter = 0;

            if (isInitiator)
            {
                _sendKey = DeriveChainKey(rootKey, "init_send");
                _recvKey = DeriveChainKey(rootKey, "init_recv");
            }
            else
            {
                _sendKey = DeriveChainKey(rootKey, "init_recv");
                _recvKey = DeriveChainKey(rootKey, "init_send");
            }
        }

        public byte[] Encrypt(byte[] plaintext)
        {
            byte[] messageKey = DeriveChainKey(_sendKey, "message");
            byte[] nonce = Shield.RandomBytes(Shield.NonceSize);

            // Generate keystream and XOR
            byte[] keystream = GenerateKeystream(messageKey, nonce, plaintext.Length);
            byte[] ciphertext = new byte[plaintext.Length];
            for (int i = 0; i < plaintext.Length; i++)
                ciphertext[i] = (byte)(plaintext[i] ^ keystream[i]);

            // Counter bytes
            byte[] counterBytes = BitConverter.GetBytes(_sendCounter);

            // MAC over counter || nonce || ciphertext
            byte[] macData = new byte[8 + Shield.NonceSize + ciphertext.Length];
            Array.Copy(counterBytes, 0, macData, 0, 8);
            Array.Copy(nonce, 0, macData, 8, Shield.NonceSize);
            Array.Copy(ciphertext, 0, macData, 8 + Shield.NonceSize, ciphertext.Length);
            byte[] mac = Shield.HmacSha256(messageKey, macData);

            // Ratchet
            _sendKey = DeriveChainKey(_sendKey, "ratchet");
            _sendCounter++;

            // Format: counter(8) || nonce(16) || ciphertext || mac(16)
            byte[] result = new byte[8 + Shield.NonceSize + ciphertext.Length + Shield.MacSize];
            Array.Copy(counterBytes, 0, result, 0, 8);
            Array.Copy(nonce, 0, result, 8, Shield.NonceSize);
            Array.Copy(ciphertext, 0, result, 8 + Shield.NonceSize, ciphertext.Length);
            Array.Copy(mac, 0, result, 8 + Shield.NonceSize + ciphertext.Length, Shield.MacSize);

            Shield.SecureWipe(messageKey);
            return result;
        }

        public byte[] Decrypt(byte[] encrypted)
        {
            if (encrypted.Length < 8 + Shield.NonceSize + Shield.MacSize)
                throw new ArgumentException("Ciphertext too short");

            // Parse
            ulong counter = BitConverter.ToUInt64(encrypted, 0);
            byte[] nonce = new byte[Shield.NonceSize];
            Array.Copy(encrypted, 8, nonce, 0, Shield.NonceSize);

            int ciphertextLen = encrypted.Length - 8 - Shield.NonceSize - Shield.MacSize;
            byte[] ciphertext = new byte[ciphertextLen];
            Array.Copy(encrypted, 8 + Shield.NonceSize, ciphertext, 0, ciphertextLen);

            byte[] receivedMac = new byte[Shield.MacSize];
            Array.Copy(encrypted, encrypted.Length - Shield.MacSize, receivedMac, 0, Shield.MacSize);

            // Check counter
            if (counter < _recvCounter)
                throw new CryptographicException("Replay detected");
            if (counter > _recvCounter)
                throw new CryptographicException("Out of order message");

            byte[] messageKey = DeriveChainKey(_recvKey, "message");

            // Verify MAC
            byte[] macData = new byte[8 + Shield.NonceSize + ciphertextLen];
            Array.Copy(encrypted, 0, macData, 0, 8);
            Array.Copy(nonce, 0, macData, 8, Shield.NonceSize);
            Array.Copy(ciphertext, 0, macData, 8 + Shield.NonceSize, ciphertextLen);
            byte[] expectedMac = Shield.HmacSha256(messageKey, macData);

            if (!Shield.ConstantTimeEquals(receivedMac, expectedMac, Shield.MacSize))
            {
                Shield.SecureWipe(messageKey);
                throw new CryptographicException("Authentication failed");
            }

            // Decrypt
            byte[] keystream = GenerateKeystream(messageKey, nonce, ciphertextLen);
            byte[] plaintext = new byte[ciphertextLen];
            for (int i = 0; i < ciphertextLen; i++)
                plaintext[i] = (byte)(ciphertext[i] ^ keystream[i]);

            // Ratchet
            _recvKey = DeriveChainKey(_recvKey, "ratchet");
            _recvCounter++;

            Shield.SecureWipe(messageKey);
            return plaintext;
        }

        public ulong SendCounter => _sendCounter;
        public ulong RecvCounter => _recvCounter;

        private static byte[] DeriveChainKey(byte[] key, string info)
        {
            using var sha = SHA256.Create();
            byte[] data = new byte[key.Length + info.Length];
            Array.Copy(key, 0, data, 0, key.Length);
            Encoding.UTF8.GetBytes(info).CopyTo(data, key.Length);
            return sha.ComputeHash(data);
        }

        private static byte[] GenerateKeystream(byte[] key, byte[] nonce, int length)
        {
            int numBlocks = (length + 31) / 32;
            byte[] keystream = new byte[numBlocks * 32];

            for (int i = 0; i < numBlocks; i++)
            {
                byte[] block = new byte[Shield.KeySize + Shield.NonceSize + 4];
                Array.Copy(key, 0, block, 0, Shield.KeySize);
                Array.Copy(nonce, 0, block, Shield.KeySize, Shield.NonceSize);
                BitConverter.GetBytes(i).CopyTo(block, Shield.KeySize + Shield.NonceSize);

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
                Shield.SecureWipe(_sendKey);
                Shield.SecureWipe(_recvKey);
                _disposed = true;
            }
        }
    }
}
