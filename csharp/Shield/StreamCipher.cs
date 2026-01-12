using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Guard8.Shield
{
    /// <summary>
    /// StreamCipher - Streaming encryption for large files.
    ///
    /// Processes data in chunks with constant memory usage.
    /// Each chunk is independently authenticated, allowing:
    /// - Early detection of tampering
    /// - Constant memory regardless of file size
    /// - Potential for parallel processing
    /// </summary>
    public class StreamCipher : IDisposable
    {
        public const int DefaultChunkSize = 64 * 1024; // 64KB
        private const int NonceSize = 16;
        private const int MacSize = 16;
        private const int HeaderSize = 20; // 4 chunk_size + 16 salt

        private readonly byte[] _key;
        private readonly int _chunkSize;
        private bool _disposed;

        /// <summary>
        /// Create StreamCipher with encryption key.
        /// </summary>
        /// <param name="key">32-byte symmetric key</param>
        /// <param name="chunkSize">Size of each chunk (default: 64KB)</param>
        public StreamCipher(byte[] key, int chunkSize = DefaultChunkSize)
        {
            if (key.Length != 32)
                throw new ArgumentException("Key must be 32 bytes", nameof(key));

            _key = new byte[32];
            Array.Copy(key, _key, 32);
            _chunkSize = chunkSize;
        }

        /// <summary>
        /// Create StreamCipher from password.
        /// </summary>
        public static StreamCipher FromPassword(string password, byte[] salt, int chunkSize = DefaultChunkSize)
        {
            byte[] key = DeriveKey(password, salt);
            return new StreamCipher(key, chunkSize);
        }

        /// <summary>
        /// Encrypt data in memory.
        /// </summary>
        public byte[] Encrypt(byte[] data)
        {
            using var output = new MemoryStream();

            // Header: chunk_size(4) || stream_salt(16)
            byte[] streamSalt = Shield.RandomBytes(16);
            output.Write(BitConverter.GetBytes(_chunkSize), 0, 4);
            output.Write(streamSalt, 0, 16);

            int offset = 0;
            int chunkNum = 0;

            while (offset < data.Length)
            {
                int remaining = data.Length - offset;
                int chunkLen = Math.Min(_chunkSize, remaining);
                byte[] chunk = new byte[chunkLen];
                Array.Copy(data, offset, chunk, 0, chunkLen);

                // Derive per-chunk key
                byte[] chunkKey = DeriveChunkKey(_key, streamSalt, chunkNum);

                // Encrypt chunk
                byte[] encrypted = EncryptBlock(chunkKey, chunk);

                // Prepend length
                output.Write(BitConverter.GetBytes(encrypted.Length), 0, 4);
                output.Write(encrypted, 0, encrypted.Length);

                offset += chunkLen;
                chunkNum++;
            }

            // End marker
            output.Write(BitConverter.GetBytes(0), 0, 4);

            return output.ToArray();
        }

        /// <summary>
        /// Decrypt data in memory.
        /// </summary>
        public byte[] Decrypt(byte[] encrypted)
        {
            if (encrypted.Length < HeaderSize + 4)
                throw new ArgumentException("Encrypted data too short");

            using var output = new MemoryStream();
            int pos = 0;

            // Read header
            int storedChunkSize = BitConverter.ToInt32(encrypted, pos);
            pos += 4;
            byte[] streamSalt = new byte[16];
            Array.Copy(encrypted, pos, streamSalt, 0, 16);
            pos += 16;

            int chunkNum = 0;

            while (pos + 4 <= encrypted.Length)
            {
                int encLen = BitConverter.ToInt32(encrypted, pos);
                pos += 4;

                if (encLen == 0)
                    break; // End marker

                if (pos + encLen > encrypted.Length)
                    throw new ArgumentException("Incomplete chunk");

                byte[] encryptedChunk = new byte[encLen];
                Array.Copy(encrypted, pos, encryptedChunk, 0, encLen);
                pos += encLen;

                // Derive per-chunk key
                byte[] chunkKey = DeriveChunkKey(_key, streamSalt, chunkNum);

                // Decrypt chunk
                byte[] decrypted = DecryptBlock(chunkKey, encryptedChunk);
                if (decrypted == null)
                    throw new CryptographicException($"Chunk {chunkNum} authentication failed");

                output.Write(decrypted, 0, decrypted.Length);
                chunkNum++;
            }

            return output.ToArray();
        }

        /// <summary>
        /// Encrypt a file.
        /// </summary>
        public void EncryptFile(string inPath, string outPath)
        {
            using var input = File.OpenRead(inPath);
            using var output = File.Create(outPath);

            // Header
            byte[] streamSalt = Shield.RandomBytes(16);
            output.Write(BitConverter.GetBytes(_chunkSize), 0, 4);
            output.Write(streamSalt, 0, 16);

            byte[] buffer = new byte[_chunkSize];
            int chunkNum = 0;
            int bytesRead;

            while ((bytesRead = input.Read(buffer, 0, buffer.Length)) > 0)
            {
                byte[] chunk = bytesRead == buffer.Length ? buffer : buffer[..bytesRead];

                byte[] chunkKey = DeriveChunkKey(_key, streamSalt, chunkNum);
                byte[] encrypted = EncryptBlock(chunkKey, chunk);

                output.Write(BitConverter.GetBytes(encrypted.Length), 0, 4);
                output.Write(encrypted, 0, encrypted.Length);

                chunkNum++;
            }

            // End marker
            output.Write(BitConverter.GetBytes(0), 0, 4);
        }

        /// <summary>
        /// Decrypt a file.
        /// </summary>
        public void DecryptFile(string inPath, string outPath)
        {
            using var input = File.OpenRead(inPath);
            using var output = File.Create(outPath);

            // Read header
            byte[] header = new byte[HeaderSize];
            if (input.Read(header, 0, HeaderSize) != HeaderSize)
                throw new IOException("Incomplete header");

            int storedChunkSize = BitConverter.ToInt32(header, 0);
            byte[] streamSalt = new byte[16];
            Array.Copy(header, 4, streamSalt, 0, 16);

            byte[] lenBytes = new byte[4];
            int chunkNum = 0;

            while (input.Read(lenBytes, 0, 4) == 4)
            {
                int encLen = BitConverter.ToInt32(lenBytes, 0);
                if (encLen == 0)
                    break;

                byte[] encrypted = new byte[encLen];
                if (input.Read(encrypted, 0, encLen) != encLen)
                    throw new IOException("Incomplete chunk");

                byte[] chunkKey = DeriveChunkKey(_key, streamSalt, chunkNum);
                byte[] decrypted = DecryptBlock(chunkKey, encrypted);
                if (decrypted == null)
                    throw new CryptographicException($"Chunk {chunkNum} authentication failed");

                output.Write(decrypted, 0, decrypted.Length);
                chunkNum++;
            }
        }

        // ============== Helper Methods ==============

        private static byte[] DeriveKey(string password, byte[] salt)
        {
            using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 100000, HashAlgorithmName.SHA256);
            return pbkdf2.GetBytes(32);
        }

        private static byte[] DeriveChunkKey(byte[] key, byte[] salt, long chunkNum)
        {
            byte[] data = new byte[32 + 16 + 8];
            Array.Copy(key, 0, data, 0, 32);
            Array.Copy(salt, 0, data, 32, 16);
            BitConverter.GetBytes(chunkNum).CopyTo(data, 48);
            return Shield.Sha256(data);
        }

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
                Shield.SecureWipe(_key);
                _disposed = true;
            }
        }
    }
}
