using System;
using System.Security.Cryptography;
using System.Text;

namespace Guard8.Shield
{
    /// <summary>
    /// SymmetricSignature provides HMAC-based signatures.
    /// </summary>
    public class SymmetricSignature : IDisposable
    {
        private readonly byte[] _signingKey;
        private readonly byte[] _verificationKey;
        private bool _disposed;

        public SymmetricSignature(byte[] signingKey)
        {
            if (signingKey.Length != Shield.KeySize)
                throw new ArgumentException("Invalid key size", nameof(signingKey));

            _signingKey = new byte[Shield.KeySize];
            Array.Copy(signingKey, _signingKey, Shield.KeySize);

            // Derive verification key
            byte[] data = new byte[7 + Shield.KeySize];
            Encoding.UTF8.GetBytes("verify:").CopyTo(data, 0);
            Array.Copy(signingKey, 0, data, 7, Shield.KeySize);
            _verificationKey = Shield.Sha256(data);
        }

        public static SymmetricSignature Generate()
        {
            return new SymmetricSignature(Shield.RandomBytes(Shield.KeySize));
        }

        public static SymmetricSignature FromPassword(string password, string identity)
        {
            byte[] salt = Shield.Sha256(Encoding.UTF8.GetBytes("sign:" + identity));
            byte[] key = Shield.Pbkdf2(password, salt, Shield.Iterations, Shield.KeySize);
            return new SymmetricSignature(key);
        }

        public byte[] Sign(byte[] message, bool includeTimestamp = false)
        {
            if (includeTimestamp)
            {
                long timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                byte[] tsBytes = BitConverter.GetBytes(timestamp);

                byte[] sigData = new byte[8 + message.Length];
                Array.Copy(tsBytes, 0, sigData, 0, 8);
                Array.Copy(message, 0, sigData, 8, message.Length);

                byte[] sig = Shield.HmacSha256(_signingKey, sigData);

                byte[] result = new byte[40];
                Array.Copy(tsBytes, 0, result, 0, 8);
                Array.Copy(sig, 0, result, 8, 32);
                return result;
            }

            return Shield.HmacSha256(_signingKey, message);
        }

        public bool Verify(byte[] message, byte[] signature, byte[] verificationKey, long maxAge = 0)
        {
            if (!Shield.ConstantTimeEquals(verificationKey, _verificationKey, Shield.KeySize))
                return false;

            if (signature.Length == 40)
            {
                long timestamp = BitConverter.ToInt64(signature, 0);

                if (maxAge > 0)
                {
                    long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                    long diff = Math.Abs(now - timestamp);
                    if (diff > maxAge)
                        return false;
                }

                byte[] sigData = new byte[8 + message.Length];
                Array.Copy(signature, 0, sigData, 0, 8);
                Array.Copy(message, 0, sigData, 8, message.Length);

                byte[] expected = Shield.HmacSha256(_signingKey, sigData);

                byte[] receivedSig = new byte[32];
                Array.Copy(signature, 8, receivedSig, 0, 32);
                return Shield.ConstantTimeEquals(receivedSig, expected, 32);
            }

            if (signature.Length == 32)
            {
                byte[] expected = Shield.HmacSha256(_signingKey, message);
                return Shield.ConstantTimeEquals(signature, expected, 32);
            }

            return false;
        }

        public byte[] VerificationKey
        {
            get
            {
                byte[] copy = new byte[_verificationKey.Length];
                Array.Copy(_verificationKey, copy, _verificationKey.Length);
                return copy;
            }
        }

        public string Fingerprint()
        {
            byte[] hash = Shield.Sha256(_verificationKey);
            return BitConverter.ToString(hash, 0, 8).Replace("-", "").ToLower();
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                Shield.SecureWipe(_signingKey);
                Shield.SecureWipe(_verificationKey);
                _disposed = true;
            }
        }
    }

    /// <summary>
    /// LamportSignature provides one-time post-quantum signatures.
    /// </summary>
    public class LamportSignature : IDisposable
    {
        private readonly byte[,,] _privateKey;  // [256, 2, 32]
        private readonly byte[] _publicKey;     // [256 * 64]
        private bool _used;
        private bool _disposed;

        private LamportSignature()
        {
            _privateKey = new byte[256, 2, Shield.KeySize];
            _publicKey = new byte[256 * 64];
            _used = false;
        }

        public static LamportSignature Generate()
        {
            var ls = new LamportSignature();

            for (int i = 0; i < 256; i++)
            {
                byte[] key0 = Shield.RandomBytes(Shield.KeySize);
                byte[] key1 = Shield.RandomBytes(Shield.KeySize);

                for (int j = 0; j < Shield.KeySize; j++)
                {
                    ls._privateKey[i, 0, j] = key0[j];
                    ls._privateKey[i, 1, j] = key1[j];
                }

                byte[] h0 = Shield.Sha256(key0);
                byte[] h1 = Shield.Sha256(key1);

                Array.Copy(h0, 0, ls._publicKey, i * 64, 32);
                Array.Copy(h1, 0, ls._publicKey, i * 64 + 32, 32);
            }

            return ls;
        }

        public byte[] Sign(byte[] message)
        {
            if (_used)
                throw new InvalidOperationException("Lamport key already used");
            _used = true;

            byte[] msgHash = Shield.Sha256(message);
            byte[] signature = new byte[256 * 32];

            for (int i = 0; i < 256; i++)
            {
                int byteIdx = i / 8;
                int bitIdx = i % 8;
                int bit = (msgHash[byteIdx] >> bitIdx) & 1;

                for (int j = 0; j < 32; j++)
                    signature[i * 32 + j] = _privateKey[i, bit, j];
            }

            return signature;
        }

        public static bool Verify(byte[] message, byte[] signature, byte[] publicKey)
        {
            if (signature.Length != 256 * 32 || publicKey.Length != 256 * 64)
                return false;

            byte[] msgHash = Shield.Sha256(message);

            for (int i = 0; i < 256; i++)
            {
                int byteIdx = i / 8;
                int bitIdx = i % 8;
                int bit = (msgHash[byteIdx] >> bitIdx) & 1;

                byte[] revealed = new byte[32];
                Array.Copy(signature, i * 32, revealed, 0, 32);
                byte[] hashed = Shield.Sha256(revealed);

                byte[] expected = new byte[32];
                if (bit == 1)
                    Array.Copy(publicKey, i * 64 + 32, expected, 0, 32);
                else
                    Array.Copy(publicKey, i * 64, expected, 0, 32);

                if (!Shield.ConstantTimeEquals(hashed, expected, 32))
                    return false;
            }

            return true;
        }

        public bool IsUsed => _used;

        public byte[] PublicKey
        {
            get
            {
                byte[] copy = new byte[_publicKey.Length];
                Array.Copy(_publicKey, copy, _publicKey.Length);
                return copy;
            }
        }

        public string Fingerprint()
        {
            byte[] hash = Shield.Sha256(_publicKey);
            return BitConverter.ToString(hash, 0, 8).Replace("-", "").ToLower();
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                for (int i = 0; i < 256; i++)
                {
                    for (int j = 0; j < 32; j++)
                    {
                        _privateKey[i, 0, j] = 0;
                        _privateKey[i, 1, j] = 0;
                    }
                }
                _disposed = true;
            }
        }
    }
}
