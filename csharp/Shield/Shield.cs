using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Dikestra.Shield
{
    /// <summary>
    /// Shield - Authenticated Symmetric Encryption Library (wire format v4).
    ///
    /// v4 replaces the previous custom SHA-256 keystream + HMAC construction with a
    /// standard AEAD (AES-256-GCM by default, ChaCha20-Poly1305 optional) from
    /// System.Security.Cryptography. No cryptography is hand-rolled; key derivation
    /// uses PBKDF2-HMAC-SHA256 + HKDF-SHA256-Expand. The wire format matches every
    /// other Shield binding byte-for-byte (see tests/v4_test_vectors.json).
    ///
    /// Wire format:
    ///   Password mode: 0x03 || suite(1) || salt(16) || nonce(12) || ciphertext||tag
    ///   Key mode:      0x13 || suite(1) ||            nonce(12) || ciphertext||tag
    /// AAD = version || suite || [salt]; inner plaintext =
    ///   timestamp_ms(8 LE) || pad_len(1) || padding(32-128) || message.
    /// </summary>
    public class Shield : IDisposable
    {
        public const int KeySize = 32;
        // NonceSize/MacSize are retained at 16 for the auxiliary keystream layers
        // (RatchetSession etc.). The base AEAD cipher uses its own 12-byte nonce.
        public const int NonceSize = 16;
        public const int MacSize = 16;
        public const int SaltSize = 16;

        // PBKDF2 iterations (OWASP 2023 floor for PBKDF2-HMAC-SHA256).
        public const int Iterations = 600000;

        // Authenticated version bytes (leading byte of the ciphertext).
        public const byte VersionPassword = 0x03; // 0x03 || suite || salt(16) || nonce(12) || ct||tag
        public const byte VersionKey = 0x13;       // 0x13 || suite || nonce(12) || ct||tag

        // Cipher-suite identifiers.
        public const byte SuiteAesGcm = 0x01;          // AES-256-GCM (default)
        public const byte SuiteChaCha20Poly1305 = 0x02; // ChaCha20-Poly1305

        public const int MinPadding = 32;
        public const int MaxPadding = 128;
        public const long DefaultMaxAgeMs = 60000L;

        // Base-AEAD constants (96-bit nonce, 128-bit tag, inner header = ts(8)+pad_len(1)).
        private const int AeadNonceSize = 12;
        private const int TagSize = 16;
        private const int InnerHeaderSize = 9;
        private static readonly byte[] HkdfAeadInfo = Encoding.UTF8.GetBytes("shield/aead/v4");

        private readonly byte[] _key;       // master key
        private readonly byte[] _aeadKey;   // HKDF-derived AEAD key
        private readonly byte _suite;
        private readonly long? _maxAgeMs;

        // Password-mode state (null in pre-shared-key mode).
        private readonly byte[] _salt;
        private readonly byte[] _password;
        private readonly byte[] _service;
        private readonly int _iterations;
        private readonly Dictionary<string, byte[]> _keyCache;

        private bool _disposed;

        /// <summary>Create Shield from password and service name.</summary>
        public Shield(string password, string service) : this(password, service, DefaultMaxAgeMs, null) { }

        /// <summary>Create Shield from password and service name with custom max age.</summary>
        public Shield(string password, string service, long? maxAgeMs) : this(password, service, maxAgeMs, null) { }

        /// <summary>Create Shield from password and service name with an optional explicit salt.</summary>
        public Shield(string password, string service, long? maxAgeMs, byte[] salt)
        {
            if (salt == null)
                salt = RandomBytes(SaltSize);
            else if (salt.Length != SaltSize)
                throw new ArgumentException("Salt must be 16 bytes", nameof(salt));

            _password = Encoding.UTF8.GetBytes(password);
            _service = Encoding.UTF8.GetBytes(service);
            _iterations = Iterations;
            _salt = (byte[])salt.Clone();
            _suite = SuiteAesGcm;
            _keyCache = new Dictionary<string, byte[]>();

            _key = DeriveKey(_salt);
            _aeadKey = DeriveAeadKey(_key);
            _maxAgeMs = maxAgeMs;
        }

        /// <summary>Create Shield with pre-shared key.</summary>
        public Shield(byte[] key) : this(key, DefaultMaxAgeMs) { }

        /// <summary>Create Shield with pre-shared key and custom max age.</summary>
        public Shield(byte[] key, long? maxAgeMs)
        {
            if (key.Length != KeySize)
                throw new ArgumentException("Invalid key size", nameof(key));

            _key = new byte[KeySize];
            Array.Copy(key, _key, KeySize);
            _aeadKey = DeriveAeadKey(_key);
            _suite = SuiteAesGcm;
            _maxAgeMs = maxAgeMs;

            // Pre-shared-key mode: no password, no salt.
            _salt = null;
            _password = null;
            _service = null;
            _iterations = 0;
            _keyCache = null;
        }

        /// <summary>
        /// Derive the 32-byte master key for a given salt (cached by salt).
        /// key = PBKDF2-HMAC-SHA256(password, salt || service, iterations, 32).
        /// </summary>
        private byte[] DeriveKey(byte[] salt)
        {
            string cacheKey = Convert.ToHexString(salt);
            if (_keyCache != null && _keyCache.TryGetValue(cacheKey, out var cached))
                return cached;

            byte[] kdfSalt = new byte[salt.Length + _service.Length];
            Array.Copy(salt, 0, kdfSalt, 0, salt.Length);
            Array.Copy(_service, 0, kdfSalt, salt.Length, _service.Length);

            byte[] key = Pbkdf2(_password, kdfSalt, _iterations, KeySize);
            if (_keyCache != null)
                _keyCache[cacheKey] = key;
            return key;
        }

        /// <summary>AEAD key = HKDF-SHA256-Expand(master, "shield/aead/v4", 32).</summary>
        public static byte[] DeriveAeadKey(byte[] masterKey)
            => HKDF.Expand(HashAlgorithmName.SHA256, masterKey, KeySize, HkdfAeadInfo);

        /// <summary>Encrypt plaintext. Output format depends on mode (password vs key).</summary>
        public byte[] Encrypt(byte[] plaintext)
            => Seal(_aeadKey, _suite, _salt, plaintext);

        /// <summary>Decrypt ciphertext. Dispatches on the leading authenticated version byte.</summary>
        public byte[] Decrypt(byte[] ciphertext)
        {
            if (ciphertext == null || ciphertext.Length < 1)
                throw new ArgumentException("Ciphertext too short");

            byte version = ciphertext[0];

            if (version == VersionPassword)
            {
                if (_salt == null)
                    throw new CryptographicException("Authentication failed");
                int aadLen = 2 + SaltSize;
                if (ciphertext.Length < aadLen + AeadNonceSize + TagSize)
                    throw new ArgumentException("Ciphertext too short");

                byte suite = ciphertext[1];
                byte[] salt = new byte[SaltSize];
                Array.Copy(ciphertext, 2, salt, 0, SaltSize);

                byte[] master = DeriveKey(salt);
                byte[] aeadKey = DeriveAeadKey(master);
                return OpenCiphertext(aeadKey, suite, ciphertext, aadLen, _maxAgeMs);
            }
            else if (version == VersionKey)
            {
                if (ciphertext.Length < 2 + AeadNonceSize + TagSize)
                    throw new ArgumentException("Ciphertext too short");
                byte suite = ciphertext[1];
                return OpenCiphertext(_aeadKey, suite, ciphertext, 2, _maxAgeMs);
            }

            throw new CryptographicException("Authentication failed");
        }

        /// <summary>Get the derived master key.</summary>
        public byte[] GetKey()
        {
            byte[] copy = new byte[KeySize];
            Array.Copy(_key, copy, KeySize);
            return copy;
        }

        /// <summary>Quick encrypt with explicit pre-shared key (AES-256-GCM, 0x13).</summary>
        public static byte[] QuickEncrypt(byte[] key, byte[] plaintext)
        {
            if (key.Length != KeySize)
                throw new ArgumentException("Invalid key size", nameof(key));
            byte[] aeadKey = DeriveAeadKey(key);
            return Seal(aeadKey, SuiteAesGcm, null, plaintext);
        }

        /// <summary>Quick decrypt with explicit pre-shared key.</summary>
        public static byte[] QuickDecrypt(byte[] key, byte[] ciphertext)
        {
            if (key.Length != KeySize)
                throw new ArgumentException("Invalid key size", nameof(key));
            if (ciphertext == null || ciphertext.Length < 1)
                throw new ArgumentException("Ciphertext too short");
            if (ciphertext[0] != VersionKey)
                throw new CryptographicException("Authentication failed");
            if (ciphertext.Length < 2 + AeadNonceSize + TagSize)
                throw new ArgumentException("Ciphertext too short");

            byte[] aeadKey = DeriveAeadKey(key);
            return OpenCiphertext(aeadKey, ciphertext[1], ciphertext, 2, null);
        }

        /// <summary>Build the AEAD additional data (= wire prefix before the nonce).</summary>
        private static byte[] BuildAad(byte suite, byte[] salt)
        {
            if (salt != null)
            {
                byte[] aad = new byte[2 + SaltSize];
                aad[0] = VersionPassword;
                aad[1] = suite;
                Array.Copy(salt, 0, aad, 2, SaltSize);
                return aad;
            }
            return new byte[] { VersionKey, suite };
        }

        private static int SamplePadLen()
        {
            int padRange = MaxPadding - MinPadding + 1; // 97
            using var rng = RandomNumberGenerator.Create();
            byte[] buf = new byte[1];
            while (true)
            {
                rng.GetBytes(buf);
                int v = buf[0];
                if (v < padRange * (256 / padRange))
                    return (v % padRange) + MinPadding;
            }
        }

        /// <summary>Seal with a fresh random nonce, timestamp and padding.</summary>
        private static byte[] Seal(byte[] aeadKey, byte suite, byte[] salt, byte[] plaintext)
        {
            byte[] nonce = RandomBytes(AeadNonceSize);
            int padLen = SamplePadLen();
            byte[] padding = RandomBytes(padLen);
            long ts = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            return SealDeterministic(aeadKey, suite, salt, nonce, ts, padLen, padding, plaintext);
        }

        /// <summary>
        /// Deterministic AEAD seal over fully specified inputs (used for conformance
        /// vectors and wrapped by the randomized Seal).
        /// </summary>
        public static byte[] SealDeterministic(byte[] aeadKey, byte suite, byte[] salt, byte[] nonce,
            long timestampMs, int padLen, byte[] padding, byte[] plaintext)
        {
            byte[] aad = BuildAad(suite, salt);

            byte[] ts = BitConverter.GetBytes(timestampMs);
            if (!BitConverter.IsLittleEndian) Array.Reverse(ts);

            byte[] inner = new byte[InnerHeaderSize + padding.Length + plaintext.Length];
            Array.Copy(ts, 0, inner, 0, 8);
            inner[8] = (byte)padLen;
            Array.Copy(padding, 0, inner, InnerHeaderSize, padding.Length);
            Array.Copy(plaintext, 0, inner, InnerHeaderSize + padding.Length, plaintext.Length);

            byte[] ctTag = AeadSeal(suite, aeadKey, nonce, aad, inner);

            byte[] result = new byte[aad.Length + nonce.Length + ctTag.Length];
            Array.Copy(aad, 0, result, 0, aad.Length);
            Array.Copy(nonce, 0, result, aad.Length, nonce.Length);
            Array.Copy(ctTag, 0, result, aad.Length + nonce.Length, ctTag.Length);
            return result;
        }

        /// <summary>
        /// Open an AEAD ciphertext, validate the inner layout and freshness window.
        /// aadLen is the offset of the nonce (= len(version||suite||[salt])).
        /// </summary>
        public static byte[] OpenCiphertext(byte[] aeadKey, byte suite, byte[] encrypted, int aadLen, long? maxAgeMs)
        {
            if (encrypted.Length < aadLen + AeadNonceSize + TagSize)
                throw new ArgumentException("Ciphertext too short");

            byte[] aad = new byte[aadLen];
            Array.Copy(encrypted, 0, aad, 0, aadLen);
            byte[] nonce = new byte[AeadNonceSize];
            Array.Copy(encrypted, aadLen, nonce, 0, AeadNonceSize);
            int ctTagLen = encrypted.Length - aadLen - AeadNonceSize;
            byte[] ctTag = new byte[ctTagLen];
            Array.Copy(encrypted, aadLen + AeadNonceSize, ctTag, 0, ctTagLen);

            byte[] inner = AeadOpen(suite, aeadKey, nonce, aad, ctTag);

            if (inner.Length < InnerHeaderSize)
                throw new CryptographicException("Authentication failed");
            byte[] tsBytes = new byte[8];
            Array.Copy(inner, 0, tsBytes, 0, 8);
            if (!BitConverter.IsLittleEndian) Array.Reverse(tsBytes);
            long timestampMs = BitConverter.ToInt64(tsBytes, 0);

            int padLen = inner[8] & 0xFF;
            if (padLen < MinPadding || padLen > MaxPadding)
                throw new CryptographicException("Authentication failed");
            int dataStart = InnerHeaderSize + padLen;
            if (inner.Length < dataStart)
                throw new ArgumentException("Ciphertext too short");

            if (maxAgeMs.HasValue)
            {
                long nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                long age = nowMs - timestampMs;
                if (timestampMs > nowMs + 5000 || age > maxAgeMs.Value)
                    throw new CryptographicException("Authentication failed");
            }

            byte[] result = new byte[inner.Length - dataStart];
            Array.Copy(inner, dataStart, result, 0, result.Length);
            return result;
        }

        /// <summary>AEAD seal: returns ciphertext||tag.</summary>
        private static byte[] AeadSeal(byte suite, byte[] key, byte[] nonce, byte[] aad, byte[] plaintext)
        {
            byte[] ct = new byte[plaintext.Length];
            byte[] tag = new byte[TagSize];
            if (suite == SuiteAesGcm)
            {
                using var aead = new AesGcm(key, TagSize);
                aead.Encrypt(nonce, plaintext, ct, tag, aad);
            }
            else if (suite == SuiteChaCha20Poly1305)
            {
                using var aead = new ChaCha20Poly1305(key);
                aead.Encrypt(nonce, plaintext, ct, tag, aad);
            }
            else
            {
                throw new CryptographicException("Unknown cipher suite");
            }
            byte[] result = new byte[ct.Length + TagSize];
            Array.Copy(ct, 0, result, 0, ct.Length);
            Array.Copy(tag, 0, result, ct.Length, TagSize);
            return result;
        }

        /// <summary>AEAD open: returns plaintext, throws CryptographicException on failure.</summary>
        private static byte[] AeadOpen(byte suite, byte[] key, byte[] nonce, byte[] aad, byte[] ctTag)
        {
            if (ctTag.Length < TagSize)
                throw new CryptographicException("Authentication failed");
            int ctLen = ctTag.Length - TagSize;
            byte[] ct = new byte[ctLen];
            Array.Copy(ctTag, 0, ct, 0, ctLen);
            byte[] tag = new byte[TagSize];
            Array.Copy(ctTag, ctLen, tag, 0, TagSize);
            byte[] pt = new byte[ctLen];
            try
            {
                if (suite == SuiteAesGcm)
                {
                    using var aead = new AesGcm(key, TagSize);
                    aead.Decrypt(nonce, ct, tag, pt, aad);
                }
                else if (suite == SuiteChaCha20Poly1305)
                {
                    using var aead = new ChaCha20Poly1305(key);
                    aead.Decrypt(nonce, ct, tag, pt, aad);
                }
                else
                {
                    throw new CryptographicException("Unknown cipher suite");
                }
            }
            catch (CryptographicException)
            {
                throw new CryptographicException("Authentication failed");
            }
            return pt;
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

        public static byte[] Pbkdf2(byte[] password, byte[] salt, int iterations, int keyLength)
        {
            return Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, keyLength);
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
            if (data != null)
                Array.Clear(data, 0, data.Length);
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                SecureWipe(_key);
                SecureWipe(_aeadKey);
                SecureWipe(_salt);
                SecureWipe(_password);
                _disposed = true;
            }
        }
    }
}
