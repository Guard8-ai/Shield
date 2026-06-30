using System;
using System.Linq;
using System.Text;
using Xunit;
using Dikestra.Shield;

namespace Shield.Tests
{
    public class ShieldTests
    {
        // ============== Core Tests ==============

        [Fact]
        public void TestEncryptDecrypt()
        {
            using var shield = new Dikestra.Shield.Shield("password123", "test-service");
            byte[] plaintext = Encoding.UTF8.GetBytes("Hello, Shield!");

            byte[] encrypted = shield.Encrypt(plaintext);
            byte[] decrypted = shield.Decrypt(encrypted);

            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void TestWithKey()
        {
            byte[] key = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();

            using var shield = new Dikestra.Shield.Shield(key);
            byte[] plaintext = Encoding.UTF8.GetBytes("Test message");

            byte[] encrypted = shield.Encrypt(plaintext);
            byte[] decrypted = shield.Decrypt(encrypted);

            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void TestQuickEncryptDecrypt()
        {
            byte[] key = new byte[32];
            byte[] plaintext = Encoding.UTF8.GetBytes("Quick test");

            byte[] encrypted = Dikestra.Shield.Shield.QuickEncrypt(key, plaintext);
            byte[] decrypted = Dikestra.Shield.Shield.QuickDecrypt(key, encrypted);

            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void TestInvalidKeySize()
        {
            Assert.Throws<ArgumentException>(() => new Dikestra.Shield.Shield(new byte[16]));
        }

        [Fact]
        public void TestAuthenticationFailed()
        {
            using var shield = new Dikestra.Shield.Shield("password", "service");
            byte[] encrypted = shield.Encrypt(Encoding.UTF8.GetBytes("test"));

            // Tamper with ciphertext
            encrypted[encrypted.Length - 1] ^= 0xFF;

            Assert.Throws<System.Security.Cryptography.CryptographicException>(
                () => shield.Decrypt(encrypted));
        }

        // ============== Security-Fix Tests (CR-1 / CR-2 / CR-3) ==============
        // Mirrors python/tests/test_core_security_fix.py. C# Decrypt throws
        // CryptographicException (instead of returning null) on auth failure,
        // so tamper/version assertions check for that exception.

        private const int SaltSize = Dikestra.Shield.Shield.SaltSize; // 16

        [Fact]
        public void TestSamePasswordServiceDifferentKeys()
        {
            // CR-1: two instances with the same password+service get DIFFERENT
            // keys, because each gets a random per-instance salt.
            using var a = new Dikestra.Shield.Shield("hunter2", "github.com");
            using var b = new Dikestra.Shield.Shield("hunter2", "github.com");

            byte[] msg = Encoding.UTF8.GetBytes("identical plaintext");
            byte[] ca = a.Encrypt(msg);
            byte[] cb = b.Encrypt(msg);

            // Salts live at bytes [2..18) of a v4 password-mode ciphertext
            // (after version + suite).
            byte[] saltA = ca[2..(2 + SaltSize)];
            byte[] saltB = cb[2..(2 + SaltSize)];
            Assert.NotEqual(saltA, saltB);

            // And the derived master keys differ (deterministic-key bug gone).
            Assert.NotEqual(a.GetKey(), b.GetKey());
        }

        [Fact]
        public void TestCrossInstanceRoundtrip()
        {
            // Bob (same password+service, different instance salt) decrypts Alice.
            using var alice = new Dikestra.Shield.Shield("correct horse battery staple", "service.example");
            using var bob = new Dikestra.Shield.Shield("correct horse battery staple", "service.example");

            byte[] msg = Encoding.UTF8.GetBytes("hello from alice");
            Assert.Equal(msg, bob.Decrypt(alice.Encrypt(msg)));
        }

        [Fact]
        public void TestTamperDetectionAllBytes()
        {
            // CR-3: flipping ANY byte (version, salt, nonce, ct, mac) fails auth.
            using var s = new Dikestra.Shield.Shield("pw", "svc");
            byte[] ct = s.Encrypt(Encoding.UTF8.GetBytes("secret payload"));

            // Sanity: untampered decrypts.
            Assert.Equal(Encoding.UTF8.GetBytes("secret payload"), s.Decrypt(ct));

            for (int i = 0; i < ct.Length; i++)
            {
                byte[] tampered = (byte[])ct.Clone();
                tampered[i] ^= 0xFF;
                Assert.True(
                    Throws(() => s.Decrypt(tampered)),
                    $"tamper at byte {i} not detected");
            }
        }

        [Fact]
        public void TestTamperVersionAndSaltBytes()
        {
            // Explicitly check the version byte (index 0) and a salt byte (index 2,
            // after version + suite) are authenticated.
            using var s = new Dikestra.Shield.Shield("pw", "svc");
            byte[] ct = s.Encrypt(Encoding.UTF8.GetBytes("data"));

            byte[] flipVersion = (byte[])ct.Clone();
            flipVersion[0] ^= 0xFF;
            Assert.True(Throws(() => s.Decrypt(flipVersion)));

            byte[] flipSalt = (byte[])ct.Clone();
            flipSalt[2] ^= 0xFF;
            Assert.True(Throws(() => s.Decrypt(flipSalt)));
        }

        [Fact]
        public void TestVersionBytes()
        {
            // v4: password ciphertext starts with 0x03; key/quick with 0x13.
            byte[] pwCt = new Dikestra.Shield.Shield("pw", "svc").Encrypt(Encoding.UTF8.GetBytes("x"));
            Assert.Equal(0x03, pwCt[0]);
            Assert.Equal(Dikestra.Shield.Shield.VersionPassword, pwCt[0]);

            byte[] key = Dikestra.Shield.Shield.RandomBytes(32);
            byte[] quickCt = Dikestra.Shield.Shield.QuickEncrypt(key, Encoding.UTF8.GetBytes("x"));
            Assert.Equal(0x13, quickCt[0]);
            Assert.Equal(Dikestra.Shield.Shield.VersionKey, quickCt[0]);

            byte[] keyedCt = new Dikestra.Shield.Shield(key).Encrypt(Encoding.UTF8.GetBytes("x"));
            Assert.Equal(0x13, keyedCt[0]);
        }

        [Fact]
        public void TestIterations600k()
        {
            // CR-2: PBKDF2 iteration count is 600,000.
            Assert.Equal(600000, Dikestra.Shield.Shield.Iterations);
        }

        [Fact]
        public void TestQuickKeyRoundtrip()
        {
            // Pre-shared-key one-shot encrypt/decrypt round-trips; wrong key fails.
            byte[] key = Dikestra.Shield.Shield.RandomBytes(32);
            byte[] msg = Encoding.UTF8.GetBytes("pre-shared key message");
            Assert.Equal(msg, Dikestra.Shield.Shield.QuickDecrypt(key, Dikestra.Shield.Shield.QuickEncrypt(key, msg)));

            byte[] wrongKey = Dikestra.Shield.Shield.RandomBytes(32);
            byte[] encrypted = Dikestra.Shield.Shield.QuickEncrypt(key, msg);
            Assert.True(Throws(() => Dikestra.Shield.Shield.QuickDecrypt(wrongKey, encrypted)));
        }

        [Fact]
        public void TestExplicitSaltIsHonoredAndStored()
        {
            // Passing an explicit salt pins it and it is stored in the header.
            byte[] salt = Dikestra.Shield.Shield.RandomBytes(SaltSize);
            using var a = new Dikestra.Shield.Shield("pw", "svc", 60000L, salt);
            using var b = new Dikestra.Shield.Shield("pw", "svc", 60000L, salt);
            Assert.Equal(a.GetKey(), b.GetKey()); // same salt -> same key

            byte[] ct = a.Encrypt(Encoding.UTF8.GetBytes("data"));
            Assert.Equal(salt, ct[2..(2 + SaltSize)]);
            Assert.Equal(Encoding.UTF8.GetBytes("data"), b.Decrypt(ct));
        }

        [Fact]
        public void TestKeyModeRejectsPasswordCiphertext()
        {
            // A pre-shared-key instance cannot decrypt a password-mode (0x02) blob.
            using var pw = new Dikestra.Shield.Shield("pw", "svc");
            byte[] ct = pw.Encrypt(Encoding.UTF8.GetBytes("x"));

            byte[] key = Dikestra.Shield.Shield.RandomBytes(32);
            using var keyed = new Dikestra.Shield.Shield(key);
            Assert.True(Throws(() => keyed.Decrypt(ct)));
        }

        /// <summary>Returns true if the action throws Crypto/Argument exception (auth failure).</summary>
        private static bool Throws(Action action)
        {
            try { action(); return false; }
            catch (System.Security.Cryptography.CryptographicException) { return true; }
            catch (ArgumentException) { return true; }
        }

        // ============== Ratchet Tests ==============

        [Fact]
        public void TestRatchetSession()
        {
            byte[] rootKey = new byte[32];

            using var alice = new RatchetSession(rootKey, true);
            using var bob = new RatchetSession(rootKey, false);

            byte[] msg = Encoding.UTF8.GetBytes("Hello Bob!");
            byte[] encrypted = alice.Encrypt(msg);
            byte[] decrypted = bob.Decrypt(encrypted);

            Assert.Equal(msg, decrypted);
            Assert.Equal(1UL, alice.SendCounter);
            Assert.Equal(1UL, bob.RecvCounter);
        }

        [Fact]
        public void TestRatchetReplayProtection()
        {
            byte[] rootKey = new byte[32];

            using var alice = new RatchetSession(rootKey, true);
            using var bob = new RatchetSession(rootKey, false);

            byte[] encrypted = alice.Encrypt(Encoding.UTF8.GetBytes("test"));
            bob.Decrypt(encrypted);

            // Try to replay
            Assert.Throws<System.Security.Cryptography.CryptographicException>(
                () => bob.Decrypt(encrypted));
        }

        // ============== TOTP Tests ==============

        [Fact]
        public void TestTotpGenerateVerify()
        {
            byte[] secret = Totp.GenerateSecret();
            using var totp = new Totp(secret);

            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            string code = totp.Generate(now);

            Assert.Equal(6, code.Length);
            Assert.True(totp.Verify(code, now, 1));
        }

        [Fact]
        public void TestTotpBase32()
        {
            byte[] secret = Encoding.UTF8.GetBytes("12345678901234567890");
            using var totp = new Totp(secret);

            string encoded = totp.ToBase32();
            using var decoded = Totp.FromBase32(encoded);

            Assert.Equal(secret, decoded.GetSecret());
        }

        [Fact]
        public void TestProvisioningUri()
        {
            byte[] secret = Encoding.UTF8.GetBytes("12345678901234567890");
            using var totp = new Totp(secret, 6, 30);

            string uri = totp.GetProvisioningUri("user@example.com", "MyService");

            Assert.StartsWith("otpauth://totp/", uri);
            Assert.Contains("MyService", uri);
        }

        // ============== Signature Tests ==============

        [Fact]
        public void TestSymmetricSignature()
        {
            using var sig = SymmetricSignature.Generate();

            byte[] message = Encoding.UTF8.GetBytes("Sign this message");
            byte[] signature = sig.Sign(message);

            Assert.True(sig.Verify(message, signature, sig.VerificationKey));
        }

        [Fact]
        public void TestSymmetricSignatureWithTimestamp()
        {
            using var sig = SymmetricSignature.Generate();

            byte[] message = Encoding.UTF8.GetBytes("Timestamped message");
            byte[] signature = sig.Sign(message, true);

            Assert.Equal(40, signature.Length);
            Assert.True(sig.Verify(message, signature, sig.VerificationKey, 60));
        }

        [Fact]
        public void TestSymmetricSignatureFromPassword()
        {
            using var sig = SymmetricSignature.FromPassword("password", "user@example.com");

            byte[] message = Encoding.UTF8.GetBytes("Test message");
            byte[] signature = sig.Sign(message);

            Assert.True(sig.Verify(message, signature, sig.VerificationKey));
        }

        [Fact]
        public void TestLamportSignature()
        {
            using var lamport = LamportSignature.Generate();

            byte[] message = Encoding.UTF8.GetBytes("Lamport signed message");
            byte[] signature = lamport.Sign(message);

            Assert.True(LamportSignature.Verify(message, signature, lamport.PublicKey));
        }

        [Fact]
        public void TestLamportOneTimeUse()
        {
            using var lamport = LamportSignature.Generate();

            lamport.Sign(Encoding.UTF8.GetBytes("first"));

            Assert.True(lamport.IsUsed);
            Assert.Throws<InvalidOperationException>(
                () => lamport.Sign(Encoding.UTF8.GetBytes("second")));
        }

        // ============== Utility Tests ==============

        [Fact]
        public void TestSecureCompare()
        {
            byte[] a = { 1, 2, 3, 4, 5, 6, 7, 8 };
            byte[] b = { 1, 2, 3, 4, 5, 6, 7, 8 };
            byte[] c = { 1, 2, 3, 4, 5, 6, 7, 9 };

            Assert.True(Dikestra.Shield.Shield.ConstantTimeEquals(a, b, 8));
            Assert.False(Dikestra.Shield.Shield.ConstantTimeEquals(a, c, 8));
        }

        [Fact]
        public void TestSha256()
        {
            byte[] expected = {
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
                0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
                0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
                0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
            };

            byte[] hash = Dikestra.Shield.Shield.Sha256(Encoding.UTF8.GetBytes("abc"));
            Assert.Equal(expected, hash);
        }

        [Fact]
        public void TestRandomBytes()
        {
            byte[] a = Dikestra.Shield.Shield.RandomBytes(32);
            byte[] b = Dikestra.Shield.Shield.RandomBytes(32);

            Assert.NotEqual(a, b);
        }

        [Fact]
        public void TestFingerprints()
        {
            using var sig = SymmetricSignature.Generate();
            Assert.Equal(16, sig.Fingerprint().Length);

            using var lamport = LamportSignature.Generate();
            Assert.Equal(16, lamport.Fingerprint().Length);
        }
    }
}
