using System;
using System.Linq;
using System.Text;
using Xunit;
using Guard8.Shield;

namespace Shield.Tests
{
    public class ShieldTests
    {
        // ============== Core Tests ==============

        [Fact]
        public void TestEncryptDecrypt()
        {
            using var shield = new Guard8.Shield.Shield("password123", "test-service");
            byte[] plaintext = Encoding.UTF8.GetBytes("Hello, Shield!");

            byte[] encrypted = shield.Encrypt(plaintext);
            byte[] decrypted = shield.Decrypt(encrypted);

            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void TestWithKey()
        {
            byte[] key = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();

            using var shield = new Guard8.Shield.Shield(key);
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

            byte[] encrypted = Guard8.Shield.Shield.QuickEncrypt(key, plaintext);
            byte[] decrypted = Guard8.Shield.Shield.QuickDecrypt(key, encrypted);

            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void TestInvalidKeySize()
        {
            Assert.Throws<ArgumentException>(() => new Guard8.Shield.Shield(new byte[16]));
        }

        [Fact]
        public void TestAuthenticationFailed()
        {
            using var shield = new Guard8.Shield.Shield("password", "service");
            byte[] encrypted = shield.Encrypt(Encoding.UTF8.GetBytes("test"));

            // Tamper with ciphertext
            encrypted[encrypted.Length - 1] ^= 0xFF;

            Assert.Throws<System.Security.Cryptography.CryptographicException>(
                () => shield.Decrypt(encrypted));
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

            Assert.True(Guard8.Shield.Shield.ConstantTimeEquals(a, b, 8));
            Assert.False(Guard8.Shield.Shield.ConstantTimeEquals(a, c, 8));
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

            byte[] hash = Guard8.Shield.Shield.Sha256(Encoding.UTF8.GetBytes("abc"));
            Assert.Equal(expected, hash);
        }

        [Fact]
        public void TestRandomBytes()
        {
            byte[] a = Guard8.Shield.Shield.RandomBytes(32);
            byte[] b = Guard8.Shield.Shield.RandomBytes(32);

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
