package ai.dikestra.shield;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;

/**
 * Shield Library Tests
 */
public class ShieldTest {

    // ============== Core Tests ==============

    @Test
    void testEncryptDecrypt() {
        Shield shield = new Shield("password123", "test-service");
        byte[] plaintext = "Hello, Shield!".getBytes();

        byte[] encrypted = shield.encrypt(plaintext);
        byte[] decrypted = shield.decrypt(encrypted);

        assertArrayEquals(plaintext, decrypted);
        shield.wipe();
    }

    @Test
    void testWithKey() {
        byte[] key = new byte[Shield.KEY_SIZE];
        for (int i = 0; i < key.length; i++) key[i] = (byte) i;

        Shield shield = new Shield(key);
        byte[] plaintext = "Test message".getBytes();

        byte[] encrypted = shield.encrypt(plaintext);
        byte[] decrypted = shield.decrypt(encrypted);

        assertArrayEquals(plaintext, decrypted);
        shield.wipe();
    }

    @Test
    void testQuickEncryptDecrypt() {
        byte[] key = new byte[Shield.KEY_SIZE];
        byte[] plaintext = "Quick test".getBytes();

        byte[] encrypted = Shield.quickEncrypt(key, plaintext);
        byte[] decrypted = Shield.quickDecrypt(key, encrypted);

        assertArrayEquals(plaintext, decrypted);
    }

    // ============== Security-fix Tests (CR-1 / CR-2 / CR-3) ==============

    @Test
    void testSamePasswordServiceDifferentKeys() {
        // CR-1: two instances with same password+service get DIFFERENT keys
        // because each generates a fresh random salt.
        Shield a = new Shield("hunter2", "github.com");
        Shield b = new Shield("hunter2", "github.com");

        byte[] msg = "identical plaintext".getBytes();
        byte[] ca = a.encrypt(msg);
        byte[] cb = b.encrypt(msg);

        // Salt lives at bytes [2..18) of a v4 password-mode ciphertext (after version + suite).
        byte[] saltA = Arrays.copyOfRange(ca, 2, 2 + Shield.SALT_SIZE);
        byte[] saltB = Arrays.copyOfRange(cb, 2, 2 + Shield.SALT_SIZE);
        assertFalse(Arrays.equals(saltA, saltB));
        assertFalse(Arrays.equals(a.getKey(), b.getKey()));
    }

    @Test
    void testCrossInstanceRoundtrip() {
        // CR-1: an independent instance with the same password+service decrypts,
        // because the random salt travels in the header and the key is re-derived.
        Shield alice = new Shield("correct horse battery staple", "service.example");
        Shield bob = new Shield("correct horse battery staple", "service.example");
        byte[] msg = "hello from alice".getBytes();
        assertArrayEquals(msg, bob.decrypt(alice.encrypt(msg)));
    }

    @Test
    void testWrongPasswordFails() {
        Shield sender = new Shield("right-password", "example.com");
        Shield wrong = new Shield("wrong-password", "example.com");
        byte[] encrypted = sender.encrypt("secret".getBytes());
        assertThrows(RuntimeException.class, () -> wrong.decrypt(encrypted));
    }

    @Test
    void testIterations600k() {
        // CR-2: PBKDF2 iteration count is 600,000.
        assertEquals(600000, Shield.ITERATIONS);
    }

    @Test
    void testVersionBytes() {
        // v4: password ciphertext starts with 0x03; key/quick with 0x13.
        byte[] pwCt = new Shield("pw", "svc").encrypt("x".getBytes());
        assertEquals(Shield.VERSION_PASSWORD, pwCt[0]);
        assertEquals((byte) 0x03, pwCt[0]);

        byte[] key = new byte[Shield.KEY_SIZE];
        byte[] keyCt = new Shield(key).encrypt("x".getBytes());
        assertEquals(Shield.VERSION_KEY, keyCt[0]);
        assertEquals((byte) 0x13, keyCt[0]);

        byte[] quickCt = Shield.quickEncrypt(key, "x".getBytes());
        assertEquals(Shield.VERSION_KEY, quickCt[0]);
    }

    @Test
    void testTamperSaltDetected() {
        // CR-3: the salt is authenticated; flipping a salt byte fails auth.
        Shield s = new Shield("pw", "svc");
        byte[] ct = s.encrypt("authenticated salt".getBytes());
        ct[2] ^= 0xFF;  // first salt byte (after version + suite)
        assertThrows(SecurityException.class, () -> s.decrypt(ct));
    }

    @Test
    void testTamperVersionDetected() {
        // CR-3: the version byte is authenticated.
        Shield s = new Shield("pw", "svc");
        byte[] ct = s.encrypt("authenticated version".getBytes());
        ct[0] ^= 0xFF;
        assertThrows(RuntimeException.class, () -> s.decrypt(ct));
    }

    @Test
    void testUnknownVersionRejected() {
        // CR-3: dispatch is on the version byte; an unknown version is rejected.
        Shield s = new Shield("pw", "svc");
        byte[] ct = s.encrypt("x".getBytes());
        ct[0] = 0x7F;
        assertThrows(SecurityException.class, () -> s.decrypt(ct));
    }

    @Test
    void testFullTamperDetection() {
        // Flipping ANY byte (version, salt, nonce, ct, mac) fails authentication.
        Shield s = new Shield("pw", "svc");
        byte[] ct = s.encrypt("secret payload".getBytes());
        assertArrayEquals("secret payload".getBytes(), s.decrypt(ct));

        for (int i = 0; i < ct.length; i++) {
            byte[] tampered = ct.clone();
            tampered[i] ^= 0xFF;
            final int idx = i;
            assertThrows(RuntimeException.class, () -> s.decrypt(tampered),
                    "tamper at byte " + idx + " not detected");
        }
    }

    @Test
    void testKeyModeRejectsPasswordCiphertext() {
        Shield pw = new Shield("password", "service");
        byte[] ct = pw.encrypt("pw secret".getBytes());
        Shield ks = new Shield(new byte[Shield.KEY_SIZE]);
        assertThrows(RuntimeException.class, () -> ks.decrypt(ct));
    }

    @Test
    void testExplicitSaltIsHonoredAndStored() {
        byte[] salt = Shield.randomBytes(Shield.SALT_SIZE);
        Shield a = new Shield("pw", "svc", salt, Shield.ITERATIONS, Shield.DEFAULT_MAX_AGE_MS);
        Shield b = new Shield("pw", "svc", salt, Shield.ITERATIONS, Shield.DEFAULT_MAX_AGE_MS);
        assertArrayEquals(a.getKey(), b.getKey());

        byte[] ct = a.encrypt("data".getBytes());
        assertArrayEquals(salt, Arrays.copyOfRange(ct, 2, 2 + Shield.SALT_SIZE));
        assertArrayEquals("data".getBytes(), b.decrypt(ct));
    }

    @Test
    void testInvalidKeySize() {
        assertThrows(IllegalArgumentException.class, () -> {
            new Shield(new byte[16]);
        });
    }

    @Test
    void testAuthenticationFailed() {
        Shield shield = new Shield("password", "service");
        byte[] encrypted = shield.encrypt("test".getBytes());

        // Tamper with ciphertext
        encrypted[encrypted.length - 1] ^= 0xFF;

        assertThrows(SecurityException.class, () -> {
            shield.decrypt(encrypted);
        });
        shield.wipe();
    }

    // ============== V2 Format Tests ==============

    @Test
    void testV2Roundtrip() {
        Shield shield = new Shield("password", "service", 60000L);
        byte[] plaintext = "Test v2 message".getBytes();

        byte[] encrypted = shield.encrypt(plaintext);
        byte[] decrypted = shield.decrypt(encrypted);

        assertArrayEquals(plaintext, decrypted);
        shield.wipe();
    }

    @Test
    void testV2ReplayProtectionFresh() {
        Shield shield = new Shield("password", "service", 60000L);
        byte[] plaintext = "Fresh message".getBytes();

        byte[] encrypted = shield.encrypt(plaintext);
        byte[] decrypted = shield.decrypt(encrypted);

        assertArrayEquals(plaintext, decrypted);
        shield.wipe();
    }

    @Test
    void testV2ReplayProtectionExpired() throws InterruptedException {
        Shield shield = new Shield("password", "service", 500L);
        byte[] encrypted = shield.encrypt("Old message".getBytes());

        // Wait for expiry
        Thread.sleep(600);

        assertThrows(SecurityException.class, () -> {
            shield.decrypt(encrypted);
        });
        shield.wipe();
    }

    @Test
    void testV2LengthVariation() {
        Shield shield = new Shield("password", "service", 60000L);
        byte[] plaintext = "Same message".getBytes();

        java.util.Set<Integer> lengths = new java.util.HashSet<>();
        for (int i = 0; i < 10; i++) {
            byte[] encrypted = shield.encrypt(plaintext);
            lengths.add(encrypted.length);
        }

        // Should have multiple different lengths due to random padding (32-128)
        assertTrue(lengths.size() > 1);
        shield.wipe();
    }

    @Test
    void testNoLegacyFallback() {
        // Clean break: legacy v1 decode has been removed. A headerless ciphertext
        // (version+salt stripped) must be rejected outright, no heuristic fallback.
        Shield shield = new Shield("password", "service", 60000L);
        byte[] encrypted = shield.encrypt("modern message".getBytes());
        byte[] legacy = Arrays.copyOfRange(encrypted, 2 + Shield.SALT_SIZE, encrypted.length);
        assertThrows(RuntimeException.class, () -> shield.decrypt(legacy));
        shield.wipe();
    }

    @Test
    void testNoFallbackOnExpiredV2() throws InterruptedException {
        Shield shield = new Shield("password", "service", 500L);
        byte[] encrypted = shield.encrypt("expired v2".getBytes());

        // Wait for expiry
        Thread.sleep(600);

        // Should reject (not fallback to v1)
        assertThrows(SecurityException.class, () -> {
            shield.decrypt(encrypted);
        });
        shield.wipe();
    }

    @Test
    void testV2DisabledReplayProtection() {
        Shield shield = new Shield("password", "service", null);  // null = disabled
        byte[] plaintext = "old but valid".getBytes();

        byte[] encrypted = shield.encrypt(plaintext);
        byte[] decrypted = shield.decrypt(encrypted);

        assertArrayEquals(plaintext, decrypted);
        shield.wipe();
    }

    // ============== Ratchet Tests ==============

    @Test
    void testRatchetSession() {
        byte[] rootKey = new byte[Shield.KEY_SIZE];

        RatchetSession alice = new RatchetSession(rootKey, true);
        RatchetSession bob = new RatchetSession(rootKey, false);

        // Alice sends to Bob
        byte[] msg = "Hello Bob!".getBytes();
        byte[] encrypted = alice.encrypt(msg);
        byte[] decrypted = bob.decrypt(encrypted);

        assertArrayEquals(msg, decrypted);
        assertEquals(1, alice.getSendCounter());
        assertEquals(1, bob.getRecvCounter());

        alice.wipe();
        bob.wipe();
    }

    @Test
    void testRatchetReplayProtection() {
        byte[] rootKey = new byte[Shield.KEY_SIZE];

        RatchetSession alice = new RatchetSession(rootKey, true);
        RatchetSession bob = new RatchetSession(rootKey, false);

        byte[] encrypted = alice.encrypt("test".getBytes());
        bob.decrypt(encrypted);

        // Try to replay
        assertThrows(SecurityException.class, () -> {
            bob.decrypt(encrypted);
        });

        alice.wipe();
        bob.wipe();
    }

    // ============== TOTP Tests ==============

    @Test
    void testTOTPGenerateVerify() {
        byte[] secret = TOTP.generateSecret();
        TOTP totp = new TOTP(secret);

        long now = System.currentTimeMillis() / 1000;
        String code = totp.generate(now);

        assertEquals(6, code.length());
        assertTrue(totp.verify(code, now, 1));

        totp.wipe();
    }

    @Test
    void testTOTPBase32() {
        byte[] secret = "12345678901234567890".getBytes();
        TOTP totp = new TOTP(secret);

        String encoded = totp.toBase32();
        TOTP decoded = TOTP.fromBase32(encoded);

        assertArrayEquals(secret, decoded.getSecret());

        totp.wipe();
        decoded.wipe();
    }

    @Test
    void testProvisioningURI() {
        byte[] secret = "12345678901234567890".getBytes();
        TOTP totp = new TOTP(secret, 6, 30);

        String uri = totp.getProvisioningUri("user@example.com", "MyService");

        assertTrue(uri.startsWith("otpauth://totp/"));
        assertTrue(uri.contains("MyService"));

        totp.wipe();
    }

    // ============== Signature Tests ==============

    @Test
    void testSymmetricSignature() {
        Signatures.SymmetricSignature sig = Signatures.SymmetricSignature.generate();

        byte[] message = "Sign this message".getBytes();
        byte[] signature = sig.sign(message);

        assertTrue(sig.verify(message, signature, sig.getVerificationKey(), 0));
        sig.wipe();
    }

    @Test
    void testSymmetricSignatureWithTimestamp() {
        Signatures.SymmetricSignature sig = Signatures.SymmetricSignature.generate();

        byte[] message = "Timestamped message".getBytes();
        byte[] signature = sig.sign(message, true);

        assertEquals(40, signature.length);
        assertTrue(sig.verify(message, signature, sig.getVerificationKey(), 60));

        sig.wipe();
    }

    @Test
    void testSymmetricSignatureFromPassword() {
        Signatures.SymmetricSignature sig =
            Signatures.SymmetricSignature.fromPassword("password", "user@example.com");

        byte[] message = "Test message".getBytes();
        byte[] signature = sig.sign(message);

        assertTrue(sig.verify(message, signature, sig.getVerificationKey(), 0));
        sig.wipe();
    }

    @Test
    void testLamportSignature() {
        Signatures.LamportSignature lamport = Signatures.LamportSignature.generate();

        byte[] message = "Lamport signed message".getBytes();
        byte[] signature = lamport.sign(message);

        assertTrue(Signatures.LamportSignature.verify(message, signature, lamport.getPublicKey()));
        lamport.wipe();
    }

    @Test
    void testLamportOneTimeUse() {
        Signatures.LamportSignature lamport = Signatures.LamportSignature.generate();

        lamport.sign("first".getBytes());

        assertTrue(lamport.isUsed());
        assertThrows(IllegalStateException.class, () -> {
            lamport.sign("second".getBytes());
        });

        lamport.wipe();
    }

    // ============== Utility Tests ==============

    @Test
    void testSecureCompare() {
        byte[] a = {1, 2, 3, 4, 5, 6, 7, 8};
        byte[] b = {1, 2, 3, 4, 5, 6, 7, 8};
        byte[] c = {1, 2, 3, 4, 5, 6, 7, 9};

        assertTrue(Shield.constantTimeEquals(a, b));
        assertFalse(Shield.constantTimeEquals(a, c));
    }

    @Test
    void testSha256() {
        // Test vector: SHA256("abc")
        byte[] expected = {
            (byte) 0xba, (byte) 0x78, (byte) 0x16, (byte) 0xbf,
            (byte) 0x8f, (byte) 0x01, (byte) 0xcf, (byte) 0xea,
            (byte) 0x41, (byte) 0x41, (byte) 0x40, (byte) 0xde,
            (byte) 0x5d, (byte) 0xae, (byte) 0x22, (byte) 0x23,
            (byte) 0xb0, (byte) 0x03, (byte) 0x61, (byte) 0xa3,
            (byte) 0x96, (byte) 0x17, (byte) 0x7a, (byte) 0x9c,
            (byte) 0xb4, (byte) 0x10, (byte) 0xff, (byte) 0x61,
            (byte) 0xf2, (byte) 0x00, (byte) 0x15, (byte) 0xad
        };

        byte[] hash = Shield.sha256("abc".getBytes());
        assertArrayEquals(expected, hash);
    }

    @Test
    void testRandomBytes() {
        byte[] a = Shield.randomBytes(32);
        byte[] b = Shield.randomBytes(32);

        assertFalse(Arrays.equals(a, b));
    }

    @Test
    void testFingerprints() {
        // Signature fingerprint
        Signatures.SymmetricSignature sig = Signatures.SymmetricSignature.generate();
        assertEquals(16, sig.fingerprint().length());
        sig.wipe();

        // Lamport fingerprint
        Signatures.LamportSignature lamport = Signatures.LamportSignature.generate();
        assertEquals(16, lamport.fingerprint().length());
        lamport.wipe();
    }
}
