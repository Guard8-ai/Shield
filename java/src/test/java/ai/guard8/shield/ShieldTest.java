package ai.guard8.shield;

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
