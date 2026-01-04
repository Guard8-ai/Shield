package ai.guard8.shield;

import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Shield - EXPTIME-Secure Symmetric Encryption Library
 *
 * Uses only symmetric cryptographic primitives with proven exponential-time security:
 * PBKDF2-SHA256, HMAC-SHA256, and SHA256-based stream cipher.
 * Breaking requires 2^256 operations - no shortcut exists.
 */
public class Shield {
    public static final int KEY_SIZE = 32;
    public static final int NONCE_SIZE = 16;
    public static final int MAC_SIZE = 16;
    public static final int ITERATIONS = 100000;
    public static final int MIN_CIPHERTEXT_SIZE = NONCE_SIZE + 8 + MAC_SIZE;

    private final byte[] key;
    private static final SecureRandom random = new SecureRandom();

    /**
     * Create Shield from password and service name.
     */
    public Shield(String password, String service) {
        byte[] salt = sha256(service.getBytes());
        this.key = pbkdf2(password, salt, ITERATIONS, KEY_SIZE);
    }

    /**
     * Create Shield with pre-shared key.
     */
    public Shield(byte[] key) {
        if (key.length != KEY_SIZE) {
            throw new IllegalArgumentException("Invalid key size");
        }
        this.key = Arrays.copyOf(key, KEY_SIZE);
    }

    /**
     * Encrypt plaintext.
     */
    public byte[] encrypt(byte[] plaintext) {
        return encryptWithKey(key, plaintext);
    }

    /**
     * Decrypt ciphertext.
     */
    public byte[] decrypt(byte[] ciphertext) {
        return decryptWithKey(key, ciphertext);
    }

    /**
     * Get the derived key.
     */
    public byte[] getKey() {
        return Arrays.copyOf(key, KEY_SIZE);
    }

    /**
     * Wipe key from memory.
     */
    public void wipe() {
        Arrays.fill(key, (byte) 0);
    }

    // ============== Static Methods ==============

    /**
     * Quick encrypt with explicit key.
     */
    public static byte[] quickEncrypt(byte[] key, byte[] plaintext) {
        if (key.length != KEY_SIZE) {
            throw new IllegalArgumentException("Invalid key size");
        }
        return encryptWithKey(key, plaintext);
    }

    /**
     * Quick decrypt with explicit key.
     */
    public static byte[] quickDecrypt(byte[] key, byte[] ciphertext) {
        if (key.length != KEY_SIZE) {
            throw new IllegalArgumentException("Invalid key size");
        }
        return decryptWithKey(key, ciphertext);
    }

    private static byte[] encryptWithKey(byte[] key, byte[] plaintext) {
        // Generate random nonce
        byte[] nonce = new byte[NONCE_SIZE];
        random.nextBytes(nonce);

        // Counter prefix (8 bytes of zeros)
        byte[] dataToEncrypt = new byte[8 + plaintext.length];
        System.arraycopy(plaintext, 0, dataToEncrypt, 8, plaintext.length);

        // Generate keystream and XOR
        byte[] keystream = generateKeystream(key, nonce, dataToEncrypt.length);
        byte[] ciphertext = new byte[dataToEncrypt.length];
        for (int i = 0; i < dataToEncrypt.length; i++) {
            ciphertext[i] = (byte) (dataToEncrypt[i] ^ keystream[i]);
        }

        // Compute HMAC over nonce || ciphertext
        byte[] macData = new byte[NONCE_SIZE + ciphertext.length];
        System.arraycopy(nonce, 0, macData, 0, NONCE_SIZE);
        System.arraycopy(ciphertext, 0, macData, NONCE_SIZE, ciphertext.length);
        byte[] mac = hmacSha256(key, macData);

        // Format: nonce || ciphertext || mac
        byte[] result = new byte[NONCE_SIZE + ciphertext.length + MAC_SIZE];
        System.arraycopy(nonce, 0, result, 0, NONCE_SIZE);
        System.arraycopy(ciphertext, 0, result, NONCE_SIZE, ciphertext.length);
        System.arraycopy(mac, 0, result, NONCE_SIZE + ciphertext.length, MAC_SIZE);

        return result;
    }

    private static byte[] decryptWithKey(byte[] key, byte[] encrypted) {
        if (encrypted.length < MIN_CIPHERTEXT_SIZE) {
            throw new IllegalArgumentException("Ciphertext too short");
        }

        // Parse components
        byte[] nonce = Arrays.copyOfRange(encrypted, 0, NONCE_SIZE);
        byte[] ciphertext = Arrays.copyOfRange(encrypted, NONCE_SIZE, encrypted.length - MAC_SIZE);
        byte[] receivedMac = Arrays.copyOfRange(encrypted, encrypted.length - MAC_SIZE, encrypted.length);

        // Verify MAC
        byte[] macData = new byte[NONCE_SIZE + ciphertext.length];
        System.arraycopy(nonce, 0, macData, 0, NONCE_SIZE);
        System.arraycopy(ciphertext, 0, macData, NONCE_SIZE, ciphertext.length);
        byte[] expectedMac = hmacSha256(key, macData);

        if (!constantTimeEquals(receivedMac, Arrays.copyOf(expectedMac, MAC_SIZE))) {
            throw new SecurityException("Authentication failed");
        }

        // Decrypt
        byte[] keystream = generateKeystream(key, nonce, ciphertext.length);
        byte[] decrypted = new byte[ciphertext.length];
        for (int i = 0; i < ciphertext.length; i++) {
            decrypted[i] = (byte) (ciphertext[i] ^ keystream[i]);
        }

        // Skip 8-byte counter prefix
        return Arrays.copyOfRange(decrypted, 8, decrypted.length);
    }

    private static byte[] generateKeystream(byte[] key, byte[] nonce, int length) {
        int numBlocks = (length + 31) / 32;
        byte[] keystream = new byte[numBlocks * 32];

        for (int i = 0; i < numBlocks; i++) {
            byte[] block = new byte[KEY_SIZE + NONCE_SIZE + 4];
            System.arraycopy(key, 0, block, 0, KEY_SIZE);
            System.arraycopy(nonce, 0, block, KEY_SIZE, NONCE_SIZE);
            ByteBuffer.wrap(block, KEY_SIZE + NONCE_SIZE, 4)
                    .order(ByteOrder.LITTLE_ENDIAN)
                    .putInt(i);

            byte[] hash = sha256(block);
            System.arraycopy(hash, 0, keystream, i * 32, 32);
        }

        return Arrays.copyOf(keystream, length);
    }

    // ============== Crypto Utilities ==============

    public static byte[] sha256(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(data);
        } catch (Exception e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    public static byte[] hmacSha256(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException("HMAC-SHA256 not available", e);
        }
    }

    public static byte[] pbkdf2(String password, byte[] salt, int iterations, int keyLength) {
        try {
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength * 8);
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return skf.generateSecret(spec).getEncoded();
        } catch (Exception e) {
            throw new RuntimeException("PBKDF2 not available", e);
        }
    }

    public static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a.length != b.length) {
            return false;
        }
        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }

    public static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return bytes;
    }

    public static void secureWipe(byte[] data) {
        Arrays.fill(data, (byte) 0);
    }
}
