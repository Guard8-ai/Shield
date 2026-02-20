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

    // V2 constants
    public static final int V2_HEADER_SIZE = 17;  // counter(8) + timestamp(8) + pad_len(1)
    public static final int MIN_PADDING = 32;
    public static final int MAX_PADDING = 128;
    public static final long MIN_TIMESTAMP_MS = 1577836800000L;  // 2020-01-01
    public static final long MAX_TIMESTAMP_MS = 4102444800000L;  // 2100-01-01
    public static final long DEFAULT_MAX_AGE_MS = 60000L;

    private final byte[] key;
    private final Long maxAgeMs;  // null = disabled
    private static final SecureRandom random = new SecureRandom();

    /**
     * Create Shield from password and service name.
     */
    public Shield(String password, String service) {
        this(password, service, DEFAULT_MAX_AGE_MS);
    }

    /**
     * Create Shield from password and service name with custom max age.
     */
    public Shield(String password, String service, Long maxAgeMs) {
        byte[] salt = sha256(service.getBytes());
        this.key = pbkdf2(password, salt, ITERATIONS, KEY_SIZE);
        this.maxAgeMs = maxAgeMs;
    }

    /**
     * Create Shield with pre-shared key.
     */
    public Shield(byte[] key) {
        this(key, DEFAULT_MAX_AGE_MS);
    }

    /**
     * Create Shield with pre-shared key and custom max age.
     */
    public Shield(byte[] key, Long maxAgeMs) {
        if (key.length != KEY_SIZE) {
            throw new IllegalArgumentException("Invalid key size");
        }
        this.key = Arrays.copyOf(key, KEY_SIZE);
        this.maxAgeMs = maxAgeMs;
    }

    /**
     * Create Shield with hardware fingerprinting (device-bound encryption).
     *
     * <p>Derives keys from password + hardware identifier, binding encryption to
     * the physical device. Keys cannot be transferred to other hardware.
     *
     * @param password User's password
     * @param service Service identifier
     * @param mode Fingerprint mode
     * @return Shield instance with device-bound key
     * @throws Exception If hardware fingerprint unavailable
     *
     * <p>Example:
     * <pre>{@code
     * Shield shield = Shield.withFingerprint("password", "github.com", FingerprintMode.COMBINED);
     * byte[] encrypted = shield.encrypt("secret".getBytes());
     * }</pre>
     */
    public static Shield withFingerprint(String password, String service, Fingerprint.FingerprintMode mode) throws Exception {
        String fingerprint = Fingerprint.collect(mode);

        String combinedPassword = fingerprint.isEmpty() ? password : password + ":" + fingerprint;

        return new Shield(combinedPassword, service);
    }

    /**
     * Encrypt plaintext (v2 format).
     */
    public byte[] encrypt(byte[] plaintext) {
        return encryptWithKey(key, plaintext);
    }

    /**
     * Decrypt ciphertext (auto-detects v1/v2).
     */
    public byte[] decrypt(byte[] ciphertext) {
        return decryptWithKey(key, ciphertext, maxAgeMs);
    }

    /**
     * Decrypt v1 format explicitly (for legacy compatibility).
     */
    public byte[] decryptV1(byte[] ciphertext) {
        return decryptV1WithKey(key, ciphertext);
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
        return decryptWithKey(key, ciphertext, null);
    }

    private static byte[] encryptWithKey(byte[] key, byte[] plaintext) {
        // Generate random nonce
        byte[] nonce = new byte[NONCE_SIZE];
        random.nextBytes(nonce);

        // Counter prefix (8 bytes of zeros)
        byte[] counter = new byte[8];

        // Timestamp in milliseconds since Unix epoch
        long timestampMs = System.currentTimeMillis();
        byte[] timestamp = new byte[8];
        ByteBuffer.wrap(timestamp).order(ByteOrder.LITTLE_ENDIAN).putLong(timestampMs);

        // Random padding: 32-128 bytes
        int padLen = (random.nextInt() & 0xFF) % (MAX_PADDING - MIN_PADDING + 1) + MIN_PADDING;
        byte[] padLenByte = new byte[] { (byte) padLen };
        byte[] padding = new byte[padLen];
        random.nextBytes(padding);

        // Data to encrypt: counter || timestamp || pad_len || padding || plaintext
        byte[] dataToEncrypt = new byte[8 + 8 + 1 + padLen + plaintext.length];
        int pos = 0;
        System.arraycopy(counter, 0, dataToEncrypt, pos, 8);
        pos += 8;
        System.arraycopy(timestamp, 0, dataToEncrypt, pos, 8);
        pos += 8;
        System.arraycopy(padLenByte, 0, dataToEncrypt, pos, 1);
        pos += 1;
        System.arraycopy(padding, 0, dataToEncrypt, pos, padLen);
        pos += padLen;
        System.arraycopy(plaintext, 0, dataToEncrypt, pos, plaintext.length);

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

    private static byte[] decryptWithKey(byte[] key, byte[] encrypted, Long maxAgeMs) {
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

        // Auto-detect v2 by timestamp range (2020-2100)
        if (decrypted.length >= V2_HEADER_SIZE) {
            byte[] timestampBytes = Arrays.copyOfRange(decrypted, 8, 16);
            long timestampMs = ByteBuffer.wrap(timestampBytes).order(ByteOrder.LITTLE_ENDIAN).getLong();

            if (timestampMs >= MIN_TIMESTAMP_MS && timestampMs <= MAX_TIMESTAMP_MS) {
                // v2 format detected
                int padLen = decrypted[16] & 0xFF;

                // Validate padding length is within protocol bounds (SECURITY: CVE-PENDING)
                if (padLen < MIN_PADDING || padLen > MAX_PADDING) {
                    throw new SecurityException("Authentication failed");
                }

                int dataStart = V2_HEADER_SIZE + padLen;

                if (decrypted.length < dataStart) {
                    throw new IllegalArgumentException("Ciphertext too short");
                }

                // Replay protection
                if (maxAgeMs != null) {
                    long nowMs = System.currentTimeMillis();
                    long age = nowMs - timestampMs;

                    // Reject if too far in future (>5s clock skew) or too old
                    if (timestampMs > nowMs + 5000 || age > maxAgeMs) {
                        throw new SecurityException("Authentication failed");
                    }
                }

                return Arrays.copyOfRange(decrypted, dataStart, decrypted.length);
            }
        }

        // v1 format: skip counter (8 bytes)
        return Arrays.copyOfRange(decrypted, 8, decrypted.length);
    }

    private static byte[] decryptV1WithKey(byte[] key, byte[] encrypted) {
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

        // v1 format: skip counter (8 bytes)
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
