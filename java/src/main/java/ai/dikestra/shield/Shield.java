package ai.dikestra.shield;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Shield - Authenticated Symmetric Encryption Library (wire format v4).
 *
 * <p>v4 replaces the previous custom SHA-256 keystream + HMAC construction with a
 * standard AEAD (AES-256-GCM by default, ChaCha20-Poly1305 optional) from the JCE.
 * No cryptography is hand-rolled; key derivation uses PBKDF2-HMAC-SHA256 +
 * HKDF-SHA256-Expand. The wire format matches every other Shield binding
 * byte-for-byte (see tests/v4_test_vectors.json).
 *
 * <ul>
 *   <li>Password mode: {@code 0x03 || suite(1) || salt(16) || nonce(12) || ciphertext||tag}</li>
 *   <li>Key mode:       {@code 0x13 || suite(1) || nonce(12) || ciphertext||tag}</li>
 * </ul>
 * AAD = {@code version || suite || [salt]}; inner plaintext =
 * {@code timestamp_ms(8 LE) || pad_len(1) || padding(32-128) || message}.
 */
public class Shield {
    public static final int KEY_SIZE = 32;
    // NONCE_SIZE/MAC_SIZE retained at 16 for API compatibility; the base AEAD
    // cipher uses its own 12-byte nonce / 16-byte tag (below).
    public static final int NONCE_SIZE = 16;
    public static final int MAC_SIZE = 16;
    public static final int SALT_SIZE = 16;
    /** PBKDF2 iteration count (OWASP 2023 floor for PBKDF2-HMAC-SHA256). */
    public static final int ITERATIONS = 600000;

    // Authenticated version bytes (leading byte of the ciphertext).
    public static final byte VERSION_PASSWORD = 0x03; // 0x03 || suite || salt(16) || nonce(12) || ct||tag
    public static final byte VERSION_KEY = 0x13;       // 0x13 || suite || nonce(12) || ct||tag

    // Cipher-suite identifiers.
    public static final byte SUITE_AES_GCM = 0x01;
    public static final byte SUITE_CHACHA20_POLY1305 = 0x02;

    public static final int MIN_PADDING = 32;
    public static final int MAX_PADDING = 128;
    public static final long DEFAULT_MAX_AGE_MS = 60000L;

    // Base-AEAD constants.
    private static final int AEAD_NONCE_SIZE = 12;
    private static final int TAG_SIZE = 16;
    private static final int INNER_HEADER_SIZE = 9; // timestamp(8) + pad_len(1)
    private static final byte[] HKDF_AEAD_INFO = "shield/aead/v4".getBytes(StandardCharsets.UTF_8);

    private final byte[] key;       // master key
    private final byte[] aeadKey;   // HKDF-derived AEAD key
    private final byte suite;
    private final Long maxAgeMs;    // null = disabled

    // Password-mode fields (null in pre-shared-key mode).
    private final String password;
    private final String service;
    private final int iterations;
    private final byte[] salt;
    private final Map<String, byte[]> keyCache;

    private static final SecureRandom random = new SecureRandom();

    /** Create Shield from password and service name (password mode). */
    public Shield(String password, String service) {
        this(password, service, DEFAULT_MAX_AGE_MS);
    }

    /** Create Shield from password and service name with custom max age. */
    public Shield(String password, String service, Long maxAgeMs) {
        this(password, service, randomBytes(SALT_SIZE), ITERATIONS, maxAgeMs);
    }

    /** Create Shield from password and service name with an explicit salt. */
    public Shield(String password, String service, byte[] salt, int iterations, Long maxAgeMs) {
        if (salt.length != SALT_SIZE) {
            throw new IllegalArgumentException("Salt must be " + SALT_SIZE + " bytes");
        }
        this.password = password;
        this.service = service;
        this.iterations = iterations;
        this.salt = Arrays.copyOf(salt, SALT_SIZE);
        this.suite = SUITE_AES_GCM;
        this.keyCache = new HashMap<>();
        this.key = deriveKey(this.salt);
        this.aeadKey = deriveAeadKey(this.key);
        this.maxAgeMs = maxAgeMs;
    }

    /** Create Shield with pre-shared key (no password/salt). */
    public Shield(byte[] key) {
        this(key, DEFAULT_MAX_AGE_MS);
    }

    /** Create Shield with pre-shared key and custom max age. */
    public Shield(byte[] key, Long maxAgeMs) {
        if (key.length != KEY_SIZE) {
            throw new IllegalArgumentException("Invalid key size");
        }
        this.key = Arrays.copyOf(key, KEY_SIZE);
        this.aeadKey = deriveAeadKey(this.key);
        this.suite = SUITE_AES_GCM;
        this.maxAgeMs = maxAgeMs;
        this.password = null;
        this.service = null;
        this.iterations = 0;
        this.salt = null;
        this.keyCache = null;
    }

    /** Derive the 32-byte master key for a given salt (cached by salt). */
    private byte[] deriveKey(byte[] saltBytes) {
        String saltKey = toHex(saltBytes);
        byte[] cached = keyCache.get(saltKey);
        if (cached != null) {
            return cached;
        }
        byte[] serviceBytes = service.getBytes(StandardCharsets.UTF_8);
        byte[] pbkdf2Salt = new byte[saltBytes.length + serviceBytes.length];
        System.arraycopy(saltBytes, 0, pbkdf2Salt, 0, saltBytes.length);
        System.arraycopy(serviceBytes, 0, pbkdf2Salt, saltBytes.length, serviceBytes.length);
        byte[] derived = pbkdf2(password, pbkdf2Salt, iterations, KEY_SIZE);
        keyCache.put(saltKey, derived);
        return derived;
    }

    /**
     * AEAD key = HKDF-SHA256-Expand(master, "shield/aead/v4", 32). For a 32-byte
     * output this is a single HKDF block: HMAC-SHA256(master, info || 0x01).
     */
    public static byte[] deriveAeadKey(byte[] masterKey) {
        byte[] input = new byte[HKDF_AEAD_INFO.length + 1];
        System.arraycopy(HKDF_AEAD_INFO, 0, input, 0, HKDF_AEAD_INFO.length);
        input[HKDF_AEAD_INFO.length] = 0x01;
        return Arrays.copyOf(hmacSha256(masterKey, input), KEY_SIZE);
    }

    /** Create Shield with hardware fingerprinting (device-bound encryption). */
    public static Shield withFingerprint(String password, String service, Fingerprint.FingerprintMode mode) throws Exception {
        String fingerprint = Fingerprint.collect(mode);
        String combinedPassword = fingerprint.isEmpty() ? password : password + ":" + fingerprint;
        return new Shield(combinedPassword, service);
    }

    /** Encrypt plaintext (password or pre-shared-key mode). */
    public byte[] encrypt(byte[] plaintext) {
        return seal(aeadKey, suite, salt, plaintext);
    }

    /** Decrypt ciphertext, dispatching on the leading authenticated version byte. */
    public byte[] decrypt(byte[] ciphertext) {
        if (ciphertext.length < 1) {
            throw new IllegalArgumentException("Ciphertext too short");
        }

        byte version = ciphertext[0];

        if (version == VERSION_PASSWORD) {
            if (salt == null) {
                throw new SecurityException("Cannot derive key without password");
            }
            int aadLen = 2 + SALT_SIZE;
            if (ciphertext.length < aadLen + AEAD_NONCE_SIZE + TAG_SIZE) {
                throw new IllegalArgumentException("Ciphertext too short");
            }
            byte msgSuite = ciphertext[1];
            byte[] msgSalt = Arrays.copyOfRange(ciphertext, 2, 2 + SALT_SIZE);
            byte[] master = deriveKey(msgSalt);
            byte[] derivedAead = deriveAeadKey(master);
            return openCiphertext(derivedAead, msgSuite, ciphertext, aadLen, maxAgeMs);

        } else if (version == VERSION_KEY) {
            if (ciphertext.length < 2 + AEAD_NONCE_SIZE + TAG_SIZE) {
                throw new IllegalArgumentException("Ciphertext too short");
            }
            return openCiphertext(aeadKey, ciphertext[1], ciphertext, 2, maxAgeMs);

        } else {
            throw new SecurityException("Invalid version byte");
        }
    }

    /**
     * @deprecated For testing/interop only.
     */
    @Deprecated
    byte[] getKey() {
        return Arrays.copyOf(key, KEY_SIZE);
    }

    /** Wipe key material from memory. */
    public void wipe() {
        Arrays.fill(key, (byte) 0);
        Arrays.fill(aeadKey, (byte) 0);
    }

    // ============== Static Methods ==============

    /** Quick encrypt with explicit key (pre-shared-key mode, AES-256-GCM, 0x13). */
    public static byte[] quickEncrypt(byte[] key, byte[] plaintext) {
        if (key.length != KEY_SIZE) {
            throw new IllegalArgumentException("Invalid key size");
        }
        byte[] aeadKey = deriveAeadKey(key);
        return seal(aeadKey, SUITE_AES_GCM, null, plaintext);
    }

    /** Quick decrypt with explicit key (pre-shared-key mode). */
    public static byte[] quickDecrypt(byte[] key, byte[] ciphertext) {
        if (key.length != KEY_SIZE) {
            throw new IllegalArgumentException("Invalid key size");
        }
        if (ciphertext.length < 1) {
            throw new IllegalArgumentException("Ciphertext too short");
        }
        if (ciphertext[0] != VERSION_KEY) {
            throw new SecurityException("Invalid version byte");
        }
        if (ciphertext.length < 2 + AEAD_NONCE_SIZE + TAG_SIZE) {
            throw new IllegalArgumentException("Ciphertext too short");
        }
        byte[] aeadKey = deriveAeadKey(key);
        return openCiphertext(aeadKey, ciphertext[1], ciphertext, 2, null);
    }

    /** Build the AEAD additional data (= wire prefix before the nonce). */
    private static byte[] buildAad(byte suite, byte[] salt) {
        if (salt != null) {
            byte[] aad = new byte[2 + SALT_SIZE];
            aad[0] = VERSION_PASSWORD;
            aad[1] = suite;
            System.arraycopy(salt, 0, aad, 2, SALT_SIZE);
            return aad;
        }
        return new byte[] { VERSION_KEY, suite };
    }

    private static int samplePadLen() {
        int padRange = MAX_PADDING - MIN_PADDING + 1; // 97
        while (true) {
            int val = random.nextInt() & 0xFF;
            if (val < padRange * (256 / padRange)) {
                return (val % padRange) + MIN_PADDING;
            }
        }
    }

    /** Seal with a fresh random nonce, timestamp and padding. */
    private static byte[] seal(byte[] aeadKey, byte suite, byte[] salt, byte[] plaintext) {
        byte[] nonce = new byte[AEAD_NONCE_SIZE];
        random.nextBytes(nonce);
        int padLen = samplePadLen();
        byte[] padding = new byte[padLen];
        random.nextBytes(padding);
        return sealDeterministic(aeadKey, suite, salt, nonce, System.currentTimeMillis(),
                padLen, padding, plaintext);
    }

    /**
     * Deterministic AEAD seal over fully specified inputs (used for conformance
     * vectors and wrapped by the randomized seal).
     */
    public static byte[] sealDeterministic(byte[] aeadKey, byte suite, byte[] salt, byte[] nonce,
            long timestampMs, int padLen, byte[] padding, byte[] plaintext) {
        byte[] aad = buildAad(suite, salt);

        byte[] inner = new byte[INNER_HEADER_SIZE + padding.length + plaintext.length];
        ByteBuffer.wrap(inner, 0, 8).order(ByteOrder.LITTLE_ENDIAN).putLong(timestampMs);
        inner[8] = (byte) padLen;
        System.arraycopy(padding, 0, inner, INNER_HEADER_SIZE, padding.length);
        System.arraycopy(plaintext, 0, inner, INNER_HEADER_SIZE + padding.length, plaintext.length);

        byte[] ctTag = aeadSeal(suite, aeadKey, nonce, aad, inner);

        byte[] result = new byte[aad.length + nonce.length + ctTag.length];
        System.arraycopy(aad, 0, result, 0, aad.length);
        System.arraycopy(nonce, 0, result, aad.length, nonce.length);
        System.arraycopy(ctTag, 0, result, aad.length + nonce.length, ctTag.length);
        return result;
    }

    /**
     * Open an AEAD ciphertext, validate the inner layout and freshness window.
     * aadLen is the offset of the nonce (= len(version||suite||[salt])).
     */
    public static byte[] openCiphertext(byte[] aeadKey, byte suite, byte[] encrypted, int aadLen, Long maxAgeMs) {
        if (encrypted.length < aadLen + AEAD_NONCE_SIZE + TAG_SIZE) {
            throw new IllegalArgumentException("Ciphertext too short");
        }
        byte[] aad = Arrays.copyOfRange(encrypted, 0, aadLen);
        byte[] nonce = Arrays.copyOfRange(encrypted, aadLen, aadLen + AEAD_NONCE_SIZE);
        byte[] ctTag = Arrays.copyOfRange(encrypted, aadLen + AEAD_NONCE_SIZE, encrypted.length);

        byte[] inner = aeadOpen(suite, aeadKey, nonce, aad, ctTag);

        if (inner.length < INNER_HEADER_SIZE) {
            throw new SecurityException("Authentication failed");
        }
        byte[] tsBytes = Arrays.copyOfRange(inner, 0, 8);
        long timestampMs = ByteBuffer.wrap(tsBytes).order(ByteOrder.LITTLE_ENDIAN).getLong();
        int padLen = inner[8] & 0xFF;
        if (padLen < MIN_PADDING || padLen > MAX_PADDING) {
            throw new SecurityException("Authentication failed");
        }
        int dataStart = INNER_HEADER_SIZE + padLen;
        if (inner.length < dataStart) {
            throw new IllegalArgumentException("Ciphertext too short");
        }

        if (maxAgeMs != null) {
            long nowMs = System.currentTimeMillis();
            long age = nowMs - timestampMs;
            if (timestampMs > nowMs + 5000 || age > maxAgeMs) {
                throw new SecurityException("Authentication failed");
            }
        }

        return Arrays.copyOfRange(inner, dataStart, inner.length);
    }

    /** AEAD seal: returns ciphertext||tag. */
    private static byte[] aeadSeal(byte suite, byte[] key, byte[] nonce, byte[] aad, byte[] plaintext) {
        try {
            Cipher cipher = aeadCipher(suite, Cipher.ENCRYPT_MODE, key, nonce);
            cipher.updateAAD(aad);
            return cipher.doFinal(plaintext);
        } catch (GeneralSecurityException e) {
            throw new SecurityException("AEAD seal failed", e);
        }
    }

    /** AEAD open: returns plaintext, throws SecurityException on auth failure. */
    private static byte[] aeadOpen(byte suite, byte[] key, byte[] nonce, byte[] aad, byte[] ctTag) {
        try {
            Cipher cipher = aeadCipher(suite, Cipher.DECRYPT_MODE, key, nonce);
            cipher.updateAAD(aad);
            return cipher.doFinal(ctTag);
        } catch (GeneralSecurityException e) {
            throw new SecurityException("Authentication failed", e);
        }
    }

    private static Cipher aeadCipher(byte suite, int mode, byte[] key, byte[] nonce) throws GeneralSecurityException {
        Cipher cipher;
        if (suite == SUITE_AES_GCM) {
            cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_SIZE * 8, nonce));
        } else if (suite == SUITE_CHACHA20_POLY1305) {
            cipher = Cipher.getInstance("ChaCha20-Poly1305");
            cipher.init(mode, new SecretKeySpec(key, "ChaCha20"), new IvParameterSpec(nonce));
        } else {
            throw new GeneralSecurityException("Unknown cipher suite");
        }
        return cipher;
    }

    // ============== Crypto Utilities ==============

    private static String toHex(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }

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
