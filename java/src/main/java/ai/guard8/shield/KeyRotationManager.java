package ai.guard8.shield;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.*;

/**
 * KeyRotationManager - Version-based key management.
 *
 * Supports seamless key rotation without breaking existing encrypted data.
 * Each ciphertext is tagged with the key version used.
 *
 * Ciphertext format: version(4) || nonce(16) || ciphertext || mac(16)
 */
public class KeyRotationManager {
    private static final int NONCE_SIZE = 16;
    private static final int MAC_SIZE = 16;
    private static final int MIN_CIPHERTEXT_SIZE = 4 + NONCE_SIZE + MAC_SIZE;
    private static final SecureRandom random = new SecureRandom();

    private final Map<Integer, byte[]> keys = new HashMap<>();
    private int currentVersion;

    /**
     * Create with initial key.
     */
    public KeyRotationManager(byte[] key, int version) {
        if (key.length != 32) {
            throw new IllegalArgumentException("Key must be 32 bytes");
        }
        keys.put(version, Arrays.copyOf(key, 32));
        currentVersion = version;
    }

    /**
     * Create with initial key (version 1).
     */
    public KeyRotationManager(byte[] key) {
        this(key, 1);
    }

    /**
     * Get current key version.
     */
    public int getCurrentVersion() {
        return currentVersion;
    }

    /**
     * Get all available versions.
     */
    public List<Integer> getVersions() {
        List<Integer> versions = new ArrayList<>(keys.keySet());
        Collections.sort(versions);
        return versions;
    }

    /**
     * Add historical key for decryption.
     */
    public void addKey(byte[] key, int version) {
        if (keys.containsKey(version)) {
            throw new IllegalArgumentException("Version " + version + " already exists");
        }
        keys.put(version, Arrays.copyOf(key, 32));
    }

    /**
     * Rotate to new key.
     */
    public int rotate(byte[] newKey) {
        return rotate(newKey, currentVersion + 1);
    }

    /**
     * Rotate to new key with specific version.
     */
    public int rotate(byte[] newKey, int newVersion) {
        if (newVersion <= currentVersion) {
            throw new IllegalArgumentException("New version must be greater than current");
        }
        keys.put(newVersion, Arrays.copyOf(newKey, 32));
        currentVersion = newVersion;
        return newVersion;
    }

    /**
     * Encrypt with current key (includes version tag).
     */
    public byte[] encrypt(byte[] plaintext) {
        byte[] key = keys.get(currentVersion);
        byte[] nonce = randomBytes(NONCE_SIZE);

        // Generate keystream and encrypt
        byte[] keystream = generateKeystream(key, nonce, plaintext.length);
        byte[] ciphertext = new byte[plaintext.length];
        for (int i = 0; i < plaintext.length; i++) {
            ciphertext[i] = (byte) (plaintext[i] ^ keystream[i]);
        }

        // Version bytes
        ByteBuffer versionBuf = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN);
        versionBuf.putInt(currentVersion);
        byte[] versionBytes = versionBuf.array();

        // HMAC authenticate (includes version)
        byte[] macData = new byte[4 + NONCE_SIZE + ciphertext.length];
        System.arraycopy(versionBytes, 0, macData, 0, 4);
        System.arraycopy(nonce, 0, macData, 4, NONCE_SIZE);
        System.arraycopy(ciphertext, 0, macData, 4 + NONCE_SIZE, ciphertext.length);
        byte[] mac = hmacSha256(key, macData);

        // Result: version || nonce || ciphertext || mac
        byte[] result = new byte[4 + NONCE_SIZE + ciphertext.length + MAC_SIZE];
        System.arraycopy(versionBytes, 0, result, 0, 4);
        System.arraycopy(nonce, 0, result, 4, NONCE_SIZE);
        System.arraycopy(ciphertext, 0, result, 4 + NONCE_SIZE, ciphertext.length);
        System.arraycopy(mac, 0, result, result.length - MAC_SIZE, MAC_SIZE);

        return result;
    }

    /**
     * Decrypt with appropriate key version.
     */
    public byte[] decrypt(byte[] encrypted) {
        if (encrypted.length < MIN_CIPHERTEXT_SIZE) {
            throw new IllegalArgumentException("Ciphertext too short");
        }

        // Parse version
        int version = ByteBuffer.wrap(encrypted, 0, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
        byte[] nonce = Arrays.copyOfRange(encrypted, 4, 4 + NONCE_SIZE);
        byte[] ciphertext = Arrays.copyOfRange(encrypted, 4 + NONCE_SIZE, encrypted.length - MAC_SIZE);
        byte[] receivedMac = Arrays.copyOfRange(encrypted, encrypted.length - MAC_SIZE, encrypted.length);

        if (!keys.containsKey(version)) {
            throw new IllegalArgumentException("Unknown key version: " + version);
        }

        byte[] key = keys.get(version);

        // Verify MAC
        byte[] macData = Arrays.copyOfRange(encrypted, 0, encrypted.length - MAC_SIZE);
        byte[] expectedMac = hmacSha256(key, macData);

        if (!constantTimeEquals(receivedMac, Arrays.copyOf(expectedMac, MAC_SIZE))) {
            throw new SecurityException("Authentication failed");
        }

        // Decrypt
        byte[] keystream = generateKeystream(key, nonce, ciphertext.length);
        byte[] plaintext = new byte[ciphertext.length];
        for (int i = 0; i < ciphertext.length; i++) {
            plaintext[i] = (byte) (ciphertext[i] ^ keystream[i]);
        }

        return plaintext;
    }

    /**
     * Re-encrypt data with current key.
     */
    public byte[] reEncrypt(byte[] encrypted) {
        byte[] plaintext = decrypt(encrypted);
        return encrypt(plaintext);
    }

    /**
     * Remove old keys, keeping only recent versions.
     */
    public List<Integer> pruneOldKeys(int keepVersions) {
        if (keepVersions < 1) {
            throw new IllegalArgumentException("Must keep at least 1 version");
        }

        List<Integer> versions = new ArrayList<>(keys.keySet());
        versions.sort(Collections.reverseOrder());

        Set<Integer> toKeep = new HashSet<>(versions.subList(0, Math.min(keepVersions, versions.size())));
        toKeep.add(currentVersion);

        List<Integer> pruned = new ArrayList<>();
        for (Integer v : new ArrayList<>(keys.keySet())) {
            if (!toKeep.contains(v)) {
                keys.remove(v);
                pruned.add(v);
            }
        }

        return pruned;
    }

    // ============== Helper Methods ==============

    private static byte[] generateKeystream(byte[] key, byte[] nonce, int length) {
        int numBlocks = (length + 31) / 32;
        byte[] keystream = new byte[numBlocks * 32];

        for (int i = 0; i < numBlocks; i++) {
            ByteBuffer buf = ByteBuffer.allocate(32 + NONCE_SIZE + 4).order(ByteOrder.LITTLE_ENDIAN);
            buf.put(key);
            buf.put(nonce);
            buf.putInt(i);
            byte[] hash = sha256(buf.array());
            System.arraycopy(hash, 0, keystream, i * 32, 32);
        }

        return Arrays.copyOf(keystream, length);
    }

    private static byte[] sha256(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(data);
        } catch (Exception e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    private static byte[] hmacSha256(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException("HMAC-SHA256 not available", e);
        }
    }

    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a.length != b.length) return false;
        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }

    private static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return bytes;
    }
}
