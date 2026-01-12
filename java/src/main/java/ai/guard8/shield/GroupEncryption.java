package ai.guard8.shield;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.*;

/**
 * GroupEncryption - Multi-recipient encryption.
 *
 * Encrypt once for multiple recipients, each can decrypt with their own key.
 * Uses a group key for message encryption, then encrypts the group key
 * separately for each member.
 */
public class GroupEncryption {
    private static final int NONCE_SIZE = 16;
    private static final int MAC_SIZE = 16;
    private static final SecureRandom random = new SecureRandom();

    private byte[] groupKey;
    private final Map<String, byte[]> members = new HashMap<>();

    /**
     * Create group encryption with generated group key.
     */
    public GroupEncryption() {
        this.groupKey = randomBytes(32);
    }

    /**
     * Create group encryption with specified group key.
     */
    public GroupEncryption(byte[] groupKey) {
        if (groupKey.length != 32) {
            throw new IllegalArgumentException("Group key must be 32 bytes");
        }
        this.groupKey = Arrays.copyOf(groupKey, 32);
    }

    /**
     * Add a member to the group.
     *
     * @param memberId Unique member identifier
     * @param sharedKey Pre-shared key with this member (32 bytes)
     */
    public void addMember(String memberId, byte[] sharedKey) {
        if (sharedKey.length != 32) {
            throw new IllegalArgumentException("Shared key must be 32 bytes");
        }
        members.put(memberId, Arrays.copyOf(sharedKey, 32));
    }

    /**
     * Remove a member from the group.
     * Note: After removing a member, you should rotate the group key.
     */
    public boolean removeMember(String memberId) {
        return members.remove(memberId) != null;
    }

    /**
     * Get list of member IDs.
     */
    public List<String> getMembers() {
        return new ArrayList<>(members.keySet());
    }

    /**
     * Encrypt for all group members.
     *
     * @param plaintext Message to encrypt
     * @return Map containing ciphertext and per-member encrypted keys
     */
    public Map<String, Object> encrypt(byte[] plaintext) {
        // Encrypt message with group key
        byte[] ciphertext = encryptBlock(groupKey, plaintext);

        // Encrypt group key for each member
        Map<String, String> encryptedKeys = new HashMap<>();
        for (Map.Entry<String, byte[]> entry : members.entrySet()) {
            byte[] encKey = encryptBlock(entry.getValue(), groupKey);
            encryptedKeys.put(entry.getKey(), Base64.getEncoder().encodeToString(encKey));
        }

        Map<String, Object> result = new HashMap<>();
        result.put("version", 1);
        result.put("ciphertext", Base64.getEncoder().encodeToString(ciphertext));
        result.put("keys", encryptedKeys);
        return result;
    }

    /**
     * Decrypt as a group member.
     *
     * @param encrypted Encrypted message from encrypt()
     * @param memberId Your member ID
     * @param memberKey Your shared key
     * @return Decrypted message, or null if decryption fails
     */
    @SuppressWarnings("unchecked")
    public static byte[] decrypt(Map<String, Object> encrypted, String memberId, byte[] memberKey) {
        Map<String, String> keys = (Map<String, String>) encrypted.get("keys");
        if (keys == null || !keys.containsKey(memberId)) {
            return null;
        }

        // Decrypt group key
        byte[] encryptedGroupKey = Base64.getDecoder().decode(keys.get(memberId));
        byte[] groupKeyDecrypted = decryptBlock(memberKey, encryptedGroupKey);
        if (groupKeyDecrypted == null) {
            return null;
        }

        // Decrypt message
        byte[] ciphertext = Base64.getDecoder().decode((String) encrypted.get("ciphertext"));
        return decryptBlock(groupKeyDecrypted, ciphertext);
    }

    /**
     * Rotate the group key.
     *
     * @return The old group key
     */
    public byte[] rotateKey() {
        byte[] oldKey = groupKey;
        groupKey = randomBytes(32);
        return oldKey;
    }

    // ============== Helper Methods ==============

    private static byte[] encryptBlock(byte[] key, byte[] data) {
        byte[] nonce = randomBytes(NONCE_SIZE);
        byte[] keystream = generateKeystream(key, nonce, data.length);
        byte[] ciphertext = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            ciphertext[i] = (byte) (data[i] ^ keystream[i]);
        }

        byte[] macData = new byte[NONCE_SIZE + ciphertext.length];
        System.arraycopy(nonce, 0, macData, 0, NONCE_SIZE);
        System.arraycopy(ciphertext, 0, macData, NONCE_SIZE, ciphertext.length);
        byte[] mac = hmacSha256(key, macData);

        byte[] result = new byte[NONCE_SIZE + ciphertext.length + MAC_SIZE];
        System.arraycopy(nonce, 0, result, 0, NONCE_SIZE);
        System.arraycopy(ciphertext, 0, result, NONCE_SIZE, ciphertext.length);
        System.arraycopy(mac, 0, result, NONCE_SIZE + ciphertext.length, MAC_SIZE);

        return result;
    }

    private static byte[] decryptBlock(byte[] key, byte[] encrypted) {
        if (encrypted.length < NONCE_SIZE + MAC_SIZE) {
            return null;
        }

        byte[] nonce = Arrays.copyOfRange(encrypted, 0, NONCE_SIZE);
        byte[] ciphertext = Arrays.copyOfRange(encrypted, NONCE_SIZE, encrypted.length - MAC_SIZE);
        byte[] receivedMac = Arrays.copyOfRange(encrypted, encrypted.length - MAC_SIZE, encrypted.length);

        byte[] macData = new byte[NONCE_SIZE + ciphertext.length];
        System.arraycopy(nonce, 0, macData, 0, NONCE_SIZE);
        System.arraycopy(ciphertext, 0, macData, NONCE_SIZE, ciphertext.length);
        byte[] expectedMac = hmacSha256(key, macData);

        if (!constantTimeEquals(receivedMac, Arrays.copyOf(expectedMac, MAC_SIZE))) {
            return null;
        }

        byte[] keystream = generateKeystream(key, nonce, ciphertext.length);
        byte[] decrypted = new byte[ciphertext.length];
        for (int i = 0; i < ciphertext.length; i++) {
            decrypted[i] = (byte) (ciphertext[i] ^ keystream[i]);
        }

        return decrypted;
    }

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
