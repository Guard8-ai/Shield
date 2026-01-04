package ai.guard8.shield;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * RatchetSession provides forward secrecy through key ratcheting.
 */
public class RatchetSession {
    private byte[] sendKey;
    private byte[] recvKey;
    private long sendCounter;
    private long recvCounter;
    private final boolean isInitiator;

    public RatchetSession(byte[] rootKey, boolean isInitiator) {
        if (rootKey.length != Shield.KEY_SIZE) {
            throw new IllegalArgumentException("Invalid key size");
        }
        this.isInitiator = isInitiator;
        this.sendCounter = 0;
        this.recvCounter = 0;

        if (isInitiator) {
            this.sendKey = deriveChainKey(rootKey, "init_send");
            this.recvKey = deriveChainKey(rootKey, "init_recv");
        } else {
            this.sendKey = deriveChainKey(rootKey, "init_recv");
            this.recvKey = deriveChainKey(rootKey, "init_send");
        }
    }

    public byte[] encrypt(byte[] plaintext) {
        byte[] messageKey = deriveChainKey(sendKey, "message");
        byte[] nonce = Shield.randomBytes(Shield.NONCE_SIZE);

        // Generate keystream and XOR
        byte[] keystream = generateKeystream(messageKey, nonce, plaintext.length);
        byte[] ciphertext = new byte[plaintext.length];
        for (int i = 0; i < plaintext.length; i++) {
            ciphertext[i] = (byte) (plaintext[i] ^ keystream[i]);
        }

        // Counter bytes
        byte[] counterBytes = new byte[8];
        ByteBuffer.wrap(counterBytes).order(ByteOrder.LITTLE_ENDIAN).putLong(sendCounter);

        // MAC over counter || nonce || ciphertext
        byte[] macData = new byte[8 + Shield.NONCE_SIZE + ciphertext.length];
        System.arraycopy(counterBytes, 0, macData, 0, 8);
        System.arraycopy(nonce, 0, macData, 8, Shield.NONCE_SIZE);
        System.arraycopy(ciphertext, 0, macData, 8 + Shield.NONCE_SIZE, ciphertext.length);
        byte[] mac = Shield.hmacSha256(messageKey, macData);

        // Ratchet
        sendKey = deriveChainKey(sendKey, "ratchet");
        sendCounter++;

        // Format: counter(8) || nonce(16) || ciphertext || mac(16)
        byte[] result = new byte[8 + Shield.NONCE_SIZE + ciphertext.length + Shield.MAC_SIZE];
        System.arraycopy(counterBytes, 0, result, 0, 8);
        System.arraycopy(nonce, 0, result, 8, Shield.NONCE_SIZE);
        System.arraycopy(ciphertext, 0, result, 8 + Shield.NONCE_SIZE, ciphertext.length);
        System.arraycopy(mac, 0, result, 8 + Shield.NONCE_SIZE + ciphertext.length, Shield.MAC_SIZE);

        Shield.secureWipe(messageKey);
        return result;
    }

    public byte[] decrypt(byte[] encrypted) {
        if (encrypted.length < 8 + Shield.NONCE_SIZE + Shield.MAC_SIZE) {
            throw new IllegalArgumentException("Ciphertext too short");
        }

        // Parse
        long counter = ByteBuffer.wrap(encrypted, 0, 8).order(ByteOrder.LITTLE_ENDIAN).getLong();
        byte[] nonce = Arrays.copyOfRange(encrypted, 8, 8 + Shield.NONCE_SIZE);
        byte[] ciphertext = Arrays.copyOfRange(encrypted, 8 + Shield.NONCE_SIZE,
                                                encrypted.length - Shield.MAC_SIZE);
        byte[] receivedMac = Arrays.copyOfRange(encrypted, encrypted.length - Shield.MAC_SIZE,
                                                 encrypted.length);

        // Check counter
        if (counter < recvCounter) {
            throw new SecurityException("Replay detected");
        }
        if (counter > recvCounter) {
            throw new SecurityException("Out of order message");
        }

        byte[] messageKey = deriveChainKey(recvKey, "message");

        // Verify MAC
        byte[] macData = new byte[8 + Shield.NONCE_SIZE + ciphertext.length];
        System.arraycopy(encrypted, 0, macData, 0, 8);
        System.arraycopy(nonce, 0, macData, 8, Shield.NONCE_SIZE);
        System.arraycopy(ciphertext, 0, macData, 8 + Shield.NONCE_SIZE, ciphertext.length);
        byte[] expectedMac = Shield.hmacSha256(messageKey, macData);

        if (!Shield.constantTimeEquals(receivedMac, Arrays.copyOf(expectedMac, Shield.MAC_SIZE))) {
            Shield.secureWipe(messageKey);
            throw new SecurityException("Authentication failed");
        }

        // Decrypt
        byte[] keystream = generateKeystream(messageKey, nonce, ciphertext.length);
        byte[] plaintext = new byte[ciphertext.length];
        for (int i = 0; i < ciphertext.length; i++) {
            plaintext[i] = (byte) (ciphertext[i] ^ keystream[i]);
        }

        // Ratchet
        recvKey = deriveChainKey(recvKey, "ratchet");
        recvCounter++;

        Shield.secureWipe(messageKey);
        return plaintext;
    }

    public long getSendCounter() {
        return sendCounter;
    }

    public long getRecvCounter() {
        return recvCounter;
    }

    public void wipe() {
        Shield.secureWipe(sendKey);
        Shield.secureWipe(recvKey);
    }

    private static byte[] deriveChainKey(byte[] key, String info) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(key);
            md.update(info.getBytes());
            return md.digest();
        } catch (Exception e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    private static byte[] generateKeystream(byte[] key, byte[] nonce, int length) {
        int numBlocks = (length + 31) / 32;
        byte[] keystream = new byte[numBlocks * 32];

        for (int i = 0; i < numBlocks; i++) {
            byte[] block = new byte[Shield.KEY_SIZE + Shield.NONCE_SIZE + 4];
            System.arraycopy(key, 0, block, 0, Shield.KEY_SIZE);
            System.arraycopy(nonce, 0, block, Shield.KEY_SIZE, Shield.NONCE_SIZE);
            ByteBuffer.wrap(block, Shield.KEY_SIZE + Shield.NONCE_SIZE, 4)
                    .order(ByteOrder.LITTLE_ENDIAN)
                    .putInt(i);

            byte[] hash = Shield.sha256(block);
            System.arraycopy(hash, 0, keystream, i * 32, 32);
        }

        return Arrays.copyOf(keystream, length);
    }
}
