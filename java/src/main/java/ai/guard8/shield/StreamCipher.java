package ai.guard8.shield;

import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * StreamCipher - Streaming encryption for large files.
 *
 * Processes data in chunks with constant memory usage.
 * Each chunk is independently authenticated, allowing:
 * - Early detection of tampering
 * - Constant memory regardless of file size
 * - Potential for parallel processing
 */
public class StreamCipher {
    public static final int DEFAULT_CHUNK_SIZE = 64 * 1024; // 64KB
    private static final int NONCE_SIZE = 16;
    private static final int MAC_SIZE = 16;
    private static final int HEADER_SIZE = 20; // 4 chunk_size + 16 salt

    private final byte[] key;
    private final int chunkSize;
    private static final SecureRandom random = new SecureRandom();

    /**
     * Create StreamCipher with encryption key.
     *
     * @param key 32-byte symmetric key
     * @param chunkSize Size of each chunk (default: 64KB)
     */
    public StreamCipher(byte[] key, int chunkSize) {
        if (key.length != 32) {
            throw new IllegalArgumentException("Key must be 32 bytes");
        }
        this.key = Arrays.copyOf(key, 32);
        this.chunkSize = chunkSize;
    }

    /**
     * Create StreamCipher with encryption key and default chunk size.
     */
    public StreamCipher(byte[] key) {
        this(key, DEFAULT_CHUNK_SIZE);
    }

    /**
     * Create StreamCipher from password.
     *
     * @param password User's password
     * @param salt Salt for key derivation
     * @param chunkSize Size of each chunk
     * @return StreamCipher instance
     */
    public static StreamCipher fromPassword(String password, byte[] salt, int chunkSize) {
        byte[] key = deriveKey(password, salt);
        return new StreamCipher(key, chunkSize);
    }

    /**
     * Create StreamCipher from password with default chunk size.
     */
    public static StreamCipher fromPassword(String password, byte[] salt) {
        return fromPassword(password, salt, DEFAULT_CHUNK_SIZE);
    }

    /**
     * Encrypt data in memory.
     *
     * @param data Data to encrypt
     * @return Encrypted data
     */
    public byte[] encrypt(byte[] data) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        // Header: chunk_size(4) || stream_salt(16)
        byte[] streamSalt = new byte[16];
        random.nextBytes(streamSalt);

        ByteBuffer header = ByteBuffer.allocate(HEADER_SIZE).order(ByteOrder.LITTLE_ENDIAN);
        header.putInt(chunkSize);
        header.put(streamSalt);
        out.write(header.array(), 0, HEADER_SIZE);

        int offset = 0;
        int chunkNum = 0;

        while (offset < data.length) {
            int end = Math.min(offset + chunkSize, data.length);
            byte[] chunk = Arrays.copyOfRange(data, offset, end);

            // Derive per-chunk key
            byte[] chunkKey = deriveChunkKey(key, streamSalt, chunkNum);

            // Encrypt chunk
            byte[] encrypted = encryptBlock(chunkKey, chunk);

            // Prepend length
            ByteBuffer lenBuf = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN);
            lenBuf.putInt(encrypted.length);
            out.write(lenBuf.array(), 0, 4);
            out.write(encrypted, 0, encrypted.length);

            offset = end;
            chunkNum++;
        }

        // End marker
        ByteBuffer endMarker = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN);
        endMarker.putInt(0);
        out.write(endMarker.array(), 0, 4);

        return out.toByteArray();
    }

    /**
     * Decrypt data in memory.
     *
     * @param encrypted Encrypted data
     * @return Decrypted data
     * @throws SecurityException If authentication fails
     */
    public byte[] decrypt(byte[] encrypted) {
        if (encrypted.length < HEADER_SIZE + 4) {
            throw new IllegalArgumentException("Encrypted data too short");
        }

        ByteBuffer buf = ByteBuffer.wrap(encrypted).order(ByteOrder.LITTLE_ENDIAN);

        // Read header
        int storedChunkSize = buf.getInt();
        byte[] streamSalt = new byte[16];
        buf.get(streamSalt);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int chunkNum = 0;

        while (buf.remaining() >= 4) {
            int encLen = buf.getInt();
            if (encLen == 0) {
                break; // End marker
            }

            if (buf.remaining() < encLen) {
                throw new IllegalArgumentException("Incomplete chunk");
            }

            byte[] encryptedChunk = new byte[encLen];
            buf.get(encryptedChunk);

            // Derive per-chunk key
            byte[] chunkKey = deriveChunkKey(key, streamSalt, chunkNum);

            // Decrypt chunk
            byte[] decrypted = decryptBlock(chunkKey, encryptedChunk);
            if (decrypted == null) {
                throw new SecurityException("Chunk " + chunkNum + " authentication failed");
            }

            out.write(decrypted, 0, decrypted.length);
            chunkNum++;
        }

        return out.toByteArray();
    }

    /**
     * Encrypt a file.
     *
     * @param inPath Path to input file
     * @param outPath Path to output file
     * @throws IOException If file operations fail
     */
    public void encryptFile(String inPath, String outPath) throws IOException {
        try (FileInputStream in = new FileInputStream(inPath);
             FileOutputStream out = new FileOutputStream(outPath)) {

            // Header
            byte[] streamSalt = new byte[16];
            random.nextBytes(streamSalt);

            ByteBuffer header = ByteBuffer.allocate(HEADER_SIZE).order(ByteOrder.LITTLE_ENDIAN);
            header.putInt(chunkSize);
            header.put(streamSalt);
            out.write(header.array());

            byte[] buffer = new byte[chunkSize];
            int chunkNum = 0;
            int bytesRead;

            while ((bytesRead = in.read(buffer)) > 0) {
                byte[] chunk = bytesRead == buffer.length ? buffer : Arrays.copyOf(buffer, bytesRead);

                byte[] chunkKey = deriveChunkKey(key, streamSalt, chunkNum);
                byte[] encrypted = encryptBlock(chunkKey, chunk);

                ByteBuffer lenBuf = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN);
                lenBuf.putInt(encrypted.length);
                out.write(lenBuf.array());
                out.write(encrypted);

                chunkNum++;
            }

            // End marker
            ByteBuffer endMarker = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN);
            endMarker.putInt(0);
            out.write(endMarker.array());
        }
    }

    /**
     * Decrypt a file.
     *
     * @param inPath Path to encrypted file
     * @param outPath Path to output file
     * @throws IOException If file operations fail
     * @throws SecurityException If authentication fails
     */
    public void decryptFile(String inPath, String outPath) throws IOException {
        try (FileInputStream in = new FileInputStream(inPath);
             FileOutputStream out = new FileOutputStream(outPath)) {

            // Read header
            byte[] headerBytes = new byte[HEADER_SIZE];
            if (in.read(headerBytes) != HEADER_SIZE) {
                throw new IOException("Incomplete header");
            }

            ByteBuffer header = ByteBuffer.wrap(headerBytes).order(ByteOrder.LITTLE_ENDIAN);
            int storedChunkSize = header.getInt();
            byte[] streamSalt = new byte[16];
            header.get(streamSalt);

            byte[] lenBytes = new byte[4];
            int chunkNum = 0;

            while (in.read(lenBytes) == 4) {
                int encLen = ByteBuffer.wrap(lenBytes).order(ByteOrder.LITTLE_ENDIAN).getInt();
                if (encLen == 0) {
                    break;
                }

                byte[] encrypted = new byte[encLen];
                if (in.read(encrypted) != encLen) {
                    throw new IOException("Incomplete chunk");
                }

                byte[] chunkKey = deriveChunkKey(key, streamSalt, chunkNum);
                byte[] decrypted = decryptBlock(chunkKey, encrypted);
                if (decrypted == null) {
                    throw new SecurityException("Chunk " + chunkNum + " authentication failed");
                }

                out.write(decrypted);
                chunkNum++;
            }
        }
    }

    // ============== Helper Methods ==============

    private static byte[] deriveKey(String password, byte[] salt) {
        try {
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 100000, 256);
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return skf.generateSecret(spec).getEncoded();
        } catch (Exception e) {
            throw new RuntimeException("PBKDF2 not available", e);
        }
    }

    private static byte[] deriveChunkKey(byte[] key, byte[] salt, long chunkNum) {
        ByteBuffer buf = ByteBuffer.allocate(32 + 16 + 8).order(ByteOrder.LITTLE_ENDIAN);
        buf.put(key);
        buf.put(salt);
        buf.putLong(chunkNum);
        return sha256(buf.array());
    }

    private static byte[] encryptBlock(byte[] key, byte[] data) {
        byte[] nonce = new byte[NONCE_SIZE];
        random.nextBytes(nonce);

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
            ByteBuffer buf = ByteBuffer.allocate(32 + 16 + 4).order(ByteOrder.LITTLE_ENDIAN);
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
}
