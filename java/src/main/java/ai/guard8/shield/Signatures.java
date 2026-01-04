package ai.guard8.shield;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

/**
 * Digital signature implementations.
 */
public class Signatures {

    /**
     * SymmetricSignature provides HMAC-based signatures.
     */
    public static class SymmetricSignature {
        private final byte[] signingKey;
        private final byte[] verificationKey;

        public SymmetricSignature(byte[] signingKey) {
            if (signingKey.length != Shield.KEY_SIZE) {
                throw new IllegalArgumentException("Invalid key size");
            }
            this.signingKey = Arrays.copyOf(signingKey, Shield.KEY_SIZE);

            // Derive verification key
            byte[] data = new byte[7 + Shield.KEY_SIZE];
            System.arraycopy("verify:".getBytes(), 0, data, 0, 7);
            System.arraycopy(signingKey, 0, data, 7, Shield.KEY_SIZE);
            this.verificationKey = Shield.sha256(data);
        }

        public static SymmetricSignature generate() {
            return new SymmetricSignature(Shield.randomBytes(Shield.KEY_SIZE));
        }

        public static SymmetricSignature fromPassword(String password, String identity) {
            byte[] salt = Shield.sha256(("sign:" + identity).getBytes());
            byte[] key = Shield.pbkdf2(password, salt, Shield.ITERATIONS, Shield.KEY_SIZE);
            return new SymmetricSignature(key);
        }

        public byte[] sign(byte[] message) {
            return sign(message, false);
        }

        public byte[] sign(byte[] message, boolean includeTimestamp) {
            if (includeTimestamp) {
                long timestamp = System.currentTimeMillis() / 1000;
                byte[] tsBytes = new byte[8];
                ByteBuffer.wrap(tsBytes).order(ByteOrder.LITTLE_ENDIAN).putLong(timestamp);

                byte[] sigData = new byte[8 + message.length];
                System.arraycopy(tsBytes, 0, sigData, 0, 8);
                System.arraycopy(message, 0, sigData, 8, message.length);

                byte[] sig = Shield.hmacSha256(signingKey, sigData);

                byte[] result = new byte[8 + 32];
                System.arraycopy(tsBytes, 0, result, 0, 8);
                System.arraycopy(sig, 0, result, 8, 32);
                return result;
            }

            return Shield.hmacSha256(signingKey, message);
        }

        public boolean verify(byte[] message, byte[] signature, byte[] verificationKey, long maxAge) {
            if (!Shield.constantTimeEquals(verificationKey, this.verificationKey)) {
                return false;
            }

            if (signature.length == 40) {
                // Timestamped signature
                long timestamp = ByteBuffer.wrap(signature, 0, 8)
                        .order(ByteOrder.LITTLE_ENDIAN).getLong();

                if (maxAge > 0) {
                    long now = System.currentTimeMillis() / 1000;
                    long diff = Math.abs(now - timestamp);
                    if (diff > maxAge) {
                        return false;
                    }
                }

                byte[] sigData = new byte[8 + message.length];
                System.arraycopy(signature, 0, sigData, 0, 8);
                System.arraycopy(message, 0, sigData, 8, message.length);

                byte[] expected = Shield.hmacSha256(signingKey, sigData);
                return Shield.constantTimeEquals(Arrays.copyOfRange(signature, 8, 40), expected);
            }

            if (signature.length == 32) {
                byte[] expected = Shield.hmacSha256(signingKey, message);
                return Shield.constantTimeEquals(signature, expected);
            }

            return false;
        }

        public byte[] getVerificationKey() {
            return Arrays.copyOf(verificationKey, verificationKey.length);
        }

        public String fingerprint() {
            byte[] hash = Shield.sha256(verificationKey);
            return bytesToHex(Arrays.copyOf(hash, 8));
        }

        public void wipe() {
            Arrays.fill(signingKey, (byte) 0);
            Arrays.fill(verificationKey, (byte) 0);
        }
    }

    /**
     * LamportSignature provides one-time post-quantum signatures.
     */
    public static class LamportSignature {
        private final byte[][][] privateKey; // [256][2][32]
        private final byte[] publicKey;      // [256 * 64]
        private boolean used;

        private LamportSignature() {
            this.privateKey = new byte[256][2][Shield.KEY_SIZE];
            this.publicKey = new byte[256 * 64];
            this.used = false;
        }

        public static LamportSignature generate() {
            LamportSignature ls = new LamportSignature();

            for (int i = 0; i < 256; i++) {
                ls.privateKey[i][0] = Shield.randomBytes(Shield.KEY_SIZE);
                ls.privateKey[i][1] = Shield.randomBytes(Shield.KEY_SIZE);

                byte[] h0 = Shield.sha256(ls.privateKey[i][0]);
                byte[] h1 = Shield.sha256(ls.privateKey[i][1]);

                System.arraycopy(h0, 0, ls.publicKey, i * 64, 32);
                System.arraycopy(h1, 0, ls.publicKey, i * 64 + 32, 32);
            }

            return ls;
        }

        public byte[] sign(byte[] message) {
            if (used) {
                throw new IllegalStateException("Lamport key already used");
            }
            used = true;

            byte[] msgHash = Shield.sha256(message);
            byte[] signature = new byte[256 * 32];

            for (int i = 0; i < 256; i++) {
                int byteIdx = i / 8;
                int bitIdx = i % 8;
                int bit = (msgHash[byteIdx] >> bitIdx) & 1;

                System.arraycopy(privateKey[i][bit], 0, signature, i * 32, 32);
            }

            return signature;
        }

        public static boolean verify(byte[] message, byte[] signature, byte[] publicKey) {
            if (signature.length != 256 * 32 || publicKey.length != 256 * 64) {
                return false;
            }

            byte[] msgHash = Shield.sha256(message);

            for (int i = 0; i < 256; i++) {
                int byteIdx = i / 8;
                int bitIdx = i % 8;
                int bit = (msgHash[byteIdx] >> bitIdx) & 1;

                byte[] revealed = Arrays.copyOfRange(signature, i * 32, (i + 1) * 32);
                byte[] hashed = Shield.sha256(revealed);

                byte[] expected;
                if (bit == 1) {
                    expected = Arrays.copyOfRange(publicKey, i * 64 + 32, i * 64 + 64);
                } else {
                    expected = Arrays.copyOfRange(publicKey, i * 64, i * 64 + 32);
                }

                if (!Shield.constantTimeEquals(hashed, expected)) {
                    return false;
                }
            }

            return true;
        }

        public boolean isUsed() {
            return used;
        }

        public byte[] getPublicKey() {
            return Arrays.copyOf(publicKey, publicKey.length);
        }

        public String fingerprint() {
            byte[] hash = Shield.sha256(publicKey);
            return bytesToHex(Arrays.copyOf(hash, 8));
        }

        public void wipe() {
            for (int i = 0; i < 256; i++) {
                Arrays.fill(privateKey[i][0], (byte) 0);
                Arrays.fill(privateKey[i][1], (byte) 0);
            }
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
