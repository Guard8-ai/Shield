package ai.guard8.shield;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.*;

/**
 * Key Exchange - Key exchange without public-key crypto.
 *
 * Methods:
 * 1. PAKE: Password-Authenticated Key Exchange
 * 2. QR: QR codes, base64 for manual exchange
 * 3. Key Splitting: XOR-based secret sharing
 */
public class Exchange {

    /**
     * Password-Authenticated Key Exchange.
     *
     * Both parties derive a shared key from a common password.
     * Uses role binding to prevent reflection attacks.
     */
    public static class PAKE {
        public static final int DEFAULT_ITERATIONS = 200000;

        /**
         * Derive key contribution from password.
         *
         * @param password Shared password between parties
         * @param salt Public salt (can be exchanged openly)
         * @param role Role identifier ('alice', 'bob', 'initiator', etc.)
         * @param iterations PBKDF2 iterations (default: 200000)
         * @return 32-byte key contribution
         */
        public static byte[] derive(String password, byte[] salt, String role, int iterations) {
            try {
                SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, 256);
                byte[] baseKey = factory.generateSecret(spec).getEncoded();

                MessageDigest md = MessageDigest.getInstance("SHA-256");
                md.update(baseKey);
                md.update(role.getBytes(StandardCharsets.UTF_8));
                return md.digest();
            } catch (Exception e) {
                throw new RuntimeException("Failed to derive key", e);
            }
        }

        public static byte[] derive(String password, byte[] salt, String role) {
            return derive(password, salt, role, DEFAULT_ITERATIONS);
        }

        /**
         * Combine key contributions into session key.
         *
         * @param contributions Key contributions from all parties
         * @return 32-byte shared session key
         */
        public static byte[] combine(byte[]... contributions) {
            try {
                // Sort contributions for deterministic output
                List<byte[]> sorted = new ArrayList<>(Arrays.asList(contributions));
                sorted.sort((a, b) -> {
                    for (int i = 0; i < Math.min(a.length, b.length); i++) {
                        int cmp = (a[i] & 0xFF) - (b[i] & 0xFF);
                        if (cmp != 0) return cmp;
                    }
                    return a.length - b.length;
                });

                MessageDigest md = MessageDigest.getInstance("SHA-256");
                for (byte[] contrib : sorted) {
                    md.update(contrib);
                }
                return md.digest();
            } catch (Exception e) {
                throw new RuntimeException("Failed to combine keys", e);
            }
        }

        /**
         * Generate random salt for key exchange.
         */
        public static byte[] generateSalt() {
            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);
            return salt;
        }
    }

    /**
     * Key exchange via QR codes or manual transfer.
     *
     * Encodes keys in URL-safe base64 for easy scanning/typing.
     */
    public static class QR {
        /**
         * Encode key for QR code or manual transfer.
         *
         * @param key Key bytes to encode
         * @return URL-safe base64 string
         */
        public static String encode(byte[] key) {
            return Base64.getUrlEncoder().withoutPadding().encodeToString(key);
        }

        /**
         * Decode key from QR code or manual input.
         *
         * @param encoded Base64 string from encode()
         * @return Key bytes
         */
        public static byte[] decode(String encoded) {
            return Base64.getUrlDecoder().decode(encoded);
        }

        /**
         * Generate complete exchange data with optional metadata.
         *
         * @param key Key to exchange
         * @param metadata Optional metadata (issuer, expiry, etc.)
         * @return JSON-like string for QR code
         */
        public static String generateExchangeData(byte[] key, Map<String, Object> metadata) {
            StringBuilder sb = new StringBuilder("{\"v\":1,\"k\":\"");
            sb.append(encode(key));
            sb.append("\"");
            if (metadata != null && !metadata.isEmpty()) {
                sb.append(",\"m\":");
                sb.append(toJson(metadata));
            }
            sb.append("}");
            return sb.toString();
        }

        public static String generateExchangeData(byte[] key) {
            return generateExchangeData(key, null);
        }

        /**
         * Parse exchange data from QR code.
         *
         * @param data JSON string from generateExchangeData()
         * @return Array of [key bytes, metadata map or null]
         */
        public static Object[] parseExchangeData(String data) {
            // Simple JSON parsing for exchange format
            int keyStart = data.indexOf("\"k\":\"") + 5;
            int keyEnd = data.indexOf("\"", keyStart);
            String keyB64 = data.substring(keyStart, keyEnd);
            byte[] key = decode(keyB64);

            Map<String, Object> metadata = null;
            int metaStart = data.indexOf("\"m\":");
            if (metaStart >= 0) {
                // Extract metadata (simplified)
                int braceStart = data.indexOf("{", metaStart);
                if (braceStart >= 0) {
                    int depth = 1;
                    int braceEnd = braceStart + 1;
                    while (braceEnd < data.length() && depth > 0) {
                        char c = data.charAt(braceEnd);
                        if (c == '{') depth++;
                        else if (c == '}') depth--;
                        braceEnd++;
                    }
                    // Would need full JSON parser for metadata
                    metadata = new HashMap<>();
                }
            }

            return new Object[] { key, metadata };
        }

        private static String toJson(Map<String, Object> map) {
            StringBuilder sb = new StringBuilder("{");
            boolean first = true;
            for (Map.Entry<String, Object> entry : map.entrySet()) {
                if (!first) sb.append(",");
                first = false;
                sb.append("\"").append(entry.getKey()).append("\":");
                Object v = entry.getValue();
                if (v instanceof String) {
                    sb.append("\"").append(v).append("\"");
                } else {
                    sb.append(v);
                }
            }
            sb.append("}");
            return sb.toString();
        }
    }

    /**
     * Split keys into shares for threshold recovery.
     *
     * This is a simplified XOR-based scheme where ALL shares
     * are required for reconstruction.
     */
    public static class KeySplitter {
        private static final SecureRandom random = new SecureRandom();

        /**
         * Split key into shares (all required for reconstruction).
         *
         * @param key Key to split
         * @param numShares Number of shares to create
         * @return List of shares
         */
        public static List<byte[]> split(byte[] key, int numShares) {
            if (numShares < 2) {
                throw new IllegalArgumentException("Need at least 2 shares");
            }

            List<byte[]> shares = new ArrayList<>();

            // Generate random shares for all but the last
            for (int i = 0; i < numShares - 1; i++) {
                byte[] share = new byte[key.length];
                random.nextBytes(share);
                shares.add(share);
            }

            // Final share = XOR of key with all other shares
            byte[] finalShare = key.clone();
            for (byte[] share : shares) {
                for (int i = 0; i < finalShare.length; i++) {
                    finalShare[i] ^= share[i];
                }
            }
            shares.add(finalShare);

            return shares;
        }

        /**
         * Combine shares to recover key.
         *
         * @param shares All shares from split()
         * @return Original key
         */
        public static byte[] combine(List<byte[]> shares) {
            if (shares.size() < 2) {
                throw new IllegalArgumentException("Need at least 2 shares");
            }

            byte[] result = shares.get(0).clone();
            for (int i = 1; i < shares.size(); i++) {
                byte[] share = shares.get(i);
                for (int j = 0; j < result.length; j++) {
                    result[j] ^= share[j];
                }
            }

            return result;
        }
    }
}
