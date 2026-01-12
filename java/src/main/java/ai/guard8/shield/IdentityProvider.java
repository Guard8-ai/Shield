package ai.guard8.shield;

import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.*;

/**
 * IdentityProvider - SSO/Identity Provider using symmetric crypto.
 *
 * Provides user registration, session management, and service tokens
 * using only symmetric cryptography (no public-key certificates).
 */
public class IdentityProvider {
    private static final int PBKDF2_ITERATIONS = 100000;
    private static final SecureRandom random = new SecureRandom();

    private final byte[] providerKey;
    private final int tokenTtl;
    private final Map<String, Identity> identities = new HashMap<>();

    /**
     * User identity.
     */
    public static class Identity {
        public final String userId;
        public final String displayName;
        public final byte[] verificationKey;
        public final long createdAt;
        public final Map<String, Object> attributes;

        public Identity(String userId, String displayName, byte[] verificationKey,
                        long createdAt, Map<String, Object> attributes) {
            this.userId = userId;
            this.displayName = displayName;
            this.verificationKey = verificationKey;
            this.createdAt = createdAt;
            this.attributes = attributes != null ? new HashMap<>(attributes) : new HashMap<>();
        }
    }

    /**
     * Session information from validated token.
     */
    public static class Session {
        public final String userId;
        public final long created;
        public final long expires;
        public final List<String> permissions;
        public final Map<String, Object> metadata;

        public Session(String userId, long created, long expires,
                       List<String> permissions, Map<String, Object> metadata) {
            this.userId = userId;
            this.created = created;
            this.expires = expires;
            this.permissions = permissions != null ? new ArrayList<>(permissions) : new ArrayList<>();
            this.metadata = metadata != null ? new HashMap<>(metadata) : new HashMap<>();
        }

        public boolean isExpired() {
            return System.currentTimeMillis() / 1000 > expires;
        }

        public long getRemainingTime() {
            return Math.max(0, expires - System.currentTimeMillis() / 1000);
        }
    }

    /**
     * Create identity provider.
     *
     * @param providerKey 32-byte provider secret key
     * @param tokenTtl Default token lifetime in seconds
     */
    public IdentityProvider(byte[] providerKey, int tokenTtl) {
        this.providerKey = providerKey.clone();
        this.tokenTtl = tokenTtl > 0 ? tokenTtl : 3600;
    }

    /**
     * Create with default 1-hour TTL.
     */
    public IdentityProvider(byte[] providerKey) {
        this(providerKey, 3600);
    }

    /**
     * Register new user identity.
     *
     * @param userId Unique user identifier
     * @param password User's password
     * @param displayName User's display name
     * @param attributes Optional user attributes
     * @return Created identity
     * @throws IllegalArgumentException if userId already exists
     */
    public Identity register(String userId, String password, String displayName,
                             Map<String, Object> attributes) {
        if (identities.containsKey(userId)) {
            throw new IllegalArgumentException("User " + userId + " already exists");
        }

        byte[] verificationKey = deriveVerificationKey(userId, password);
        Identity identity = new Identity(
                userId,
                displayName,
                verificationKey,
                System.currentTimeMillis() / 1000,
                attributes
        );

        identities.put(userId, identity);
        return identity;
    }

    public Identity register(String userId, String password, String displayName) {
        return register(userId, password, displayName, null);
    }

    /**
     * Authenticate user and return session token.
     *
     * @param userId User identifier
     * @param password User's password
     * @param permissions Optional permission list
     * @param ttl Token lifetime (or default if null)
     * @return Session token, or null if authentication fails
     */
    public String authenticate(String userId, String password,
                               List<String> permissions, Integer ttl) {
        Identity identity = identities.get(userId);
        if (identity == null) {
            return null;
        }

        byte[] verificationKey = deriveVerificationKey(userId, password);
        if (!constantTimeEquals(verificationKey, identity.verificationKey)) {
            return null;
        }

        int actualTtl = ttl != null ? ttl : tokenTtl;
        long now = System.currentTimeMillis() / 1000;

        Map<String, Object> sessionData = new LinkedHashMap<>();
        sessionData.put("user_id", userId);
        sessionData.put("created", now);
        sessionData.put("expires", now + actualTtl);
        sessionData.put("permissions", permissions != null ? permissions : new ArrayList<>());
        sessionData.put("nonce", generateNonce());

        return signToken(sessionData);
    }

    public String authenticate(String userId, String password) {
        return authenticate(userId, password, null, null);
    }

    /**
     * Validate session token.
     *
     * @param token Session token from authenticate()
     * @return Session object, or null if invalid/expired
     */
    public Session validateToken(String token) {
        Map<String, Object> sessionData = verifyToken(token);
        if (sessionData == null) {
            return null;
        }

        long expires = ((Number) sessionData.get("expires")).longValue();
        if (expires < System.currentTimeMillis() / 1000) {
            return null;
        }

        @SuppressWarnings("unchecked")
        List<String> permissions = (List<String>) sessionData.getOrDefault("permissions", new ArrayList<>());

        @SuppressWarnings("unchecked")
        Map<String, Object> metadata = (Map<String, Object>) sessionData.getOrDefault("metadata", new HashMap<>());

        return new Session(
                (String) sessionData.get("user_id"),
                ((Number) sessionData.get("created")).longValue(),
                expires,
                permissions,
                metadata
        );
    }

    /**
     * Create service-specific access token.
     *
     * @param sessionToken Valid session token
     * @param service Target service identifier
     * @param permissions Scoped permissions for this service
     * @param ttl Token lifetime (default 300 seconds)
     * @return Service token, or null if session invalid
     */
    public String createServiceToken(String sessionToken, String service,
                                     List<String> permissions, int ttl) {
        Session session = validateToken(sessionToken);
        if (session == null) {
            return null;
        }

        long now = System.currentTimeMillis() / 1000;
        Map<String, Object> serviceData = new LinkedHashMap<>();
        serviceData.put("user_id", session.userId);
        serviceData.put("service", service);
        serviceData.put("created", now);
        serviceData.put("expires", now + ttl);
        serviceData.put("permissions", permissions != null ? permissions : new ArrayList<>());
        serviceData.put("parent_expires", session.expires);

        return signToken(serviceData);
    }

    public String createServiceToken(String sessionToken, String service) {
        return createServiceToken(sessionToken, service, null, 300);
    }

    /**
     * Validate service-specific token.
     *
     * @param token Service token
     * @param service Expected service identifier
     * @return Session object, or null if invalid
     */
    public Session validateServiceToken(String token, String service) {
        Map<String, Object> tokenData = verifyToken(token);
        if (tokenData == null) {
            return null;
        }

        if (!service.equals(tokenData.get("service"))) {
            return null;
        }

        long now = System.currentTimeMillis() / 1000;
        long expires = ((Number) tokenData.get("expires")).longValue();
        if (expires < now) {
            return null;
        }

        Number parentExpires = (Number) tokenData.get("parent_expires");
        if (parentExpires != null && parentExpires.longValue() < now) {
            return null;
        }

        @SuppressWarnings("unchecked")
        List<String> permissions = (List<String>) tokenData.getOrDefault("permissions", new ArrayList<>());

        Map<String, Object> metadata = new HashMap<>();
        metadata.put("service", service);

        return new Session(
                (String) tokenData.get("user_id"),
                ((Number) tokenData.get("created")).longValue(),
                expires,
                permissions,
                metadata
        );
    }

    /**
     * Refresh session token.
     *
     * @param token Current valid session token
     * @param ttl New lifetime (or default if null)
     * @return New session token, or null if current token invalid
     */
    public String refreshToken(String token, Integer ttl) {
        Session session = validateToken(token);
        if (session == null) {
            return null;
        }

        int actualTtl = ttl != null ? ttl : tokenTtl;
        long now = System.currentTimeMillis() / 1000;

        Map<String, Object> sessionData = new LinkedHashMap<>();
        sessionData.put("user_id", session.userId);
        sessionData.put("created", now);
        sessionData.put("expires", now + actualTtl);
        sessionData.put("permissions", session.permissions);
        sessionData.put("nonce", generateNonce());

        return signToken(sessionData);
    }

    public String refreshToken(String token) {
        return refreshToken(token, null);
    }

    /**
     * Revoke user identity.
     *
     * @param userId User to revoke
     * @return true if user was revoked
     */
    public boolean revokeUser(String userId) {
        return identities.remove(userId) != null;
    }

    /**
     * Get identity by user ID.
     */
    public Identity getIdentity(String userId) {
        return identities.get(userId);
    }

    // Private helpers

    private byte[] deriveVerificationKey(String userId, String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] salt = md.digest(("user:" + userId).getBytes(StandardCharsets.UTF_8));

            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, 256);
            byte[] userKey = factory.generateSecret(spec).getEncoded();

            md.reset();
            md.update("verify:".getBytes(StandardCharsets.UTF_8));
            md.update(userKey);
            return md.digest();
        } catch (Exception e) {
            throw new RuntimeException("Failed to derive key", e);
        }
    }

    private String signToken(Map<String, Object> data) {
        try {
            String json = toJson(data);
            byte[] tokenBytes = json.getBytes(StandardCharsets.UTF_8);

            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(providerKey, "HmacSHA256"));
            byte[] fullMac = mac.doFinal(tokenBytes);
            byte[] truncatedMac = Arrays.copyOf(fullMac, 16);

            byte[] result = new byte[tokenBytes.length + 16];
            System.arraycopy(tokenBytes, 0, result, 0, tokenBytes.length);
            System.arraycopy(truncatedMac, 0, result, tokenBytes.length, 16);

            return Base64.getUrlEncoder().withoutPadding().encodeToString(result);
        } catch (Exception e) {
            throw new RuntimeException("Failed to sign token", e);
        }
    }

    private Map<String, Object> verifyToken(String token) {
        try {
            byte[] decoded = Base64.getUrlDecoder().decode(token);
            if (decoded.length < 17) {
                return null;
            }

            byte[] tokenBytes = Arrays.copyOf(decoded, decoded.length - 16);
            byte[] receivedMac = Arrays.copyOfRange(decoded, decoded.length - 16, decoded.length);

            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(providerKey, "HmacSHA256"));
            byte[] fullExpectedMac = mac.doFinal(tokenBytes);
            byte[] expectedMac = Arrays.copyOf(fullExpectedMac, 16);

            if (!constantTimeEquals(receivedMac, expectedMac)) {
                return null;
            }

            return parseJson(new String(tokenBytes, StandardCharsets.UTF_8));
        } catch (Exception e) {
            return null;
        }
    }

    private String generateNonce() {
        byte[] bytes = new byte[8];
        random.nextBytes(bytes);
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

    private boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a.length != b.length) return false;
        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }

    // Simple JSON serialization (avoiding external dependencies)
    private String toJson(Map<String, Object> map) {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            if (!first) sb.append(",");
            first = false;
            sb.append("\"").append(entry.getKey()).append("\":");
            sb.append(valueToJson(entry.getValue()));
        }
        sb.append("}");
        return sb.toString();
    }

    private String valueToJson(Object value) {
        if (value == null) return "null";
        if (value instanceof String) return "\"" + escapeJson((String) value) + "\"";
        if (value instanceof Number) return value.toString();
        if (value instanceof Boolean) return value.toString();
        if (value instanceof List) {
            StringBuilder sb = new StringBuilder("[");
            boolean first = true;
            for (Object item : (List<?>) value) {
                if (!first) sb.append(",");
                first = false;
                sb.append(valueToJson(item));
            }
            sb.append("]");
            return sb.toString();
        }
        if (value instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> map = (Map<String, Object>) value;
            return toJson(map);
        }
        return "\"" + escapeJson(value.toString()) + "\"";
    }

    private String escapeJson(String s) {
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> parseJson(String json) {
        // Simple JSON parser for tokens
        json = json.trim();
        if (!json.startsWith("{") || !json.endsWith("}")) {
            throw new IllegalArgumentException("Invalid JSON");
        }

        Map<String, Object> result = new LinkedHashMap<>();
        json = json.substring(1, json.length() - 1).trim();

        int i = 0;
        while (i < json.length()) {
            // Skip whitespace
            while (i < json.length() && Character.isWhitespace(json.charAt(i))) i++;
            if (i >= json.length()) break;

            // Parse key
            if (json.charAt(i) != '"') break;
            int keyStart = i + 1;
            int keyEnd = json.indexOf('"', keyStart);
            String key = json.substring(keyStart, keyEnd);
            i = keyEnd + 1;

            // Skip to colon
            while (i < json.length() && json.charAt(i) != ':') i++;
            i++;

            // Skip whitespace
            while (i < json.length() && Character.isWhitespace(json.charAt(i))) i++;

            // Parse value
            Object value;
            char c = json.charAt(i);
            if (c == '"') {
                int valStart = i + 1;
                int valEnd = valStart;
                while (valEnd < json.length() && json.charAt(valEnd) != '"') {
                    if (json.charAt(valEnd) == '\\') valEnd++;
                    valEnd++;
                }
                value = unescapeJson(json.substring(valStart, valEnd));
                i = valEnd + 1;
            } else if (c == '[') {
                int depth = 1;
                int start = i;
                i++;
                while (i < json.length() && depth > 0) {
                    if (json.charAt(i) == '[') depth++;
                    else if (json.charAt(i) == ']') depth--;
                    else if (json.charAt(i) == '"') {
                        i++;
                        while (i < json.length() && json.charAt(i) != '"') {
                            if (json.charAt(i) == '\\') i++;
                            i++;
                        }
                    }
                    i++;
                }
                value = parseJsonArray(json.substring(start, i));
            } else if (c == '{') {
                int depth = 1;
                int start = i;
                i++;
                while (i < json.length() && depth > 0) {
                    if (json.charAt(i) == '{') depth++;
                    else if (json.charAt(i) == '}') depth--;
                    else if (json.charAt(i) == '"') {
                        i++;
                        while (i < json.length() && json.charAt(i) != '"') {
                            if (json.charAt(i) == '\\') i++;
                            i++;
                        }
                    }
                    i++;
                }
                value = parseJson(json.substring(start, i));
            } else {
                // Number, boolean, or null
                int start = i;
                while (i < json.length() && json.charAt(i) != ',' && json.charAt(i) != '}') i++;
                String valStr = json.substring(start, i).trim();
                if (valStr.equals("true")) value = true;
                else if (valStr.equals("false")) value = false;
                else if (valStr.equals("null")) value = null;
                else if (valStr.contains(".")) value = Double.parseDouble(valStr);
                else value = Long.parseLong(valStr);
            }

            result.put(key, value);

            // Skip to next entry
            while (i < json.length() && json.charAt(i) != ',' && json.charAt(i) != '}') i++;
            if (i < json.length() && json.charAt(i) == ',') i++;
        }

        return result;
    }

    private List<Object> parseJsonArray(String json) {
        List<Object> result = new ArrayList<>();
        json = json.trim();
        if (!json.startsWith("[") || !json.endsWith("]")) {
            return result;
        }
        json = json.substring(1, json.length() - 1).trim();
        if (json.isEmpty()) return result;

        int i = 0;
        while (i < json.length()) {
            while (i < json.length() && Character.isWhitespace(json.charAt(i))) i++;
            if (i >= json.length()) break;

            char c = json.charAt(i);
            Object value;
            if (c == '"') {
                int valStart = i + 1;
                int valEnd = valStart;
                while (valEnd < json.length() && json.charAt(valEnd) != '"') {
                    if (json.charAt(valEnd) == '\\') valEnd++;
                    valEnd++;
                }
                value = unescapeJson(json.substring(valStart, valEnd));
                i = valEnd + 1;
            } else {
                int start = i;
                while (i < json.length() && json.charAt(i) != ',' && json.charAt(i) != ']') i++;
                String valStr = json.substring(start, i).trim();
                if (valStr.equals("true")) value = true;
                else if (valStr.equals("false")) value = false;
                else if (valStr.equals("null")) value = null;
                else if (valStr.contains(".")) value = Double.parseDouble(valStr);
                else value = Long.parseLong(valStr);
            }
            result.add(value);

            while (i < json.length() && json.charAt(i) != ',') i++;
            if (i < json.length() && json.charAt(i) == ',') i++;
        }
        return result;
    }

    private String unescapeJson(String s) {
        return s.replace("\\n", "\n")
                .replace("\\r", "\r")
                .replace("\\t", "\t")
                .replace("\\\"", "\"")
                .replace("\\\\", "\\");
    }
}
