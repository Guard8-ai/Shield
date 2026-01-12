package ai.guard8.shield

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * User identity.
 */
data class Identity(
    val userId: String,
    val displayName: String,
    val verificationKey: ByteArray,
    val createdAt: Long,
    val attributes: MutableMap<String, Any> = mutableMapOf()
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Identity) return false
        return userId == other.userId
    }

    override fun hashCode() = userId.hashCode()
}

/**
 * Session information from validated token.
 */
data class Session(
    val userId: String,
    val created: Long,
    val expires: Long,
    val permissions: List<String> = emptyList(),
    val metadata: MutableMap<String, Any> = mutableMapOf()
) {
    val isExpired: Boolean
        get() = System.currentTimeMillis() / 1000 > expires

    val remainingTime: Long
        get() = maxOf(0, expires - System.currentTimeMillis() / 1000)
}

/**
 * IdentityProvider - SSO/Identity Provider using symmetric crypto.
 *
 * Provides user registration, session management, and service tokens
 * using only symmetric cryptography (no public-key certificates).
 */
class IdentityProvider(
    private val providerKey: ByteArray,
    private val tokenTtl: Int = 3600
) : AutoCloseable {

    private val identities = mutableMapOf<String, Identity>()

    companion object {
        private const val PBKDF2_ITERATIONS = 100000
        private val random = SecureRandom()
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
    fun register(
        userId: String,
        password: String,
        displayName: String,
        attributes: Map<String, Any>? = null
    ): Identity {
        if (identities.containsKey(userId)) {
            throw IllegalArgumentException("User $userId already exists")
        }

        val verificationKey = deriveVerificationKey(userId, password)
        val identity = Identity(
            userId = userId,
            displayName = displayName,
            verificationKey = verificationKey,
            createdAt = System.currentTimeMillis() / 1000,
            attributes = (attributes?.toMutableMap() ?: mutableMapOf())
        )

        identities[userId] = identity
        return identity
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
    fun authenticate(
        userId: String,
        password: String,
        permissions: List<String>? = null,
        ttl: Int? = null
    ): String? {
        val identity = identities[userId] ?: return null

        val verificationKey = deriveVerificationKey(userId, password)
        if (!constantTimeEquals(verificationKey, identity.verificationKey)) {
            return null
        }

        val actualTtl = ttl ?: tokenTtl
        val now = System.currentTimeMillis() / 1000

        val sessionData = linkedMapOf<String, Any>(
            "user_id" to userId,
            "created" to now,
            "expires" to (now + actualTtl),
            "permissions" to (permissions ?: emptyList<String>()),
            "nonce" to generateNonce()
        )

        return signToken(sessionData)
    }

    /**
     * Validate session token.
     *
     * @param token Session token from authenticate()
     * @return Session object, or null if invalid/expired
     */
    fun validateToken(token: String): Session? {
        val sessionData = verifyToken(token) ?: return null

        val expires = (sessionData["expires"] as? Number)?.toLong() ?: return null
        if (expires < System.currentTimeMillis() / 1000) {
            return null
        }

        @Suppress("UNCHECKED_CAST")
        val permissions = (sessionData["permissions"] as? List<String>) ?: emptyList()

        @Suppress("UNCHECKED_CAST")
        val metadata = (sessionData["metadata"] as? Map<String, Any>)?.toMutableMap() ?: mutableMapOf()

        return Session(
            userId = sessionData["user_id"] as? String ?: "",
            created = (sessionData["created"] as? Number)?.toLong() ?: 0,
            expires = expires,
            permissions = permissions,
            metadata = metadata
        )
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
    fun createServiceToken(
        sessionToken: String,
        service: String,
        permissions: List<String>? = null,
        ttl: Int = 300
    ): String? {
        val session = validateToken(sessionToken) ?: return null

        val now = System.currentTimeMillis() / 1000
        val serviceData = linkedMapOf<String, Any>(
            "user_id" to session.userId,
            "service" to service,
            "created" to now,
            "expires" to (now + ttl),
            "permissions" to (permissions ?: emptyList<String>()),
            "parent_expires" to session.expires
        )

        return signToken(serviceData)
    }

    /**
     * Validate service-specific token.
     *
     * @param token Service token
     * @param service Expected service identifier
     * @return Session object, or null if invalid
     */
    fun validateServiceToken(token: String, service: String): Session? {
        val tokenData = verifyToken(token) ?: return null

        if (tokenData["service"] != service) {
            return null
        }

        val now = System.currentTimeMillis() / 1000
        val expires = (tokenData["expires"] as? Number)?.toLong() ?: return null
        if (expires < now) {
            return null
        }

        val parentExpires = (tokenData["parent_expires"] as? Number)?.toLong()
        if (parentExpires != null && parentExpires < now) {
            return null
        }

        @Suppress("UNCHECKED_CAST")
        val permissions = (tokenData["permissions"] as? List<String>) ?: emptyList()

        return Session(
            userId = tokenData["user_id"] as? String ?: "",
            created = (tokenData["created"] as? Number)?.toLong() ?: 0,
            expires = expires,
            permissions = permissions,
            metadata = mutableMapOf("service" to service)
        )
    }

    /**
     * Refresh session token.
     *
     * @param token Current valid session token
     * @param ttl New lifetime (or default if null)
     * @return New session token, or null if current token invalid
     */
    fun refreshToken(token: String, ttl: Int? = null): String? {
        val session = validateToken(token) ?: return null

        val actualTtl = ttl ?: tokenTtl
        val now = System.currentTimeMillis() / 1000

        val sessionData = linkedMapOf<String, Any>(
            "user_id" to session.userId,
            "created" to now,
            "expires" to (now + actualTtl),
            "permissions" to session.permissions,
            "nonce" to generateNonce()
        )

        return signToken(sessionData)
    }

    /**
     * Revoke user identity.
     *
     * @param userId User to revoke
     * @return true if user was revoked
     */
    fun revokeUser(userId: String): Boolean {
        return identities.remove(userId) != null
    }

    /**
     * Get identity by user ID.
     */
    fun getIdentity(userId: String): Identity? = identities[userId]

    override fun close() {
        providerKey.fill(0)
        identities.clear()
    }

    // Private helpers

    private fun deriveVerificationKey(userId: String, password: String): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        val salt = md.digest("user:$userId".toByteArray(StandardCharsets.UTF_8))

        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val spec = PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, 256)
        val userKey = factory.generateSecret(spec).encoded

        md.reset()
        md.update("verify:".toByteArray(StandardCharsets.UTF_8))
        md.update(userKey)
        return md.digest()
    }

    private fun signToken(data: Map<String, Any>): String {
        val json = toJson(data)
        val tokenBytes = json.toByteArray(StandardCharsets.UTF_8)

        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(providerKey, "HmacSHA256"))
        val fullMac = mac.doFinal(tokenBytes)
        val truncatedMac = fullMac.copyOf(16)

        val result = ByteArray(tokenBytes.size + 16)
        System.arraycopy(tokenBytes, 0, result, 0, tokenBytes.size)
        System.arraycopy(truncatedMac, 0, result, tokenBytes.size, 16)

        return Base64.getUrlEncoder().withoutPadding().encodeToString(result)
    }

    private fun verifyToken(token: String): Map<String, Any>? {
        return try {
            val decoded = Base64.getUrlDecoder().decode(token)
            if (decoded.size < 17) return null

            val tokenBytes = decoded.copyOf(decoded.size - 16)
            val receivedMac = decoded.copyOfRange(decoded.size - 16, decoded.size)

            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(providerKey, "HmacSHA256"))
            val fullExpectedMac = mac.doFinal(tokenBytes)
            val expectedMac = fullExpectedMac.copyOf(16)

            if (!constantTimeEquals(receivedMac, expectedMac)) {
                return null
            }

            parseJson(String(tokenBytes, StandardCharsets.UTF_8))
        } catch (e: Exception) {
            null
        }
    }

    private fun generateNonce(): String {
        val bytes = ByteArray(8)
        random.nextBytes(bytes)
        return bytes.joinToString("") { "%02x".format(it) }
    }

    private fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var result = 0
        for (i in a.indices) {
            result = result or (a[i].toInt() xor b[i].toInt())
        }
        return result == 0
    }

    // Simple JSON serialization
    private fun toJson(map: Map<String, Any>): String {
        val sb = StringBuilder("{")
        var first = true
        for ((key, value) in map) {
            if (!first) sb.append(",")
            first = false
            sb.append("\"$key\":")
            sb.append(valueToJson(value))
        }
        sb.append("}")
        return sb.toString()
    }

    private fun valueToJson(value: Any?): String = when (value) {
        null -> "null"
        is String -> "\"${escapeJson(value)}\""
        is Number -> value.toString()
        is Boolean -> value.toString()
        is List<*> -> "[${value.joinToString(",") { valueToJson(it) }}]"
        is Map<*, *> -> {
            @Suppress("UNCHECKED_CAST")
            toJson(value as Map<String, Any>)
        }
        else -> "\"${escapeJson(value.toString())}\""
    }

    private fun escapeJson(s: String): String = s
        .replace("\\", "\\\\")
        .replace("\"", "\\\"")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")

    @Suppress("UNCHECKED_CAST")
    private fun parseJson(json: String): Map<String, Any>? {
        val trimmed = json.trim()
        if (!trimmed.startsWith("{") || !trimmed.endsWith("}")) return null

        val result = mutableMapOf<String, Any>()
        val content = trimmed.substring(1, trimmed.length - 1).trim()

        var i = 0
        while (i < content.length) {
            while (i < content.length && content[i].isWhitespace()) i++
            if (i >= content.length) break

            if (content[i] != '"') break
            val keyStart = i + 1
            val keyEnd = content.indexOf('"', keyStart)
            val key = content.substring(keyStart, keyEnd)
            i = keyEnd + 1

            while (i < content.length && content[i] != ':') i++
            i++
            while (i < content.length && content[i].isWhitespace()) i++

            val (value, newIndex) = parseValue(content, i)
            i = newIndex
            result[key] = value

            while (i < content.length && content[i] != ',' && content[i] != '}') i++
            if (i < content.length && content[i] == ',') i++
        }

        return result
    }

    private fun parseValue(content: String, startIndex: Int): Pair<Any, Int> {
        var i = startIndex
        val c = content[i]

        return when {
            c == '"' -> {
                val valStart = i + 1
                var valEnd = valStart
                while (valEnd < content.length && content[valEnd] != '"') {
                    if (content[valEnd] == '\\') valEnd++
                    valEnd++
                }
                Pair(unescapeJson(content.substring(valStart, valEnd)), valEnd + 1)
            }
            c == '[' -> {
                var depth = 1
                val start = i
                i++
                while (i < content.length && depth > 0) {
                    when (content[i]) {
                        '[' -> depth++
                        ']' -> depth--
                        '"' -> {
                            i++
                            while (i < content.length && content[i] != '"') {
                                if (content[i] == '\\') i++
                                i++
                            }
                        }
                    }
                    i++
                }
                Pair(parseJsonArray(content.substring(start, i)), i)
            }
            c == '{' -> {
                var depth = 1
                val start = i
                i++
                while (i < content.length && depth > 0) {
                    when (content[i]) {
                        '{' -> depth++
                        '}' -> depth--
                        '"' -> {
                            i++
                            while (i < content.length && content[i] != '"') {
                                if (content[i] == '\\') i++
                                i++
                            }
                        }
                    }
                    i++
                }
                Pair(parseJson(content.substring(start, i)) ?: emptyMap<String, Any>(), i)
            }
            else -> {
                val start = i
                while (i < content.length && content[i] != ',' && content[i] != '}' && content[i] != ']') i++
                val valStr = content.substring(start, i).trim()
                val value: Any = when {
                    valStr == "true" -> true
                    valStr == "false" -> false
                    valStr == "null" -> ""
                    valStr.contains('.') -> valStr.toDouble()
                    else -> valStr.toLong()
                }
                Pair(value, i)
            }
        }
    }

    private fun parseJsonArray(json: String): List<Any> {
        val trimmed = json.trim()
        if (!trimmed.startsWith("[") || !trimmed.endsWith("]")) return emptyList()

        val result = mutableListOf<Any>()
        val content = trimmed.substring(1, trimmed.length - 1).trim()
        if (content.isEmpty()) return result

        var i = 0
        while (i < content.length) {
            while (i < content.length && content[i].isWhitespace()) i++
            if (i >= content.length) break

            val (value, newIndex) = parseValue(content, i)
            i = newIndex
            result.add(value)

            while (i < content.length && content[i] != ',') i++
            if (i < content.length && content[i] == ',') i++
        }

        return result
    }

    private fun unescapeJson(s: String): String = s
        .replace("\\n", "\n")
        .replace("\\r", "\r")
        .replace("\\t", "\t")
        .replace("\\\"", "\"")
        .replace("\\\\", "\\")
}
