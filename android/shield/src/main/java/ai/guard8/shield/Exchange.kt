package ai.guard8.shield

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

/**
 * Key Exchange - Key exchange without public-key crypto.
 *
 * Methods:
 * 1. PAKE: Password-Authenticated Key Exchange
 * 2. QR: QR codes, base64 for manual exchange
 * 3. Key Splitting: XOR-based secret sharing
 */

/**
 * Password-Authenticated Key Exchange.
 *
 * Both parties derive a shared key from a common password.
 * Uses role binding to prevent reflection attacks.
 */
object PAKEExchange {
    const val DEFAULT_ITERATIONS = 200000
    private val random = SecureRandom()

    /**
     * Derive key contribution from password.
     *
     * @param password Shared password between parties
     * @param salt Public salt (can be exchanged openly)
     * @param role Role identifier ('alice', 'bob', 'initiator', etc.)
     * @param iterations PBKDF2 iterations (default: 200000)
     * @return 32-byte key contribution
     */
    fun derive(password: String, salt: ByteArray, role: String, iterations: Int = DEFAULT_ITERATIONS): ByteArray {
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val spec = PBEKeySpec(password.toCharArray(), salt, iterations, 256)
        val baseKey = factory.generateSecret(spec).encoded

        val md = MessageDigest.getInstance("SHA-256")
        md.update(baseKey)
        md.update(role.toByteArray(StandardCharsets.UTF_8))
        return md.digest()
    }

    /**
     * Combine key contributions into session key.
     *
     * @param contributions Key contributions from all parties
     * @return 32-byte shared session key
     */
    fun combine(vararg contributions: ByteArray): ByteArray {
        // Sort contributions for deterministic output
        val sorted = contributions.sortedWith { a, b ->
            for (i in 0 until minOf(a.size, b.size)) {
                val cmp = (a[i].toInt() and 0xFF) - (b[i].toInt() and 0xFF)
                if (cmp != 0) return@sortedWith cmp
            }
            a.size - b.size
        }

        val md = MessageDigest.getInstance("SHA-256")
        for (contrib in sorted) {
            md.update(contrib)
        }
        return md.digest()
    }

    /**
     * Generate random salt for key exchange.
     */
    fun generateSalt(): ByteArray {
        val salt = ByteArray(16)
        random.nextBytes(salt)
        return salt
    }
}

/**
 * Key exchange via QR codes or manual transfer.
 *
 * Encodes keys in URL-safe base64 for easy scanning/typing.
 */
object QRExchange {
    /**
     * Encode key for QR code or manual transfer.
     *
     * @param key Key bytes to encode
     * @return URL-safe base64 string
     */
    fun encode(key: ByteArray): String {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(key)
    }

    /**
     * Decode key from QR code or manual input.
     *
     * @param encoded Base64 string from encode()
     * @return Key bytes
     */
    fun decode(encoded: String): ByteArray {
        return Base64.getUrlDecoder().decode(encoded)
    }

    /**
     * Generate complete exchange data with optional metadata.
     *
     * @param key Key to exchange
     * @param metadata Optional metadata (issuer, expiry, etc.)
     * @return JSON-like string for QR code
     */
    fun generateExchangeData(key: ByteArray, metadata: Map<String, Any>? = null): String {
        val sb = StringBuilder("{\"v\":1,\"k\":\"")
        sb.append(encode(key))
        sb.append("\"")
        if (metadata != null && metadata.isNotEmpty()) {
            sb.append(",\"m\":")
            sb.append(toJson(metadata))
        }
        sb.append("}")
        return sb.toString()
    }

    /**
     * Parse exchange data from QR code.
     *
     * @param data JSON string from generateExchangeData()
     * @return Pair of (key, metadata)
     */
    fun parseExchangeData(data: String): Pair<ByteArray, Map<String, Any>?> {
        // Simple JSON parsing for exchange format
        val keyStart = data.indexOf("\"k\":\"") + 5
        val keyEnd = data.indexOf("\"", keyStart)
        val keyB64 = data.substring(keyStart, keyEnd)
        val key = decode(keyB64)

        var metadata: Map<String, Any>? = null
        val metaStart = data.indexOf("\"m\":")
        if (metaStart >= 0) {
            // Would need full JSON parser for proper metadata parsing
            metadata = emptyMap()
        }

        return Pair(key, metadata)
    }

    private fun toJson(map: Map<String, Any>): String {
        val sb = StringBuilder("{")
        var first = true
        for ((key, value) in map) {
            if (!first) sb.append(",")
            first = false
            sb.append("\"$key\":")
            when (value) {
                is String -> sb.append("\"$value\"")
                else -> sb.append(value)
            }
        }
        sb.append("}")
        return sb.toString()
    }
}

/**
 * Split keys into shares for threshold recovery.
 *
 * This is a simplified XOR-based scheme where ALL shares
 * are required for reconstruction.
 */
object KeySplitter {
    private val random = SecureRandom()

    /**
     * Split key into shares (all required for reconstruction).
     *
     * @param key Key to split
     * @param numShares Number of shares to create
     * @return List of shares
     */
    fun split(key: ByteArray, numShares: Int): List<ByteArray> {
        require(numShares >= 2) { "Need at least 2 shares" }

        val shares = mutableListOf<ByteArray>()

        // Generate random shares for all but the last
        repeat(numShares - 1) {
            val share = ByteArray(key.size)
            random.nextBytes(share)
            shares.add(share)
        }

        // Final share = XOR of key with all other shares
        val finalShare = key.copyOf()
        for (share in shares) {
            for (i in finalShare.indices) {
                finalShare[i] = (finalShare[i].toInt() xor share[i].toInt()).toByte()
            }
        }
        shares.add(finalShare)

        return shares
    }

    /**
     * Combine shares to recover key.
     *
     * @param shares All shares from split()
     * @return Original key
     */
    fun combine(shares: List<ByteArray>): ByteArray {
        require(shares.size >= 2) { "Need at least 2 shares" }

        val result = shares[0].copyOf()
        for (i in 1 until shares.size) {
            for (j in result.indices) {
                result[j] = (result[j].toInt() xor shares[i][j].toInt()).toByte()
            }
        }

        return result
    }
}
