package ai.dikestra.shield

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.GeneralSecurityException
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import java.security.MessageDigest

/**
 * Authenticated symmetric encryption for Android (wire format v4).
 *
 * v4 replaces the previous custom SHA-256 keystream + HMAC construction with a
 * standard AEAD (AES-256-GCM by default, ChaCha20-Poly1305 optional) from the JCE.
 * No cryptography is hand-rolled; key derivation uses PBKDF2-HMAC-SHA256 +
 * HKDF-SHA256-Expand. The wire format matches every other Shield binding
 * byte-for-byte (see tests/v4_test_vectors.json).
 *
 * - Password mode: 0x03 || suite(1) || salt(16) || nonce(12) || ciphertext||tag
 * - Key mode:       0x13 || suite(1) || nonce(12) || ciphertext||tag
 *
 * AAD = version || suite || [salt]; inner plaintext =
 * timestamp_ms(8 LE) || pad_len(1) || padding(32-128) || message.
 *
 * Example:
 * ```kotlin
 * val shield = Shield.create("my_password", "github.com")
 * val encrypted = shield.encrypt("secret data".toByteArray())
 * val decrypted = shield.decrypt(encrypted)
 * ```
 */
class Shield private constructor(
    private val key: ByteArray,
    // Password-mode fields (null in pre-shared-key mode).
    private val password: String?,
    private val service: String?,
    private val iterations: Int,
    private val salt: ByteArray?,
    private val maxAgeMs: Long?
) {

    private val aeadKey: ByteArray = deriveAeadKey(key)
    private val suite: Byte = SUITE_AES_GCM
    // Cache of derived master keys keyed by the hex of the 16-byte salt.
    private val keyCache: MutableMap<String, ByteArray> = HashMap()

    init {
        if (salt != null) {
            keyCache[toHex(salt)] = key
        }
    }

    /** Derive the 32-byte master key for a given salt (cached by salt). */
    private fun deriveKey(saltBytes: ByteArray): ByteArray {
        val saltKey = toHex(saltBytes)
        keyCache[saltKey]?.let { return it }
        val pbkdf2Salt = saltBytes + service!!.toByteArray(Charsets.UTF_8)
        val derived = pbkdf2(password!!, pbkdf2Salt, iterations, KEY_SIZE)
        keyCache[saltKey] = derived
        return derived
    }

    companion object {
        private const val DEFAULT_ITERATIONS = 600_000  // OWASP 2023 floor for PBKDF2-HMAC-SHA256
        internal const val NONCE_SIZE = 16  // auxiliary layers; base AEAD uses 12-byte nonce
        internal const val MAC_SIZE = 16
        internal const val KEY_SIZE = 32
        internal const val SALT_SIZE = 16

        // Authenticated version bytes (leading byte of the ciphertext).
        internal const val VERSION_PASSWORD: Byte = 0x03  // 0x03 || suite || salt(16) || nonce(12) || ct||tag
        internal const val VERSION_KEY: Byte = 0x13       // 0x13 || suite || nonce(12) || ct||tag

        // Cipher-suite identifiers.
        internal const val SUITE_AES_GCM: Byte = 0x01
        internal const val SUITE_CHACHA20_POLY1305: Byte = 0x02

        private const val MIN_PADDING = 32
        private const val MAX_PADDING = 128
        private const val DEFAULT_MAX_AGE_MS = 60000L

        // Base-AEAD constants.
        private const val AEAD_NONCE_SIZE = 12
        private const val TAG_SIZE = 16
        private const val INNER_HEADER_SIZE = 9 // timestamp(8) + pad_len(1)
        private val HKDF_AEAD_INFO = "shield/aead/v4".toByteArray(Charsets.UTF_8)

        private val random = SecureRandom()

        /** Create Shield instance from password and service name (password mode). */
        @JvmStatic
        @JvmOverloads
        fun create(
            password: String,
            service: String,
            iterations: Int = DEFAULT_ITERATIONS
        ): Shield {
            val salt = randomBytes(SALT_SIZE)
            val pbkdf2Salt = salt + service.toByteArray(Charsets.UTF_8)
            val key = pbkdf2(password, pbkdf2Salt, iterations, KEY_SIZE)
            return Shield(key, password, service, iterations, salt, DEFAULT_MAX_AGE_MS)
        }

        /** Create Shield with pre-shared key (pre-shared-key mode, no password/salt). */
        @JvmStatic
        fun withKey(key: ByteArray): Shield {
            require(key.size == KEY_SIZE) { "Key must be $KEY_SIZE bytes, got ${key.size}" }
            return Shield(key.copyOf(), null, null, 0, null, DEFAULT_MAX_AGE_MS)
        }

        /** Quick encrypt with pre-shared key (pre-shared-key mode, AES-256-GCM, 0x13). */
        @JvmStatic
        fun quickEncrypt(key: ByteArray, plaintext: ByteArray): ByteArray {
            require(key.size == KEY_SIZE) { "Key must be $KEY_SIZE bytes" }
            return seal(deriveAeadKey(key), SUITE_AES_GCM, null, plaintext)
        }

        /** Quick decrypt with pre-shared key (pre-shared-key mode). */
        @JvmStatic
        fun quickDecrypt(key: ByteArray, ciphertext: ByteArray): ByteArray {
            require(key.size == KEY_SIZE) { "Key must be $KEY_SIZE bytes" }
            if (ciphertext.isEmpty() || ciphertext[0] != VERSION_KEY) {
                throw ShieldException.AuthenticationFailed()
            }
            if (ciphertext.size < 2 + AEAD_NONCE_SIZE + TAG_SIZE) throw ShieldException.CiphertextTooShort()
            return openCiphertext(deriveAeadKey(key), ciphertext[1], ciphertext, 2, null)
        }

        /** AEAD key = HKDF-SHA256-Expand(master, "shield/aead/v4", 32) (single HKDF block). */
        internal fun deriveAeadKey(masterKey: ByteArray): ByteArray =
            hmacSha256(masterKey, HKDF_AEAD_INFO + byteArrayOf(0x01)).copyOf(KEY_SIZE)

        /** Build the AEAD additional data (= wire prefix before the nonce). */
        private fun buildAad(suite: Byte, salt: ByteArray?): ByteArray =
            if (salt != null) byteArrayOf(VERSION_PASSWORD, suite) + salt
            else byteArrayOf(VERSION_KEY, suite)

        private fun samplePadLen(): Int {
            val padRange = MAX_PADDING - MIN_PADDING + 1 // 97
            while (true) {
                val v = random.nextInt() and 0xFF
                if (v < padRange * (256 / padRange)) {
                    return (v % padRange) + MIN_PADDING
                }
            }
        }

        /** Seal with a fresh random nonce, timestamp and padding. */
        private fun seal(aeadKey: ByteArray, suite: Byte, salt: ByteArray?, plaintext: ByteArray): ByteArray {
            val nonce = randomBytes(AEAD_NONCE_SIZE)
            val padLen = samplePadLen()
            val padding = randomBytes(padLen)
            return sealDeterministic(aeadKey, suite, salt, nonce, System.currentTimeMillis(),
                padLen, padding, plaintext)
        }

        /**
         * Deterministic AEAD seal over fully specified inputs (used for conformance
         * vectors and wrapped by the randomized seal).
         */
        internal fun sealDeterministic(
            aeadKey: ByteArray, suite: Byte, salt: ByteArray?, nonce: ByteArray,
            timestampMs: Long, padLen: Int, padding: ByteArray, plaintext: ByteArray
        ): ByteArray {
            val aad = buildAad(suite, salt)
            val tsBytes = ByteArray(8)
            ByteBuffer.wrap(tsBytes).order(ByteOrder.LITTLE_ENDIAN).putLong(timestampMs)
            val inner = tsBytes + byteArrayOf(padLen.toByte()) + padding + plaintext
            val ctTag = aeadSeal(suite, aeadKey, nonce, aad, inner)
            return aad + nonce + ctTag
        }

        /**
         * Open an AEAD ciphertext, validate the inner layout and freshness window.
         * aadLen is the offset of the nonce (= len(version||suite||[salt])).
         */
        internal fun openCiphertext(aeadKey: ByteArray, suite: Byte, encrypted: ByteArray, aadLen: Int, maxAgeMs: Long?): ByteArray {
            if (encrypted.size < aadLen + AEAD_NONCE_SIZE + TAG_SIZE) throw ShieldException.CiphertextTooShort()
            val aad = encrypted.copyOfRange(0, aadLen)
            val nonce = encrypted.copyOfRange(aadLen, aadLen + AEAD_NONCE_SIZE)
            val ctTag = encrypted.copyOfRange(aadLen + AEAD_NONCE_SIZE, encrypted.size)

            val inner = aeadOpen(suite, aeadKey, nonce, aad, ctTag)

            if (inner.size < INNER_HEADER_SIZE) throw ShieldException.AuthenticationFailed()
            val tsBytes = inner.copyOfRange(0, 8)
            val timestampMs = ByteBuffer.wrap(tsBytes).order(ByteOrder.LITTLE_ENDIAN).getLong()
            val padLen = inner[8].toInt() and 0xFF
            if (padLen < MIN_PADDING || padLen > MAX_PADDING) throw ShieldException.AuthenticationFailed()
            val dataStart = INNER_HEADER_SIZE + padLen
            if (inner.size < dataStart) throw ShieldException.CiphertextTooShort()

            if (maxAgeMs != null) {
                val nowMs = System.currentTimeMillis()
                val age = nowMs - timestampMs
                if (timestampMs > nowMs + 5000 || age > maxAgeMs) {
                    throw ShieldException.AuthenticationFailed()
                }
            }

            return inner.copyOfRange(dataStart, inner.size)
        }

        /** AEAD seal: returns ciphertext||tag. */
        private fun aeadSeal(suite: Byte, key: ByteArray, nonce: ByteArray, aad: ByteArray, plaintext: ByteArray): ByteArray {
            return try {
                val cipher = aeadCipher(suite, Cipher.ENCRYPT_MODE, key, nonce)
                cipher.updateAAD(aad)
                cipher.doFinal(plaintext)
            } catch (e: GeneralSecurityException) {
                throw ShieldException.AuthenticationFailed()
            }
        }

        /** AEAD open: returns plaintext, throws on auth failure. */
        private fun aeadOpen(suite: Byte, key: ByteArray, nonce: ByteArray, aad: ByteArray, ctTag: ByteArray): ByteArray {
            return try {
                val cipher = aeadCipher(suite, Cipher.DECRYPT_MODE, key, nonce)
                cipher.updateAAD(aad)
                cipher.doFinal(ctTag)
            } catch (e: GeneralSecurityException) {
                throw ShieldException.AuthenticationFailed()
            }
        }

        private fun aeadCipher(suite: Byte, mode: Int, key: ByteArray, nonce: ByteArray): Cipher {
            return when (suite) {
                SUITE_AES_GCM -> Cipher.getInstance("AES/GCM/NoPadding").apply {
                    init(mode, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_SIZE * 8, nonce))
                }
                SUITE_CHACHA20_POLY1305 -> {
                    // Android runtime registers "ChaCha20/Poly1305/NoPadding"; the JDK
                    // (used by local unit tests) registers "ChaCha20-Poly1305". Try both.
                    val cipher = try {
                        Cipher.getInstance("ChaCha20/Poly1305/NoPadding")
                    } catch (e: GeneralSecurityException) {
                        Cipher.getInstance("ChaCha20-Poly1305")
                    }
                    cipher.init(mode, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce))
                    cipher
                }
                else -> throw GeneralSecurityException("Unknown cipher suite")
            }
        }

        private fun toHex(data: ByteArray): String {
            val sb = StringBuilder(data.size * 2)
            for (b in data) {
                sb.append("0123456789abcdef"[(b.toInt() shr 4) and 0xF])
                sb.append("0123456789abcdef"[b.toInt() and 0xF])
            }
            return sb.toString()
        }

        private fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(key, "HmacSHA256"))
            return mac.doFinal(data)
        }

        private fun randomBytes(length: Int): ByteArray {
            val bytes = ByteArray(length)
            random.nextBytes(bytes)
            return bytes
        }

        private fun pbkdf2(password: String, salt: ByteArray, iterations: Int, keyLength: Int): ByteArray {
            val spec = PBEKeySpec(password.toCharArray(), salt, iterations, keyLength * 8)
            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            return factory.generateSecret(spec).encoded
        }
    }

    /** Encrypt plaintext (password or pre-shared-key mode). */
    fun encrypt(plaintext: ByteArray): ByteArray = seal(aeadKey, suite, salt, plaintext)

    /**
     * Decrypt and verify, dispatching on the leading authenticated version byte.
     * Hard-rejects any unknown version byte (no legacy heuristic fallback).
     */
    fun decrypt(encrypted: ByteArray): ByteArray {
        if (encrypted.isEmpty()) throw ShieldException.CiphertextTooShort()

        return when (encrypted[0]) {
            VERSION_PASSWORD -> {
                if (salt == null) {
                    throw ShieldException.AuthenticationFailed()
                }
                val aadLen = 2 + SALT_SIZE
                if (encrypted.size < aadLen + AEAD_NONCE_SIZE + TAG_SIZE) throw ShieldException.CiphertextTooShort()
                val msgSuite = encrypted[1]
                val msgSalt = encrypted.copyOfRange(2, 2 + SALT_SIZE)
                val derivedKey = deriveKey(msgSalt)
                val derivedAead = deriveAeadKey(derivedKey)
                openCiphertext(derivedAead, msgSuite, encrypted, aadLen, maxAgeMs)
            }
            VERSION_KEY -> {
                if (encrypted.size < 2 + AEAD_NONCE_SIZE + TAG_SIZE) throw ShieldException.CiphertextTooShort()
                openCiphertext(aeadKey, encrypted[1], encrypted, 2, maxAgeMs)
            }
            else -> throw ShieldException.AuthenticationFailed()
        }
    }
}

/**
 * Shield cryptographic utility functions.
 */
object ShieldUtils {
    const val KEY_SIZE = 32

    /**
     * Generate cryptographically secure random bytes.
     */
    @JvmStatic
    fun randomBytes(length: Int): ByteArray {
        return ByteArray(length).also { SecureRandom().nextBytes(it) }
    }

    /**
     * SHA256 hash.
     */
    @JvmStatic
    fun sha256(data: ByteArray): ByteArray {
        return MessageDigest.getInstance("SHA-256").digest(data)
    }

    /**
     * Constant-time byte array comparison.
     */
    @JvmStatic
    fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var result = 0
        for (i in a.indices) {
            result = result or (a[i].toInt() xor b[i].toInt())
        }
        return result == 0
    }

    /**
     * Securely wipe sensitive data from memory.
     */
    @JvmStatic
    fun secureWipe(data: ByteArray) {
        data.fill(0)
    }

    /**
     * PBKDF2-SHA256 key derivation.
     */
    @JvmStatic
    fun pbkdf2(password: String, salt: ByteArray, iterations: Int, keyLength: Int): ByteArray {
        val spec = javax.crypto.spec.PBEKeySpec(
            password.toCharArray(),
            salt,
            iterations,
            keyLength * 8
        )
        val factory = javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        return factory.generateSecret(spec).encoded
    }
}

/**
 * Shield exceptions.
 */
sealed class ShieldException(message: String) : Exception(message) {
    class InvalidKeySize : ShieldException("Invalid key size")
    class CiphertextTooShort : ShieldException("Ciphertext too short")
    class AuthenticationFailed : ShieldException("Authentication failed")
    class ReplayDetected : ShieldException("Replay attack detected")
    class OutOfOrder : ShieldException("Out of order message")
    class TokenExpired : ShieldException("Token expired")
    class InvalidToken : ShieldException("Invalid token")
    class SessionExpired : ShieldException("Session expired")
}
