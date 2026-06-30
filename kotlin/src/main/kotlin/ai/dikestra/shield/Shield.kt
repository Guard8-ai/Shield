package ai.dikestra.shield

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * Shield - Authenticated Symmetric Encryption Library (wire format v4).
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
 */
class Shield private constructor(
    private val key: ByteArray,
    // Password-mode fields (null in pre-shared-key mode).
    private val password: String?,
    private val service: String?,
    private val iterations: Int,
    private val salt: ByteArray?,
    private val maxAgeMs: Long?
) : AutoCloseable {

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
        val serviceBytes = service!!.toByteArray()
        val pbkdf2Salt = saltBytes + serviceBytes
        val derived = pbkdf2(password!!, pbkdf2Salt, iterations, KEY_SIZE)
        keyCache[saltKey] = derived
        return derived
    }

    companion object {
        const val KEY_SIZE = 32
        // NONCE_SIZE/MAC_SIZE retained at 16 for API compatibility; the base AEAD
        // cipher uses its own 12-byte nonce / 16-byte tag (below).
        const val NONCE_SIZE = 16
        const val MAC_SIZE = 16
        const val SALT_SIZE = 16

        /** PBKDF2 iteration count (OWASP 2023 floor for PBKDF2-HMAC-SHA256). */
        const val ITERATIONS = 600_000

        // Authenticated version bytes (leading byte of the ciphertext).
        const val VERSION_PASSWORD: Byte = 0x03  // 0x03 || suite || salt(16) || nonce(12) || ct||tag
        const val VERSION_KEY: Byte = 0x13       // 0x13 || suite || nonce(12) || ct||tag

        // Cipher-suite identifiers.
        const val SUITE_AES_GCM: Byte = 0x01
        const val SUITE_CHACHA20_POLY1305: Byte = 0x02

        const val MIN_PADDING = 32
        const val MAX_PADDING = 128
        const val DEFAULT_MAX_AGE_MS = 60000L

        // Base-AEAD constants.
        private const val AEAD_NONCE_SIZE = 12
        private const val TAG_SIZE = 16
        private const val INNER_HEADER_SIZE = 9 // timestamp(8) + pad_len(1)
        private val HKDF_AEAD_INFO = "shield/aead/v4".toByteArray()

        private val random = SecureRandom()

        /** Create Shield from password and service name (password mode). */
        fun create(
            password: String,
            service: String,
            maxAgeMs: Long? = DEFAULT_MAX_AGE_MS
        ): Shield = createWithSalt(password, service, randomBytes(SALT_SIZE), ITERATIONS, maxAgeMs)

        /** Create Shield from password and service with an explicit salt and iteration count. */
        fun createWithSalt(
            password: String,
            service: String,
            salt: ByteArray,
            iterations: Int = ITERATIONS,
            maxAgeMs: Long? = DEFAULT_MAX_AGE_MS
        ): Shield {
            require(salt.size == SALT_SIZE) { "Salt must be $SALT_SIZE bytes" }
            val pbkdf2Salt = salt + service.toByteArray()
            val key = pbkdf2(password, pbkdf2Salt, iterations, KEY_SIZE)
            return Shield(key, password, service, iterations, salt.copyOf(), maxAgeMs)
        }

        /** Create Shield with pre-shared key (pre-shared-key mode, no password/salt). */
        fun withKey(key: ByteArray): Shield {
            require(key.size == KEY_SIZE) { "Invalid key size" }
            return Shield(key.copyOf(), null, null, 0, null, DEFAULT_MAX_AGE_MS)
        }

        /** Quick encrypt with explicit key (pre-shared-key mode, AES-256-GCM, 0x13). */
        fun quickEncrypt(key: ByteArray, plaintext: ByteArray): ByteArray {
            require(key.size == KEY_SIZE) { "Invalid key size" }
            return seal(deriveAeadKey(key), SUITE_AES_GCM, null, plaintext)
        }

        /** Quick decrypt with explicit key (pre-shared-key mode). */
        fun quickDecrypt(key: ByteArray, ciphertext: ByteArray): ByteArray {
            require(key.size == KEY_SIZE) { "Invalid key size" }
            require(ciphertext.isNotEmpty()) { "Ciphertext too short" }
            if (ciphertext[0] != VERSION_KEY) {
                throw SecurityException("Invalid version byte")
            }
            require(ciphertext.size >= 2 + AEAD_NONCE_SIZE + TAG_SIZE) { "Ciphertext too short" }
            return openCiphertext(deriveAeadKey(key), ciphertext[1], ciphertext, 2, null)
        }

        /** AEAD key = HKDF-SHA256-Expand(master, "shield/aead/v4", 32) (single HKDF block). */
        fun deriveAeadKey(masterKey: ByteArray): ByteArray =
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
        fun sealDeterministic(
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
        fun openCiphertext(aeadKey: ByteArray, suite: Byte, encrypted: ByteArray, aadLen: Int, maxAgeMs: Long?): ByteArray {
            require(encrypted.size >= aadLen + AEAD_NONCE_SIZE + TAG_SIZE) { "Ciphertext too short" }
            val aad = encrypted.copyOfRange(0, aadLen)
            val nonce = encrypted.copyOfRange(aadLen, aadLen + AEAD_NONCE_SIZE)
            val ctTag = encrypted.copyOfRange(aadLen + AEAD_NONCE_SIZE, encrypted.size)

            val inner = aeadOpen(suite, aeadKey, nonce, aad, ctTag)

            if (inner.size < INNER_HEADER_SIZE) {
                throw SecurityException("Authentication failed")
            }
            val tsBytes = inner.copyOfRange(0, 8)
            val timestampMs = ByteBuffer.wrap(tsBytes).order(ByteOrder.LITTLE_ENDIAN).getLong()
            val padLen = inner[8].toInt() and 0xFF
            if (padLen < MIN_PADDING || padLen > MAX_PADDING) {
                throw SecurityException("Authentication failed")
            }
            val dataStart = INNER_HEADER_SIZE + padLen
            if (inner.size < dataStart) {
                throw IllegalArgumentException("Ciphertext too short")
            }

            if (maxAgeMs != null) {
                val nowMs = System.currentTimeMillis()
                val age = nowMs - timestampMs
                if (timestampMs > nowMs + 5000 || age > maxAgeMs) {
                    throw SecurityException("Authentication failed")
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
            } catch (e: java.security.GeneralSecurityException) {
                throw SecurityException("AEAD seal failed", e)
            }
        }

        /** AEAD open: returns plaintext, throws SecurityException on auth failure. */
        private fun aeadOpen(suite: Byte, key: ByteArray, nonce: ByteArray, aad: ByteArray, ctTag: ByteArray): ByteArray {
            return try {
                val cipher = aeadCipher(suite, Cipher.DECRYPT_MODE, key, nonce)
                cipher.updateAAD(aad)
                cipher.doFinal(ctTag)
            } catch (e: java.security.GeneralSecurityException) {
                throw SecurityException("Authentication failed", e)
            }
        }

        private fun aeadCipher(suite: Byte, mode: Int, key: ByteArray, nonce: ByteArray): Cipher {
            return when (suite) {
                SUITE_AES_GCM -> Cipher.getInstance("AES/GCM/NoPadding").apply {
                    init(mode, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_SIZE * 8, nonce))
                }
                SUITE_CHACHA20_POLY1305 -> Cipher.getInstance("ChaCha20-Poly1305").apply {
                    init(mode, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce))
                }
                else -> throw java.security.GeneralSecurityException("Unknown cipher suite")
            }
        }

        // ============== Crypto Utilities ==============

        private fun toHex(data: ByteArray): String {
            val sb = StringBuilder(data.size * 2)
            for (b in data) {
                sb.append("0123456789abcdef"[(b.toInt() shr 4) and 0xF])
                sb.append("0123456789abcdef"[b.toInt() and 0xF])
            }
            return sb.toString()
        }

        fun sha256(data: ByteArray): ByteArray {
            return MessageDigest.getInstance("SHA-256").digest(data)
        }

        fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(key, "HmacSHA256"))
            return mac.doFinal(data)
        }

        fun pbkdf2(password: String, salt: ByteArray, iterations: Int, keyLength: Int): ByteArray {
            val spec = PBEKeySpec(password.toCharArray(), salt, iterations, keyLength * 8)
            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            return factory.generateSecret(spec).encoded
        }

        fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
            if (a.size != b.size) return false
            var result = 0
            for (i in a.indices) {
                result = result or (a[i].toInt() xor b[i].toInt())
            }
            return result == 0
        }

        fun randomBytes(length: Int): ByteArray {
            val bytes = ByteArray(length)
            random.nextBytes(bytes)
            return bytes
        }

        fun secureWipe(data: ByteArray) {
            data.fill(0)
        }
    }

    /** Encrypt plaintext (password or pre-shared-key mode). */
    fun encrypt(plaintext: ByteArray): ByteArray = seal(aeadKey, suite, salt, plaintext)

    /** Decrypt ciphertext, dispatching on the leading authenticated version byte. */
    fun decrypt(ciphertext: ByteArray): ByteArray {
        require(ciphertext.isNotEmpty()) { "Ciphertext too short" }

        when (ciphertext[0]) {
            VERSION_PASSWORD -> {
                if (salt == null) {
                    throw SecurityException("Cannot derive key without password")
                }
                val aadLen = 2 + SALT_SIZE
                require(ciphertext.size >= aadLen + AEAD_NONCE_SIZE + TAG_SIZE) { "Ciphertext too short" }
                val msgSuite = ciphertext[1]
                val msgSalt = ciphertext.copyOfRange(2, 2 + SALT_SIZE)
                val derivedKey = deriveKey(msgSalt)
                val derivedAead = deriveAeadKey(derivedKey)
                return openCiphertext(derivedAead, msgSuite, ciphertext, aadLen, maxAgeMs)
            }
            VERSION_KEY -> {
                require(ciphertext.size >= 2 + AEAD_NONCE_SIZE + TAG_SIZE) { "Ciphertext too short" }
                return openCiphertext(aeadKey, ciphertext[1], ciphertext, 2, maxAgeMs)
            }
            else -> throw SecurityException("Invalid version byte")
        }
    }

    /** Get the derived master key. */
    fun getKey(): ByteArray = key.copyOf()

    /** Wipe key material from memory. */
    override fun close() {
        secureWipe(key)
        secureWipe(aeadKey)
    }
}

/**
 * Shield errors.
 */
sealed class ShieldException(message: String) : Exception(message) {
    class InvalidKeySize : ShieldException("Invalid key size")
    class CiphertextTooShort : ShieldException("Ciphertext too short")
    class AuthenticationFailed : ShieldException("Authentication failed")
    class LamportKeyUsed : ShieldException("Lamport key already used")
    class ReplayDetected : ShieldException("Replay detected")
    class OutOfOrder : ShieldException("Out of order message")
    class TokenExpired : ShieldException("Token expired")
    class InvalidToken : ShieldException("Invalid token")
    class SessionExpired : ShieldException("Session expired")
}
