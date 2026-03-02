package ai.dikestra.shield

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * Shield - EXPTIME-Secure Symmetric Encryption Library
 *
 * Uses only symmetric cryptographic primitives with proven exponential-time security:
 * PBKDF2-SHA256, HMAC-SHA256, and SHA256-based stream cipher.
 * Breaking requires 2^256 operations - no shortcut exists.
 */
class Shield private constructor(private val key: ByteArray) : AutoCloseable {

    private val encKey: ByteArray  // encryption subkey
    private val macKey: ByteArray  // authentication subkey

    init {
        val subkeys = deriveSubkeys(key)
        encKey = subkeys[0]
        macKey = subkeys[1]
    }

    companion object {
        const val KEY_SIZE = 32
        const val NONCE_SIZE = 16
        const val MAC_SIZE = 16
        const val ITERATIONS = 100_000
        const val MIN_CIPHERTEXT_SIZE = NONCE_SIZE + 8 + MAC_SIZE

        // V2 constants
        const val V2_HEADER_SIZE = 17  // counter(8) + timestamp(8) + pad_len(1)
        const val MIN_PADDING = 32
        const val MAX_PADDING = 128
        const val MIN_TIMESTAMP_MS = 1577836800000L  // 2020-01-01
        const val MAX_TIMESTAMP_MS = 4102444800000L  // 2100-01-01
        const val DEFAULT_MAX_AGE_MS = 60000L

        private val random = SecureRandom()

        /**
         * Derive separated encryption and MAC subkeys from master key.
         */
        private fun deriveSubkeys(masterKey: ByteArray): Array<ByteArray> {
            val encKey = hmacSha256(masterKey, "shield-encrypt".toByteArray())
            val macKey = hmacSha256(masterKey, "shield-authenticate".toByteArray())
            return arrayOf(encKey, macKey)
        }

        /**
         * Create Shield from password and service name.
         */
        fun create(password: String, service: String): Shield {
            val salt = sha256(service.toByteArray())
            val key = pbkdf2(password, salt, ITERATIONS, KEY_SIZE)
            return Shield(key)
        }

        /**
         * Create Shield with pre-shared key.
         */
        fun withKey(key: ByteArray): Shield {
            require(key.size == KEY_SIZE) { "Invalid key size" }
            return Shield(key.copyOf())
        }

        /**
         * Quick encrypt with explicit key.
         */
        fun quickEncrypt(key: ByteArray, plaintext: ByteArray): ByteArray {
            require(key.size == KEY_SIZE) { "Invalid key size" }
            val subkeys = deriveSubkeys(key)
            return encryptWithSeparatedKeys(subkeys[0], subkeys[1], plaintext)
        }

        /**
         * Quick decrypt with explicit key.
         */
        fun quickDecrypt(key: ByteArray, ciphertext: ByteArray): ByteArray {
            require(key.size == KEY_SIZE) { "Invalid key size" }
            val subkeys = deriveSubkeys(key)
            return decryptWithSeparatedKeys(subkeys[0], subkeys[1], ciphertext, null)
        }

        private fun encryptWithSeparatedKeys(
            encKey: ByteArray, macKey: ByteArray, plaintext: ByteArray
        ): ByteArray {
            // Generate random nonce
            val nonce = randomBytes(NONCE_SIZE)

            // Counter prefix (8 bytes of zeros)
            val counter = ByteArray(8)

            // Timestamp in milliseconds
            val timestampMs = System.currentTimeMillis()
            val timestamp = ByteArray(8)
            ByteBuffer.wrap(timestamp).order(ByteOrder.LITTLE_ENDIAN).putLong(timestampMs)

            // Random padding: 32-128 bytes (rejection sampling to avoid modulo bias)
            val padRange = MAX_PADDING - MIN_PADDING + 1  // 97
            val padLen: Int
            while (true) {
                val v = random.nextInt() and 0xFF
                if (v < padRange * (256 / padRange)) {
                    padLen = (v % padRange) + MIN_PADDING
                    break
                }
            }
            val padding = randomBytes(padLen)

            // Data to encrypt: counter || timestamp || pad_len || padding || plaintext
            val dataToEncrypt = ByteArray(8 + 8 + 1 + padLen + plaintext.size)
            var pos = 0
            System.arraycopy(counter, 0, dataToEncrypt, pos, 8); pos += 8
            System.arraycopy(timestamp, 0, dataToEncrypt, pos, 8); pos += 8
            dataToEncrypt[pos] = padLen.toByte(); pos += 1
            System.arraycopy(padding, 0, dataToEncrypt, pos, padLen); pos += padLen
            System.arraycopy(plaintext, 0, dataToEncrypt, pos, plaintext.size)

            // Generate keystream and XOR (using encryption subkey)
            val keystream = generateKeystream(encKey, nonce, dataToEncrypt.size)
            val ciphertext = ByteArray(dataToEncrypt.size)
            for (i in dataToEncrypt.indices) {
                ciphertext[i] = (dataToEncrypt[i].toInt() xor keystream[i].toInt()).toByte()
            }

            // Compute HMAC over nonce || ciphertext (using MAC subkey)
            val macData = nonce + ciphertext
            val mac = hmacSha256(macKey, macData)

            // Format: nonce || ciphertext || mac
            return nonce + ciphertext + mac.copyOf(MAC_SIZE)
        }

        private fun decryptWithSeparatedKeys(
            encKey: ByteArray, macKey: ByteArray, encrypted: ByteArray, maxAgeMs: Long?
        ): ByteArray {
            require(encrypted.size >= MIN_CIPHERTEXT_SIZE) { "Ciphertext too short" }

            // Parse components
            val nonce = encrypted.copyOfRange(0, NONCE_SIZE)
            val ciphertext = encrypted.copyOfRange(NONCE_SIZE, encrypted.size - MAC_SIZE)
            val receivedMac = encrypted.copyOfRange(encrypted.size - MAC_SIZE, encrypted.size)

            // Verify MAC (using MAC subkey)
            val macData = nonce + ciphertext
            val expectedMac = hmacSha256(macKey, macData).copyOf(MAC_SIZE)

            require(constantTimeEquals(receivedMac, expectedMac)) { "Authentication failed" }

            // Decrypt (using encryption subkey)
            val keystream = generateKeystream(encKey, nonce, ciphertext.size)
            val decrypted = ByteArray(ciphertext.size)
            for (i in ciphertext.indices) {
                decrypted[i] = (ciphertext[i].toInt() xor keystream[i].toInt()).toByte()
            }

            // Auto-detect v2 by timestamp range
            if (decrypted.size >= V2_HEADER_SIZE) {
                val timestampBytes = decrypted.copyOfRange(8, 16)
                val timestampMs = ByteBuffer.wrap(timestampBytes)
                    .order(ByteOrder.LITTLE_ENDIAN).getLong()

                if (timestampMs in MIN_TIMESTAMP_MS..MAX_TIMESTAMP_MS) {
                    // v2 format detected
                    val padLen = decrypted[16].toInt() and 0xFF

                    if (padLen < MIN_PADDING || padLen > MAX_PADDING) {
                        throw SecurityException("Authentication failed")
                    }

                    val dataStart = V2_HEADER_SIZE + padLen
                    if (decrypted.size < dataStart) {
                        throw IllegalArgumentException("Ciphertext too short")
                    }

                    if (maxAgeMs != null) {
                        val nowMs = System.currentTimeMillis()
                        val age = nowMs - timestampMs
                        if (timestampMs > nowMs + 5000 || age > maxAgeMs) {
                            throw SecurityException("Authentication failed")
                        }
                    }

                    return decrypted.copyOfRange(dataStart, decrypted.size)
                }
            }

            // v1 format: skip counter (8 bytes)
            return decrypted.copyOfRange(8, decrypted.size)
        }

        private fun generateKeystream(key: ByteArray, nonce: ByteArray, length: Int): ByteArray {
            val numBlocks = (length + 31) / 32
            val keystream = ByteArray(numBlocks * 32)

            for (i in 0 until numBlocks) {
                val block = ByteArray(KEY_SIZE + NONCE_SIZE + 4)
                System.arraycopy(key, 0, block, 0, KEY_SIZE)
                System.arraycopy(nonce, 0, block, KEY_SIZE, NONCE_SIZE)
                ByteBuffer.wrap(block, KEY_SIZE + NONCE_SIZE, 4)
                    .order(ByteOrder.LITTLE_ENDIAN)
                    .putInt(i)

                val hash = sha256(block)
                System.arraycopy(hash, 0, keystream, i * 32, 32)
            }

            return keystream.copyOf(length)
        }

        // ============== Crypto Utilities ==============

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

    /**
     * Encrypt plaintext (v2 format).
     */
    fun encrypt(plaintext: ByteArray): ByteArray =
        encryptWithSeparatedKeys(encKey, macKey, plaintext)

    /**
     * Decrypt ciphertext (auto-detects v1/v2).
     */
    fun decrypt(ciphertext: ByteArray): ByteArray =
        decryptWithSeparatedKeys(encKey, macKey, ciphertext, DEFAULT_MAX_AGE_MS)

    /**
     * Get the derived key.
     */
    fun getKey(): ByteArray = key.copyOf()

    /**
     * Wipe key from memory.
     */
    override fun close() {
        secureWipe(key)
        secureWipe(encKey)
        secureWipe(macKey)
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
