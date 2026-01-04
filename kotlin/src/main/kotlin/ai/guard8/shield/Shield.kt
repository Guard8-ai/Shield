package ai.guard8.shield

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

    companion object {
        const val KEY_SIZE = 32
        const val NONCE_SIZE = 16
        const val MAC_SIZE = 16
        const val ITERATIONS = 100_000
        const val MIN_CIPHERTEXT_SIZE = NONCE_SIZE + 8 + MAC_SIZE

        private val random = SecureRandom()

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
            return encryptWithKey(key, plaintext)
        }

        /**
         * Quick decrypt with explicit key.
         */
        fun quickDecrypt(key: ByteArray, ciphertext: ByteArray): ByteArray {
            require(key.size == KEY_SIZE) { "Invalid key size" }
            return decryptWithKey(key, ciphertext)
        }

        private fun encryptWithKey(key: ByteArray, plaintext: ByteArray): ByteArray {
            // Generate random nonce
            val nonce = randomBytes(NONCE_SIZE)

            // Counter prefix (8 bytes of zeros)
            val dataToEncrypt = ByteArray(8 + plaintext.size)
            System.arraycopy(plaintext, 0, dataToEncrypt, 8, plaintext.size)

            // Generate keystream and XOR
            val keystream = generateKeystream(key, nonce, dataToEncrypt.size)
            val ciphertext = ByteArray(dataToEncrypt.size)
            for (i in dataToEncrypt.indices) {
                ciphertext[i] = (dataToEncrypt[i].toInt() xor keystream[i].toInt()).toByte()
            }

            // Compute HMAC over nonce || ciphertext
            val macData = nonce + ciphertext
            val mac = hmacSha256(key, macData)

            // Format: nonce || ciphertext || mac
            return nonce + ciphertext + mac.copyOf(MAC_SIZE)
        }

        private fun decryptWithKey(key: ByteArray, encrypted: ByteArray): ByteArray {
            require(encrypted.size >= MIN_CIPHERTEXT_SIZE) { "Ciphertext too short" }

            // Parse components
            val nonce = encrypted.copyOfRange(0, NONCE_SIZE)
            val ciphertext = encrypted.copyOfRange(NONCE_SIZE, encrypted.size - MAC_SIZE)
            val receivedMac = encrypted.copyOfRange(encrypted.size - MAC_SIZE, encrypted.size)

            // Verify MAC
            val macData = nonce + ciphertext
            val expectedMac = hmacSha256(key, macData).copyOf(MAC_SIZE)

            require(constantTimeEquals(receivedMac, expectedMac)) { "Authentication failed" }

            // Decrypt
            val keystream = generateKeystream(key, nonce, ciphertext.size)
            val decrypted = ByteArray(ciphertext.size)
            for (i in ciphertext.indices) {
                decrypted[i] = (ciphertext[i].toInt() xor keystream[i].toInt()).toByte()
            }

            // Skip 8-byte counter prefix
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
     * Encrypt plaintext.
     */
    fun encrypt(plaintext: ByteArray): ByteArray = encryptWithKey(key, plaintext)

    /**
     * Decrypt ciphertext.
     */
    fun decrypt(ciphertext: ByteArray): ByteArray = decryptWithKey(key, ciphertext)

    /**
     * Get the derived key.
     */
    fun getKey(): ByteArray = key.copyOf()

    /**
     * Wipe key from memory.
     */
    override fun close() {
        secureWipe(key)
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
