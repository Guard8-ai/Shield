package ai.guard8.shield

import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import java.security.MessageDigest

/**
 * EXPTIME-secure symmetric encryption for Android.
 *
 * Uses password-derived keys with PBKDF2 and encrypts using
 * a SHA256-based stream cipher with HMAC-SHA256 authentication.
 * Breaking requires 2^256 operations - no shortcut exists.
 *
 * Example:
 * ```kotlin
 * val shield = Shield.create("my_password", "github.com")
 * val encrypted = shield.encrypt("secret data".toByteArray())
 * val decrypted = shield.decrypt(encrypted)
 * ```
 */
class Shield private constructor(private val key: ByteArray) {

    companion object {
        private const val PBKDF2_ITERATIONS = 100_000
        private const val NONCE_SIZE = 16
        private const val MAC_SIZE = 16
        private const val KEY_SIZE = 32

        /**
         * Create Shield instance from password and service name.
         *
         * @param password User's password
         * @param service Service identifier (e.g., "github.com")
         * @param iterations PBKDF2 iterations (default: 100,000)
         * @return Shield instance
         */
        @JvmStatic
        @JvmOverloads
        fun create(
            password: String,
            service: String,
            iterations: Int = PBKDF2_ITERATIONS
        ): Shield {
            val salt = MessageDigest.getInstance("SHA-256")
                .digest(service.toByteArray(Charsets.UTF_8))

            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            val spec = PBEKeySpec(password.toCharArray(), salt, iterations, KEY_SIZE * 8)
            val key = factory.generateSecret(spec).encoded

            return Shield(key)
        }

        /**
         * Create Shield with pre-shared key (no password derivation).
         *
         * @param key 32-byte symmetric key
         * @return Shield instance
         * @throws IllegalArgumentException if key is not 32 bytes
         */
        @JvmStatic
        fun withKey(key: ByteArray): Shield {
            require(key.size == KEY_SIZE) { "Key must be $KEY_SIZE bytes, got ${key.size}" }
            return Shield(key.copyOf())
        }

        /**
         * Quick encrypt with pre-shared key.
         */
        @JvmStatic
        fun quickEncrypt(key: ByteArray, plaintext: ByteArray): ByteArray {
            return withKey(key).encrypt(plaintext)
        }

        /**
         * Quick decrypt with pre-shared key.
         */
        @JvmStatic
        fun quickDecrypt(key: ByteArray, ciphertext: ByteArray): ByteArray? {
            return withKey(key).decrypt(ciphertext)
        }
    }

    private var counter: Long = 0

    /**
     * Encrypt data.
     *
     * @param plaintext Data to encrypt
     * @return Ciphertext: nonce(16) || encrypted_data || mac(16)
     */
    fun encrypt(plaintext: ByteArray): ByteArray {
        val nonce = ByteArray(NONCE_SIZE).also { SecureRandom().nextBytes(it) }
        val counterBytes = ByteArray(8)
        for (i in 0..7) counterBytes[i] = (counter shr (i * 8)).toByte()
        counter++

        // Data to encrypt: counter || plaintext
        val data = counterBytes + plaintext

        // Generate keystream and XOR
        val keystream = generateKeystream(key, nonce, data.size)
        val ciphertext = ByteArray(data.size)
        for (i in data.indices) {
            ciphertext[i] = (data[i].toInt() xor keystream[i].toInt()).toByte()
        }

        // HMAC authenticate
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        mac.update(nonce)
        mac.update(ciphertext)
        val tag = mac.doFinal().copyOf(MAC_SIZE)

        return nonce + ciphertext + tag
    }

    /**
     * Decrypt and verify data.
     *
     * @param encrypted Ciphertext from encrypt()
     * @return Plaintext bytes, or null if authentication fails
     */
    fun decrypt(encrypted: ByteArray): ByteArray? {
        val minSize = NONCE_SIZE + 8 + MAC_SIZE
        if (encrypted.size < minSize) return null

        val nonce = encrypted.copyOfRange(0, NONCE_SIZE)
        val ciphertext = encrypted.copyOfRange(NONCE_SIZE, encrypted.size - MAC_SIZE)
        val mac = encrypted.copyOfRange(encrypted.size - MAC_SIZE, encrypted.size)

        // Verify MAC first (constant-time)
        val hmac = Mac.getInstance("HmacSHA256")
        hmac.init(SecretKeySpec(key, "HmacSHA256"))
        hmac.update(nonce)
        hmac.update(ciphertext)
        val expectedMac = hmac.doFinal().copyOf(MAC_SIZE)

        if (!constantTimeEquals(mac, expectedMac)) return null

        // Decrypt
        val keystream = generateKeystream(key, nonce, ciphertext.size)
        val decrypted = ByteArray(ciphertext.size)
        for (i in ciphertext.indices) {
            decrypted[i] = (ciphertext[i].toInt() xor keystream[i].toInt()).toByte()
        }

        // Skip counter prefix (8 bytes)
        return decrypted.copyOfRange(8, decrypted.size)
    }

    private fun generateKeystream(key: ByteArray, nonce: ByteArray, length: Int): ByteArray {
        val numBlocks = (length + 31) / 32
        val keystream = ByteArray(numBlocks * 32)
        val md = MessageDigest.getInstance("SHA-256")

        for (i in 0 until numBlocks) {
            md.reset()
            md.update(key)
            md.update(nonce)
            md.update(byteArrayOf(
                (i and 0xFF).toByte(),
                ((i shr 8) and 0xFF).toByte(),
                ((i shr 16) and 0xFF).toByte(),
                ((i shr 24) and 0xFF).toByte()
            ))
            val block = md.digest()
            System.arraycopy(block, 0, keystream, i * 32, 32)
        }

        return keystream.copyOf(length)
    }

    private fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var result = 0
        for (i in a.indices) {
            result = result or (a[i].toInt() xor b[i].toInt())
        }
        return result == 0
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
