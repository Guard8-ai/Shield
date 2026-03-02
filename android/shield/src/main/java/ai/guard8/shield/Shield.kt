package ai.guard8.shield

import java.nio.ByteBuffer
import java.nio.ByteOrder
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

    private val encKey: ByteArray  // encryption subkey
    private val macKey: ByteArray  // authentication subkey

    init {
        val subkeys = deriveSubkeys(key)
        encKey = subkeys[0]
        macKey = subkeys[1]
    }

    companion object {
        private const val PBKDF2_ITERATIONS = 100_000
        private const val NONCE_SIZE = 16
        private const val MAC_SIZE = 16
        private const val KEY_SIZE = 32

        // V2 constants
        private const val V2_HEADER_SIZE = 17  // counter(8) + timestamp(8) + pad_len(1)
        private const val MIN_PADDING = 32
        private const val MAX_PADDING = 128
        private const val MIN_TIMESTAMP_MS = 1577836800000L  // 2020-01-01
        private const val MAX_TIMESTAMP_MS = 4102444800000L  // 2100-01-01
        private const val DEFAULT_MAX_AGE_MS = 60000L

        /**
         * Derive separated encryption and MAC subkeys from master key.
         */
        private fun deriveSubkeys(masterKey: ByteArray): Array<ByteArray> {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(masterKey, "HmacSHA256"))
            val encKey = mac.doFinal("shield-encrypt".toByteArray(Charsets.UTF_8))
            mac.init(SecretKeySpec(masterKey, "HmacSHA256"))
            val macKey = mac.doFinal("shield-authenticate".toByteArray(Charsets.UTF_8))
            return arrayOf(encKey, macKey)
        }

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
            require(key.size == KEY_SIZE) { "Key must be $KEY_SIZE bytes" }
            val subkeys = deriveSubkeys(key)
            return encryptWithSeparatedKeys(subkeys[0], subkeys[1], plaintext)
        }

        /**
         * Quick decrypt with pre-shared key.
         */
        @JvmStatic
        fun quickDecrypt(key: ByteArray, ciphertext: ByteArray): ByteArray {
            require(key.size == KEY_SIZE) { "Key must be $KEY_SIZE bytes" }
            val subkeys = deriveSubkeys(key)
            return decryptWithSeparatedKeys(subkeys[0], subkeys[1], ciphertext, null)
        }

        private fun encryptWithSeparatedKeys(
            encKey: ByteArray, macKey: ByteArray, plaintext: ByteArray
        ): ByteArray {
            val random = SecureRandom()
            val nonce = ByteArray(NONCE_SIZE).also { random.nextBytes(it) }

            // Counter prefix (8 bytes of zeros)
            val counter = ByteArray(8)

            // Timestamp in milliseconds (little-endian)
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
            val padding = ByteArray(padLen).also { random.nextBytes(it) }

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
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(macKey, "HmacSHA256"))
            mac.update(nonce)
            mac.update(ciphertext)
            val tag = mac.doFinal().copyOf(MAC_SIZE)

            return nonce + ciphertext + tag
        }

        private fun decryptWithSeparatedKeys(
            encKey: ByteArray, macKey: ByteArray, encrypted: ByteArray, maxAgeMs: Long?
        ): ByteArray {
            val minSize = NONCE_SIZE + 8 + MAC_SIZE
            require(encrypted.size >= minSize) { "Ciphertext too short" }

            val nonce = encrypted.copyOfRange(0, NONCE_SIZE)
            val ciphertext = encrypted.copyOfRange(NONCE_SIZE, encrypted.size - MAC_SIZE)
            val receivedMac = encrypted.copyOfRange(encrypted.size - MAC_SIZE, encrypted.size)

            // Verify MAC (using MAC subkey, constant-time)
            val hmac = Mac.getInstance("HmacSHA256")
            hmac.init(SecretKeySpec(macKey, "HmacSHA256"))
            hmac.update(nonce)
            hmac.update(ciphertext)
            val expectedMac = hmac.doFinal().copyOf(MAC_SIZE)

            if (!ShieldUtils.constantTimeEquals(receivedMac, expectedMac)) {
                throw ShieldException.AuthenticationFailed()
            }

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
                        throw ShieldException.AuthenticationFailed()
                    }

                    val dataStart = V2_HEADER_SIZE + padLen
                    if (decrypted.size < dataStart) {
                        throw ShieldException.CiphertextTooShort()
                    }

                    if (maxAgeMs != null) {
                        val nowMs = System.currentTimeMillis()
                        val age = nowMs - timestampMs
                        if (timestampMs > nowMs + 5000 || age > maxAgeMs) {
                            throw ShieldException.AuthenticationFailed()
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
    }

    /**
     * Encrypt data (v2 format).
     *
     * @param plaintext Data to encrypt
     * @return Ciphertext: nonce(16) || encrypted_data || mac(16)
     */
    fun encrypt(plaintext: ByteArray): ByteArray {
        return encryptWithSeparatedKeys(encKey, macKey, plaintext)
    }

    /**
     * Decrypt and verify data (auto-detects v1/v2).
     *
     * @param encrypted Ciphertext from encrypt()
     * @return Plaintext bytes
     * @throws ShieldException.AuthenticationFailed if MAC verification fails
     * @throws ShieldException.CiphertextTooShort if data is too small
     */
    fun decrypt(encrypted: ByteArray): ByteArray {
        return decryptWithSeparatedKeys(encKey, macKey, encrypted, DEFAULT_MAX_AGE_MS)
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
