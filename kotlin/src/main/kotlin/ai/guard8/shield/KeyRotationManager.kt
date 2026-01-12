package ai.guard8.shield

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * KeyRotationManager - Version-based key management.
 *
 * Supports seamless key rotation without breaking existing encrypted data.
 * Each ciphertext is tagged with the key version used.
 *
 * Ciphertext format: version(4) || nonce(16) || ciphertext || mac(16)
 */
class KeyRotationManager private constructor(
    key: ByteArray,
    version: Int
) : AutoCloseable {

    private val keys = mutableMapOf<Int, ByteArray>()
    private var _currentVersion: Int = version

    val currentVersion: Int get() = _currentVersion
    val versions: List<Int> get() = keys.keys.sorted()

    init {
        keys[version] = key.copyOf()
    }

    companion object {
        private const val NONCE_SIZE = 16
        private const val MAC_SIZE = 16
        private const val MIN_CIPHERTEXT_SIZE = 4 + NONCE_SIZE + MAC_SIZE
        private val random = SecureRandom()

        /**
         * Create with initial key.
         */
        fun create(key: ByteArray, version: Int = 1): KeyRotationManager {
            require(key.size == 32) { "Key must be 32 bytes" }
            return KeyRotationManager(key, version)
        }

        private fun generateKeystream(key: ByteArray, nonce: ByteArray, length: Int): ByteArray {
            val numBlocks = (length + 31) / 32
            val keystream = ByteArray(numBlocks * 32)

            for (i in 0 until numBlocks) {
                val block = ByteBuffer.allocate(32 + NONCE_SIZE + 4).order(ByteOrder.LITTLE_ENDIAN)
                block.put(key)
                block.put(nonce)
                block.putInt(i)
                val hash = sha256(block.array())
                System.arraycopy(hash, 0, keystream, i * 32, 32)
            }

            return keystream.copyOf(length)
        }

        private fun sha256(data: ByteArray): ByteArray {
            return MessageDigest.getInstance("SHA-256").digest(data)
        }

        private fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(key, "HmacSHA256"))
            return mac.doFinal(data)
        }

        private fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
            if (a.size != b.size) return false
            var result = 0
            for (i in a.indices) {
                result = result or (a[i].toInt() xor b[i].toInt())
            }
            return result == 0
        }

        private fun randomBytes(length: Int): ByteArray {
            val bytes = ByteArray(length)
            random.nextBytes(bytes)
            return bytes
        }
    }

    /**
     * Add historical key for decryption.
     */
    fun addKey(key: ByteArray, version: Int) {
        require(!keys.containsKey(version)) { "Version $version already exists" }
        keys[version] = key.copyOf()
    }

    /**
     * Rotate to new key.
     */
    fun rotate(newKey: ByteArray, newVersion: Int? = null): Int {
        val version = newVersion ?: (_currentVersion + 1)
        require(version > _currentVersion) { "New version must be greater than current" }
        keys[version] = newKey.copyOf()
        _currentVersion = version
        return version
    }

    /**
     * Encrypt with current key (includes version tag).
     */
    fun encrypt(plaintext: ByteArray): ByteArray {
        val key = keys[_currentVersion]!!
        val nonce = randomBytes(NONCE_SIZE)

        // Generate keystream and encrypt
        val keystream = generateKeystream(key, nonce, plaintext.size)
        val ciphertext = ByteArray(plaintext.size)
        for (i in plaintext.indices) {
            ciphertext[i] = (plaintext[i].toInt() xor keystream[i].toInt()).toByte()
        }

        // Version bytes
        val versionBuf = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN)
        versionBuf.putInt(_currentVersion)
        val versionBytes = versionBuf.array()

        // HMAC authenticate (includes version)
        val macData = versionBytes + nonce + ciphertext
        val mac = hmacSha256(key, macData)

        // Result: version || nonce || ciphertext || mac
        return versionBytes + nonce + ciphertext + mac.copyOf(MAC_SIZE)
    }

    /**
     * Decrypt with appropriate key version.
     */
    fun decrypt(encrypted: ByteArray): ByteArray {
        require(encrypted.size >= MIN_CIPHERTEXT_SIZE) { "Ciphertext too short" }

        // Parse version
        val version = ByteBuffer.wrap(encrypted, 0, 4).order(ByteOrder.LITTLE_ENDIAN).int
        val nonce = encrypted.copyOfRange(4, 4 + NONCE_SIZE)
        val ciphertext = encrypted.copyOfRange(4 + NONCE_SIZE, encrypted.size - MAC_SIZE)
        val receivedMac = encrypted.copyOfRange(encrypted.size - MAC_SIZE, encrypted.size)

        val key = keys[version] ?: throw IllegalArgumentException("Unknown key version: $version")

        // Verify MAC
        val macData = encrypted.copyOfRange(0, encrypted.size - MAC_SIZE)
        val expectedMac = hmacSha256(key, macData).copyOf(MAC_SIZE)

        require(constantTimeEquals(receivedMac, expectedMac)) { "Authentication failed" }

        // Decrypt
        val keystream = generateKeystream(key, nonce, ciphertext.size)
        val plaintext = ByteArray(ciphertext.size)
        for (i in ciphertext.indices) {
            plaintext[i] = (ciphertext[i].toInt() xor keystream[i].toInt()).toByte()
        }

        return plaintext
    }

    /**
     * Re-encrypt data with current key.
     */
    fun reEncrypt(encrypted: ByteArray): ByteArray {
        val plaintext = decrypt(encrypted)
        return encrypt(plaintext)
    }

    /**
     * Remove old keys, keeping only recent versions.
     */
    fun pruneOldKeys(keepVersions: Int = 2): List<Int> {
        require(keepVersions >= 1) { "Must keep at least 1 version" }

        val sortedVersions = keys.keys.sortedDescending()
        val toKeep = sortedVersions.take(keepVersions).toMutableSet()
        toKeep.add(_currentVersion)

        val pruned = mutableListOf<Int>()
        for (v in keys.keys.toList()) {
            if (v !in toKeep) {
                keys[v]?.fill(0)
                keys.remove(v)
                pruned.add(v)
            }
        }

        return pruned
    }

    override fun close() {
        keys.values.forEach { it.fill(0) }
        keys.clear()
    }
}
