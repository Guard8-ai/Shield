package ai.guard8.shield

import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Ratcheting session for forward secrecy.
 *
 * Each encrypt/decrypt advances the key chain,
 * destroying previous keys automatically.
 *
 * Security:
 * - Compromise of current key doesn't reveal past messages
 * - Each message encrypted with unique key
 * - Replay protection via counters
 *
 * Example:
 * ```kotlin
 * val rootKey = SecureRandom().let { ByteArray(32).also { b -> it.nextBytes(b) } }
 * val alice = RatchetSession(rootKey, isInitiator = true)
 * val bob = RatchetSession(rootKey, isInitiator = false)
 *
 * val encrypted = alice.encrypt("Hello Bob!".toByteArray())
 * val decrypted = bob.decrypt(encrypted)
 * ```
 */
class RatchetSession(
    rootKey: ByteArray,
    isInitiator: Boolean
) {

    private var sendChain: ByteArray
    private var recvChain: ByteArray
    private var _sendCounter: Long = 0
    private var _recvCounter: Long = 0

    /**
     * Current send counter (for diagnostics).
     */
    val sendCounter: Long get() = _sendCounter

    /**
     * Current receive counter (for diagnostics).
     */
    val recvCounter: Long get() = _recvCounter

    init {
        // Derive separate send/receive chains
        val (sendLabel, recvLabel) = if (isInitiator) {
            "send".toByteArray() to "recv".toByteArray()
        } else {
            "recv".toByteArray() to "send".toByteArray()
        }

        sendChain = deriveChainKey(rootKey, sendLabel)
        recvChain = deriveChainKey(rootKey, recvLabel)
    }

    /**
     * Encrypt a message with forward secrecy.
     *
     * Advances the send chain - previous keys are destroyed.
     *
     * @param plaintext Message to encrypt
     * @return Encrypted message
     *
     * Note:
     *   Each call advances the ratchet. The same plaintext
     *   will produce different ciphertext each time.
     */
    fun encrypt(plaintext: ByteArray): ByteArray {
        // Ratchet send chain
        val (newChain, msgKey) = ratchetChain(sendChain)
        sendChain = newChain

        // Counter for ordering
        val counter = _sendCounter
        _sendCounter++

        // Encrypt with message key
        return encryptWithKey(msgKey, plaintext, counter)
    }

    /**
     * Decrypt a message with forward secrecy.
     *
     * Advances the receive chain - previous keys are destroyed.
     *
     * @param ciphertext Encrypted message from encrypt()
     * @return Decrypted message, or null if authentication fails
     *         or message is out of order
     *
     * Note:
     *   Messages must be decrypted in order. Out-of-order
     *   messages will fail authentication.
     */
    fun decrypt(ciphertext: ByteArray): ByteArray? {
        // Ratchet receive chain
        val (newChain, msgKey) = ratchetChain(recvChain)
        recvChain = newChain

        // Decrypt with message key
        val result = decryptWithKey(msgKey, ciphertext) ?: return null

        val (plaintext, counter) = result

        // Verify counter (replay protection)
        if (counter != _recvCounter) {
            return null
        }

        _recvCounter++
        return plaintext
    }

    private fun deriveChainKey(root: ByteArray, label: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        md.update(root)
        md.update(label)
        return md.digest()
    }

    /**
     * Advance chain forward, returning (new_chain_key, message_key).
     * The old chain key is destroyed after this operation.
     */
    private fun ratchetChain(chainKey: ByteArray): Pair<ByteArray, ByteArray> {
        val md = MessageDigest.getInstance("SHA-256")

        md.reset()
        md.update(chainKey)
        md.update("chain".toByteArray())
        val newChain = md.digest()

        md.reset()
        md.update(chainKey)
        md.update("message".toByteArray())
        val msgKey = md.digest()

        return newChain to msgKey
    }

    private fun encryptWithKey(key: ByteArray, plaintext: ByteArray, counter: Long): ByteArray {
        val nonce = ByteArray(NONCE_SIZE).also { SecureRandom().nextBytes(it) }

        // Counter as 8-byte little-endian
        val counterBytes = ByteArray(8)
        for (i in 0..7) counterBytes[i] = (counter shr (i * 8)).toByte()

        // Data: counter || plaintext
        val data = counterBytes + plaintext

        // Generate keystream
        val keystream = generateKeystream(key, nonce, data.size)

        // XOR encrypt
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

    private fun decryptWithKey(key: ByteArray, encrypted: ByteArray): Pair<ByteArray, Long>? {
        if (encrypted.size < MIN_SIZE) return null

        val nonce = encrypted.copyOfRange(0, NONCE_SIZE)
        val ciphertext = encrypted.copyOfRange(NONCE_SIZE, encrypted.size - MAC_SIZE)
        val mac = encrypted.copyOfRange(encrypted.size - MAC_SIZE, encrypted.size)

        // Verify MAC
        val hmac = Mac.getInstance("HmacSHA256")
        hmac.init(SecretKeySpec(key, "HmacSHA256"))
        hmac.update(nonce)
        hmac.update(ciphertext)
        val expectedMac = hmac.doFinal().copyOf(MAC_SIZE)

        if (!constantTimeEquals(mac, expectedMac)) {
            return null
        }

        // Decrypt
        val keystream = generateKeystream(key, nonce, ciphertext.size)
        val decrypted = ByteArray(ciphertext.size)
        for (i in ciphertext.indices) {
            decrypted[i] = (ciphertext[i].toInt() xor keystream[i].toInt()).toByte()
        }

        // Parse counter (little-endian)
        var counter: Long = 0
        for (i in 0..7) {
            counter = counter or ((decrypted[i].toLong() and 0xFF) shl (i * 8))
        }

        return decrypted.copyOfRange(8, decrypted.size) to counter
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

    companion object {
        private const val NONCE_SIZE = 16
        private const val MAC_SIZE = 16
        private const val MIN_SIZE = NONCE_SIZE + 8 + MAC_SIZE  // nonce + counter + mac
    }
}
