package ai.guard8.shield

import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Ratcheting session for forward secrecy.
 *
 * Compatible with Shield Rust core (shield-core crate).
 *
 * Each encrypt/decrypt advances the key chain,
 * destroying previous keys automatically.
 *
 * Security:
 * - Compromise of current key doesn't reveal past messages
 * - Each message encrypted with unique key
 * - Replay protection via counters
 *
 * Wire format: nonce(16) || enc(counter || plaintext) || mac(16)
 * MAC computed over: nonce || ciphertext
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
) : AutoCloseable {

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
        require(rootKey.size == KEY_SIZE) { "Invalid key size" }

        // Match Rust core labels exactly: "send"/"recv"
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
     * @return Encrypted message in wire format: nonce(16) || enc(counter || plaintext) || mac(16)
     *
     * Note:
     *   Each call advances the ratchet. The same plaintext
     *   will produce different ciphertext each time.
     */
    fun encrypt(plaintext: ByteArray): ByteArray {
        // Ratchet BEFORE encrypt (matches Rust core)
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
     * @return Decrypted message
     * @throws ShieldException on authentication failure or replay/out-of-order
     *
     * Note:
     *   Messages must be decrypted in order. Out-of-order
     *   messages will fail with ShieldException.
     */
    fun decrypt(ciphertext: ByteArray): ByteArray {
        // Ratchet BEFORE decrypt (matches Rust core)
        val (newChain, msgKey) = ratchetChain(recvChain)
        recvChain = newChain

        // Decrypt with message key
        val (plaintext, counter) = decryptWithKey(msgKey, ciphertext)

        // Verify counter (replay protection)
        if (counter != _recvCounter) {
            throw ShieldException.OutOfOrder()
        }

        _recvCounter++
        return plaintext
    }

    override fun close() {
        secureWipe(sendChain)
        secureWipe(recvChain)
    }

    companion object {
        private const val KEY_SIZE = 32
        private const val NONCE_SIZE = 16
        private const val MAC_SIZE = 16
        private const val MIN_SIZE = NONCE_SIZE + 8 + MAC_SIZE // nonce + counter + mac

        private fun deriveChainKey(root: ByteArray, label: ByteArray): ByteArray {
            val md = MessageDigest.getInstance("SHA-256")
            md.update(root)
            md.update(label)
            return md.digest()
        }

        /**
         * Ratchet chain forward, returning (new_chain_key, message_key).
         * Matches Rust core: derives both new chain ("chain") and message key ("message").
         */
        private fun ratchetChain(chainKey: ByteArray): Pair<ByteArray, ByteArray> {
            val md = MessageDigest.getInstance("SHA-256")

            // New chain key: SHA256(chainKey || "chain")
            md.reset()
            md.update(chainKey)
            md.update("chain".toByteArray())
            val newChain = md.digest()

            // Message key: SHA256(chainKey || "message")
            md.reset()
            md.update(chainKey)
            md.update("message".toByteArray())
            val msgKey = md.digest()

            return newChain to msgKey
        }

        /**
         * Encrypt with message key.
         * Wire format: nonce(16) || enc(counter || plaintext) || mac(16)
         * MAC over: nonce || ciphertext
         */
        private fun encryptWithKey(key: ByteArray, plaintext: ByteArray, counter: Long): ByteArray {
            val nonce = ByteArray(NONCE_SIZE).also { SecureRandom().nextBytes(it) }

            // Counter as 8-byte little-endian
            val counterBytes = ByteArray(8)
            for (i in 0..7) counterBytes[i] = (counter shr (i * 8)).toByte()

            // Data to encrypt: counter || plaintext
            val data = counterBytes + plaintext

            // Generate keystream
            val keystream = generateKeystream(key, nonce, data.size)

            // XOR encrypt
            val ciphertext = ByteArray(data.size)
            for (i in data.indices) {
                ciphertext[i] = (data[i].toInt() xor keystream[i].toInt()).toByte()
            }

            // HMAC over nonce || ciphertext (matches Rust core)
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(key, "HmacSHA256"))
            mac.update(nonce)
            mac.update(ciphertext)
            val tag = mac.doFinal().copyOf(MAC_SIZE)

            // Wire format: nonce(16) || ciphertext || mac(16)
            return nonce + ciphertext + tag
        }

        /**
         * Decrypt with message key, returns (plaintext, counter).
         * Wire format: nonce(16) || ciphertext || mac(16)
         */
        private fun decryptWithKey(key: ByteArray, encrypted: ByteArray): Pair<ByteArray, Long> {
            if (encrypted.size < MIN_SIZE) {
                throw ShieldException.CiphertextTooShort()
            }

            val nonce = encrypted.copyOfRange(0, NONCE_SIZE)
            val ciphertext = encrypted.copyOfRange(NONCE_SIZE, encrypted.size - MAC_SIZE)
            val receivedMac = encrypted.copyOfRange(encrypted.size - MAC_SIZE, encrypted.size)

            // Verify MAC over nonce || ciphertext
            val hmac = Mac.getInstance("HmacSHA256")
            hmac.init(SecretKeySpec(key, "HmacSHA256"))
            hmac.update(nonce)
            hmac.update(ciphertext)
            val expectedMac = hmac.doFinal().copyOf(MAC_SIZE)

            if (!constantTimeEquals(receivedMac, expectedMac)) {
                throw ShieldException.AuthenticationFailed()
            }

            // Generate keystream
            val keystream = generateKeystream(key, nonce, ciphertext.size)

            // XOR decrypt
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

        private fun secureWipe(data: ByteArray) {
            data.fill(0)
        }
    }
}
