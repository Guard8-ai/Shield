package ai.guard8.shield

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest

/**
 * RatchetSession provides forward secrecy through key ratcheting.
 */
class RatchetSession(rootKey: ByteArray, private val isInitiator: Boolean) : AutoCloseable {
    private var sendKey: ByteArray
    private var recvKey: ByteArray
    var sendCounter: Long = 0
        private set
    var recvCounter: Long = 0
        private set

    init {
        require(rootKey.size == Shield.KEY_SIZE) { "Invalid key size" }

        if (isInitiator) {
            sendKey = deriveChainKey(rootKey, "init_send")
            recvKey = deriveChainKey(rootKey, "init_recv")
        } else {
            sendKey = deriveChainKey(rootKey, "init_recv")
            recvKey = deriveChainKey(rootKey, "init_send")
        }
    }

    fun encrypt(plaintext: ByteArray): ByteArray {
        val messageKey = deriveChainKey(sendKey, "message")
        val nonce = Shield.randomBytes(Shield.NONCE_SIZE)

        // Generate keystream and XOR
        val keystream = generateKeystream(messageKey, nonce, plaintext.size)
        val ciphertext = ByteArray(plaintext.size)
        for (i in plaintext.indices) {
            ciphertext[i] = (plaintext[i].toInt() xor keystream[i].toInt()).toByte()
        }

        // Counter bytes
        val counterBytes = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(sendCounter).array()

        // MAC over counter || nonce || ciphertext
        val macData = counterBytes + nonce + ciphertext
        val mac = Shield.hmacSha256(messageKey, macData)

        // Ratchet
        sendKey = deriveChainKey(sendKey, "ratchet")
        sendCounter++

        // Format: counter(8) || nonce(16) || ciphertext || mac(16)
        return counterBytes + nonce + ciphertext + mac.copyOf(Shield.MAC_SIZE)
    }

    fun decrypt(encrypted: ByteArray): ByteArray {
        require(encrypted.size >= 8 + Shield.NONCE_SIZE + Shield.MAC_SIZE) { "Ciphertext too short" }

        // Parse
        val counter = ByteBuffer.wrap(encrypted, 0, 8).order(ByteOrder.LITTLE_ENDIAN).long
        val nonce = encrypted.copyOfRange(8, 8 + Shield.NONCE_SIZE)
        val ciphertext = encrypted.copyOfRange(8 + Shield.NONCE_SIZE, encrypted.size - Shield.MAC_SIZE)
        val receivedMac = encrypted.copyOfRange(encrypted.size - Shield.MAC_SIZE, encrypted.size)

        // Check counter
        if (counter < recvCounter) throw ShieldException.ReplayDetected()
        if (counter > recvCounter) throw ShieldException.OutOfOrder()

        val messageKey = deriveChainKey(recvKey, "message")

        // Verify MAC
        val macData = encrypted.copyOfRange(0, 8) + nonce + ciphertext
        val expectedMac = Shield.hmacSha256(messageKey, macData).copyOf(Shield.MAC_SIZE)

        if (!Shield.constantTimeEquals(receivedMac, expectedMac)) {
            throw ShieldException.AuthenticationFailed()
        }

        // Decrypt
        val keystream = generateKeystream(messageKey, nonce, ciphertext.size)
        val plaintext = ByteArray(ciphertext.size)
        for (i in ciphertext.indices) {
            plaintext[i] = (ciphertext[i].toInt() xor keystream[i].toInt()).toByte()
        }

        // Ratchet
        recvKey = deriveChainKey(recvKey, "ratchet")
        recvCounter++

        return plaintext
    }

    override fun close() {
        Shield.secureWipe(sendKey)
        Shield.secureWipe(recvKey)
    }

    companion object {
        private fun deriveChainKey(key: ByteArray, info: String): ByteArray {
            val md = MessageDigest.getInstance("SHA-256")
            md.update(key)
            md.update(info.toByteArray())
            return md.digest()
        }

        private fun generateKeystream(key: ByteArray, nonce: ByteArray, length: Int): ByteArray {
            val numBlocks = (length + 31) / 32
            val keystream = ByteArray(numBlocks * 32)

            for (i in 0 until numBlocks) {
                val block = ByteArray(Shield.KEY_SIZE + Shield.NONCE_SIZE + 4)
                System.arraycopy(key, 0, block, 0, Shield.KEY_SIZE)
                System.arraycopy(nonce, 0, block, Shield.KEY_SIZE, Shield.NONCE_SIZE)
                ByteBuffer.wrap(block, Shield.KEY_SIZE + Shield.NONCE_SIZE, 4)
                    .order(ByteOrder.LITTLE_ENDIAN)
                    .putInt(i)

                val hash = Shield.sha256(block)
                System.arraycopy(hash, 0, keystream, i * 32, 32)
            }

            return keystream.copyOf(length)
        }
    }
}
