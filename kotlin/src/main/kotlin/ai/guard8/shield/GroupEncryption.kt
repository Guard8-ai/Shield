package ai.guard8.shield

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * GroupEncryption - Multi-recipient encryption.
 *
 * Encrypt once for multiple recipients, each can decrypt with their own key.
 * Uses a group key for message encryption, then encrypts the group key
 * separately for each member.
 */
class GroupEncryption private constructor(private var groupKey: ByteArray) : AutoCloseable {

    private val members = mutableMapOf<String, ByteArray>()

    companion object {
        private const val NONCE_SIZE = 16
        private const val MAC_SIZE = 16
        private val random = SecureRandom()

        /**
         * Create group encryption with generated group key.
         */
        fun create(): GroupEncryption {
            return GroupEncryption(randomBytes(32))
        }

        /**
         * Create group encryption with specified group key.
         */
        fun create(groupKey: ByteArray): GroupEncryption {
            require(groupKey.size == 32) { "Group key must be 32 bytes" }
            return GroupEncryption(groupKey.copyOf())
        }

        /**
         * Decrypt as a group member.
         */
        @Suppress("UNCHECKED_CAST")
        fun decrypt(encrypted: Map<String, Any>, memberId: String, memberKey: ByteArray): ByteArray? {
            val keys = encrypted["keys"] as? Map<String, String> ?: return null
            val encryptedKeyB64 = keys[memberId] ?: return null

            // Decrypt group key
            val encryptedGroupKey = Base64.getDecoder().decode(encryptedKeyB64)
            val groupKey = decryptBlock(memberKey, encryptedGroupKey) ?: return null

            // Decrypt message
            val ciphertext = Base64.getDecoder().decode(encrypted["ciphertext"] as String)
            return decryptBlock(groupKey, ciphertext)
        }

        private fun encryptBlock(key: ByteArray, data: ByteArray): ByteArray {
            val nonce = randomBytes(NONCE_SIZE)
            val keystream = generateKeystream(key, nonce, data.size)
            val ciphertext = ByteArray(data.size)
            for (i in data.indices) {
                ciphertext[i] = (data[i].toInt() xor keystream[i].toInt()).toByte()
            }

            val macData = nonce + ciphertext
            val mac = hmacSha256(key, macData)

            return nonce + ciphertext + mac.copyOf(MAC_SIZE)
        }

        private fun decryptBlock(key: ByteArray, encrypted: ByteArray): ByteArray? {
            if (encrypted.size < NONCE_SIZE + MAC_SIZE) return null

            val nonce = encrypted.copyOfRange(0, NONCE_SIZE)
            val ciphertext = encrypted.copyOfRange(NONCE_SIZE, encrypted.size - MAC_SIZE)
            val receivedMac = encrypted.copyOfRange(encrypted.size - MAC_SIZE, encrypted.size)

            val macData = nonce + ciphertext
            val expectedMac = hmacSha256(key, macData).copyOf(MAC_SIZE)

            if (!constantTimeEquals(receivedMac, expectedMac)) return null

            val keystream = generateKeystream(key, nonce, ciphertext.size)
            val decrypted = ByteArray(ciphertext.size)
            for (i in ciphertext.indices) {
                decrypted[i] = (ciphertext[i].toInt() xor keystream[i].toInt()).toByte()
            }

            return decrypted
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
     * Add a member to the group.
     */
    fun addMember(memberId: String, sharedKey: ByteArray) {
        require(sharedKey.size == 32) { "Shared key must be 32 bytes" }
        members[memberId] = sharedKey.copyOf()
    }

    /**
     * Remove a member from the group.
     */
    fun removeMember(memberId: String): Boolean {
        return members.remove(memberId) != null
    }

    /**
     * Get list of member IDs.
     */
    fun getMembers(): List<String> = members.keys.toList()

    /**
     * Encrypt for all group members.
     */
    fun encrypt(plaintext: ByteArray): Map<String, Any> {
        // Encrypt message with group key
        val ciphertext = encryptBlock(groupKey, plaintext)

        // Encrypt group key for each member
        val encryptedKeys = mutableMapOf<String, String>()
        for ((memberId, memberKey) in members) {
            val encKey = encryptBlock(memberKey, groupKey)
            encryptedKeys[memberId] = Base64.getEncoder().encodeToString(encKey)
        }

        return mapOf(
            "version" to 1,
            "ciphertext" to Base64.getEncoder().encodeToString(ciphertext),
            "keys" to encryptedKeys
        )
    }

    /**
     * Rotate the group key.
     */
    fun rotateKey(): ByteArray {
        val oldKey = groupKey
        groupKey = randomBytes(32)
        return oldKey
    }

    override fun close() {
        groupKey.fill(0)
        members.values.forEach { it.fill(0) }
        members.clear()
    }
}
