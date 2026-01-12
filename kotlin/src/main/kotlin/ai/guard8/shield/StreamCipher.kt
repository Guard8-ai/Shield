package ai.guard8.shield

import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * StreamCipher - Streaming encryption for large files.
 *
 * Processes data in chunks with constant memory usage.
 * Each chunk is independently authenticated, allowing:
 * - Early detection of tampering
 * - Constant memory regardless of file size
 * - Potential for parallel processing
 */
class StreamCipher private constructor(
    private val key: ByteArray,
    private val chunkSize: Int
) : AutoCloseable {

    companion object {
        const val DEFAULT_CHUNK_SIZE = 64 * 1024 // 64KB
        private const val NONCE_SIZE = 16
        private const val MAC_SIZE = 16
        private const val HEADER_SIZE = 20 // 4 chunk_size + 16 salt

        private val random = SecureRandom()

        /**
         * Create StreamCipher with encryption key.
         */
        fun create(key: ByteArray, chunkSize: Int = DEFAULT_CHUNK_SIZE): StreamCipher {
            require(key.size == 32) { "Key must be 32 bytes" }
            return StreamCipher(key.copyOf(), chunkSize)
        }

        /**
         * Create StreamCipher from password.
         */
        fun fromPassword(password: String, salt: ByteArray, chunkSize: Int = DEFAULT_CHUNK_SIZE): StreamCipher {
            val key = deriveKey(password, salt)
            return StreamCipher(key, chunkSize)
        }

        private fun deriveKey(password: String, salt: ByteArray): ByteArray {
            val spec = PBEKeySpec(password.toCharArray(), salt, 100_000, 256)
            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            return factory.generateSecret(spec).encoded
        }

        private fun deriveChunkKey(key: ByteArray, salt: ByteArray, chunkNum: Long): ByteArray {
            val data = ByteBuffer.allocate(32 + 16 + 8).order(ByteOrder.LITTLE_ENDIAN)
            data.put(key)
            data.put(salt)
            data.putLong(chunkNum)
            return sha256(data.array())
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
     * Encrypt data in memory.
     */
    fun encrypt(data: ByteArray): ByteArray {
        val output = mutableListOf<Byte>()

        // Header: chunk_size(4) || stream_salt(16)
        val streamSalt = randomBytes(16)
        val header = ByteBuffer.allocate(HEADER_SIZE).order(ByteOrder.LITTLE_ENDIAN)
        header.putInt(chunkSize)
        header.put(streamSalt)
        output.addAll(header.array().toList())

        var offset = 0
        var chunkNum = 0L

        while (offset < data.size) {
            val end = minOf(offset + chunkSize, data.size)
            val chunk = data.copyOfRange(offset, end)

            // Derive per-chunk key
            val chunkKey = deriveChunkKey(key, streamSalt, chunkNum)

            // Encrypt chunk
            val encrypted = encryptBlock(chunkKey, chunk)

            // Prepend length
            val lenBuf = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN)
            lenBuf.putInt(encrypted.size)
            output.addAll(lenBuf.array().toList())
            output.addAll(encrypted.toList())

            offset = end
            chunkNum++
        }

        // End marker
        val endMarker = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN)
        endMarker.putInt(0)
        output.addAll(endMarker.array().toList())

        return output.toByteArray()
    }

    /**
     * Decrypt data in memory.
     */
    fun decrypt(encrypted: ByteArray): ByteArray {
        require(encrypted.size >= HEADER_SIZE + 4) { "Encrypted data too short" }

        val output = mutableListOf<Byte>()
        val buf = ByteBuffer.wrap(encrypted).order(ByteOrder.LITTLE_ENDIAN)

        // Read header
        val storedChunkSize = buf.int
        val streamSalt = ByteArray(16)
        buf.get(streamSalt)

        var chunkNum = 0L

        while (buf.remaining() >= 4) {
            val encLen = buf.int
            if (encLen == 0) break // End marker

            require(buf.remaining() >= encLen) { "Incomplete chunk" }

            val encryptedChunk = ByteArray(encLen)
            buf.get(encryptedChunk)

            // Derive per-chunk key
            val chunkKey = deriveChunkKey(key, streamSalt, chunkNum)

            // Decrypt chunk
            val decrypted = decryptBlock(chunkKey, encryptedChunk)
                ?: throw SecurityException("Chunk $chunkNum authentication failed")

            output.addAll(decrypted.toList())
            chunkNum++
        }

        return output.toByteArray()
    }

    /**
     * Encrypt a file.
     */
    fun encryptFile(inPath: String, outPath: String) {
        FileInputStream(inPath).use { input ->
            FileOutputStream(outPath).use { output ->
                // Header
                val streamSalt = randomBytes(16)
                val header = ByteBuffer.allocate(HEADER_SIZE).order(ByteOrder.LITTLE_ENDIAN)
                header.putInt(chunkSize)
                header.put(streamSalt)
                output.write(header.array())

                val buffer = ByteArray(chunkSize)
                var chunkNum = 0L
                var bytesRead: Int

                while (input.read(buffer).also { bytesRead = it } > 0) {
                    val chunk = if (bytesRead == buffer.size) buffer else buffer.copyOf(bytesRead)

                    val chunkKey = deriveChunkKey(key, streamSalt, chunkNum)
                    val encrypted = encryptBlock(chunkKey, chunk)

                    val lenBuf = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN)
                    lenBuf.putInt(encrypted.size)
                    output.write(lenBuf.array())
                    output.write(encrypted)

                    chunkNum++
                }

                // End marker
                val endMarker = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN)
                endMarker.putInt(0)
                output.write(endMarker.array())
            }
        }
    }

    /**
     * Decrypt a file.
     */
    fun decryptFile(inPath: String, outPath: String) {
        FileInputStream(inPath).use { input ->
            FileOutputStream(outPath).use { output ->
                // Read header
                val headerBytes = ByteArray(HEADER_SIZE)
                require(input.read(headerBytes) == HEADER_SIZE) { "Incomplete header" }

                val header = ByteBuffer.wrap(headerBytes).order(ByteOrder.LITTLE_ENDIAN)
                val storedChunkSize = header.int
                val streamSalt = ByteArray(16)
                header.get(streamSalt)

                val lenBytes = ByteArray(4)
                var chunkNum = 0L

                while (input.read(lenBytes) == 4) {
                    val encLen = ByteBuffer.wrap(lenBytes).order(ByteOrder.LITTLE_ENDIAN).int
                    if (encLen == 0) break

                    val encrypted = ByteArray(encLen)
                    require(input.read(encrypted) == encLen) { "Incomplete chunk" }

                    val chunkKey = deriveChunkKey(key, streamSalt, chunkNum)
                    val decrypted = decryptBlock(chunkKey, encrypted)
                        ?: throw SecurityException("Chunk $chunkNum authentication failed")

                    output.write(decrypted)
                    chunkNum++
                }
            }
        }
    }

    override fun close() {
        key.fill(0)
    }
}
