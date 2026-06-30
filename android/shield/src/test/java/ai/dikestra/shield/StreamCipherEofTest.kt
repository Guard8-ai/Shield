package ai.dikestra.shield

import org.junit.Assert.*
import org.junit.Test

/**
 * Tests for the authenticated end-of-stream tag in StreamCipher.
 */
class StreamCipherEofTest {

    // Cross-language golden vector:
    //   master_key = 32 x 0x42, stream_salt = 16 x 0x01, chunk_count = 3
    private val expectedTagHex =
        "52d4dfbeccc364bd69a2f232aa460bd1eb79b0c93903f344dd7b937703918431"

    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

    private fun computeEofTag(key: ByteArray, salt: ByteArray, count: Long): ByteArray {
        val comp = StreamCipher.Companion
        val m = comp.javaClass.getDeclaredMethod(
            "computeEofTag", ByteArray::class.java, ByteArray::class.java, Long::class.javaPrimitiveType
        )
        m.isAccessible = true
        return m.invoke(comp, key, salt, count) as ByteArray
    }

    @Test
    fun testEofTagConformanceVector() {
        val key = ByteArray(32) { 0x42 }
        val salt = ByteArray(16) { 0x01 }
        assertEquals(expectedTagHex, hex(computeEofTag(key, salt, 3L)))
    }

    @Test
    fun testStreamRoundtrip() {
        val key = ByteArray(32) { 0x42 }
        StreamCipher.create(key, 16).use { sc ->
            val data = ByteArray(64) { it.toByte() }
            assertArrayEquals(data, sc.decrypt(sc.encrypt(data)))
        }
    }

    @Test
    fun testTruncationAtChunkBoundaryRejected() {
        val key = ByteArray(32) { 0x42 }
        StreamCipher.create(key, 16).use { sc ->
            val data = ByteArray(64) { it.toByte() }
            val enc = sc.encrypt(data)
            val truncated = enc.copyOf(enc.size - 36) // drop marker + tag
            assertThrows(Exception::class.java) { sc.decrypt(truncated) }
        }
    }

    @Test
    fun testForgedEndMarkerRejected() {
        val key = ByteArray(32) { 0x42 }
        StreamCipher.create(key, 16).use { sc ->
            val data = ByteArray(64) { it.toByte() }
            val enc = sc.encrypt(data)
            val forged = enc.copyOf(enc.size - 36 + 4) // bare zero marker, no tag
            assertThrows(Exception::class.java) { sc.decrypt(forged) }
        }
    }
}
