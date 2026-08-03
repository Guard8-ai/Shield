package ai.dikestra.shield

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.File

/**
 * Conformance: the Kotlin post-quantum hybrid KEX must satisfy the shared
 * cross-language vectors (tests/pq_kex_vectors.json), proving byte-identical key
 * reconstruction and shared-key derivation against Python/Go/Rust/JS/C#/Java.
 */
class PqKexVectorsTest {

    private fun vectorsFile(): File {
        var dir: File? = File("").absoluteFile
        repeat(8) {
            if (dir == null) return@repeat
            val candidate = File(dir, "tests/pq_kex_vectors.json")
            if (candidate.exists()) return candidate
            dir = dir!!.parentFile
        }
        throw RuntimeException("pq_kex_vectors.json not found")
    }

    private fun all(json: String, field: String): List<String> =
        Regex("\"$field\"\\s*:\\s*\"([^\"]*)\"").findAll(json).map { it.groupValues[1] }.toList()

    private fun hex(h: String): ByteArray =
        ByteArray(h.length / 2) { h.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    private fun hx(b: ByteArray): String = b.joinToString("") { "%02x".format(it) }

    @Test
    fun reproducesAllVectors() {
        val json = vectorsFile().readText()
        val names = all(json, "name")
        val privs = all(json, "bob_private_hex")
        val bundles = all(json, "bob_public_bundle_hex")
        val handshakes = all(json, "handshake_hex")
        val shareds = all(json, "expected_shared_key_hex")
        assertTrue(privs.isNotEmpty(), "no vectors loaded")

        for (i in privs.indices) {
            val bob = HybridPrivateKey.fromBytes(hex(privs[i]))
            assertEquals(bundles[i], hx(bob.publicKey().toBytes()), "bundle mismatch for ${names[i]}")
            val shared = bob.accept(hex(handshakes[i]))
            assertEquals(shareds[i], hx(shared), "shared key mismatch for ${names[i]}")
        }
    }

    @Test
    fun initiateAcceptRoundTrips() {
        val bob = HybridPrivateKey.generate()
        val r = PqHybrid.initiate(bob.publicKey())
        assertEquals(PqHybrid.HANDSHAKE_SIZE, r.handshake.size)
        assertArrayEquals(r.sharedKey, bob.accept(r.handshake))
    }

    @Test
    fun privateKeySerializationRoundTrips() {
        val bob = HybridPrivateKey.generate()
        val restored = HybridPrivateKey.fromBytes(bob.toBytes())
        assertArrayEquals(bob.publicKey().toBytes(), restored.publicKey().toBytes())
        val r = PqHybrid.initiate(bob.publicKey())
        assertArrayEquals(r.sharedKey, restored.accept(r.handshake))
    }

    @Test
    fun rejectsWrongSizes() {
        val bob = HybridPrivateKey.generate()
        assertThrows(IllegalArgumentException::class.java) { bob.accept(ByteArray(10)) }
        assertThrows(IllegalArgumentException::class.java) { HybridPublicKey.fromBytes(ByteArray(10)) }
        assertThrows(IllegalArgumentException::class.java) { HybridPrivateKey.fromBytes(ByteArray(10)) }
    }
}
