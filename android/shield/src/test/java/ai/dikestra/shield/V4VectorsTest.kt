package ai.dikestra.shield

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Conformance: reproduce the Rust-generated v4 vectors byte-for-byte.
 *
 * Dependency-free: scans each object inside the deterministic arrays of
 * tests/v4_test_vectors.json and extracts fields with regular expressions.
 * Runs on the local JVM (testDebugUnitTest), so the JCE AEADs are available.
 */
class V4VectorsTest {

    private fun vectorsFile(): File {
        var dir: File? = File("").absoluteFile
        repeat(8) {
            if (dir != null) {
                val candidate = File(dir, "tests/v4_test_vectors.json")
                if (candidate.exists()) return candidate
                dir = dir!!.parentFile
            }
        }
        throw RuntimeException("v4_test_vectors.json not found")
    }

    private fun str(obj: String, field: String): String? =
        Regex("\"$field\"\\s*:\\s*\"([^\"]*)\"").find(obj)?.groupValues?.get(1)

    private fun num(obj: String, field: String): Long =
        Regex("\"$field\"\\s*:\\s*(\\d+)").find(obj)?.groupValues?.get(1)?.toLong() ?: 0L

    private fun objectsInArray(json: String, arrayName: String): List<String> {
        val objects = mutableListOf<String>()
        val key = json.indexOf("\"$arrayName\"")
        if (key < 0) return objects
        val start = json.indexOf('[', key)
        var depth = 0
        var objStart = -1
        var i = start
        while (i < json.length) {
            when (json[i]) {
                '[' -> depth++
                ']' -> { depth--; if (depth == 0) break }
                '{' -> if (objStart < 0) objStart = i
                '}' -> if (objStart >= 0) { objects.add(json.substring(objStart, i + 1)); objStart = -1 }
            }
            i++
        }
        return objects
    }

    private fun allVectors(): List<String> {
        val json = vectorsFile().readText()
        return objectsInArray(json, "deterministic_vectors") +
            objectsInArray(json, "deterministic_vectors_chacha")
    }

    private fun hex(s: String): ByteArray =
        ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    private fun toHex(b: ByteArray): String = b.joinToString("") { "%02x".format(it) }

    private fun suiteByte(obj: String): Byte =
        if (str(obj, "suite") == "0x02") Shield.SUITE_CHACHA20_POLY1305 else Shield.SUITE_AES_GCM

    private fun masterFor(obj: String): ByteArray {
        return if (str(obj, "mode") == "password") {
            val salt = hex(str(obj, "salt_hex")!!)
            val pbkdf2Salt = salt + str(obj, "service")!!.toByteArray(Charsets.UTF_8)
            ShieldUtils.pbkdf2(str(obj, "password")!!, pbkdf2Salt, num(obj, "iterations").toInt(), 32)
        } else {
            hex(str(obj, "key_hex")!!)
        }
    }

    @Test
    fun testKdfVectors() {
        val vectors = allVectors()
        assertTrue("expected vectors loaded", vectors.size >= 6)
        for (v in vectors) {
            val master = masterFor(v)
            assertEquals("master drift ${str(v, "name")}", str(v, "master_key_hex"), toHex(master))
            assertEquals("aead drift ${str(v, "name")}", str(v, "aead_key_hex"), toHex(Shield.deriveAeadKey(master)))
        }
    }

    @Test
    fun testReproduceBytes() {
        for (v in allVectors()) {
            val aeadKey = Shield.deriveAeadKey(masterFor(v))
            val salt = if (str(v, "mode") == "password") hex(str(v, "salt_hex")!!) else null
            val out = Shield.sealDeterministic(
                aeadKey, suiteByte(v), salt, hex(str(v, "nonce_hex")!!),
                num(v, "timestamp_ms"), num(v, "pad_len").toInt(),
                hex(str(v, "padding_hex")!!), hex(str(v, "plaintext_hex")!!)
            )
            assertEquals("BYTE DRIFT ${str(v, "name")}", str(v, "expected_output_hex"), toHex(out))
        }
    }

    @Test
    fun testDecryptVectors() {
        for (v in allVectors()) {
            val aeadKey = Shield.deriveAeadKey(masterFor(v))
            val encrypted = hex(str(v, "expected_output_hex")!!)
            val aadLen = if (str(v, "mode") == "password") 2 + Shield.SALT_SIZE else 2
            val opened = Shield.openCiphertext(aeadKey, suiteByte(v), encrypted, aadLen, null)
            assertEquals("decrypt failed ${str(v, "name")}", str(v, "plaintext_hex"), toHex(opened))
        }
    }
}
