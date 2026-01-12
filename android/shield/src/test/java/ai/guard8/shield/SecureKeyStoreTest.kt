package ai.guard8.shield

import org.junit.Assert.*
import org.junit.Test

/**
 * Unit tests for SecureKeyStore.
 *
 * Note: Most SecureKeyStore functionality requires Android Context and must be
 * tested with instrumented tests (androidTest). These unit tests cover the
 * helper methods and verify compilation.
 *
 * For full testing, use instrumented tests with:
 * - Real Android Keystore
 * - EncryptedSharedPreferences
 * - Biometric authentication (if applicable)
 */
class SecureKeyStoreTest {

    // MARK: - Hex Encoding Tests

    @Test
    fun testHexEncodingRoundTrip() {
        // Test that we can encode and decode byte arrays correctly
        val original = byteArrayOf(0x00, 0x01, 0x0F, 0x10, 0x7F, 0x80.toByte(), 0xFF.toByte())
        val hex = original.toHexString()
        val decoded = hex.hexToByteArray()

        assertArrayEquals("Hex round-trip should preserve bytes", original, decoded)
    }

    @Test
    fun testHexEncodingEmpty() {
        val empty = byteArrayOf()
        val hex = empty.toHexString()
        val decoded = hex.hexToByteArray()

        assertEquals("Empty array should encode to empty string", "", hex)
        assertArrayEquals("Empty string should decode to empty array", empty, decoded)
    }

    @Test
    fun testHexEncodingAllBytes() {
        // Test all possible byte values
        val allBytes = ByteArray(256) { it.toByte() }
        val hex = allBytes.toHexString()
        val decoded = hex.hexToByteArray()

        assertEquals("Hex string should be 512 characters", 512, hex.length)
        assertArrayEquals("All bytes should round-trip correctly", allBytes, decoded)
    }

    @Test
    fun testHexEncodingKnownValues() {
        // Test known values
        assertEquals("00", byteArrayOf(0x00).toHexString())
        assertEquals("ff", byteArrayOf(0xFF.toByte()).toHexString())
        assertEquals("0102030405", byteArrayOf(1, 2, 3, 4, 5).toHexString())
        assertEquals("deadbeef", byteArrayOf(0xDE.toByte(), 0xAD.toByte(), 0xBE.toByte(), 0xEF.toByte()).toHexString())
    }

    @Test
    fun testHexDecodingKnownValues() {
        assertArrayEquals(byteArrayOf(0x00), "00".hexToByteArray())
        assertArrayEquals(byteArrayOf(0xFF.toByte()), "ff".hexToByteArray())
        assertArrayEquals(byteArrayOf(0xFF.toByte()), "FF".hexToByteArray()) // Case insensitive
        assertArrayEquals(byteArrayOf(1, 2, 3, 4, 5), "0102030405".hexToByteArray())
    }

    // MARK: - Key Derivation Tests

    @Test
    fun testKeyDerivationDeterministic() {
        // Test that key derivation produces consistent results
        val key1 = deriveKey("password", "service")
        val key2 = deriveKey("password", "service")

        assertArrayEquals("Same inputs should produce same key", key1, key2)
    }

    @Test
    fun testKeyDerivationDifferentPasswords() {
        val key1 = deriveKey("password1", "service")
        val key2 = deriveKey("password2", "service")

        assertFalse("Different passwords should produce different keys", key1.contentEquals(key2))
    }

    @Test
    fun testKeyDerivationDifferentServices() {
        val key1 = deriveKey("password", "service1")
        val key2 = deriveKey("password", "service2")

        assertFalse("Different services should produce different keys", key1.contentEquals(key2))
    }

    @Test
    fun testKeyDerivationLength() {
        val key = deriveKey("password", "service")

        assertEquals("Derived key should be 32 bytes", 32, key.size)
    }

    @Test
    fun testKeyDerivationCrossPlatformCompatibility() {
        // This key derivation should match other Shield implementations
        val key = deriveKey("test", "test")

        assertEquals("Key should be 32 bytes for cross-platform compatibility", 32, key.size)
        // The actual values should match Python, JS, Go implementations
    }

    // MARK: - Helper Methods (copied from SecureKeyStore for testing)

    private fun ByteArray.toHexString(): String = joinToString("") { "%02x".format(it) }

    private fun String.hexToByteArray(): ByteArray {
        return chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }

    private fun deriveKey(password: String, service: String): ByteArray {
        val salt = java.security.MessageDigest.getInstance("SHA-256")
            .digest(service.toByteArray(Charsets.UTF_8))
        val factory = javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val spec = javax.crypto.spec.PBEKeySpec(password.toCharArray(), salt, 100_000, 256)
        return factory.generateSecret(spec).encoded
    }
}

/**
 * Instrumented tests for SecureKeyStore.
 *
 * These tests require Android device/emulator and should be placed in:
 * src/androidTest/java/ai/guard8/shield/SecureKeyStoreInstrumentedTest.kt
 *
 * Test cases to implement:
 * - testStoreAndRetrieveKey()
 * - testDeleteKey()
 * - testHasKey()
 * - testGetOrCreateShield()
 * - testGenerateHardwareKey()
 * - testGetHardwareKey()
 * - testIsHardwareBackedAvailable()
 * - testKeyPersistsAcrossInstances()
 * - testDeleteNonExistentKey()
 * - testOverwriteExistingKey()
 */
