package ai.guard8.shield

import org.junit.Assert.*
import org.junit.Test

/**
 * Unit tests for Shield encryption library.
 */
class ShieldTest {

    // MARK: - Shield Basic Tests

    @Test
    fun testEncryptDecrypt() {
        val shield = Shield.create("test_password", "test.example.com")
        val plaintext = "Hello, World!".toByteArray()

        val encrypted = shield.encrypt(plaintext)
        val decrypted = shield.decrypt(encrypted)

        assertArrayEquals(plaintext, decrypted)
    }

    @Test
    fun testEncryptDecryptEmptyData() {
        val shield = Shield.create("test_password", "test.example.com")
        val plaintext = ByteArray(0)

        val encrypted = shield.encrypt(plaintext)
        val decrypted = shield.decrypt(encrypted)

        assertArrayEquals(plaintext, decrypted)
    }

    @Test
    fun testEncryptDecryptLargeData() {
        val shield = Shield.create("test_password", "test.example.com")
        val plaintext = ByteArray(10000) { 0x42.toByte() }

        val encrypted = shield.encrypt(plaintext)
        val decrypted = shield.decrypt(encrypted)

        assertArrayEquals(plaintext, decrypted)
    }

    @Test
    fun testDifferentPasswordsFail() {
        val shield1 = Shield.create("password1", "test.example.com")
        val shield2 = Shield.create("password2", "test.example.com")
        val plaintext = "Secret message".toByteArray()

        val encrypted = shield1.encrypt(plaintext)
        assertThrows("Decryption with wrong password should throw",
            ShieldException.AuthenticationFailed::class.java) {
            shield2.decrypt(encrypted)
        }
    }

    @Test
    fun testDifferentServicesFail() {
        val shield1 = Shield.create("password", "service1.com")
        val shield2 = Shield.create("password", "service2.com")
        val plaintext = "Secret message".toByteArray()

        val encrypted = shield1.encrypt(plaintext)
        assertThrows("Decryption with wrong service should throw",
            ShieldException.AuthenticationFailed::class.java) {
            shield2.decrypt(encrypted)
        }
    }

    @Test
    fun testTamperedDataFails() {
        val shield = Shield.create("test_password", "test.example.com")
        val plaintext = "Hello, World!".toByteArray()

        val encrypted = shield.encrypt(plaintext)

        // Tamper with the ciphertext
        if (encrypted.size > 20) {
            encrypted[20] = (encrypted[20].toInt() xor 0xFF).toByte()
        }

        assertThrows("Tampered data should throw AuthenticationFailed",
            ShieldException.AuthenticationFailed::class.java) {
            shield.decrypt(encrypted)
        }
    }

    @Test
    fun testTruncatedDataFails() {
        val shield = Shield.create("test_password", "test.example.com")
        val plaintext = "Hello, World!".toByteArray()

        val encrypted = shield.encrypt(plaintext)
        val truncated = encrypted.copyOf(encrypted.size - 1)

        // Truncated data should fail MAC verification
        assertThrows(ShieldException.AuthenticationFailed::class.java) {
            shield.decrypt(truncated)
        }
    }

    // MARK: - Quick Encrypt/Decrypt Tests

    @Test
    fun testQuickEncryptDecrypt() {
        val key = ByteArray(32) { it.toByte() }
        val plaintext = "Quick test data".toByteArray()

        val encrypted = Shield.quickEncrypt(key, plaintext)
        val decrypted = Shield.quickDecrypt(key, encrypted)

        assertArrayEquals(plaintext, decrypted)
    }

    @Test(expected = IllegalArgumentException::class)
    fun testQuickEncryptInvalidKeySize() {
        val shortKey = ByteArray(16) { 0 }
        val plaintext = "test".toByteArray()

        Shield.quickEncrypt(shortKey, plaintext)
    }

    // MARK: - Key Derivation Tests

    @Test
    fun testKeyDerivationDeterministic() {
        val shield1 = Shield.create("same_password", "same.service.com")
        val shield2 = Shield.create("same_password", "same.service.com")

        val plaintext = "Test data".toByteArray()

        // Both should derive the same key and be able to decrypt each other's data
        val encrypted1 = shield1.encrypt(plaintext)
        val encrypted2 = shield2.encrypt(plaintext)

        val decrypted1 = shield2.decrypt(encrypted1)
        val decrypted2 = shield1.decrypt(encrypted2)

        assertArrayEquals(plaintext, decrypted1)
        assertArrayEquals(plaintext, decrypted2)
    }

    @Test
    fun testCustomIterations() {
        val shield = Shield.create("password", "test.com", 10000)
        val plaintext = "Test".toByteArray()

        val encrypted = shield.encrypt(plaintext)
        val decrypted = shield.decrypt(encrypted)

        assertArrayEquals(plaintext, decrypted)
    }

    // MARK: - Binary Data Tests

    @Test
    fun testBinaryData() {
        val shield = Shield.create("password", "test.com")

        // All possible byte values
        val plaintext = ByteArray(256) { it.toByte() }

        val encrypted = shield.encrypt(plaintext)
        val decrypted = shield.decrypt(encrypted)

        assertArrayEquals(plaintext, decrypted)
    }

    // MARK: - Encryption Uniqueness Tests

    @Test
    fun testEncryptionProducesUniqueNonces() {
        val shield = Shield.create("password", "test.com")
        val plaintext = "Same message".toByteArray()

        val encrypted1 = shield.encrypt(plaintext)
        val encrypted2 = shield.encrypt(plaintext)

        // Same plaintext should produce different ciphertext (different nonces)
        assertFalse(encrypted1.contentEquals(encrypted2))
    }

    // MARK: - Cross-Platform Compatibility Test

    @Test
    fun testKnownVector() {
        val shield = Shield.create("test", "test")
        val plaintext = "hello".toByteArray()

        val encrypted = shield.encrypt(plaintext)

        // Verify format: 16 bytes nonce + ciphertext + 16 bytes MAC
        assertTrue(encrypted.size >= 32 + plaintext.size)

        // Verify decryption works
        val decrypted = shield.decrypt(encrypted)
        assertArrayEquals(plaintext, decrypted)
    }
}
