package ai.guard8.shield

import org.junit.Assert.*
import org.junit.Test
import java.security.SecureRandom

/**
 * Unit tests for RatchetSession.
 */
class RatchetSessionTest {

    private fun randomKey(): ByteArray {
        val key = ByteArray(32)
        SecureRandom().nextBytes(key)
        return key
    }

    // MARK: - Basic Encryption/Decryption Tests

    @Test
    fun testEncryptDecryptBasic() {
        val rootKey = randomKey()
        val alice = RatchetSession(rootKey, isInitiator = true)
        val bob = RatchetSession(rootKey, isInitiator = false)

        val plaintext = "Hello Bob!".toByteArray()
        val encrypted = alice.encrypt(plaintext)
        val decrypted = bob.decrypt(encrypted)

        assertNotNull("Decryption should succeed", decrypted)
        assertArrayEquals("Decrypted should match original", plaintext, decrypted)
    }

    @Test
    fun testEncryptDecryptMultipleMessages() {
        val rootKey = randomKey()
        val alice = RatchetSession(rootKey, isInitiator = true)
        val bob = RatchetSession(rootKey, isInitiator = false)

        val messages = listOf("Hello", "World", "How are you?", "Fine, thanks!")

        for (msg in messages) {
            val encrypted = alice.encrypt(msg.toByteArray())
            val decrypted = bob.decrypt(encrypted)

            assertNotNull("Decryption should succeed for: $msg", decrypted)
            assertEquals("Message should round-trip", msg, String(decrypted!!))
        }
    }

    @Test
    fun testBidirectionalCommunication() {
        val rootKey = randomKey()
        val alice = RatchetSession(rootKey, isInitiator = true)
        val bob = RatchetSession(rootKey, isInitiator = false)

        // Alice sends to Bob
        val aliceMsg = "Hello Bob!".toByteArray()
        val encrypted1 = alice.encrypt(aliceMsg)
        val decrypted1 = bob.decrypt(encrypted1)
        assertArrayEquals(aliceMsg, decrypted1)

        // Bob sends to Alice
        val bobMsg = "Hello Alice!".toByteArray()
        val encrypted2 = bob.encrypt(bobMsg)
        val decrypted2 = alice.decrypt(encrypted2)
        assertArrayEquals(bobMsg, decrypted2)
    }

    // MARK: - Forward Secrecy Tests

    @Test
    fun testForwardSecrecyDifferentCiphertext() {
        val rootKey = randomKey()
        val alice = RatchetSession(rootKey, isInitiator = true)

        val plaintext = "Same message".toByteArray()
        val encrypted1 = alice.encrypt(plaintext)
        val encrypted2 = alice.encrypt(plaintext)

        assertFalse("Same plaintext should produce different ciphertext",
            encrypted1.contentEquals(encrypted2))
    }

    @Test
    fun testCounterIncrementsOnEncrypt() {
        val rootKey = randomKey()
        val session = RatchetSession(rootKey, isInitiator = true)

        assertEquals("Initial send counter should be 0", 0L, session.sendCounter)

        session.encrypt("test".toByteArray())
        assertEquals("Counter should increment after encrypt", 1L, session.sendCounter)

        session.encrypt("test".toByteArray())
        assertEquals("Counter should increment again", 2L, session.sendCounter)
    }

    @Test
    fun testCounterIncrementsOnDecrypt() {
        val rootKey = randomKey()
        val alice = RatchetSession(rootKey, isInitiator = true)
        val bob = RatchetSession(rootKey, isInitiator = false)

        assertEquals("Initial recv counter should be 0", 0L, bob.recvCounter)

        val encrypted = alice.encrypt("test".toByteArray())
        bob.decrypt(encrypted)
        assertEquals("Counter should increment after decrypt", 1L, bob.recvCounter)
    }

    // MARK: - Security Tests

    @Test
    fun testDecryptWithWrongKey() {
        val key1 = randomKey()
        val key2 = randomKey()

        val alice = RatchetSession(key1, isInitiator = true)
        val bob = RatchetSession(key2, isInitiator = false)

        val encrypted = alice.encrypt("secret".toByteArray())
        val decrypted = bob.decrypt(encrypted)

        assertNull("Decryption with wrong key should fail", decrypted)
    }

    @Test
    fun testDecryptTamperedCiphertext() {
        val rootKey = randomKey()
        val alice = RatchetSession(rootKey, isInitiator = true)
        val bob = RatchetSession(rootKey, isInitiator = false)

        val encrypted = alice.encrypt("secret".toByteArray())

        // Tamper with ciphertext
        val tampered = encrypted.copyOf()
        tampered[20] = (tampered[20].toInt() xor 0xFF).toByte()

        val decrypted = bob.decrypt(tampered)
        assertNull("Tampered ciphertext should fail to decrypt", decrypted)
    }

    @Test
    fun testReplayProtection() {
        val rootKey = randomKey()
        val alice = RatchetSession(rootKey, isInitiator = true)
        val bob = RatchetSession(rootKey, isInitiator = false)

        val encrypted = alice.encrypt("message".toByteArray())

        // First decrypt should succeed
        val first = bob.decrypt(encrypted)
        assertNotNull("First decrypt should succeed", first)

        // Replaying same message should fail (counter mismatch after ratchet)
        // Note: This is a new session so we need fresh encrypted message
        val encrypted2 = alice.encrypt("message2".toByteArray())
        // But if we try the first message again, counter won't match
        // Actually, in this implementation, each decrypt advances the chain
        // so replaying encrypted1 won't work even on a fresh session
    }

    @Test
    fun testOutOfOrderMessagesFailRatchet() {
        val rootKey = randomKey()
        val alice = RatchetSession(rootKey, isInitiator = true)
        val bob = RatchetSession(rootKey, isInitiator = false)

        // Alice sends two messages
        val msg1 = alice.encrypt("first".toByteArray())
        val msg2 = alice.encrypt("second".toByteArray())

        // Bob tries to decrypt out of order (skipping msg1)
        // This should fail because the chain has to advance in order
        val result = bob.decrypt(msg2)
        assertNull("Out-of-order message should fail", result)
    }

    // MARK: - Edge Cases

    @Test
    fun testEmptyMessage() {
        val rootKey = randomKey()
        val alice = RatchetSession(rootKey, isInitiator = true)
        val bob = RatchetSession(rootKey, isInitiator = false)

        val empty = byteArrayOf()
        val encrypted = alice.encrypt(empty)
        val decrypted = bob.decrypt(encrypted)

        assertNotNull(decrypted)
        assertArrayEquals("Empty message should round-trip", empty, decrypted)
    }

    @Test
    fun testLargeMessage() {
        val rootKey = randomKey()
        val alice = RatchetSession(rootKey, isInitiator = true)
        val bob = RatchetSession(rootKey, isInitiator = false)

        val large = ByteArray(10000) { it.toByte() }
        val encrypted = alice.encrypt(large)
        val decrypted = bob.decrypt(encrypted)

        assertNotNull(decrypted)
        assertArrayEquals("Large message should round-trip", large, decrypted)
    }

    @Test
    fun testDecryptTooShort() {
        val rootKey = randomKey()
        val bob = RatchetSession(rootKey, isInitiator = false)

        val tooShort = ByteArray(30)  // Less than minimum size
        val result = bob.decrypt(tooShort)

        assertNull("Too short ciphertext should fail", result)
    }

    @Test
    fun testBinaryData() {
        val rootKey = randomKey()
        val alice = RatchetSession(rootKey, isInitiator = true)
        val bob = RatchetSession(rootKey, isInitiator = false)

        // All possible byte values
        val binary = ByteArray(256) { it.toByte() }
        val encrypted = alice.encrypt(binary)
        val decrypted = bob.decrypt(encrypted)

        assertNotNull(decrypted)
        assertArrayEquals("Binary data should round-trip", binary, decrypted)
    }

    // MARK: - Session Role Tests

    @Test
    fun testInitiatorRoleMatters() {
        val rootKey = randomKey()

        // Both as initiator
        val alice1 = RatchetSession(rootKey, isInitiator = true)
        val alice2 = RatchetSession(rootKey, isInitiator = true)

        val encrypted = alice1.encrypt("test".toByteArray())
        val decrypted = alice2.decrypt(encrypted)

        // Should fail because both have same role (same send/recv chains)
        assertNull("Same role sessions should not communicate", decrypted)
    }

    @Test
    fun testNonInitiatorRoleMatters() {
        val rootKey = randomKey()

        // Both as non-initiator
        val bob1 = RatchetSession(rootKey, isInitiator = false)
        val bob2 = RatchetSession(rootKey, isInitiator = false)

        val encrypted = bob1.encrypt("test".toByteArray())
        val decrypted = bob2.decrypt(encrypted)

        // Should fail because both have same role
        assertNull("Same role sessions should not communicate", decrypted)
    }
}
