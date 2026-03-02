package ai.dikestra.shield

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

            assertEquals("Message should round-trip", msg, String(decrypted))
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
        assertThrows("Decryption with wrong key should throw AuthenticationFailed",
            ShieldException.AuthenticationFailed::class.java) {
            bob.decrypt(encrypted)
        }
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

        assertThrows("Tampered ciphertext should throw AuthenticationFailed",
            ShieldException.AuthenticationFailed::class.java) {
            bob.decrypt(tampered)
        }
    }

    @Test
    fun testReplayProtection() {
        val rootKey = randomKey()
        val alice = RatchetSession(rootKey, isInitiator = true)
        val bob = RatchetSession(rootKey, isInitiator = false)

        val encrypted = alice.encrypt("message".toByteArray())

        // First decrypt should succeed
        val first = bob.decrypt(encrypted)
        assertArrayEquals("First decrypt should succeed", "message".toByteArray(), first)

        // Replay fails: chain advanced → different msgKey → MAC mismatch
        assertThrows("Replayed message should throw AuthenticationFailed",
            ShieldException.AuthenticationFailed::class.java) {
            bob.decrypt(encrypted)
        }
    }

    @Test
    fun testOutOfOrderMessagesFail() {
        val rootKey = randomKey()
        val alice = RatchetSession(rootKey, isInitiator = true)
        val bob = RatchetSession(rootKey, isInitiator = false)

        // Alice sends two messages
        val msg1 = alice.encrypt("first".toByteArray())
        val msg2 = alice.encrypt("second".toByteArray())

        // Bob tries to decrypt out of order (skipping msg1)
        // msg2 was encrypted with chain key at position 2, but Bob's chain is at position 1
        // → different derived key → MAC mismatch → AuthenticationFailed
        assertThrows("Out-of-order message should throw AuthenticationFailed",
            ShieldException.AuthenticationFailed::class.java) {
            bob.decrypt(msg2)
        }
    }

    @Test
    fun testTamperedDoesNotAdvanceChain() {
        val rootKey = randomKey()
        val alice = RatchetSession(rootKey, isInitiator = true)
        val bob = RatchetSession(rootKey, isInitiator = false)

        val msg1 = alice.encrypt("first".toByteArray())
        val msg2 = alice.encrypt("second".toByteArray())

        // Tamper with msg1
        val tampered = msg1.copyOf()
        tampered[20] = (tampered[20].toInt() xor 0xFF).toByte()

        // Failed decrypt should NOT advance chain
        assertThrows(ShieldException.AuthenticationFailed::class.java) {
            bob.decrypt(tampered)
        }

        // Original msg1 should still work (chain not advanced)
        val decrypted1 = bob.decrypt(msg1)
        assertArrayEquals("first".toByteArray(), decrypted1)

        // msg2 should also work (chain now at position 2)
        val decrypted2 = bob.decrypt(msg2)
        assertArrayEquals("second".toByteArray(), decrypted2)
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

        assertArrayEquals("Large message should round-trip", large, decrypted)
    }

    @Test
    fun testDecryptTooShort() {
        val rootKey = randomKey()
        val bob = RatchetSession(rootKey, isInitiator = false)

        val tooShort = ByteArray(30)  // Less than minimum size (nonce + counter + mac)
        assertThrows("Too short ciphertext should throw CiphertextTooShort",
            ShieldException.CiphertextTooShort::class.java) {
            bob.decrypt(tooShort)
        }
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

        assertArrayEquals("Binary data should round-trip", binary, decrypted)
    }

    // MARK: - Session Role Tests

    @Test
    fun testInitiatorRoleMatters() {
        val rootKey = randomKey()

        // Both as initiator — send/recv chains are swapped
        val alice1 = RatchetSession(rootKey, isInitiator = true)
        val alice2 = RatchetSession(rootKey, isInitiator = true)

        val encrypted = alice1.encrypt("test".toByteArray())
        // Both have same role → alice1's send chain == alice2's send chain
        // → alice2's recv chain derives a different key → MAC fails
        assertThrows("Same role sessions should not communicate",
            ShieldException.AuthenticationFailed::class.java) {
            alice2.decrypt(encrypted)
        }
    }

    @Test
    fun testNonInitiatorRoleMatters() {
        val rootKey = randomKey()

        // Both as non-initiator
        val bob1 = RatchetSession(rootKey, isInitiator = false)
        val bob2 = RatchetSession(rootKey, isInitiator = false)

        val encrypted = bob1.encrypt("test".toByteArray())
        assertThrows("Same role sessions should not communicate",
            ShieldException.AuthenticationFailed::class.java) {
            bob2.decrypt(encrypted)
        }
    }
}
