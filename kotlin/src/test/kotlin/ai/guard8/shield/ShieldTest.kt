package ai.guard8.shield

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ShieldTest {

    // Core Tests
    @Test
    fun `test encrypt decrypt`() {
        Shield.create("password123", "test-service").use { shield ->
            val plaintext = "Hello, Shield!".toByteArray()
            val encrypted = shield.encrypt(plaintext)
            val decrypted = shield.decrypt(encrypted)
            assertContentEquals(plaintext, decrypted)
        }
    }

    @Test
    fun `test with key`() {
        val key = ByteArray(32) { it.toByte() }
        Shield.withKey(key).use { shield ->
            val plaintext = "Test message".toByteArray()
            val encrypted = shield.encrypt(plaintext)
            val decrypted = shield.decrypt(encrypted)
            assertContentEquals(plaintext, decrypted)
        }
    }

    @Test
    fun `test quick encrypt decrypt`() {
        val key = ByteArray(32)
        val plaintext = "Quick test".toByteArray()
        val encrypted = Shield.quickEncrypt(key, plaintext)
        val decrypted = Shield.quickDecrypt(key, encrypted)
        assertContentEquals(plaintext, decrypted)
    }

    @Test
    fun `test invalid key size`() {
        assertThrows<IllegalArgumentException> {
            Shield.withKey(ByteArray(16))
        }
    }

    @Test
    fun `test authentication failed`() {
        Shield.create("password", "service").use { shield ->
            val encrypted = shield.encrypt("test".toByteArray())
            encrypted[encrypted.size - 1] = (encrypted.last().toInt() xor 0xFF).toByte()
            assertThrows<IllegalArgumentException> {
                shield.decrypt(encrypted)
            }
        }
    }

    // Ratchet Tests
    @Test
    fun `test ratchet session`() {
        val rootKey = ByteArray(32)
        RatchetSession(rootKey, true).use { alice ->
            RatchetSession(rootKey, false).use { bob ->
                val msg = "Hello Bob!".toByteArray()
                val encrypted = alice.encrypt(msg)
                val decrypted = bob.decrypt(encrypted)
                assertContentEquals(msg, decrypted)
                assertEquals(1L, alice.sendCounter)
                assertEquals(1L, bob.recvCounter)
            }
        }
    }

    @Test
    fun `test ratchet replay protection`() {
        val rootKey = ByteArray(32)
        RatchetSession(rootKey, true).use { alice ->
            RatchetSession(rootKey, false).use { bob ->
                val encrypted = alice.encrypt("test".toByteArray())
                bob.decrypt(encrypted)
                assertThrows<ShieldException.ReplayDetected> {
                    bob.decrypt(encrypted)
                }
            }
        }
    }

    // TOTP Tests
    @Test
    fun `test TOTP generate verify`() {
        val secret = TOTP.generateSecret()
        TOTP(secret).use { totp ->
            val now = System.currentTimeMillis() / 1000
            val code = totp.generate(now)
            assertEquals(6, code.length)
            assertTrue(totp.verify(code, now, 1))
        }
    }

    @Test
    fun `test TOTP base32`() {
        val secret = "12345678901234567890".toByteArray()
        TOTP(secret).use { totp ->
            val encoded = totp.toBase32()
            val decoded = TOTP.fromBase32(encoded)
            assertContentEquals(secret, decoded.getSecret())
        }
    }

    @Test
    fun `test recovery codes`() {
        val rc = RecoveryCodes(5)
        assertEquals(5, rc.remaining)
        val codes = rc.allCodes
        assertEquals(5, codes.size)
        assertTrue(rc.verify(codes[0]))
        assertEquals(4, rc.remaining)
        assertFalse(rc.verify(codes[0]))
    }

    // Signature Tests
    @Test
    fun `test symmetric signature`() {
        SymmetricSignature.generate().use { sig ->
            val message = "Sign this message".toByteArray()
            val signature = sig.sign(message)
            assertTrue(sig.verify(message, signature, sig.verificationKey))
        }
    }

    @Test
    fun `test symmetric signature with timestamp`() {
        SymmetricSignature.generate().use { sig ->
            val message = "Timestamped message".toByteArray()
            val signature = sig.sign(message, true)
            assertEquals(40, signature.size)
            assertTrue(sig.verify(message, signature, sig.verificationKey, 60))
        }
    }

    @Test
    fun `test symmetric signature from password`() {
        SymmetricSignature.fromPassword("password", "user@example.com").use { sig ->
            val message = "Test message".toByteArray()
            val signature = sig.sign(message)
            assertTrue(sig.verify(message, signature, sig.verificationKey))
        }
    }

    @Test
    fun `test Lamport signature`() {
        LamportSignature.generate().use { lamport ->
            val message = "Lamport signed message".toByteArray()
            val signature = lamport.sign(message)
            assertTrue(LamportSignature.verify(message, signature, lamport.publicKey))
        }
    }

    @Test
    fun `test Lamport one-time use`() {
        LamportSignature.generate().use { lamport ->
            lamport.sign("first".toByteArray())
            assertTrue(lamport.isUsed)
            assertThrows<ShieldException.LamportKeyUsed> {
                lamport.sign("second".toByteArray())
            }
        }
    }

    // Utility Tests
    @Test
    fun `test secure compare`() {
        val a = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8)
        val b = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8)
        val c = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 9)
        assertTrue(Shield.constantTimeEquals(a, b))
        assertFalse(Shield.constantTimeEquals(a, c))
    }

    @Test
    fun `test SHA256`() {
        val expected = byteArrayOf(
            0xba.toByte(), 0x78, 0x16, 0xbf.toByte(), 0x8f.toByte(), 0x01, 0xcf.toByte(), 0xea.toByte(),
            0x41, 0x41, 0x40, 0xde.toByte(), 0x5d, 0xae.toByte(), 0x22, 0x23,
            0xb0.toByte(), 0x03, 0x61, 0xa3.toByte(), 0x96.toByte(), 0x17, 0x7a, 0x9c.toByte(),
            0xb4.toByte(), 0x10, 0xff.toByte(), 0x61, 0xf2.toByte(), 0x00, 0x15, 0xad.toByte()
        )
        val hash = Shield.sha256("abc".toByteArray())
        assertContentEquals(expected, hash)
    }

    @Test
    fun `test random bytes`() {
        val a = Shield.randomBytes(32)
        val b = Shield.randomBytes(32)
        assertFalse(a.contentEquals(b))
    }

    @Test
    fun `test fingerprints`() {
        SymmetricSignature.generate().use { sig ->
            assertEquals(16, sig.fingerprint().length)
        }
        LamportSignature.generate().use { lamport ->
            assertEquals(16, lamport.fingerprint().length)
        }
    }
}
