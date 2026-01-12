package ai.guard8.shield

import org.junit.Assert.*
import org.junit.Test

/**
 * Unit tests for TOTP.
 */
class TOTPTest {

    // MARK: - Secret Generation Tests

    @Test
    fun testGenerateSecret() {
        val secret = TOTP.generateSecret()
        assertEquals("Default secret should be 20 bytes", 20, secret.size)
    }

    @Test
    fun testGenerateSecretCustomLength() {
        val secret = TOTP.generateSecret(32)
        assertEquals("Custom secret should be 32 bytes", 32, secret.size)
    }

    @Test
    fun testGenerateSecretUniqueness() {
        val secret1 = TOTP.generateSecret()
        val secret2 = TOTP.generateSecret()
        assertFalse("Secrets should be unique", secret1.contentEquals(secret2))
    }

    // MARK: - Base32 Encoding Tests

    @Test
    fun testBase32RoundTrip() {
        val original = byteArrayOf(0x48, 0x65, 0x6C, 0x6C, 0x6F)  // "Hello"
        val encoded = TOTP.secretToBase32(original)
        val decoded = TOTP.secretFromBase32(encoded)
        assertArrayEquals("Base32 round-trip should preserve bytes", original, decoded)
    }

    @Test
    fun testBase32KnownValue() {
        // Test vector: "JBSWY3DPEHPK3PXP" = "Hello!"
        val decoded = TOTP.secretFromBase32("JBSWY3DPEHPK3PXP")
        val expected = "Hello!".toByteArray()
        assertArrayEquals("Known base32 value should decode correctly", expected, decoded)
    }

    @Test
    fun testBase32EmptyInput() {
        val encoded = TOTP.secretToBase32(byteArrayOf())
        assertEquals("Empty input should produce empty output", "", encoded)
    }

    // MARK: - TOTP Generation Tests

    @Test
    fun testGenerateCode() {
        val secret = TOTP.secretFromBase32("JBSWY3DPEHPK3PXP")
        val totp = TOTP(secret)
        val code = totp.generate()

        assertEquals("Code should be 6 digits", 6, code.length)
        assertTrue("Code should be numeric", code.all { it.isDigit() })
    }

    @Test
    fun testGenerateCodeDeterministic() {
        val secret = TOTP.secretFromBase32("JBSWY3DPEHPK3PXP")
        val totp = TOTP(secret)
        val timestamp = 1234567890L

        val code1 = totp.generate(timestamp)
        val code2 = totp.generate(timestamp)

        assertEquals("Same timestamp should produce same code", code1, code2)
    }

    @Test
    fun testGenerateCodeRFC6238Vector() {
        // Test vector from RFC 6238
        // Time: 59 seconds since epoch
        // Secret: "12345678901234567890" (20 bytes)
        // Expected TOTP (SHA1, 8 digits): 94287082
        val secret = "12345678901234567890".toByteArray()
        val totp = TOTP(secret, digits = 8)

        val code = totp.generate(59)
        assertEquals("RFC 6238 test vector should match", "94287082", code)
    }

    @Test
    fun testGenerateCode8Digits() {
        val secret = TOTP.generateSecret()
        val totp = TOTP(secret, digits = 8)
        val code = totp.generate()

        assertEquals("Code should be 8 digits", 8, code.length)
    }

    @Test
    fun testGenerateCodeSHA256() {
        val secret = TOTP.generateSecret()
        val totp = TOTP(secret, algorithm = TOTP.Algorithm.SHA256)
        val code = totp.generate()

        assertEquals("SHA256 code should be 6 digits", 6, code.length)
    }

    // MARK: - Verification Tests

    @Test
    fun testVerifyValidCode() {
        val secret = TOTP.generateSecret()
        val totp = TOTP(secret)
        val timestamp = System.currentTimeMillis() / 1000

        val code = totp.generate(timestamp)
        assertTrue("Generated code should verify", totp.verify(code, timestamp))
    }

    @Test
    fun testVerifyInvalidCode() {
        val secret = TOTP.generateSecret()
        val totp = TOTP(secret)

        assertFalse("Invalid code should not verify", totp.verify("000000"))
    }

    @Test
    fun testVerifyWithWindow() {
        val secret = TOTP.generateSecret()
        val totp = TOTP(secret, interval = 30)
        val timestamp = System.currentTimeMillis() / 1000

        // Code from previous interval should verify within window
        val previousCode = totp.generate(timestamp - 30)
        assertTrue("Previous interval code should verify", totp.verify(previousCode, timestamp, window = 1))

        // Code from 2 intervals ago should not verify with window=1
        val oldCode = totp.generate(timestamp - 60)
        assertFalse("Old code should not verify", totp.verify(oldCode, timestamp, window = 1))
    }

    // MARK: - Provisioning URI Tests

    @Test
    fun testProvisioningUri() {
        val secret = TOTP.secretFromBase32("JBSWY3DPEHPK3PXP")
        val totp = TOTP(secret)
        val uri = totp.provisioningUri("user@example.com", "TestApp")

        assertTrue("URI should start with otpauth://totp/", uri.startsWith("otpauth://totp/"))
        assertTrue("URI should contain account", uri.contains("user@example.com"))
        assertTrue("URI should contain issuer", uri.contains("issuer=TestApp"))
        assertTrue("URI should contain secret", uri.contains("secret=JBSWY3DPEHPK3PXP"))
    }

    // MARK: - Cross-Platform Compatibility Tests

    @Test
    fun testCrossPlatformCompatibility() {
        // Use a known secret and timestamp to verify cross-platform compatibility
        val secret = byteArrayOf(
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30
        )  // "12345678901234567890"
        val totp = TOTP(secret)

        // These should match the Python implementation
        val code59 = totp.generate(59)
        val code1111111109 = totp.generate(1111111109)

        // 6-digit SHA1 codes
        assertEquals("287082", code59)
        assertEquals("081804", code1111111109)
    }
}

/**
 * Unit tests for RecoveryCodes.
 */
class RecoveryCodesTest {

    @Test
    fun testGenerateCodesDefault() {
        val recovery = RecoveryCodes()
        assertEquals("Should generate 10 codes by default", 10, recovery.codes.size)
        assertEquals("All codes should be unused", 10, recovery.remaining)
    }

    @Test
    fun testGenerateCodesFormat() {
        val codes = RecoveryCodes.generateCodes()
        for (code in codes) {
            assertTrue("Code should match format XXXX-XXXX", code.matches(Regex("[A-F0-9]{4}-[A-F0-9]{4}")))
        }
    }

    @Test
    fun testVerifyValidCode() {
        val recovery = RecoveryCodes()
        val code = recovery.codes.first()

        assertTrue("Valid code should verify", recovery.verify(code))
        assertEquals("Remaining should decrease", 9, recovery.remaining)
    }

    @Test
    fun testVerifyCodeOnlyOnce() {
        val recovery = RecoveryCodes()
        val code = recovery.codes.first()

        assertTrue("First verification should succeed", recovery.verify(code))
        assertFalse("Second verification should fail", recovery.verify(code))
    }

    @Test
    fun testVerifyInvalidCode() {
        val recovery = RecoveryCodes()
        assertFalse("Invalid code should not verify", recovery.verify("XXXX-YYYY"))
    }

    @Test
    fun testVerifyNormalizedFormat() {
        val recovery = RecoveryCodes()
        val code = recovery.codes.first()

        // Test without dash
        val noDash = code.replace("-", "")
        assertTrue("Code without dash should verify", recovery.verify(noDash))
    }

    @Test
    fun testVerifyCaseInsensitive() {
        val recovery = RecoveryCodes()
        val code = recovery.codes.first()

        // Test lowercase
        val lower = code.lowercase()
        assertTrue("Lowercase code should verify", recovery.verify(lower))
    }

    @Test
    fun testCodesUnique() {
        val codes = RecoveryCodes.generateCodes(100)
        val unique = codes.toSet()
        assertEquals("All codes should be unique", codes.size, unique.size)
    }
}
