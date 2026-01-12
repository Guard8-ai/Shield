import XCTest
@testable import Shield

/// Tests for TOTP and RecoveryCodes.
final class TOTPTests: XCTestCase {

    // MARK: - Secret Generation Tests

    func testGenerateSecret() {
        let secret = TOTP.generateSecret()
        XCTAssertEqual(secret.count, 20, "Default secret should be 20 bytes")
    }

    func testGenerateSecretCustomLength() {
        let secret = TOTP.generateSecret(length: 32)
        XCTAssertEqual(secret.count, 32, "Custom secret should be 32 bytes")
    }

    func testGenerateSecretUniqueness() {
        let secret1 = TOTP.generateSecret()
        let secret2 = TOTP.generateSecret()
        XCTAssertNotEqual(secret1, secret2, "Secrets should be unique")
    }

    // MARK: - Base32 Encoding Tests

    func testBase32RoundTrip() {
        let original: [UInt8] = [0x48, 0x65, 0x6C, 0x6C, 0x6F]  // "Hello"
        let encoded = TOTP.secretToBase32(original)
        let decoded = TOTP.secretFromBase32(encoded)
        XCTAssertEqual(decoded, original, "Base32 round-trip should preserve bytes")
    }

    func testBase32KnownValue() {
        // Test vector: "JBSWY3DPEHPK3PXP" = "Hello!"
        let decoded = TOTP.secretFromBase32("JBSWY3DPEHPK3PXP")
        let expected = Array("Hello!".utf8)
        XCTAssertEqual(decoded, expected, "Known base32 value should decode correctly")
    }

    func testBase32EmptyInput() {
        let encoded = TOTP.secretToBase32([])
        XCTAssertEqual(encoded, "", "Empty input should produce empty output")
    }

    // MARK: - TOTP Generation Tests

    func testGenerateCode() {
        let secret = TOTP.secretFromBase32("JBSWY3DPEHPK3PXP")
        let totp = TOTP(secret: secret)
        let code = totp.generate()

        XCTAssertEqual(code.count, 6, "Code should be 6 digits")
        XCTAssertTrue(code.allSatisfy { $0.isNumber }, "Code should be numeric")
    }

    func testGenerateCodeDeterministic() {
        let secret = TOTP.secretFromBase32("JBSWY3DPEHPK3PXP")
        let totp = TOTP(secret: secret)
        let timestamp = 1234567890

        let code1 = totp.generate(timestamp: timestamp)
        let code2 = totp.generate(timestamp: timestamp)

        XCTAssertEqual(code1, code2, "Same timestamp should produce same code")
    }

    func testGenerateCodeRFC6238Vector() {
        // Test vector from RFC 6238
        // Time: 59 seconds since epoch
        // Secret: "12345678901234567890" (20 bytes)
        // Expected TOTP (SHA1, 8 digits): 94287082
        let secret = Array("12345678901234567890".utf8)
        let totp = TOTP(secret: secret, digits: 8)

        let code = totp.generate(timestamp: 59)
        XCTAssertEqual(code, "94287082", "RFC 6238 test vector should match")
    }

    func testGenerateCode8Digits() {
        let secret = TOTP.generateSecret()
        let totp = TOTP(secret: secret, digits: 8)
        let code = totp.generate()

        XCTAssertEqual(code.count, 8, "Code should be 8 digits")
    }

    func testGenerateCodeSHA256() {
        let secret = TOTP.generateSecret()
        let totp = TOTP(secret: secret, algorithm: .sha256)
        let code = totp.generate()

        XCTAssertEqual(code.count, 6, "SHA256 code should be 6 digits")
    }

    // MARK: - Verification Tests

    func testVerifyValidCode() {
        let secret = TOTP.generateSecret()
        let totp = TOTP(secret: secret)
        let timestamp = Int(Date().timeIntervalSince1970)

        let code = totp.generate(timestamp: timestamp)
        XCTAssertTrue(totp.verify(code, timestamp: timestamp), "Generated code should verify")
    }

    func testVerifyInvalidCode() {
        let secret = TOTP.generateSecret()
        let totp = TOTP(secret: secret)

        XCTAssertFalse(totp.verify("000000"), "Invalid code should not verify")
    }

    func testVerifyWithWindow() {
        let secret = TOTP.generateSecret()
        let totp = TOTP(secret: secret, interval: 30)
        let timestamp = Int(Date().timeIntervalSince1970)

        // Code from previous interval should verify within window
        let previousCode = totp.generate(timestamp: timestamp - 30)
        XCTAssertTrue(totp.verify(previousCode, timestamp: timestamp, window: 1),
                      "Previous interval code should verify")

        // Code from 2 intervals ago should not verify with window=1
        let oldCode = totp.generate(timestamp: timestamp - 60)
        XCTAssertFalse(totp.verify(oldCode, timestamp: timestamp, window: 1),
                       "Old code should not verify")
    }

    // MARK: - Provisioning URI Tests

    func testProvisioningUri() {
        let secret = TOTP.secretFromBase32("JBSWY3DPEHPK3PXP")
        let totp = TOTP(secret: secret)
        let uri = totp.provisioningUri(account: "user@example.com", issuer: "TestApp")

        XCTAssertTrue(uri.hasPrefix("otpauth://totp/"), "URI should start with otpauth://totp/")
        XCTAssertTrue(uri.contains("user@example.com"), "URI should contain account")
        XCTAssertTrue(uri.contains("issuer=TestApp"), "URI should contain issuer")
        XCTAssertTrue(uri.contains("secret=JBSWY3DPEHPK3PXP"), "URI should contain secret")
    }

    // MARK: - Cross-Platform Compatibility Tests

    func testCrossPlatformCompatibility() {
        // Use a known secret and timestamp to verify cross-platform compatibility
        let secret: [UInt8] = [
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30
        ]  // "12345678901234567890"
        let totp = TOTP(secret: secret)

        // These should match the Python implementation
        let code59 = totp.generate(timestamp: 59)
        let code1111111109 = totp.generate(timestamp: 1111111109)

        // 6-digit SHA1 codes
        XCTAssertEqual(code59, "287082")
        XCTAssertEqual(code1111111109, "081804")
    }
}

// MARK: - RecoveryCodes Tests

final class RecoveryCodesTests: XCTestCase {

    func testGenerateCodesDefault() {
        let recovery = RecoveryCodes()
        XCTAssertEqual(recovery.codes.count, 10, "Should generate 10 codes by default")
        XCTAssertEqual(recovery.remaining, 10, "All codes should be unused")
    }

    func testGenerateCodesFormat() {
        let codes = RecoveryCodes.generateCodes()
        let regex = try! NSRegularExpression(pattern: "^[A-F0-9]{4}-[A-F0-9]{4}$")
        for code in codes {
            let range = NSRange(code.startIndex..., in: code)
            XCTAssertNotNil(regex.firstMatch(in: code, range: range),
                           "Code should match format XXXX-XXXX")
        }
    }

    func testVerifyValidCode() {
        let recovery = RecoveryCodes()
        let code = recovery.codes.first!

        XCTAssertTrue(recovery.verify(code), "Valid code should verify")
        XCTAssertEqual(recovery.remaining, 9, "Remaining should decrease")
    }

    func testVerifyCodeOnlyOnce() {
        let recovery = RecoveryCodes()
        let code = recovery.codes.first!

        XCTAssertTrue(recovery.verify(code), "First verification should succeed")
        XCTAssertFalse(recovery.verify(code), "Second verification should fail")
    }

    func testVerifyInvalidCode() {
        let recovery = RecoveryCodes()
        XCTAssertFalse(recovery.verify("XXXX-YYYY"), "Invalid code should not verify")
    }

    func testVerifyNormalizedFormat() {
        let recovery = RecoveryCodes()
        let code = recovery.codes.first!

        // Test without dash
        let noDash = code.replacingOccurrences(of: "-", with: "")
        XCTAssertTrue(recovery.verify(noDash), "Code without dash should verify")
    }

    func testVerifyCaseInsensitive() {
        let recovery = RecoveryCodes()
        let code = recovery.codes.first!

        // Test lowercase
        let lower = code.lowercased()
        XCTAssertTrue(recovery.verify(lower), "Lowercase code should verify")
    }

    func testCodesUnique() {
        let codes = RecoveryCodes.generateCodes(count: 100)
        let unique = Set(codes)
        XCTAssertEqual(codes.count, unique.count, "All codes should be unique")
    }
}
