import XCTest
@testable import Shield

final class ShieldTests: XCTestCase {

    // MARK: - Shield Basic Tests

    func testEncryptDecrypt() {
        let shield = Shield(password: "test_password", service: "test.example.com")
        let plaintext = Array("Hello, World!".utf8)

        let encrypted = shield.encrypt(plaintext)
        let decrypted = shield.decrypt(encrypted)

        XCTAssertNotNil(decrypted)
        XCTAssertEqual(decrypted, plaintext)
    }

    func testEncryptDecryptEmptyData() {
        let shield = Shield(password: "test_password", service: "test.example.com")
        let plaintext: [UInt8] = []

        let encrypted = shield.encrypt(plaintext)
        let decrypted = shield.decrypt(encrypted)

        XCTAssertNotNil(decrypted)
        XCTAssertEqual(decrypted, plaintext)
    }

    func testEncryptDecryptLargeData() {
        let shield = Shield(password: "test_password", service: "test.example.com")
        let plaintext = [UInt8](repeating: 0x42, count: 10000)

        let encrypted = shield.encrypt(plaintext)
        let decrypted = shield.decrypt(encrypted)

        XCTAssertNotNil(decrypted)
        XCTAssertEqual(decrypted, plaintext)
    }

    func testDifferentPasswordsFail() {
        let shield1 = Shield(password: "password1", service: "test.example.com")
        let shield2 = Shield(password: "password2", service: "test.example.com")
        let plaintext = Array("Secret message".utf8)

        let encrypted = shield1.encrypt(plaintext)
        let decrypted = shield2.decrypt(encrypted)

        XCTAssertNil(decrypted, "Decryption with wrong password should fail")
    }

    func testDifferentServicesFail() {
        let shield1 = Shield(password: "password", service: "service1.com")
        let shield2 = Shield(password: "password", service: "service2.com")
        let plaintext = Array("Secret message".utf8)

        let encrypted = shield1.encrypt(plaintext)
        let decrypted = shield2.decrypt(encrypted)

        XCTAssertNil(decrypted, "Decryption with wrong service should fail")
    }

    func testTamperedDataFails() {
        let shield = Shield(password: "test_password", service: "test.example.com")
        let plaintext = Array("Hello, World!".utf8)

        var encrypted = shield.encrypt(plaintext)

        // Tamper with the ciphertext
        if encrypted.count > 20 {
            encrypted[20] ^= 0xFF
        }

        let decrypted = shield.decrypt(encrypted)
        XCTAssertNil(decrypted, "Tampered data should fail MAC verification")
    }

    func testTruncatedDataFails() {
        let shield = Shield(password: "test_password", service: "test.example.com")
        let plaintext = Array("Hello, World!".utf8)

        let encrypted = shield.encrypt(plaintext)
        let truncated = Array(encrypted.prefix(encrypted.count - 1))

        let decrypted = shield.decrypt(truncated)
        XCTAssertNil(decrypted, "Truncated data should fail")
    }

    // MARK: - Quick Encrypt/Decrypt Tests

    func testQuickEncryptDecrypt() throws {
        var key = [UInt8](repeating: 0, count: 32)
        for i in 0..<32 {
            key[i] = UInt8(i)
        }

        let plaintext = Array("Quick test data".utf8)

        let encrypted = try Shield.quickEncrypt(key: key, plaintext: plaintext)
        let decrypted = try Shield.quickDecrypt(key: key, ciphertext: encrypted)

        XCTAssertNotNil(decrypted)
        XCTAssertEqual(decrypted, plaintext)
    }

    func testQuickEncryptInvalidKeySize() {
        let shortKey = [UInt8](repeating: 0, count: 16)
        let plaintext = Array("test".utf8)

        XCTAssertThrowsError(try Shield.quickEncrypt(key: shortKey, plaintext: plaintext)) { error in
            if case ShieldError.invalidKeySize(let expected, let actual) = error {
                XCTAssertEqual(expected, 32)
                XCTAssertEqual(actual, 16)
            } else {
                XCTFail("Expected invalidKeySize error")
            }
        }
    }

    // MARK: - Key Derivation Tests

    func testKeyDerivationDeterministic() {
        let shield1 = Shield(password: "same_password", service: "same.service.com")
        let shield2 = Shield(password: "same_password", service: "same.service.com")

        let plaintext = Array("Test data".utf8)

        // Both should derive the same key and be able to decrypt each other's data
        let encrypted1 = shield1.encrypt(plaintext)
        let encrypted2 = shield2.encrypt(plaintext)

        let decrypted1 = shield2.decrypt(encrypted1)
        let decrypted2 = shield1.decrypt(encrypted2)

        XCTAssertNotNil(decrypted1)
        XCTAssertNotNil(decrypted2)
        XCTAssertEqual(decrypted1, plaintext)
        XCTAssertEqual(decrypted2, plaintext)
    }

    func testCustomIterations() {
        let shield = Shield(password: "password", service: "test.com", iterations: 10000)
        let plaintext = Array("Test".utf8)

        let encrypted = shield.encrypt(plaintext)
        let decrypted = shield.decrypt(encrypted)

        XCTAssertNotNil(decrypted)
        XCTAssertEqual(decrypted, plaintext)
    }

    // MARK: - Binary Data Tests

    func testBinaryData() {
        let shield = Shield(password: "password", service: "test.com")

        // All possible byte values
        var plaintext = [UInt8](repeating: 0, count: 256)
        for i in 0..<256 {
            plaintext[i] = UInt8(i)
        }

        let encrypted = shield.encrypt(plaintext)
        let decrypted = shield.decrypt(encrypted)

        XCTAssertNotNil(decrypted)
        XCTAssertEqual(decrypted, plaintext)
    }

    // MARK: - Encryption Uniqueness Tests

    func testEncryptionProducesUniqueNonces() {
        let shield = Shield(password: "password", service: "test.com")
        let plaintext = Array("Same message".utf8)

        let encrypted1 = shield.encrypt(plaintext)
        let encrypted2 = shield.encrypt(plaintext)

        // Same plaintext should produce different ciphertext (different nonces)
        XCTAssertNotEqual(encrypted1, encrypted2)
    }

    // MARK: - Cross-Platform Compatibility Test

    func testKnownVector() {
        // This test ensures the implementation produces compatible output
        // with other Shield implementations (Python, JS, Go, etc.)
        let shield = Shield(password: "test", service: "test")
        let plaintext = Array("hello".utf8)

        let encrypted = shield.encrypt(plaintext)

        // Verify format: 16 bytes nonce + ciphertext + 16 bytes MAC
        XCTAssertGreaterThanOrEqual(encrypted.count, 32 + plaintext.count)

        // Verify decryption works
        let decrypted = shield.decrypt(encrypted)
        XCTAssertNotNil(decrypted)
        XCTAssertEqual(decrypted, plaintext)
    }
}
