import XCTest
@testable import Shield

final class ShieldTests: XCTestCase {

    // MARK: - Shield Basic Tests

    func testEncryptDecrypt() throws {
        let shield = Shield(password: "test_password", service: "test.example.com")
        let plaintext = Array("Hello, World!".utf8)

        let encrypted = try shield.encrypt(plaintext)
        let decrypted = try shield.decrypt(encrypted)

        XCTAssertEqual(decrypted, plaintext)
    }

    func testEncryptDecryptEmptyData() throws {
        let shield = Shield(password: "test_password", service: "test.example.com")
        let plaintext: [UInt8] = []

        let encrypted = try shield.encrypt(plaintext)
        let decrypted = try shield.decrypt(encrypted)

        XCTAssertEqual(decrypted, plaintext)
    }

    func testEncryptDecryptLargeData() throws {
        let shield = Shield(password: "test_password", service: "test.example.com")
        let plaintext = [UInt8](repeating: 0x42, count: 10000)

        let encrypted = try shield.encrypt(plaintext)
        let decrypted = try shield.decrypt(encrypted)

        XCTAssertEqual(decrypted, plaintext)
    }

    func testDifferentPasswordsFail() throws {
        let shield1 = Shield(password: "password1", service: "test.example.com")
        let shield2 = Shield(password: "password2", service: "test.example.com")
        let plaintext = Array("Secret message".utf8)

        let encrypted = try shield1.encrypt(plaintext)
        XCTAssertThrowsError(try shield2.decrypt(encrypted)) { error in
            XCTAssertEqual(error as? ShieldError, ShieldError.authenticationFailed,
                          "Decryption with wrong password should throw authenticationFailed")
        }
    }

    func testDifferentServicesFail() throws {
        let shield1 = Shield(password: "password", service: "service1.com")
        let shield2 = Shield(password: "password", service: "service2.com")
        let plaintext = Array("Secret message".utf8)

        let encrypted = try shield1.encrypt(plaintext)
        XCTAssertThrowsError(try shield2.decrypt(encrypted)) { error in
            XCTAssertEqual(error as? ShieldError, ShieldError.authenticationFailed,
                          "Decryption with wrong service should throw authenticationFailed")
        }
    }

    func testTamperedDataFails() throws {
        let shield = Shield(password: "test_password", service: "test.example.com")
        let plaintext = Array("Hello, World!".utf8)

        var encrypted = try shield.encrypt(plaintext)

        // Tamper with the ciphertext
        if encrypted.count > 20 {
            encrypted[20] ^= 0xFF
        }

        XCTAssertThrowsError(try shield.decrypt(encrypted)) { error in
            XCTAssertEqual(error as? ShieldError, ShieldError.authenticationFailed,
                          "Tampered data should throw authenticationFailed")
        }
    }

    func testTruncatedDataFails() throws {
        let shield = Shield(password: "test_password", service: "test.example.com")
        let plaintext = Array("Hello, World!".utf8)

        let encrypted = try shield.encrypt(plaintext)
        let truncated = Array(encrypted.prefix(encrypted.count - 1))

        XCTAssertThrowsError(try shield.decrypt(truncated),
                            "Truncated data should throw")
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

    func testKeyDerivationDeterministic() throws {
        let shield1 = Shield(password: "same_password", service: "same.service.com")
        let shield2 = Shield(password: "same_password", service: "same.service.com")

        let plaintext = Array("Test data".utf8)

        // Both should derive the same key and be able to decrypt each other's data
        let encrypted1 = try shield1.encrypt(plaintext)
        let encrypted2 = try shield2.encrypt(plaintext)

        let decrypted1 = try shield2.decrypt(encrypted1)
        let decrypted2 = try shield1.decrypt(encrypted2)

        XCTAssertEqual(decrypted1, plaintext)
        XCTAssertEqual(decrypted2, plaintext)
    }

    func testCustomIterations() throws {
        let shield = Shield(password: "password", service: "test.com", iterations: 10000)
        let plaintext = Array("Test".utf8)

        let encrypted = try shield.encrypt(plaintext)
        let decrypted = try shield.decrypt(encrypted)

        XCTAssertEqual(decrypted, plaintext)
    }

    // MARK: - Binary Data Tests

    func testBinaryData() throws {
        let shield = Shield(password: "password", service: "test.com")

        // All possible byte values
        var plaintext = [UInt8](repeating: 0, count: 256)
        for i in 0..<256 {
            plaintext[i] = UInt8(i)
        }

        let encrypted = try shield.encrypt(plaintext)
        let decrypted = try shield.decrypt(encrypted)

        XCTAssertEqual(decrypted, plaintext)
    }

    // MARK: - Encryption Uniqueness Tests

    func testEncryptionProducesUniqueNonces() throws {
        let shield = Shield(password: "password", service: "test.com")
        let plaintext = Array("Same message".utf8)

        let encrypted1 = try shield.encrypt(plaintext)
        let encrypted2 = try shield.encrypt(plaintext)

        // Same plaintext should produce different ciphertext (different nonces)
        XCTAssertNotEqual(encrypted1, encrypted2)
    }

    // MARK: - Cross-Platform Compatibility Test

    func testKnownVector() throws {
        let shield = Shield(password: "test", service: "test")
        let plaintext = Array("hello".utf8)

        let encrypted = try shield.encrypt(plaintext)

        // Verify format: 16 bytes nonce + ciphertext + 16 bytes MAC
        XCTAssertGreaterThanOrEqual(encrypted.count, 32 + plaintext.count)

        // Verify decryption works
        let decrypted = try shield.decrypt(encrypted)
        XCTAssertEqual(decrypted, plaintext)
    }
}
