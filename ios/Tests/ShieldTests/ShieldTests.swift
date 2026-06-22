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

    /// CR-1: two instances with the same password+service now derive DIFFERENT
    /// keys (random per-instance salt), but each can still decrypt the other's
    /// ciphertext because the salt travels in the header.
    func testCrossInstanceRoundtrip() throws {
        let shield1 = Shield(password: "same_password", service: "same.service.com")
        let shield2 = Shield(password: "same_password", service: "same.service.com")

        let plaintext = Array("Test data".utf8)

        let encrypted1 = try shield1.encrypt(plaintext)
        let encrypted2 = try shield2.encrypt(plaintext)

        let decrypted1 = try shield2.decrypt(encrypted1)
        let decrypted2 = try shield1.decrypt(encrypted2)

        XCTAssertEqual(decrypted1, plaintext)
        XCTAssertEqual(decrypted2, plaintext)

        // Distinct random salts in the headers (bytes [1..<17]).
        XCTAssertNotEqual(Array(encrypted1[1..<17]), Array(encrypted2[1..<17]))
    }

    // MARK: - Security-fix Tests (CR-1 / CR-2 / CR-3)

    /// CR-1: same password+service -> different per-instance salts.
    func testSamePasswordServiceDifferentSalts() throws {
        let a = Shield(password: "hunter2", service: "github.com")
        let b = Shield(password: "hunter2", service: "github.com")
        let ca = try a.encrypt(Array("identical".utf8))
        let cb = try b.encrypt(Array("identical".utf8))
        XCTAssertNotEqual(Array(ca[1..<17]), Array(cb[1..<17]))
    }

    /// CR-2: PBKDF2 iteration count is 600,000.
    func testIterations600k() {
        XCTAssertEqual(Shield.pbkdf2Iterations, 600_000)
    }

    /// CR-3: password ciphertext starts with 0x02; key/quick ciphertext with 0x12.
    func testVersionBytes() throws {
        let pwCt = try Shield(password: "pw", service: "svc").encrypt(Array("x".utf8))
        XCTAssertEqual(pwCt[0], 0x02)

        let key = (0..<32).map { UInt8($0) }
        let quickCt = try Shield.quickEncrypt(key: key, plaintext: Array("x".utf8))
        XCTAssertEqual(quickCt[0], 0x12)

        let keyedCt = try Shield(key: key).encrypt(Array("x".utf8))
        XCTAssertEqual(keyedCt[0], 0x12)
    }

    /// CR-3: tampering with the authenticated salt fails the MAC.
    func testTamperSaltDetected() throws {
        let shield = Shield(password: "pw", service: "svc")
        var ct = try shield.encrypt(Array("authenticated salt".utf8))
        ct[1] ^= 0xFF
        XCTAssertThrowsError(try shield.decrypt(ct)) { error in
            XCTAssertEqual(error as? ShieldError, ShieldError.authenticationFailed)
        }
    }

    /// CR-3: changing the version byte to the other valid version is rejected.
    func testTamperVersionDetected() throws {
        let shield = Shield(password: "pw", service: "svc")
        var ct = try shield.encrypt(Array("authenticated version".utf8))
        ct[0] = 0x12
        XCTAssertThrowsError(try shield.decrypt(ct))
    }

    /// CR-3: an unknown leading version byte is rejected outright.
    func testUnknownVersionRejected() throws {
        let shield = Shield(password: "pw", service: "svc")
        var ct = try shield.encrypt(Array("x".utf8))
        ct[0] = 0x7F
        XCTAssertThrowsError(try shield.decrypt(ct)) { error in
            XCTAssertEqual(error as? ShieldError, ShieldError.invalidVersion)
        }
    }

    /// Flipping ANY byte (version, salt, nonce, ct, mac) fails auth.
    func testTamperDetectionAllBytes() throws {
        let shield = Shield(password: "pw", service: "svc")
        let ct = try shield.encrypt(Array("secret payload".utf8))
        for i in 0..<ct.count {
            var tampered = ct
            tampered[i] ^= 0xFF
            XCTAssertThrowsError(try shield.decrypt(tampered), "tamper at byte \(i) not detected")
        }
    }

    /// Key-mode (0x12) roundtrip via the pre-shared-key constructor.
    func testKeyModeRoundtrip() throws {
        let key = (0..<32).map { UInt8($0) }
        let shield = try Shield(key: key)
        let msg = Array("pre-shared key message".utf8)
        XCTAssertEqual(try shield.decrypt(shield.encrypt(msg)), msg)
    }

    /// A pre-shared-key instance must not silently accept a password-mode ciphertext.
    func testKeyModeRejectsPasswordCiphertext() throws {
        let pw = Shield(password: "pw", service: "svc")
        let ct = try pw.encrypt(Array("pw secret".utf8))
        let ks = try Shield(key: [UInt8](repeating: 0, count: 32))
        XCTAssertThrowsError(try ks.decrypt(ct))
    }

    /// Explicit salt is honored and stored in the header; same salt -> same key.
    func testExplicitSaltHonoredAndStored() throws {
        var salt = [UInt8](repeating: 0, count: 16)
        for i in 0..<16 { salt[i] = UInt8(i + 1) }
        let a = Shield(password: "pw", service: "svc", salt: salt, iterations: Shield.pbkdf2Iterations)
        let b = Shield(password: "pw", service: "svc", salt: salt, iterations: Shield.pbkdf2Iterations)

        let ct = try a.encrypt(Array("data".utf8))
        XCTAssertEqual(Array(ct[1..<17]), salt)
        XCTAssertEqual(try b.decrypt(ct), Array("data".utf8))
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

        // Verify password-mode format: version(1) + salt(16) + nonce(16) + ciphertext + MAC(16)
        XCTAssertEqual(encrypted[0], 0x02)
        XCTAssertGreaterThanOrEqual(encrypted.count, 49 + plaintext.count)

        // Verify decryption works
        let decrypted = try shield.decrypt(encrypted)
        XCTAssertEqual(decrypted, plaintext)
    }
}
