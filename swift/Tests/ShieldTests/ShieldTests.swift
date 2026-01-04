import XCTest
@testable import Shield

final class ShieldTests: XCTestCase {

    // MARK: - Core Tests

    func testEncryptDecrypt() throws {
        let shield = Shield(password: "password123", service: "test-service")
        let plaintext = Array("Hello, Shield!".utf8)

        let encrypted = try shield.encrypt(plaintext)
        let decrypted = try shield.decrypt(encrypted)

        XCTAssertEqual(plaintext, decrypted)
    }

    func testWithKey() throws {
        let key = (0..<32).map { UInt8($0) }
        let shield = try Shield(key: key)
        let plaintext = Array("Test message".utf8)

        let encrypted = try shield.encrypt(plaintext)
        let decrypted = try shield.decrypt(encrypted)

        XCTAssertEqual(plaintext, decrypted)
    }

    func testQuickEncryptDecrypt() throws {
        let key = [UInt8](repeating: 0, count: 32)
        let plaintext = Array("Quick test".utf8)

        let encrypted = try Shield.quickEncrypt(key: key, plaintext: plaintext)
        let decrypted = try Shield.quickDecrypt(key: key, ciphertext: encrypted)

        XCTAssertEqual(plaintext, decrypted)
    }

    func testInvalidKeySize() {
        XCTAssertThrowsError(try Shield(key: [UInt8](repeating: 0, count: 16))) { error in
            XCTAssertEqual(error as? ShieldError, ShieldError.invalidKeySize)
        }
    }

    func testAuthenticationFailed() throws {
        let shield = Shield(password: "password", service: "service")
        var encrypted = try shield.encrypt(Array("test".utf8))

        // Tamper with ciphertext
        encrypted[encrypted.count - 1] ^= 0xFF

        XCTAssertThrowsError(try shield.decrypt(encrypted)) { error in
            XCTAssertEqual(error as? ShieldError, ShieldError.authenticationFailed)
        }
    }

    // MARK: - Ratchet Tests

    func testRatchetSession() throws {
        let rootKey = [UInt8](repeating: 0, count: 32)

        let alice = try RatchetSession(rootKey: rootKey, isInitiator: true)
        let bob = try RatchetSession(rootKey: rootKey, isInitiator: false)

        let msg = Array("Hello Bob!".utf8)
        let encrypted = try alice.encrypt(msg)
        let decrypted = try bob.decrypt(encrypted)

        XCTAssertEqual(msg, decrypted)
        XCTAssertEqual(alice.currentSendCounter, 1)
        XCTAssertEqual(bob.currentRecvCounter, 1)
    }

    func testRatchetReplayProtection() throws {
        let rootKey = [UInt8](repeating: 0, count: 32)

        let alice = try RatchetSession(rootKey: rootKey, isInitiator: true)
        let bob = try RatchetSession(rootKey: rootKey, isInitiator: false)

        let encrypted = try alice.encrypt(Array("test".utf8))
        _ = try bob.decrypt(encrypted)

        XCTAssertThrowsError(try bob.decrypt(encrypted)) { error in
            XCTAssertEqual(error as? ShieldError, ShieldError.replayDetected)
        }
    }

    // MARK: - TOTP Tests

    func testTOTPGenerateVerify() throws {
        guard let secret = TOTP.generateSecret() else {
            XCTFail("Failed to generate secret")
            return
        }

        let totp = TOTP(secret: secret)
        let now = Int64(Date().timeIntervalSince1970)
        let code = totp.generate(timestamp: now)

        XCTAssertEqual(code.count, 6)
        XCTAssertTrue(totp.verify(code: code, timestamp: now, window: 1))
    }

    func testTOTPBase32() {
        let secret = Array("12345678901234567890".utf8)
        let totp = TOTP(secret: secret)

        let encoded = totp.toBase32()
        let decoded = TOTP.fromBase32(encoded)

        XCTAssertEqual(secret, decoded.getSecret())
    }

    func testRecoveryCodes() {
        let rc = RecoveryCodes(count: 5)

        XCTAssertEqual(rc.remaining, 5)

        let codes = rc.allCodes
        XCTAssertEqual(codes.count, 5)

        XCTAssertTrue(rc.verify(codes[0]))
        XCTAssertEqual(rc.remaining, 4)

        XCTAssertFalse(rc.verify(codes[0]))
    }

    // MARK: - Signature Tests

    func testSymmetricSignature() throws {
        let sig = try SymmetricSignature.generate()
        let message = Array("Sign this message".utf8)
        let signature = sig.sign(message)

        XCTAssertTrue(sig.verify(message, signature: signature, verificationKey: sig.verificationKey))
    }

    func testSymmetricSignatureWithTimestamp() throws {
        let sig = try SymmetricSignature.generate()
        let message = Array("Timestamped message".utf8)
        let signature = sig.sign(message, includeTimestamp: true)

        XCTAssertEqual(signature.count, 40)
        XCTAssertTrue(sig.verify(message, signature: signature, verificationKey: sig.verificationKey, maxAge: 60))
    }

    func testSymmetricSignatureFromPassword() throws {
        let sig = SymmetricSignature.fromPassword("password", identity: "user@example.com")
        let message = Array("Test message".utf8)
        let signature = sig.sign(message)

        XCTAssertTrue(sig.verify(message, signature: signature, verificationKey: sig.verificationKey))
    }

    func testLamportSignature() throws {
        let lamport = try LamportSignature.generate()
        let message = Array("Lamport signed message".utf8)
        let signature = try lamport.sign(message)

        XCTAssertTrue(LamportSignature.verify(message, signature: signature, publicKey: lamport.publicKey))
    }

    func testLamportOneTimeUse() throws {
        let lamport = try LamportSignature.generate()
        _ = try lamport.sign(Array("first".utf8))

        XCTAssertTrue(lamport.isUsed)
        XCTAssertThrowsError(try lamport.sign(Array("second".utf8))) { error in
            XCTAssertEqual(error as? ShieldError, ShieldError.lamportKeyUsed)
        }
    }

    // MARK: - Utility Tests

    func testSecureCompare() {
        let a: [UInt8] = [1, 2, 3, 4, 5, 6, 7, 8]
        let b: [UInt8] = [1, 2, 3, 4, 5, 6, 7, 8]
        let c: [UInt8] = [1, 2, 3, 4, 5, 6, 7, 9]

        XCTAssertTrue(Shield.constantTimeEquals(a, b))
        XCTAssertFalse(Shield.constantTimeEquals(a, c))
    }

    func testSha256() {
        let expected: [UInt8] = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
            0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
            0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
            0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
        ]

        let hash = Shield.sha256(Array("abc".utf8))
        XCTAssertEqual(hash, expected)
    }

    func testRandomBytes() {
        guard let a = Shield.randomBytes(32),
              let b = Shield.randomBytes(32) else {
            XCTFail("Failed to generate random bytes")
            return
        }

        XCTAssertNotEqual(a, b)
    }

    func testFingerprints() throws {
        let sig = try SymmetricSignature.generate()
        XCTAssertEqual(sig.fingerprint().count, 16)

        let lamport = try LamportSignature.generate()
        XCTAssertEqual(lamport.fingerprint().count, 16)
    }
}
