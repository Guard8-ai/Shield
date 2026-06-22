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

    // MARK: - Security-fix Tests (CR-1 / CR-2 / CR-3)

    /// CR-1: two instances with the same password+service get DIFFERENT random
    /// salts and DIFFERENT derived keys (deterministic-salt bug fixed).
    func testSamePasswordServiceDifferentKeys() throws {
        let pw = "hunter2", svc = "github.com"
        let a = Shield(password: pw, service: svc)
        let b = Shield(password: pw, service: svc)

        let ca = try a.encrypt(Array("identical plaintext".utf8))
        let cb = try b.encrypt(Array("identical plaintext".utf8))

        // Salts live at bytes [1..<17] of a password-mode ciphertext.
        let saltA = Array(ca[1..<(1 + Shield.saltSize)])
        let saltB = Array(cb[1..<(1 + Shield.saltSize)])
        XCTAssertNotEqual(saltA, saltB)
        XCTAssertNotEqual(a.getKey(), b.getKey())
    }

    /// CR-1: a recipient with the same password+service (different instance salt)
    /// decrypts the sender's ciphertext via the salt carried in the header.
    func testCrossInstanceRoundtrip() throws {
        let alice = Shield(password: "correct horse battery staple", service: "service.example")
        let bob = Shield(password: "correct horse battery staple", service: "service.example")
        let msg = Array("hello from alice".utf8)
        XCTAssertEqual(try bob.decrypt(alice.encrypt(msg)), msg)
    }

    /// CR-1: a different password (same service) must NOT decrypt.
    func testWrongPasswordFails() throws {
        let sender = Shield(password: "right-password", service: "example.com")
        let wrong = Shield(password: "wrong-password", service: "example.com")
        let encrypted = try sender.encrypt(Array("secret".utf8))
        XCTAssertThrowsError(try wrong.decrypt(encrypted))
    }

    /// CR-2: PBKDF2 iteration count is 600,000.
    func testIterations600k() {
        XCTAssertEqual(Shield.iterations, 600_000)
    }

    /// CR-3: password ciphertext starts with 0x02; key/quick ciphertext with 0x12.
    func testVersionBytes() throws {
        let pwCt = try Shield(password: "pw", service: "svc").encrypt(Array("x".utf8))
        XCTAssertEqual(pwCt[0], Shield.versionPassword)
        XCTAssertEqual(Shield.versionPassword, 0x02)

        let key = (0..<32).map { UInt8($0) }
        let quickCt = try Shield.quickEncrypt(key: key, plaintext: Array("x".utf8))
        XCTAssertEqual(quickCt[0], Shield.versionKey)

        let keyedCt = try Shield(key: key).encrypt(Array("x".utf8))
        XCTAssertEqual(keyedCt[0], Shield.versionKey)
        XCTAssertEqual(Shield.versionKey, 0x12)
    }

    /// CR-3: flipping ANY byte (version, salt, nonce, ct, mac) fails auth.
    func testTamperDetection() throws {
        let shield = Shield(password: "pw", service: "svc")
        let ct = try shield.encrypt(Array("secret payload".utf8))
        XCTAssertEqual(try shield.decrypt(ct), Array("secret payload".utf8))

        for i in 0..<ct.count {
            var tampered = ct
            tampered[i] ^= 0xFF
            XCTAssertThrowsError(try shield.decrypt(tampered), "tamper at byte \(i) not detected")
        }
    }

    /// CR-3: tampering with the authenticated salt fails the MAC.
    func testTamperSaltDetected() throws {
        let shield = Shield(password: "pw", service: "svc")
        var ct = try shield.encrypt(Array("authenticated salt".utf8))
        ct[1] ^= 0xFF  // flip a salt byte
        XCTAssertThrowsError(try shield.decrypt(ct)) { error in
            XCTAssertEqual(error as? ShieldError, ShieldError.authenticationFailed)
        }
    }

    /// CR-3: changing the version byte to the other valid version is rejected.
    func testTamperVersionDetected() throws {
        let shield = Shield(password: "pw", service: "svc")
        var ct = try shield.encrypt(Array("authenticated version".utf8))
        ct[0] = Shield.versionKey
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

    /// A pre-shared-key instance must not silently accept a password-mode ciphertext.
    func testKeyModeRejectsPasswordCiphertext() throws {
        let pw = Shield(password: "pw", service: "svc")
        let ct = try pw.encrypt(Array("pw secret".utf8))
        let ks = try Shield(key: [UInt8](repeating: 0, count: 32))
        XCTAssertThrowsError(try ks.decrypt(ct))
    }

    /// Key-mode (0x12) roundtrip via the pre-shared-key constructor.
    func testKeyModeRoundtrip() throws {
        let key = (0..<32).map { UInt8($0) }
        let shield = try Shield(key: key)
        let msg = Array("pre-shared key message".utf8)
        XCTAssertEqual(try shield.decrypt(shield.encrypt(msg)), msg)
    }

    /// Explicit salt is honored and stored in the header; same salt -> same key.
    func testExplicitSaltHonoredAndStored() throws {
        guard let salt = Shield.randomBytes(Shield.saltSize) else {
            XCTFail("random salt"); return
        }
        let a = Shield(password: "pw", service: "svc", salt: salt, iterations: Shield.iterations)
        let b = Shield(password: "pw", service: "svc", salt: salt, iterations: Shield.iterations)
        XCTAssertEqual(a.getKey(), b.getKey())

        let ct = try a.encrypt(Array("data".utf8))
        XCTAssertEqual(Array(ct[1..<(1 + Shield.saltSize)]), salt)
        XCTAssertEqual(try b.decrypt(ct), Array("data".utf8))
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
