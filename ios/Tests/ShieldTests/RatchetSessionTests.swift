import XCTest
@testable import Shield

/// Tests for RatchetSession.
final class RatchetSessionTests: XCTestCase {

    private func randomKey() -> [UInt8] {
        var key = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, 32, &key)
        return key
    }

    // MARK: - Basic Encryption/Decryption Tests

    func testEncryptDecryptBasic() {
        let rootKey = randomKey()
        let alice = RatchetSession(rootKey: rootKey, isInitiator: true)
        let bob = RatchetSession(rootKey: rootKey, isInitiator: false)

        let plaintext = Array("Hello Bob!".utf8)
        let encrypted = alice.encrypt(plaintext)
        let decrypted = bob.decrypt(encrypted)

        XCTAssertNotNil(decrypted, "Decryption should succeed")
        XCTAssertEqual(decrypted, plaintext, "Decrypted should match original")
    }

    func testEncryptDecryptMultipleMessages() {
        let rootKey = randomKey()
        let alice = RatchetSession(rootKey: rootKey, isInitiator: true)
        let bob = RatchetSession(rootKey: rootKey, isInitiator: false)

        let messages = ["Hello", "World", "How are you?", "Fine, thanks!"]

        for msg in messages {
            let plaintext = Array(msg.utf8)
            let encrypted = alice.encrypt(plaintext)
            let decrypted = bob.decrypt(encrypted)

            XCTAssertNotNil(decrypted, "Decryption should succeed for: \(msg)")
            XCTAssertEqual(decrypted, plaintext, "Message should round-trip")
        }
    }

    func testBidirectionalCommunication() {
        let rootKey = randomKey()
        let alice = RatchetSession(rootKey: rootKey, isInitiator: true)
        let bob = RatchetSession(rootKey: rootKey, isInitiator: false)

        // Alice sends to Bob
        let aliceMsg = Array("Hello Bob!".utf8)
        let encrypted1 = alice.encrypt(aliceMsg)
        let decrypted1 = bob.decrypt(encrypted1)
        XCTAssertEqual(decrypted1, aliceMsg)

        // Bob sends to Alice
        let bobMsg = Array("Hello Alice!".utf8)
        let encrypted2 = bob.encrypt(bobMsg)
        let decrypted2 = alice.decrypt(encrypted2)
        XCTAssertEqual(decrypted2, bobMsg)
    }

    // MARK: - Forward Secrecy Tests

    func testForwardSecrecyDifferentCiphertext() {
        let rootKey = randomKey()
        let alice = RatchetSession(rootKey: rootKey, isInitiator: true)

        let plaintext = Array("Same message".utf8)
        let encrypted1 = alice.encrypt(plaintext)
        let encrypted2 = alice.encrypt(plaintext)

        XCTAssertNotEqual(encrypted1, encrypted2,
                          "Same plaintext should produce different ciphertext")
    }

    func testCounterIncrementsOnEncrypt() {
        let rootKey = randomKey()
        let session = RatchetSession(rootKey: rootKey, isInitiator: true)

        XCTAssertEqual(session.sendCounter, 0, "Initial send counter should be 0")

        _ = session.encrypt(Array("test".utf8))
        XCTAssertEqual(session.sendCounter, 1, "Counter should increment after encrypt")

        _ = session.encrypt(Array("test".utf8))
        XCTAssertEqual(session.sendCounter, 2, "Counter should increment again")
    }

    func testCounterIncrementsOnDecrypt() {
        let rootKey = randomKey()
        let alice = RatchetSession(rootKey: rootKey, isInitiator: true)
        let bob = RatchetSession(rootKey: rootKey, isInitiator: false)

        XCTAssertEqual(bob.recvCounter, 0, "Initial recv counter should be 0")

        let encrypted = alice.encrypt(Array("test".utf8))
        _ = bob.decrypt(encrypted)
        XCTAssertEqual(bob.recvCounter, 1, "Counter should increment after decrypt")
    }

    // MARK: - Security Tests

    func testDecryptWithWrongKey() {
        let key1 = randomKey()
        let key2 = randomKey()

        let alice = RatchetSession(rootKey: key1, isInitiator: true)
        let bob = RatchetSession(rootKey: key2, isInitiator: false)

        let encrypted = alice.encrypt(Array("secret".utf8))
        let decrypted = bob.decrypt(encrypted)

        XCTAssertNil(decrypted, "Decryption with wrong key should fail")
    }

    func testDecryptTamperedCiphertext() {
        let rootKey = randomKey()
        let alice = RatchetSession(rootKey: rootKey, isInitiator: true)
        let bob = RatchetSession(rootKey: rootKey, isInitiator: false)

        let encrypted = alice.encrypt(Array("secret".utf8))

        // Tamper with ciphertext
        var tampered = encrypted
        tampered[20] ^= 0xFF

        let decrypted = bob.decrypt(tampered)
        XCTAssertNil(decrypted, "Tampered ciphertext should fail to decrypt")
    }

    func testOutOfOrderMessagesFailRatchet() {
        let rootKey = randomKey()
        let alice = RatchetSession(rootKey: rootKey, isInitiator: true)
        let bob = RatchetSession(rootKey: rootKey, isInitiator: false)

        // Alice sends two messages
        _ = alice.encrypt(Array("first".utf8))
        let msg2 = alice.encrypt(Array("second".utf8))

        // Bob tries to decrypt out of order (skipping msg1)
        // This should fail because the chain has to advance in order
        let result = bob.decrypt(msg2)
        XCTAssertNil(result, "Out-of-order message should fail")
    }

    // MARK: - Edge Cases

    func testEmptyMessage() {
        let rootKey = randomKey()
        let alice = RatchetSession(rootKey: rootKey, isInitiator: true)
        let bob = RatchetSession(rootKey: rootKey, isInitiator: false)

        let empty: [UInt8] = []
        let encrypted = alice.encrypt(empty)
        let decrypted = bob.decrypt(encrypted)

        XCTAssertNotNil(decrypted)
        XCTAssertEqual(decrypted, empty, "Empty message should round-trip")
    }

    func testLargeMessage() {
        let rootKey = randomKey()
        let alice = RatchetSession(rootKey: rootKey, isInitiator: true)
        let bob = RatchetSession(rootKey: rootKey, isInitiator: false)

        let large = (0..<10000).map { UInt8($0 & 0xFF) }
        let encrypted = alice.encrypt(large)
        let decrypted = bob.decrypt(encrypted)

        XCTAssertNotNil(decrypted)
        XCTAssertEqual(decrypted, large, "Large message should round-trip")
    }

    func testDecryptTooShort() {
        let rootKey = randomKey()
        let bob = RatchetSession(rootKey: rootKey, isInitiator: false)

        let tooShort = [UInt8](repeating: 0, count: 30)  // Less than minimum size
        let result = bob.decrypt(tooShort)

        XCTAssertNil(result, "Too short ciphertext should fail")
    }

    func testBinaryData() {
        let rootKey = randomKey()
        let alice = RatchetSession(rootKey: rootKey, isInitiator: true)
        let bob = RatchetSession(rootKey: rootKey, isInitiator: false)

        // All possible byte values
        let binary = (0..<256).map { UInt8($0) }
        let encrypted = alice.encrypt(binary)
        let decrypted = bob.decrypt(encrypted)

        XCTAssertNotNil(decrypted)
        XCTAssertEqual(decrypted, binary, "Binary data should round-trip")
    }

    // MARK: - Session Role Tests

    func testInitiatorRoleMatters() {
        let rootKey = randomKey()

        // Both as initiator
        let alice1 = RatchetSession(rootKey: rootKey, isInitiator: true)
        let alice2 = RatchetSession(rootKey: rootKey, isInitiator: true)

        let encrypted = alice1.encrypt(Array("test".utf8))
        let decrypted = alice2.decrypt(encrypted)

        // Should fail because both have same role (same send/recv chains)
        XCTAssertNil(decrypted, "Same role sessions should not communicate")
    }

    func testNonInitiatorRoleMatters() {
        let rootKey = randomKey()

        // Both as non-initiator
        let bob1 = RatchetSession(rootKey: rootKey, isInitiator: false)
        let bob2 = RatchetSession(rootKey: rootKey, isInitiator: false)

        let encrypted = bob1.encrypt(Array("test".utf8))
        let decrypted = bob2.decrypt(encrypted)

        // Should fail because both have same role
        XCTAssertNil(decrypted, "Same role sessions should not communicate")
    }

    // MARK: - Cross-Platform Compatibility Tests

    func testDeterministicChainDerivation() {
        // Same root key should produce same chains
        let rootKey: [UInt8] = Array(repeating: 0xAB, count: 32)

        let session1 = RatchetSession(rootKey: rootKey, isInitiator: true)
        let session2 = RatchetSession(rootKey: rootKey, isInitiator: true)

        // Both should start with same counter
        XCTAssertEqual(session1.sendCounter, session2.sendCounter)
        XCTAssertEqual(session1.recvCounter, session2.recvCounter)
    }
}
