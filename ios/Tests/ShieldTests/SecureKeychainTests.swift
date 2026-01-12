import XCTest
@testable import Shield

/// Tests for SecureKeychain.
///
/// Note: Some tests require a real Keychain and may not work in all CI environments.
/// Tests are designed to clean up after themselves to avoid test pollution.
final class SecureKeychainTests: XCTestCase {

    private var keychain: SecureKeychain!
    private let testAlias = "test_key_\(UUID().uuidString)"

    override func setUp() {
        super.setUp()
        keychain = SecureKeychain(serviceName: "ai.guard8.shield.tests")
    }

    override func tearDown() {
        // Clean up test keys
        try? keychain.delete(for: testAlias)
        super.tearDown()
    }

    // MARK: - Store and Retrieve Tests

    func testStoreAndRetrieveKey() throws {
        let originalKey: [UInt8] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                                    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32]

        try keychain.store(key: originalKey, for: testAlias)
        let retrieved = try keychain.retrieve(for: testAlias)

        XCTAssertNotNil(retrieved)
        XCTAssertEqual(retrieved, originalKey)
    }

    func testRetrieveNonExistentKey() throws {
        let retrieved = try keychain.retrieve(for: "non_existent_key_\(UUID().uuidString)")
        XCTAssertNil(retrieved)
    }

    func testOverwriteExistingKey() throws {
        let key1: [UInt8] = Array(repeating: 0x01, count: 32)
        let key2: [UInt8] = Array(repeating: 0x02, count: 32)

        try keychain.store(key: key1, for: testAlias)
        try keychain.store(key: key2, for: testAlias)

        let retrieved = try keychain.retrieve(for: testAlias)
        XCTAssertEqual(retrieved, key2)
    }

    // MARK: - Delete Tests

    func testDeleteKey() throws {
        let key: [UInt8] = Array(repeating: 0xAB, count: 32)

        try keychain.store(key: key, for: testAlias)
        XCTAssertTrue(keychain.exists(for: testAlias))

        try keychain.delete(for: testAlias)
        XCTAssertFalse(keychain.exists(for: testAlias))
    }

    func testDeleteNonExistentKey() {
        // Should not throw for non-existent key
        XCTAssertNoThrow(try keychain.delete(for: "non_existent_key_\(UUID().uuidString)"))
    }

    // MARK: - Exists Tests

    func testExistsForStoredKey() throws {
        let key: [UInt8] = Array(repeating: 0xCD, count: 32)

        XCTAssertFalse(keychain.exists(for: testAlias))

        try keychain.store(key: key, for: testAlias)

        XCTAssertTrue(keychain.exists(for: testAlias))
    }

    func testExistsForNonExistentKey() {
        XCTAssertFalse(keychain.exists(for: "non_existent_\(UUID().uuidString)"))
    }

    // MARK: - Shield Integration Tests

    func testGetOrCreateShieldCreatesNew() throws {
        let shield = try keychain.getOrCreateShield(
            alias: testAlias,
            password: "test_password",
            service: "test.example.com"
        )

        // Should have stored the key
        XCTAssertTrue(keychain.exists(for: testAlias))

        // Shield should work
        let plaintext = Array("Hello, World!".utf8)
        let encrypted = shield.encrypt(plaintext)
        let decrypted = shield.decrypt(encrypted)

        XCTAssertNotNil(decrypted)
        XCTAssertEqual(decrypted, plaintext)
    }

    func testGetOrCreateShieldRetrievesExisting() throws {
        // Create first Shield
        let shield1 = try keychain.getOrCreateShield(
            alias: testAlias,
            password: "password",
            service: "service.com"
        )

        // Encrypt with first Shield
        let plaintext = Array("Secret data".utf8)
        let encrypted = shield1.encrypt(plaintext)

        // Get Shield again (should use stored key)
        let shield2 = try keychain.getOrCreateShield(
            alias: testAlias,
            password: "different_password",  // Password is ignored for existing key
            service: "different_service"
        )

        // Should be able to decrypt with second Shield
        let decrypted = shield2.decrypt(encrypted)

        XCTAssertNotNil(decrypted)
        XCTAssertEqual(decrypted, plaintext)
    }

    // MARK: - Binary Data Tests

    func testStoreBinaryKey() throws {
        // Test with all possible byte values
        var key = [UInt8](repeating: 0, count: 256)
        for i in 0..<256 {
            key[i] = UInt8(i)
        }

        try keychain.store(key: key, for: testAlias)
        let retrieved = try keychain.retrieve(for: testAlias)

        XCTAssertEqual(retrieved, key)
    }

    func testStoreEmptyKey() throws {
        let emptyKey: [UInt8] = []

        try keychain.store(key: emptyKey, for: testAlias)
        let retrieved = try keychain.retrieve(for: testAlias)

        XCTAssertNotNil(retrieved)
        XCTAssertEqual(retrieved, emptyKey)
    }

    // MARK: - Multiple Keys Tests

    func testMultipleKeys() throws {
        let alias1 = "\(testAlias)_1"
        let alias2 = "\(testAlias)_2"
        let alias3 = "\(testAlias)_3"

        let key1: [UInt8] = Array(repeating: 0x01, count: 32)
        let key2: [UInt8] = Array(repeating: 0x02, count: 32)
        let key3: [UInt8] = Array(repeating: 0x03, count: 32)

        defer {
            try? keychain.delete(for: alias1)
            try? keychain.delete(for: alias2)
            try? keychain.delete(for: alias3)
        }

        try keychain.store(key: key1, for: alias1)
        try keychain.store(key: key2, for: alias2)
        try keychain.store(key: key3, for: alias3)

        XCTAssertEqual(try keychain.retrieve(for: alias1), key1)
        XCTAssertEqual(try keychain.retrieve(for: alias2), key2)
        XCTAssertEqual(try keychain.retrieve(for: alias3), key3)
    }

    // MARK: - Service Name Tests

    func testDifferentServiceNames() throws {
        let keychain1 = SecureKeychain(serviceName: "service1")
        let keychain2 = SecureKeychain(serviceName: "service2")

        let alias = "shared_alias_\(UUID().uuidString)"
        let key1: [UInt8] = Array(repeating: 0x11, count: 32)
        let key2: [UInt8] = Array(repeating: 0x22, count: 32)

        defer {
            try? keychain1.delete(for: alias)
            try? keychain2.delete(for: alias)
        }

        try keychain1.store(key: key1, for: alias)
        try keychain2.store(key: key2, for: alias)

        // Each service should have its own key
        XCTAssertEqual(try keychain1.retrieve(for: alias), key1)
        XCTAssertEqual(try keychain2.retrieve(for: alias), key2)
    }

    // MARK: - Thread Safety (Basic)

    func testConcurrentAccess() throws {
        let key: [UInt8] = Array(repeating: 0xAA, count: 32)
        try keychain.store(key: key, for: testAlias)

        let expectation = XCTestExpectation(description: "Concurrent reads")
        expectation.expectedFulfillmentCount = 10

        for _ in 0..<10 {
            DispatchQueue.global().async {
                do {
                    let retrieved = try self.keychain.retrieve(for: self.testAlias)
                    XCTAssertEqual(retrieved, key)
                } catch {
                    XCTFail("Concurrent read failed: \(error)")
                }
                expectation.fulfill()
            }
        }

        wait(for: [expectation], timeout: 5.0)
    }
}
