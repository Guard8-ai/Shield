import XCTest
@testable import Shield

// MARK: - v4 Test Vector Conformance Tests (iOS/macOS)
//
// Loads tests/v4_test_vectors.json (copied into test bundle resources)
// and verifies that Shield.decrypt produces the expected plaintext
// for each deterministic vector.
//
// Vectors use fixed key + fixed nonce + fixed padding so the output is
// deterministic; encryption is non-deterministic (random nonce/padding).
// All v2 vectors set max_age_ms = nil so timestamp checks are disabled.

final class VectorTests: XCTestCase {

    // MARK: - JSON structures

    private struct TestVectorsFile: Decodable {
        let version: String
        let description: String
        let test_vectors: [TestVector]

        enum CodingKeys: String, CodingKey {
            case version
            case description
            case test_vectors
        }
    }

    private struct TestVector: Decodable {
        let id: String
        let description: String
        let format: String
        let key_hex: String
        let expected_plaintext_hex: String
        let ciphertext_hex: String
        let max_age_ms: Int64?

        enum CodingKeys: String, CodingKey {
            case id
            case description
            case format
            case key_hex
            case expected_plaintext_hex
            case ciphertext_hex
            case max_age_ms
        }
    }

    // MARK: - Helpers

    private func hexToBytes(_ hex: String) -> [UInt8] {
        guard !hex.isEmpty else { return [] }
        var bytes = [UInt8]()
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2, limitedBy: hex.endIndex) ?? hex.endIndex
            if let byte = UInt8(hex[index..<next], radix: 16) {
                bytes.append(byte)
            }
            index = next
        }
        return bytes
    }

    private func loadVectors() throws -> TestVectorsFile {
        guard let url = Bundle.module.url(forResource: "v4_test_vectors", withExtension: "json") else {
            XCTFail("v4_test_vectors.json not found in test bundle")
            throw XCTestError(.failureWhileWaiting)
        }
        let data = try Data(contentsOf: url)
        return try JSONDecoder().decode(TestVectorsFile.self, from: data)
    }

    // MARK: - Vector Tests

    func testV4VectorBundleLoads() throws {
        let file = try loadVectors()
        XCTAssertEqual(file.version, "4.0", "Expected version 4.0")
        XCTAssertGreaterThanOrEqual(file.test_vectors.count, 8,
            "Expected at least 8 test vectors, got \(file.test_vectors.count)")
    }

    func testV4AllVectors() throws {
        let file = try loadVectors()
        var passed = 0
        var failed = [String]()

        for vector in file.test_vectors {
            let key = hexToBytes(vector.key_hex)
            let ciphertext = hexToBytes(vector.ciphertext_hex)
            let expectedPlaintext = hexToBytes(vector.expected_plaintext_hex)

            do {
                // Decrypt with max_age_ms = nil (replay protection disabled for historical vectors)
                let shield = try Shield(key: key, maxAgeMs: nil)
                let decrypted = try shield.decrypt(ciphertext)

                if decrypted == expectedPlaintext {
                    passed += 1
                } else {
                    failed.append("\(vector.id): got \(decrypted.map { String(format: "%02x", $0) }.joined()), " +
                                  "expected \(vector.expected_plaintext_hex)")
                }
            } catch {
                failed.append("\(vector.id): threw \(error)")
            }
        }

        XCTAssertTrue(failed.isEmpty,
            "Vector failures (\(failed.count)/\(file.test_vectors.count)):\n" + failed.joined(separator: "\n"))
        XCTAssertGreaterThanOrEqual(passed, 8,
            "Expected at least 8 vectors to pass, only \(passed) passed")
    }

    // MARK: - Individual vector spot checks (fail fast with clear names)

    func testV1VectorZeroKey() throws {
        // v4-v1-001: zero key, zero nonce, plaintext=hello
        let key = [UInt8](repeating: 0, count: 32)
        let ciphertextHex = try loadVectors().test_vectors
            .first(where: { $0.id == "v4-v1-001" })
            .map { $0.ciphertext_hex }

        guard let hex = ciphertextHex else {
            XCTFail("Vector v4-v1-001 not found"); return
        }

        let shield = try Shield(key: key, maxAgeMs: nil)
        let decrypted = try shield.decrypt(hexToBytes(hex))
        let expected = Array("hello".utf8)
        XCTAssertEqual(decrypted, expected,
            "v4-v1-001: expected 'hello', got \(String(bytes: decrypted, encoding: .utf8) ?? "<non-utf8>")")
    }

    func testV2VectorHelloWorld() throws {
        // v4-v2-001: key=0xAB*32, plaintext="Hello, World!"
        let key = [UInt8](repeating: 0xAB, count: 32)
        let ciphertextHex = try loadVectors().test_vectors
            .first(where: { $0.id == "v4-v2-001" })
            .map { $0.ciphertext_hex }

        guard let hex = ciphertextHex else {
            XCTFail("Vector v4-v2-001 not found"); return
        }

        let shield = try Shield(key: key, maxAgeMs: nil)
        let decrypted = try shield.decrypt(hexToBytes(hex))
        let expected = Array("Hello, World!".utf8)
        XCTAssertEqual(decrypted, expected,
            "v4-v2-001: expected 'Hello, World!', got \(String(bytes: decrypted, encoding: .utf8) ?? "<non-utf8>")")
    }

    func testV2VectorEmptyPlaintext() throws {
        // v4-v2-002: empty plaintext
        let key: [UInt8] = [
            0x01, 0x02, 0x01, 0x02, 0x01, 0x02, 0x01, 0x02,
            0x01, 0x02, 0x01, 0x02, 0x01, 0x02, 0x01, 0x02,
            0x01, 0x02, 0x01, 0x02, 0x01, 0x02, 0x01, 0x02,
            0x01, 0x02, 0x01, 0x02, 0x01, 0x02, 0x01, 0x02,
        ]
        let ciphertextHex = try loadVectors().test_vectors
            .first(where: { $0.id == "v4-v2-002" })
            .map { $0.ciphertext_hex }

        guard let hex = ciphertextHex else {
            XCTFail("Vector v4-v2-002 not found"); return
        }

        let shield = try Shield(key: key, maxAgeMs: nil)
        let decrypted = try shield.decrypt(hexToBytes(hex))
        XCTAssertEqual(decrypted, [],
            "v4-v2-002: expected empty plaintext, got \(decrypted.count) bytes")
    }

    func testV2VectorPangram() throws {
        // v4-v2-003: pangram
        let key = [UInt8](Array(0..<32))
        let ciphertextHex = try loadVectors().test_vectors
            .first(where: { $0.id == "v4-v2-003" })
            .map { $0.ciphertext_hex }

        guard let hex = ciphertextHex else {
            XCTFail("Vector v4-v2-003 not found"); return
        }

        let shield = try Shield(key: key, maxAgeMs: nil)
        let decrypted = try shield.decrypt(hexToBytes(hex))
        let expected = Array("The quick brown fox jumps over the lazy dog".utf8)
        XCTAssertEqual(decrypted, expected,
            "v4-v2-003: pangram mismatch")
    }

    func testV2VectorQuickEncryptKey() throws {
        // v4-v2-005: quickEncrypt key (0x01..0x20), plaintext="quick encrypt test"
        let key = [UInt8](Array(1...32))
        let ciphertextHex = try loadVectors().test_vectors
            .first(where: { $0.id == "v4-v2-005" })
            .map { $0.ciphertext_hex }

        guard let hex = ciphertextHex else {
            XCTFail("Vector v4-v2-005 not found"); return
        }

        let shield = try Shield(key: key, maxAgeMs: nil)
        let decrypted = try shield.decrypt(hexToBytes(hex))
        let expected = Array("quick encrypt test".utf8)
        XCTAssertEqual(decrypted, expected,
            "v4-v2-005: quickEncrypt key vector mismatch")
    }

    func testV1VectorSequentialKey() throws {
        // v4-v1-002: sequential key, plaintext="Shield v4 test"
        let key = [UInt8](Array(0..<32))
        let ciphertextHex = try loadVectors().test_vectors
            .first(where: { $0.id == "v4-v1-002" })
            .map { $0.ciphertext_hex }

        guard let hex = ciphertextHex else {
            XCTFail("Vector v4-v1-002 not found"); return
        }

        let shield = try Shield(key: key, maxAgeMs: nil)
        let decrypted = try shield.decrypt(hexToBytes(hex))
        let expected = Array("Shield v4 test".utf8)
        XCTAssertEqual(decrypted, expected,
            "v4-v1-002: sequential key vector mismatch")
    }

    func testV2VectorBinaryData() throws {
        // v4-v2-004: binary plaintext (16 bytes 0x00..0x0F)
        let key = [UInt8]((0..<32).map { UInt8(0xFF - $0) })
        let ciphertextHex = try loadVectors().test_vectors
            .first(where: { $0.id == "v4-v2-004" })
            .map { $0.ciphertext_hex }

        guard let hex = ciphertextHex else {
            XCTFail("Vector v4-v2-004 not found"); return
        }

        let shield = try Shield(key: key, maxAgeMs: nil)
        let decrypted = try shield.decrypt(hexToBytes(hex))
        let expected = [UInt8](Array(0..<16))
        XCTAssertEqual(decrypted, expected,
            "v4-v2-004: binary data vector mismatch")
    }

    func testV1VectorBinaryPlaintext() throws {
        // v4-v1-003: key=0x55*32, plaintext=8 bytes 0xFF
        let key = [UInt8](repeating: 0x55, count: 32)
        let ciphertextHex = try loadVectors().test_vectors
            .first(where: { $0.id == "v4-v1-003" })
            .map { $0.ciphertext_hex }

        guard let hex = ciphertextHex else {
            XCTFail("Vector v4-v1-003 not found"); return
        }

        let shield = try Shield(key: key, maxAgeMs: nil)
        let decrypted = try shield.decrypt(hexToBytes(hex))
        let expected = [UInt8](repeating: 0xFF, count: 8)
        XCTAssertEqual(decrypted, expected,
            "v4-v1-003: binary v1 vector mismatch")
    }
}
