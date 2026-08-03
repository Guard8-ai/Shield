import XCTest
@testable import Shield

// MARK: - v4 Test Vector Conformance Tests
//
// Vectors are embedded directly as Swift literals (no JSON/Bundle) to avoid
// JSON parsing issues on different platform versions.
//
// Each ciphertext was produced with:
//   nonce = 0x00 * 12, timestamp_ms = 0, pad_len = 32, padding = 0x00 * 32
//   aeadKey = HKDF-SHA256-Expand(masterKey, "shield/aead/v4", 32)
//   wire:   0x13 || 0x01 || nonce(12) || AES-GCM(ct||tag)
// Set maxAgeMs = nil to disable timestamp validation.

final class VectorTests: XCTestCase {

    private struct Vector {
        let id: String
        let keyHex: String
        let plaintextHex: String
        let ciphertextHex: String
    }

    private let vectors: [Vector] = [
        Vector(id: "v4-v1-001",
               keyHex:       "0000000000000000000000000000000000000000000000000000000000000000",
               plaintextHex: "68656c6c6f",
               ciphertextHex: "1301000000000000000000000000e6c2b83d449e146be3bac68ba551440a0ebb73b91564bf80b232f328348d5e27db23b7c25dae4eee5e29d17b403708d0f94f2d41758dfae07f7e6bf08343"),
        Vector(id: "v4-v1-002",
               keyHex:       "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
               plaintextHex: "536869656c642076342074657374",
               ciphertextHex: "13010000000000000000000000008dd4e86b7951593ab5a79f79164f08e5987f867211a2520dfed69f0a09f358d05cb0be217a4501935f4d440ca4002e5343b93392651f89e6f963ac072138060bf27dc16d67d8f3"),
        Vector(id: "v4-v1-003",
               keyHex:       "5555555555555555555555555555555555555555555555555555555555555555",
               plaintextHex: "ffffffffffffffff",
               ciphertextHex: "13010000000000000000000000002600f6ea8805189d78b642c527f685aa4b668ab0cb6b41b4e84e5ee63fa0c1bd0fcc289caf88ca34ea69d5acc2b3e0559de0df4f5b65d52e67ecf23a757b42d7f0"),
        Vector(id: "v4-v2-001",
               keyHex:       "abababababababababababababababababababababababababababababababab",
               plaintextHex: "48656c6c6f2c20576f726c6421",
               ciphertextHex: "1301000000000000000000000000ed207ffc8bbeb03aa1c03f8a64bbd51f1c4a7dc3243a0797272b2a92281054cd5a19d9bb12eb13c672deb5804b4677e88bd1d40c487cf4a10b139b25fcdb0c78702a90e17ddb"),
        Vector(id: "v4-v2-002",
               keyHex:       "0102010201020102010201020102010201020102010201020102010201020102",
               plaintextHex: "",
               ciphertextHex: "1301000000000000000000000000f7001914791ade674b2a332e54b16b0db8ef1932f2d2c1f571347542e81176e0fcdaae67067aff0cf0a95954af5123308ff2021d401fd7b1d4"),
        Vector(id: "v4-v2-003",
               keyHex:       "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
               plaintextHex: "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67",
               ciphertextHex: "13010000000000000000000000008dd4e86b7951593ab5a79f79164f08e5987f867211a2520dfed69f0a09f358d05cb0be217a4501935f4a4400e11d3f1a56e6338472038ad80f0e44633d4c97f0ae1a15f7b246e67b3e964dba8c16e84517a2177aad4d1ff59a2a0b21d97671fd0844b6ea"),
        Vector(id: "v4-v2-004",
               keyHex:       "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0",
               plaintextHex: "000102030405060708090a0b0c0d0e0f",
               ciphertextHex: "1301000000000000000000000000b046ac47a56f6b5d33dd98d793ef3b797ed61510e3e508ba602613ded85522f3d6534f029d51eab4ae290e61efc27f71ae8b1ac642c588e1b73ead252116b38cd7a3602a44e6795147"),
        Vector(id: "v4-v2-005",
               keyHex:       "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
               plaintextHex: "717569636b20656e63727970742074657374",
               ciphertextHex: "130100000000000000000000000063ed16c5e3afd25ee93e2804fa0e1b5ee070e1791dffd555c2f0985fa8b0c7b7562b1ec438755687cb1dbb8de9b266e76222c93730baf9b5065aadaa9f7a044459ccdb270b7a23d1088977"),
    ]

    // MARK: - Helpers

    private func hex(_ s: String) -> [UInt8] {
        guard !s.isEmpty else { return [] }
        var bytes = [UInt8]()
        var index = s.startIndex
        while index < s.endIndex {
            let next = s.index(index, offsetBy: 2, limitedBy: s.endIndex) ?? s.endIndex
            if let byte = UInt8(s[index..<next], radix: 16) {
                bytes.append(byte)
            }
            index = next
        }
        return bytes
    }

    // MARK: - Tests

    func testV4AllVectors() throws {
        var passed = 0
        var failures = [String]()
        for v in vectors {
            let key = hex(v.keyHex)
            let ciphertext = hex(v.ciphertextHex)
            let expected = hex(v.plaintextHex)
            do {
                let shield = try Shield(key: key, maxAgeMs: nil)
                let decrypted = try shield.decrypt(ciphertext)
                if decrypted == expected { passed += 1 }
                else {
                    failures.append("\(v.id): got \(decrypted.map { String(format: "%02x", $0) }.joined()) want \(v.plaintextHex)")
                }
            } catch {
                failures.append("\(v.id): threw \(error)")
            }
        }
        XCTAssertTrue(failures.isEmpty,
            "Vector failures (\(failures.count)/\(vectors.count)):\n" + failures.joined(separator: "\n"))
        XCTAssertGreaterThanOrEqual(passed, 8, "Expected at least 8 vectors to pass, got \(passed)")
    }

    func testV1VectorZeroKey() throws {
        let v = vectors.first(where: { $0.id == "v4-v1-001" })!
        let shield = try Shield(key: hex(v.keyHex), maxAgeMs: nil)
        XCTAssertEqual(try shield.decrypt(hex(v.ciphertextHex)), hex(v.plaintextHex))
    }

    func testV2VectorHelloWorld() throws {
        let v = vectors.first(where: { $0.id == "v4-v2-001" })!
        let shield = try Shield(key: hex(v.keyHex), maxAgeMs: nil)
        XCTAssertEqual(try shield.decrypt(hex(v.ciphertextHex)), hex(v.plaintextHex))
    }

    func testV2VectorEmptyPlaintext() throws {
        let v = vectors.first(where: { $0.id == "v4-v2-002" })!
        let shield = try Shield(key: hex(v.keyHex), maxAgeMs: nil)
        XCTAssertEqual(try shield.decrypt(hex(v.ciphertextHex)), [])
    }

    func testV2VectorPangram() throws {
        let v = vectors.first(where: { $0.id == "v4-v2-003" })!
        let shield = try Shield(key: hex(v.keyHex), maxAgeMs: nil)
        XCTAssertEqual(try shield.decrypt(hex(v.ciphertextHex)), hex(v.plaintextHex))
    }

    func testV2VectorQuickEncryptKey() throws {
        let v = vectors.first(where: { $0.id == "v4-v2-005" })!
        let shield = try Shield(key: hex(v.keyHex), maxAgeMs: nil)
        XCTAssertEqual(try shield.decrypt(hex(v.ciphertextHex)), hex(v.plaintextHex))
    }

    func testV1VectorSequentialKey() throws {
        let v = vectors.first(where: { $0.id == "v4-v1-002" })!
        let shield = try Shield(key: hex(v.keyHex), maxAgeMs: nil)
        XCTAssertEqual(try shield.decrypt(hex(v.ciphertextHex)), hex(v.plaintextHex))
    }

    func testV2VectorBinaryData() throws {
        let v = vectors.first(where: { $0.id == "v4-v2-004" })!
        let shield = try Shield(key: hex(v.keyHex), maxAgeMs: nil)
        XCTAssertEqual(try shield.decrypt(hex(v.ciphertextHex)), hex(v.plaintextHex))
    }

    func testV1VectorBinaryPlaintext() throws {
        let v = vectors.first(where: { $0.id == "v4-v1-003" })!
        let shield = try Shield(key: hex(v.keyHex), maxAgeMs: nil)
        XCTAssertEqual(try shield.decrypt(hex(v.ciphertextHex)), hex(v.plaintextHex))
    }
}
