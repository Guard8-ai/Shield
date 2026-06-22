import XCTest
import Foundation
@testable import Shield

/// Conformance: the Swift post-quantum hybrid KEX must satisfy the shared
/// cross-language vectors (tests/pq_kex_vectors.json), proving byte-identical key
/// reconstruction and shared-key derivation against the other Shield bindings.
///
/// Requires macOS 15 / iOS 18 (CryptoKit MLKEM768). Run on an Apple host.
@available(macOS 15.0, iOS 18.0, tvOS 18.0, watchOS 11.0, *)
final class PqHybridTests: XCTestCase {

    private func hexToData(_ h: String) -> Data {
        var d = Data(); var i = h.startIndex
        while i < h.endIndex {
            let n = h.index(i, offsetBy: 2)
            d.append(UInt8(h[i..<n], radix: 16)!)
            i = n
        }
        return d
    }

    private func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

    private func vectorsURL() throws -> URL {
        var dir = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
        for _ in 0..<8 {
            let candidate = dir.appendingPathComponent("tests/pq_kex_vectors.json")
            if FileManager.default.fileExists(atPath: candidate.path) { return candidate }
            dir = dir.deletingLastPathComponent()
        }
        throw XCTSkip("pq_kex_vectors.json not found from \(FileManager.default.currentDirectoryPath)")
    }

    func testReproducesVectors() throws {
        let url = try vectorsURL()
        let doc = try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as! [String: Any]
        let vectors = doc["vectors"] as! [[String: Any]]
        XCTAssertFalse(vectors.isEmpty)
        for v in vectors {
            let bob = try HybridPrivateKey.fromBytes(hexToData(v["bob_private_hex"] as! String))
            XCTAssertEqual(hex(try bob.publicKey().toBytes()), v["bob_public_bundle_hex"] as! String,
                           "bundle mismatch for \(v["name"] as! String)")
            let shared = try bob.accept(hexToData(v["handshake_hex"] as! String))
            XCTAssertEqual(hex(shared), v["expected_shared_key_hex"] as! String,
                           "shared key mismatch for \(v["name"] as! String)")
        }
    }

    func testInitiateAcceptRoundTrips() throws {
        let bob = try HybridPrivateKey.generate()
        let (handshake, aliceKey) = try PqHybrid.initiate(peer: bob.publicKey())
        XCTAssertEqual(handshake.count, PqHybrid.handshakeSize)
        XCTAssertEqual(try bob.accept(handshake), aliceKey)
    }

    func testPrivateKeySerializationRoundTrips() throws {
        let bob = try HybridPrivateKey.generate()
        let restored = try HybridPrivateKey.fromBytes(bob.toBytes())
        XCTAssertEqual(try bob.publicKey().toBytes(), try restored.publicKey().toBytes())
        let (handshake, aliceKey) = try PqHybrid.initiate(peer: bob.publicKey())
        XCTAssertEqual(try restored.accept(handshake), aliceKey)
    }
}
