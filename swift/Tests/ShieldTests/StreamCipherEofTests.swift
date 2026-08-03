import XCTest
@testable import Shield

/// Tests for the authenticated end-of-stream tag in StreamCipher.
final class StreamCipherEofTests: XCTestCase {

    // Cross-language golden vector:
    //   master_key = 32 x 0x42, stream_salt = 16 x 0x01, chunk_count = 3
    private let expectedTagHex =
        "52d4dfbeccc364bd69a2f232aa460bd1eb79b0c93903f344dd7b937703918431"

    private func hex(_ b: [UInt8]) -> String {
        b.map { String(format: "%02x", $0) }.joined()
    }

    /// Recomputes the end-of-stream tag using the same byte layout the
    /// StreamCipher uses, and checks it against the shared golden vector.
    func testEofTagConformanceVector() {
        let masterKey = [UInt8](repeating: 0x42, count: 32)
        let streamSalt = [UInt8](repeating: 0x01, count: 16)
        let chunkCount: UInt64 = 3

        let eofKey = Shield.hmacSha256(key: masterKey, data: Array("shield-stream-eof".utf8))
        var input = streamSalt
        input.append(contentsOf: withUnsafeBytes(of: chunkCount.littleEndian) { Array($0) })
        let tag = Shield.hmacSha256(key: eofKey, data: input)

        XCTAssertEqual(hex(tag), expectedTagHex)
    }

    func testStreamRoundtrip() throws {
        let key = [UInt8](repeating: 0x42, count: 32)
        let cipher = try StreamCipher(key: key, chunkSize: 16)
        let data = (0..<64).map { UInt8($0) }
        XCTAssertEqual(try cipher.decrypt(cipher.encrypt(data)), data)
    }

    func testTruncationAtChunkBoundaryRejected() throws {
        let key = [UInt8](repeating: 0x42, count: 32)
        let cipher = try StreamCipher(key: key, chunkSize: 16)
        let data = (0..<64).map { UInt8($0) }
        let enc = try cipher.encrypt(data)
        // Drop the trailing 4-byte zero marker and the 32-byte EOF tag.
        let truncated = Array(enc[0..<(enc.count - 36)])
        XCTAssertThrowsError(try cipher.decrypt(truncated))
    }

    func testForgedEndMarkerRejected() throws {
        let key = [UInt8](repeating: 0x42, count: 32)
        let cipher = try StreamCipher(key: key, chunkSize: 16)
        let data = (0..<64).map { UInt8($0) }
        let enc = try cipher.encrypt(data)
        // Strip trailer, then re-append a bare zero marker (no valid tag).
        var forged = Array(enc[0..<(enc.count - 36)])
        forged.append(contentsOf: [0, 0, 0, 0])
        XCTAssertThrowsError(try cipher.decrypt(forged))
    }
}
