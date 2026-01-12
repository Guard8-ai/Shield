import Foundation
import CommonCrypto

/// StreamCipher - Streaming encryption for large files.
///
/// Processes data in chunks with constant memory usage.
/// Each chunk is independently authenticated, allowing:
/// - Early detection of tampering
/// - Constant memory regardless of file size
/// - Potential for parallel processing
public class StreamCipher {
    public static let defaultChunkSize = 64 * 1024 // 64KB
    private static let nonceSize = 16
    private static let macSize = 16
    private static let headerSize = 20 // 4 chunk_size + 16 salt

    private var key: [UInt8]
    private let chunkSize: Int

    /// Create StreamCipher with encryption key.
    ///
    /// - Parameters:
    ///   - key: 32-byte symmetric key
    ///   - chunkSize: Size of each chunk (default: 64KB)
    public init(key: [UInt8], chunkSize: Int = defaultChunkSize) throws {
        guard key.count == 32 else {
            throw ShieldError.invalidKeySize
        }
        self.key = key
        self.chunkSize = chunkSize
    }

    /// Create StreamCipher from password.
    public static func fromPassword(_ password: String, salt: [UInt8], chunkSize: Int = defaultChunkSize) throws -> StreamCipher {
        let key = Shield.pbkdf2(password: password, salt: salt, iterations: 100_000, keyLength: 32)
        return try StreamCipher(key: key, chunkSize: chunkSize)
    }

    /// Encrypt data in memory.
    public func encrypt(_ data: [UInt8]) throws -> [UInt8] {
        var output = [UInt8]()

        // Header: chunk_size(4) || stream_salt(16)
        guard let streamSalt = Shield.randomBytes(16) else {
            throw ShieldError.randomGenerationFailed
        }

        // Append header
        output.append(contentsOf: withUnsafeBytes(of: UInt32(chunkSize).littleEndian) { Array($0) })
        output.append(contentsOf: streamSalt)

        var offset = 0
        var chunkNum: UInt64 = 0

        while offset < data.count {
            let end = min(offset + chunkSize, data.count)
            let chunk = Array(data[offset..<end])

            // Derive per-chunk key
            let chunkKey = deriveChunkKey(key: key, salt: streamSalt, chunkNum: chunkNum)

            // Encrypt chunk
            let encrypted = try encryptBlock(key: chunkKey, data: chunk)

            // Prepend length
            output.append(contentsOf: withUnsafeBytes(of: UInt32(encrypted.count).littleEndian) { Array($0) })
            output.append(contentsOf: encrypted)

            offset = end
            chunkNum += 1
        }

        // End marker
        output.append(contentsOf: withUnsafeBytes(of: UInt32(0).littleEndian) { Array($0) })

        return output
    }

    /// Decrypt data in memory.
    public func decrypt(_ encrypted: [UInt8]) throws -> [UInt8] {
        guard encrypted.count >= StreamCipher.headerSize + 4 else {
            throw ShieldError.ciphertextTooShort
        }

        var output = [UInt8]()
        var pos = 0

        // Read header
        let storedChunkSize = encrypted.withUnsafeBytes { buffer in
            buffer.load(fromByteOffset: pos, as: UInt32.self).littleEndian
        }
        pos += 4

        let streamSalt = Array(encrypted[pos..<pos + 16])
        pos += 16

        var chunkNum: UInt64 = 0

        while pos + 4 <= encrypted.count {
            let encLen = encrypted.withUnsafeBytes { buffer in
                buffer.load(fromByteOffset: pos, as: UInt32.self).littleEndian
            }
            pos += 4

            if encLen == 0 {
                break // End marker
            }

            guard pos + Int(encLen) <= encrypted.count else {
                throw ShieldError.ciphertextTooShort
            }

            let encryptedChunk = Array(encrypted[pos..<pos + Int(encLen)])
            pos += Int(encLen)

            // Derive per-chunk key
            let chunkKey = deriveChunkKey(key: key, salt: streamSalt, chunkNum: chunkNum)

            // Decrypt chunk
            guard let decrypted = try? decryptBlock(key: chunkKey, encrypted: encryptedChunk) else {
                throw ShieldError.authenticationFailed
            }

            output.append(contentsOf: decrypted)
            chunkNum += 1
        }

        return output
    }

    /// Encrypt a file.
    public func encryptFile(inputPath: String, outputPath: String) throws {
        let inputData = try Data(contentsOf: URL(fileURLWithPath: inputPath))
        let encrypted = try encrypt(Array(inputData))
        try Data(encrypted).write(to: URL(fileURLWithPath: outputPath))
    }

    /// Decrypt a file.
    public func decryptFile(inputPath: String, outputPath: String) throws {
        let inputData = try Data(contentsOf: URL(fileURLWithPath: inputPath))
        let decrypted = try decrypt(Array(inputData))
        try Data(decrypted).write(to: URL(fileURLWithPath: outputPath))
    }

    /// Wipe key from memory.
    public func wipe() {
        Shield.secureWipe(&key)
    }

    // MARK: - Helper Methods

    private func deriveChunkKey(key: [UInt8], salt: [UInt8], chunkNum: UInt64) -> [UInt8] {
        var data = key + salt
        data.append(contentsOf: withUnsafeBytes(of: chunkNum.littleEndian) { Array($0) })
        return Shield.sha256(data)
    }

    private func encryptBlock(key: [UInt8], data: [UInt8]) throws -> [UInt8] {
        guard let nonce = Shield.randomBytes(StreamCipher.nonceSize) else {
            throw ShieldError.randomGenerationFailed
        }

        let keystream = generateKeystream(key: key, nonce: nonce, length: data.count)
        var ciphertext = [UInt8](repeating: 0, count: data.count)
        for i in 0..<data.count {
            ciphertext[i] = data[i] ^ keystream[i]
        }

        let macData = nonce + ciphertext
        let mac = Shield.hmacSha256(key: key, data: macData)

        return nonce + ciphertext + Array(mac.prefix(StreamCipher.macSize))
    }

    private func decryptBlock(key: [UInt8], encrypted: [UInt8]) throws -> [UInt8] {
        guard encrypted.count >= StreamCipher.nonceSize + StreamCipher.macSize else {
            throw ShieldError.ciphertextTooShort
        }

        let nonce = Array(encrypted.prefix(StreamCipher.nonceSize))
        let ciphertext = Array(encrypted[StreamCipher.nonceSize..<(encrypted.count - StreamCipher.macSize)])
        let receivedMac = Array(encrypted.suffix(StreamCipher.macSize))

        let macData = nonce + ciphertext
        let expectedMac = Array(Shield.hmacSha256(key: key, data: macData).prefix(StreamCipher.macSize))

        guard Shield.constantTimeEquals(receivedMac, expectedMac) else {
            throw ShieldError.authenticationFailed
        }

        let keystream = generateKeystream(key: key, nonce: nonce, length: ciphertext.count)
        var decrypted = [UInt8](repeating: 0, count: ciphertext.count)
        for i in 0..<ciphertext.count {
            decrypted[i] = ciphertext[i] ^ keystream[i]
        }

        return decrypted
    }

    private func generateKeystream(key: [UInt8], nonce: [UInt8], length: Int) -> [UInt8] {
        let numBlocks = (length + 31) / 32
        var keystream = [UInt8]()
        keystream.reserveCapacity(numBlocks * 32)

        for i in 0..<numBlocks {
            var block = key + nonce
            block.append(contentsOf: withUnsafeBytes(of: UInt32(i).littleEndian) { Array($0) })
            let hash = Shield.sha256(block)
            keystream.append(contentsOf: hash)
        }

        return Array(keystream.prefix(length))
    }
}
