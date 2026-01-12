import Foundation
import CommonCrypto

/// KeyRotationManager - Version-based key management.
///
/// Supports seamless key rotation without breaking existing encrypted data.
/// Each ciphertext is tagged with the key version used.
///
/// Ciphertext format: version(4) || nonce(16) || ciphertext || mac(16)
public class KeyRotationManager {
    private static let nonceSize = 16
    private static let macSize = 16
    private static let minCiphertextSize = 4 + nonceSize + macSize

    private var keys: [Int: [UInt8]] = [:]
    private var _currentVersion: Int

    /// Get current key version.
    public var currentVersion: Int { _currentVersion }

    /// Get all available versions.
    public var versions: [Int] { keys.keys.sorted() }

    /// Create with initial key.
    public init(key: [UInt8], version: Int = 1) throws {
        guard key.count == 32 else {
            throw ShieldError.invalidKeySize
        }
        keys[version] = key
        _currentVersion = version
    }

    /// Add historical key for decryption.
    public func addKey(_ key: [UInt8], version: Int) throws {
        guard keys[version] == nil else {
            throw ShieldError.invalidToken
        }
        keys[version] = key
    }

    /// Rotate to new key.
    public func rotate(to newKey: [UInt8], version newVersion: Int? = nil) throws -> Int {
        let version = newVersion ?? _currentVersion + 1
        guard version > _currentVersion else {
            throw ShieldError.invalidToken
        }
        keys[version] = newKey
        _currentVersion = version
        return version
    }

    /// Encrypt with current key (includes version tag).
    public func encrypt(_ plaintext: [UInt8]) throws -> [UInt8] {
        guard let key = keys[_currentVersion] else {
            throw ShieldError.invalidKeySize
        }
        guard let nonce = Shield.randomBytes(KeyRotationManager.nonceSize) else {
            throw ShieldError.randomGenerationFailed
        }

        // Generate keystream and encrypt
        let keystream = generateKeystream(key: key, nonce: nonce, length: plaintext.count)
        var ciphertext = [UInt8](repeating: 0, count: plaintext.count)
        for i in 0..<plaintext.count {
            ciphertext[i] = plaintext[i] ^ keystream[i]
        }

        // Version bytes
        let versionBytes = withUnsafeBytes(of: UInt32(_currentVersion).littleEndian) { Array($0) }

        // HMAC authenticate (includes version)
        let macData = versionBytes + nonce + ciphertext
        let mac = Shield.hmacSha256(key: key, data: macData)

        // Result: version || nonce || ciphertext || mac
        return versionBytes + nonce + ciphertext + Array(mac.prefix(KeyRotationManager.macSize))
    }

    /// Decrypt with appropriate key version.
    public func decrypt(_ encrypted: [UInt8]) throws -> [UInt8] {
        guard encrypted.count >= KeyRotationManager.minCiphertextSize else {
            throw ShieldError.ciphertextTooShort
        }

        // Parse version
        let version = encrypted.withUnsafeBytes { buffer in
            buffer.load(as: UInt32.self).littleEndian
        }
        let nonce = Array(encrypted[4..<4 + KeyRotationManager.nonceSize])
        let ciphertext = Array(encrypted[4 + KeyRotationManager.nonceSize..<encrypted.count - KeyRotationManager.macSize])
        let receivedMac = Array(encrypted.suffix(KeyRotationManager.macSize))

        guard let key = keys[Int(version)] else {
            throw ShieldError.invalidToken
        }

        // Verify MAC
        let macData = Array(encrypted[0..<encrypted.count - KeyRotationManager.macSize])
        let expectedMac = Array(Shield.hmacSha256(key: key, data: macData).prefix(KeyRotationManager.macSize))

        guard Shield.constantTimeEquals(receivedMac, expectedMac) else {
            throw ShieldError.authenticationFailed
        }

        // Decrypt
        let keystream = generateKeystream(key: key, nonce: nonce, length: ciphertext.count)
        var plaintext = [UInt8](repeating: 0, count: ciphertext.count)
        for i in 0..<ciphertext.count {
            plaintext[i] = ciphertext[i] ^ keystream[i]
        }

        return plaintext
    }

    /// Re-encrypt data with current key.
    public func reEncrypt(_ encrypted: [UInt8]) throws -> [UInt8] {
        let plaintext = try decrypt(encrypted)
        return try encrypt(plaintext)
    }

    /// Remove old keys, keeping only recent versions.
    public func pruneOldKeys(keepVersions: Int = 2) -> [Int] {
        guard keepVersions >= 1 else { return [] }

        let sortedVersions = keys.keys.sorted().reversed()
        var toKeep = Set(sortedVersions.prefix(keepVersions))
        toKeep.insert(_currentVersion)

        var pruned: [Int] = []
        for v in keys.keys {
            if !toKeep.contains(v) {
                keys.removeValue(forKey: v)
                pruned.append(v)
            }
        }

        return pruned
    }

    /// Wipe all keys from memory.
    public func wipe() {
        for key in keys.keys {
            if var keyData = keys[key] {
                Shield.secureWipe(&keyData)
            }
        }
        keys.removeAll()
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
