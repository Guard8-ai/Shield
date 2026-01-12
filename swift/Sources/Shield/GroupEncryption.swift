import Foundation
import CommonCrypto

/// GroupEncryption - Multi-recipient encryption.
///
/// Encrypt once for multiple recipients, each can decrypt with their own key.
/// Uses a group key for message encryption, then encrypts the group key
/// separately for each member.
public class GroupEncryption {
    private static let nonceSize = 16
    private static let macSize = 16

    private var groupKey: [UInt8]
    private var members: [String: [UInt8]] = [:]

    /// Create group encryption with generated group key.
    public init() {
        self.groupKey = Shield.randomBytes(32) ?? [UInt8](repeating: 0, count: 32)
    }

    /// Create group encryption with specified group key.
    public init(groupKey: [UInt8]) throws {
        guard groupKey.count == 32 else {
            throw ShieldError.invalidKeySize
        }
        self.groupKey = groupKey
    }

    /// Add a member to the group.
    public func addMember(_ memberId: String, sharedKey: [UInt8]) throws {
        guard sharedKey.count == 32 else {
            throw ShieldError.invalidKeySize
        }
        members[memberId] = sharedKey
    }

    /// Remove a member from the group.
    public func removeMember(_ memberId: String) -> Bool {
        return members.removeValue(forKey: memberId) != nil
    }

    /// Get list of member IDs.
    public var memberIds: [String] {
        return Array(members.keys)
    }

    /// Encrypt for all group members.
    public func encrypt(_ plaintext: [UInt8]) throws -> [String: Any] {
        // Encrypt message with group key
        let ciphertext = try encryptBlock(key: groupKey, data: plaintext)

        // Encrypt group key for each member
        var encryptedKeys: [String: String] = [:]
        for (memberId, memberKey) in members {
            let encKey = try encryptBlock(key: memberKey, data: groupKey)
            encryptedKeys[memberId] = Data(encKey).base64EncodedString()
        }

        return [
            "version": 1,
            "ciphertext": Data(ciphertext).base64EncodedString(),
            "keys": encryptedKeys
        ]
    }

    /// Decrypt as a group member.
    public static func decrypt(_ encrypted: [String: Any], memberId: String, memberKey: [UInt8]) -> [UInt8]? {
        guard let keys = encrypted["keys"] as? [String: String],
              let encryptedKeyB64 = keys[memberId],
              let encryptedKeyData = Data(base64Encoded: encryptedKeyB64) else {
            return nil
        }

        // Decrypt group key
        guard let groupKey = try? decryptBlock(key: memberKey, encrypted: Array(encryptedKeyData)) else {
            return nil
        }

        // Decrypt message
        guard let ciphertextB64 = encrypted["ciphertext"] as? String,
              let ciphertextData = Data(base64Encoded: ciphertextB64) else {
            return nil
        }

        return try? decryptBlock(key: groupKey, encrypted: Array(ciphertextData))
    }

    /// Rotate the group key.
    public func rotateKey() -> [UInt8] {
        let oldKey = groupKey
        groupKey = Shield.randomBytes(32) ?? [UInt8](repeating: 0, count: 32)
        return oldKey
    }

    /// Wipe keys from memory.
    public func wipe() {
        Shield.secureWipe(&groupKey)
        for key in members.keys {
            if var memberKey = members[key] {
                Shield.secureWipe(&memberKey)
            }
        }
        members.removeAll()
    }

    // MARK: - Helper Methods

    private func encryptBlock(key: [UInt8], data: [UInt8]) throws -> [UInt8] {
        guard let nonce = Shield.randomBytes(GroupEncryption.nonceSize) else {
            throw ShieldError.randomGenerationFailed
        }

        let keystream = generateKeystream(key: key, nonce: nonce, length: data.count)
        var ciphertext = [UInt8](repeating: 0, count: data.count)
        for i in 0..<data.count {
            ciphertext[i] = data[i] ^ keystream[i]
        }

        let macData = nonce + ciphertext
        let mac = Shield.hmacSha256(key: key, data: macData)

        return nonce + ciphertext + Array(mac.prefix(GroupEncryption.macSize))
    }

    private static func decryptBlock(key: [UInt8], encrypted: [UInt8]) throws -> [UInt8] {
        guard encrypted.count >= nonceSize + macSize else {
            throw ShieldError.ciphertextTooShort
        }

        let nonce = Array(encrypted.prefix(nonceSize))
        let ciphertext = Array(encrypted[nonceSize..<(encrypted.count - macSize)])
        let receivedMac = Array(encrypted.suffix(macSize))

        let macData = nonce + ciphertext
        let expectedMac = Array(Shield.hmacSha256(key: key, data: macData).prefix(macSize))

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

    private static func generateKeystream(key: [UInt8], nonce: [UInt8], length: Int) -> [UInt8] {
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
