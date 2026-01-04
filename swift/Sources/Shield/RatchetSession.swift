import Foundation
import CommonCrypto

/// RatchetSession provides forward secrecy through key ratcheting.
public class RatchetSession {
    private var sendKey: [UInt8]
    private var recvKey: [UInt8]
    private var sendCounter: UInt64 = 0
    private var recvCounter: UInt64 = 0
    private let isInitiator: Bool

    public init(rootKey: [UInt8], isInitiator: Bool) throws {
        guard rootKey.count == Shield.keySize else {
            throw ShieldError.invalidKeySize
        }

        self.isInitiator = isInitiator

        if isInitiator {
            self.sendKey = RatchetSession.deriveChainKey(rootKey, info: "init_send")
            self.recvKey = RatchetSession.deriveChainKey(rootKey, info: "init_recv")
        } else {
            self.sendKey = RatchetSession.deriveChainKey(rootKey, info: "init_recv")
            self.recvKey = RatchetSession.deriveChainKey(rootKey, info: "init_send")
        }
    }

    public func encrypt(_ plaintext: [UInt8]) throws -> [UInt8] {
        let messageKey = RatchetSession.deriveChainKey(sendKey, info: "message")

        guard let nonce = Shield.randomBytes(Shield.nonceSize) else {
            throw ShieldError.randomGenerationFailed
        }

        // Generate keystream and XOR
        let keystream = generateKeystream(key: messageKey, nonce: nonce, length: plaintext.count)
        var ciphertext = [UInt8](repeating: 0, count: plaintext.count)
        for i in 0..<plaintext.count {
            ciphertext[i] = plaintext[i] ^ keystream[i]
        }

        // Counter bytes
        let counterBytes = withUnsafeBytes(of: sendCounter.littleEndian) { Array($0) }

        // MAC over counter || nonce || ciphertext
        let macData = counterBytes + nonce + ciphertext
        let mac = Shield.hmacSha256(key: messageKey, data: macData)

        // Ratchet
        sendKey = RatchetSession.deriveChainKey(sendKey, info: "ratchet")
        sendCounter += 1

        // Format: counter(8) || nonce(16) || ciphertext || mac(16)
        return counterBytes + nonce + ciphertext + Array(mac.prefix(Shield.macSize))
    }

    public func decrypt(_ encrypted: [UInt8]) throws -> [UInt8] {
        guard encrypted.count >= 8 + Shield.nonceSize + Shield.macSize else {
            throw ShieldError.ciphertextTooShort
        }

        // Parse
        let counter = encrypted.prefix(8).withUnsafeBytes { $0.load(as: UInt64.self).littleEndian }
        let nonce = Array(encrypted[8..<(8 + Shield.nonceSize)])
        let ciphertext = Array(encrypted[(8 + Shield.nonceSize)..<(encrypted.count - Shield.macSize)])
        let receivedMac = Array(encrypted.suffix(Shield.macSize))

        // Check counter
        if counter < recvCounter {
            throw ShieldError.replayDetected
        }
        if counter > recvCounter {
            throw ShieldError.outOfOrder
        }

        let messageKey = RatchetSession.deriveChainKey(recvKey, info: "message")

        // Verify MAC
        let macData = Array(encrypted.prefix(8)) + nonce + ciphertext
        let expectedMac = Array(Shield.hmacSha256(key: messageKey, data: macData).prefix(Shield.macSize))

        guard Shield.constantTimeEquals(receivedMac, expectedMac) else {
            throw ShieldError.authenticationFailed
        }

        // Decrypt
        let keystream = generateKeystream(key: messageKey, nonce: nonce, length: ciphertext.count)
        var plaintext = [UInt8](repeating: 0, count: ciphertext.count)
        for i in 0..<ciphertext.count {
            plaintext[i] = ciphertext[i] ^ keystream[i]
        }

        // Ratchet
        recvKey = RatchetSession.deriveChainKey(recvKey, info: "ratchet")
        recvCounter += 1

        return plaintext
    }

    public var currentSendCounter: UInt64 { sendCounter }
    public var currentRecvCounter: UInt64 { recvCounter }

    public func wipe() {
        Shield.secureWipe(&sendKey)
        Shield.secureWipe(&recvKey)
    }

    private static func deriveChainKey(_ key: [UInt8], info: String) -> [UInt8] {
        return Shield.sha256(key + Array(info.utf8))
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
