import Foundation
import CommonCrypto

/// Ratcheting session for forward secrecy.
///
/// Each encrypt/decrypt advances the key chain,
/// destroying previous keys automatically.
///
/// Security:
/// - Compromise of current key doesn't reveal past messages
/// - Each message encrypted with unique key
/// - Replay protection via counters
///
/// Example:
/// ```swift
/// let rootKey = TOTP.generateSecret(length: 32)
/// let alice = RatchetSession(rootKey: rootKey, isInitiator: true)
/// let bob = RatchetSession(rootKey: rootKey, isInitiator: false)
///
/// let encrypted = alice.encrypt(Array("Hello Bob!".utf8))
/// if let decrypted = bob.decrypt(encrypted) {
///     print(String(bytes: decrypted, encoding: .utf8)!)
/// }
/// ```
public final class RatchetSession {

    // MARK: - Constants

    private static let nonceSize = 16
    private static let macSize = 16
    private static let minSize = nonceSize + 8 + macSize  // nonce + counter + mac

    // MARK: - Properties

    private var sendChain: [UInt8]
    private var recvChain: [UInt8]
    private var _sendCounter: UInt64 = 0
    private var _recvCounter: UInt64 = 0

    /// Current send counter (for diagnostics).
    public var sendCounter: UInt64 { _sendCounter }

    /// Current receive counter (for diagnostics).
    public var recvCounter: UInt64 { _recvCounter }

    // MARK: - Initialization

    /// Create a new ratchet session from shared root key.
    ///
    /// - Parameters:
    ///   - rootKey: 32-byte shared secret from key exchange
    ///   - isInitiator: True if this party initiated the session
    public init(rootKey: [UInt8], isInitiator: Bool) {
        // Derive separate send/receive chains
        let (sendLabel, recvLabel): ([UInt8], [UInt8])
        if isInitiator {
            sendLabel = Array("send".utf8)
            recvLabel = Array("recv".utf8)
        } else {
            sendLabel = Array("recv".utf8)
            recvLabel = Array("send".utf8)
        }

        sendChain = Self.deriveChainKey(root: rootKey, label: sendLabel)
        recvChain = Self.deriveChainKey(root: rootKey, label: recvLabel)
    }

    // MARK: - Public Methods

    /// Encrypt a message with forward secrecy.
    ///
    /// Advances the send chain - previous keys are destroyed.
    ///
    /// - Parameter plaintext: Message to encrypt
    /// - Returns: Encrypted message
    ///
    /// Note:
    ///   Each call advances the ratchet. The same plaintext
    ///   will produce different ciphertext each time.
    public func encrypt(_ plaintext: [UInt8]) -> [UInt8] {
        // Ratchet send chain
        let (newChain, msgKey) = ratchetChain(sendChain)
        sendChain = newChain

        // Counter for ordering
        let counter = _sendCounter
        _sendCounter += 1

        // Encrypt with message key
        return encryptWithKey(msgKey, plaintext: plaintext, counter: counter)
    }

    /// Decrypt a message with forward secrecy.
    ///
    /// Advances the receive chain - previous keys are destroyed.
    ///
    /// - Parameter ciphertext: Encrypted message from encrypt()
    /// - Returns: Decrypted message, or nil if authentication fails
    ///            or message is out of order
    ///
    /// Note:
    ///   Messages must be decrypted in order. Out-of-order
    ///   messages will fail authentication.
    public func decrypt(_ ciphertext: [UInt8]) -> [UInt8]? {
        // Ratchet receive chain
        let (newChain, msgKey) = ratchetChain(recvChain)
        recvChain = newChain

        // Decrypt with message key
        guard let (plaintext, counter) = decryptWithKey(msgKey, encrypted: ciphertext) else {
            return nil
        }

        // Verify counter (replay protection)
        guard counter == _recvCounter else {
            return nil
        }

        _recvCounter += 1
        return plaintext
    }

    // MARK: - Private Methods

    private static func deriveChainKey(root: [UInt8], label: [UInt8]) -> [UInt8] {
        (root + label).sha256()
    }

    /// Advance chain forward, returning (new_chain_key, message_key).
    /// The old chain key is destroyed after this operation.
    private func ratchetChain(_ chainKey: [UInt8]) -> ([UInt8], [UInt8]) {
        let newChain = (chainKey + Array("chain".utf8)).sha256()
        let msgKey = (chainKey + Array("message".utf8)).sha256()
        return (newChain, msgKey)
    }

    private func encryptWithKey(_ key: [UInt8], plaintext: [UInt8], counter: UInt64) -> [UInt8] {
        // Generate random nonce
        var nonce = [UInt8](repeating: 0, count: Self.nonceSize)
        _ = SecRandomCopyBytes(kSecRandomDefault, Self.nonceSize, &nonce)

        // Counter as 8-byte little-endian
        var counterBytes = [UInt8](repeating: 0, count: 8)
        for i in 0..<8 {
            counterBytes[i] = UInt8(truncatingIfNeeded: counter >> (i * 8))
        }

        // Data: counter || plaintext
        let data = counterBytes + plaintext

        // Generate keystream
        let keystream = generateKeystream(key: key, nonce: nonce, length: data.count)

        // XOR encrypt
        var ciphertext = [UInt8](repeating: 0, count: data.count)
        for i in 0..<data.count {
            ciphertext[i] = data[i] ^ keystream[i]
        }

        // HMAC authenticate
        let mac = Array(hmacSHA256(key: key, data: nonce + ciphertext).prefix(Self.macSize))

        return nonce + ciphertext + mac
    }

    private func decryptWithKey(_ key: [UInt8], encrypted: [UInt8]) -> ([UInt8], UInt64)? {
        guard encrypted.count >= Self.minSize else { return nil }

        let nonce = Array(encrypted[0..<Self.nonceSize])
        let ciphertext = Array(encrypted[Self.nonceSize..<(encrypted.count - Self.macSize)])
        let mac = Array(encrypted[(encrypted.count - Self.macSize)...])

        // Verify MAC
        let expectedMac = Array(hmacSHA256(key: key, data: nonce + ciphertext).prefix(Self.macSize))
        guard constantTimeEquals(mac, expectedMac) else { return nil }

        // Decrypt
        let keystream = generateKeystream(key: key, nonce: nonce, length: ciphertext.count)
        var decrypted = [UInt8](repeating: 0, count: ciphertext.count)
        for i in 0..<ciphertext.count {
            decrypted[i] = ciphertext[i] ^ keystream[i]
        }

        // Parse counter (little-endian)
        var counter: UInt64 = 0
        for i in 0..<8 {
            counter |= UInt64(decrypted[i]) << (i * 8)
        }

        return (Array(decrypted[8...]), counter)
    }

    private func generateKeystream(key: [UInt8], nonce: [UInt8], length: Int) -> [UInt8] {
        let numBlocks = (length + 31) / 32
        var keystream = [UInt8]()
        keystream.reserveCapacity(numBlocks * 32)

        for i in 0..<numBlocks {
            let counter: [UInt8] = [
                UInt8(truncatingIfNeeded: i),
                UInt8(truncatingIfNeeded: i >> 8),
                UInt8(truncatingIfNeeded: i >> 16),
                UInt8(truncatingIfNeeded: i >> 24)
            ]
            let block = (key + nonce + counter).sha256()
            keystream.append(contentsOf: block)
        }

        return Array(keystream.prefix(length))
    }

    private func hmacSHA256(key: [UInt8], data: [UInt8]) -> [UInt8] {
        var result = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256), key, key.count, data, data.count, &result)
        return result
    }

    private func constantTimeEquals(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        guard a.count == b.count else { return false }
        var result: UInt8 = 0
        for i in 0..<a.count {
            result |= a[i] ^ b[i]
        }
        return result == 0
    }
}

// MARK: - SHA256 Extension

private extension Array where Element == UInt8 {
    func sha256() -> [UInt8] {
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        _ = CC_SHA256(self, CC_LONG(self.count), &hash)
        return hash
    }
}
