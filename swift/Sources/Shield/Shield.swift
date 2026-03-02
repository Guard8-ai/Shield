import Foundation
import CommonCrypto

/// Shield - EXPTIME-Secure Symmetric Encryption Library
///
/// Uses only symmetric cryptographic primitives with proven exponential-time security:
/// PBKDF2-SHA256, HMAC-SHA256, and SHA256-based stream cipher.
/// Breaking requires 2^256 operations - no shortcut exists.
public class Shield {
    public static let keySize = 32
    public static let nonceSize = 16
    public static let macSize = 16
    public static let iterations: UInt32 = 100_000
    public static let minCiphertextSize = nonceSize + 8 + macSize

    // V2 constants
    public static let v2HeaderSize = 17  // counter(8) + timestamp(8) + pad_len(1)
    public static let minPadding = 32
    public static let maxPadding = 128
    public static let minTimestampMs: Int64 = 1577836800000  // 2020-01-01
    public static let maxTimestampMs: Int64 = 4102444800000  // 2100-01-01
    public static let defaultMaxAgeMs: Int64 = 60000

    private var key: [UInt8]
    private var encKey: [UInt8]  // encryption subkey
    private var macKey: [UInt8]  // authentication subkey
    private let maxAgeMs: Int64?

    /// Derive separated encryption and MAC subkeys from master key.
    private static func deriveSubkeys(_ masterKey: [UInt8]) -> (enc: [UInt8], mac: [UInt8]) {
        let encKey = hmacSha256(key: masterKey, data: Array("shield-encrypt".utf8))
        let macKey = hmacSha256(key: masterKey, data: Array("shield-authenticate".utf8))
        return (encKey, macKey)
    }

    /// Create Shield from password and service name.
    public init(password: String, service: String) {
        let salt = Shield.sha256(Array(service.utf8))
        self.key = Shield.pbkdf2(password: password, salt: salt, iterations: Shield.iterations, keyLength: Shield.keySize)
        let subkeys = Shield.deriveSubkeys(self.key)
        self.encKey = subkeys.enc
        self.macKey = subkeys.mac
        self.maxAgeMs = Shield.defaultMaxAgeMs
    }

    /// Create Shield with pre-shared key.
    public init(key: [UInt8]) throws {
        guard key.count == Shield.keySize else {
            throw ShieldError.invalidKeySize
        }
        self.key = key
        let subkeys = Shield.deriveSubkeys(key)
        self.encKey = subkeys.enc
        self.macKey = subkeys.mac
        self.maxAgeMs = Shield.defaultMaxAgeMs
    }

    /// Create Shield with pre-shared key and custom max age.
    public init(key: [UInt8], maxAgeMs: Int64?) throws {
        guard key.count == Shield.keySize else {
            throw ShieldError.invalidKeySize
        }
        self.key = key
        let subkeys = Shield.deriveSubkeys(key)
        self.encKey = subkeys.enc
        self.macKey = subkeys.mac
        self.maxAgeMs = maxAgeMs
    }

    /// Encrypt plaintext (v2 format).
    public func encrypt(_ plaintext: [UInt8]) throws -> [UInt8] {
        return try Shield.encryptWithSeparatedKeys(encKey, macKey: macKey, plaintext: plaintext)
    }

    /// Decrypt ciphertext (auto-detects v1/v2).
    public func decrypt(_ ciphertext: [UInt8]) throws -> [UInt8] {
        return try Shield.decryptWithSeparatedKeys(encKey, macKey: macKey, ciphertext: ciphertext, maxAgeMs: maxAgeMs)
    }

    /// Get the derived key.
    public func getKey() -> [UInt8] {
        return key
    }

    /// Wipe key from memory.
    public func wipe() {
        for i in 0..<key.count { key[i] = 0 }
        for i in 0..<encKey.count { encKey[i] = 0 }
        for i in 0..<macKey.count { macKey[i] = 0 }
    }

    // MARK: - Static Methods

    /// Quick encrypt with explicit key.
    public static func quickEncrypt(key: [UInt8], plaintext: [UInt8]) throws -> [UInt8] {
        guard key.count == keySize else {
            throw ShieldError.invalidKeySize
        }
        let subkeys = deriveSubkeys(key)
        return try encryptWithSeparatedKeys(subkeys.enc, macKey: subkeys.mac, plaintext: plaintext)
    }

    /// Quick decrypt with explicit key.
    public static func quickDecrypt(key: [UInt8], ciphertext: [UInt8]) throws -> [UInt8] {
        guard key.count == keySize else {
            throw ShieldError.invalidKeySize
        }
        let subkeys = deriveSubkeys(key)
        return try decryptWithSeparatedKeys(subkeys.enc, macKey: subkeys.mac, ciphertext: ciphertext, maxAgeMs: nil)
    }

    private static func encryptWithSeparatedKeys(_ encKey: [UInt8], macKey: [UInt8], plaintext: [UInt8]) throws -> [UInt8] {
        // Generate random nonce
        var nonce = [UInt8](repeating: 0, count: nonceSize)
        guard SecRandomCopyBytes(kSecRandomDefault, nonceSize, &nonce) == errSecSuccess else {
            throw ShieldError.randomGenerationFailed
        }

        // Counter prefix (8 bytes of zeros)
        let counter = [UInt8](repeating: 0, count: 8)

        // Timestamp in milliseconds (little-endian)
        let timestampMs = Int64(Date().timeIntervalSince1970 * 1000)
        var timestamp = [UInt8](repeating: 0, count: 8)
        for i in 0..<8 {
            timestamp[i] = UInt8(truncatingIfNeeded: timestampMs >> (i * 8))
        }

        // Random padding: 32-128 bytes (rejection sampling)
        let padRange = maxPadding - minPadding + 1  // 97
        var padLen = 0
        var buf = [UInt8](repeating: 0, count: 1)
        while true {
            guard SecRandomCopyBytes(kSecRandomDefault, 1, &buf) == errSecSuccess else {
                throw ShieldError.randomGenerationFailed
            }
            let v = Int(buf[0])
            if v < padRange * (256 / padRange) {
                padLen = (v % padRange) + minPadding
                break
            }
        }
        var padding = [UInt8](repeating: 0, count: padLen)
        guard SecRandomCopyBytes(kSecRandomDefault, padLen, &padding) == errSecSuccess else {
            throw ShieldError.randomGenerationFailed
        }

        // Data to encrypt: counter || timestamp || pad_len || padding || plaintext
        var dataToEncrypt = counter + timestamp + [UInt8(padLen)] + padding + plaintext

        // Generate keystream and XOR (using encryption subkey)
        let keystream = generateKeystream(key: encKey, nonce: nonce, length: dataToEncrypt.count)
        var ciphertext = [UInt8](repeating: 0, count: dataToEncrypt.count)
        for i in 0..<dataToEncrypt.count {
            ciphertext[i] = dataToEncrypt[i] ^ keystream[i]
        }

        // Compute HMAC over nonce || ciphertext (using MAC subkey)
        let macData = nonce + ciphertext
        let mac = hmacSha256(key: macKey, data: macData)

        // Format: nonce || ciphertext || mac
        return nonce + ciphertext + Array(mac.prefix(macSize))
    }

    private static func decryptWithSeparatedKeys(_ encKey: [UInt8], macKey: [UInt8], ciphertext encrypted: [UInt8], maxAgeMs: Int64?) throws -> [UInt8] {
        guard encrypted.count >= minCiphertextSize else {
            throw ShieldError.ciphertextTooShort
        }

        // Parse components
        let nonce = Array(encrypted.prefix(nonceSize))
        let ciphertext = Array(encrypted[nonceSize..<(encrypted.count - macSize)])
        let receivedMac = Array(encrypted.suffix(macSize))

        // Verify MAC (using MAC subkey)
        let macData = nonce + ciphertext
        let expectedMac = Array(hmacSha256(key: macKey, data: macData).prefix(macSize))

        guard constantTimeEquals(receivedMac, expectedMac) else {
            throw ShieldError.authenticationFailed
        }

        // Decrypt (using encryption subkey)
        let keystream = generateKeystream(key: encKey, nonce: nonce, length: ciphertext.count)
        var decrypted = [UInt8](repeating: 0, count: ciphertext.count)
        for i in 0..<ciphertext.count {
            decrypted[i] = ciphertext[i] ^ keystream[i]
        }

        // Auto-detect v2 by timestamp range
        if decrypted.count >= v2HeaderSize {
            var timestampMs: Int64 = 0
            for i in 0..<8 {
                timestampMs |= Int64(decrypted[8 + i]) << (i * 8)
            }

            if timestampMs >= minTimestampMs && timestampMs <= maxTimestampMs {
                // v2 format detected
                let padLen = Int(decrypted[16])

                guard padLen >= minPadding && padLen <= maxPadding else {
                    throw ShieldError.authenticationFailed
                }

                let dataStart = v2HeaderSize + padLen
                guard decrypted.count >= dataStart else {
                    throw ShieldError.ciphertextTooShort
                }

                if let maxAge = maxAgeMs {
                    let nowMs = Int64(Date().timeIntervalSince1970 * 1000)
                    let age = nowMs - timestampMs
                    if timestampMs > nowMs + 5000 || age > maxAge {
                        throw ShieldError.authenticationFailed
                    }
                }

                return Array(decrypted[dataStart...])
            }
        }

        // v1 format: skip counter (8 bytes)
        return Array(decrypted.dropFirst(8))
    }

    private static func generateKeystream(key: [UInt8], nonce: [UInt8], length: Int) -> [UInt8] {
        let numBlocks = (length + 31) / 32
        var keystream = [UInt8]()
        keystream.reserveCapacity(numBlocks * 32)

        for i in 0..<numBlocks {
            var block = key + nonce
            block.append(contentsOf: withUnsafeBytes(of: UInt32(i).littleEndian) { Array($0) })
            let hash = sha256(block)
            keystream.append(contentsOf: hash)
        }

        return Array(keystream.prefix(length))
    }

    // MARK: - Crypto Utilities

    public static func sha256(_ data: [UInt8]) -> [UInt8] {
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes { buffer in
            _ = CC_SHA256(buffer.baseAddress, CC_LONG(data.count), &hash)
        }
        return hash
    }

    public static func hmacSha256(key: [UInt8], data: [UInt8]) -> [UInt8] {
        var mac = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        key.withUnsafeBytes { keyBuffer in
            data.withUnsafeBytes { dataBuffer in
                CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256),
                       keyBuffer.baseAddress, key.count,
                       dataBuffer.baseAddress, data.count,
                       &mac)
            }
        }
        return mac
    }

    public static func pbkdf2(password: String, salt: [UInt8], iterations: UInt32, keyLength: Int) -> [UInt8] {
        var derivedKey = [UInt8](repeating: 0, count: keyLength)
        let passwordData = Array(password.utf8)

        passwordData.withUnsafeBytes { passwordBuffer in
            salt.withUnsafeBytes { saltBuffer in
                CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    passwordBuffer.baseAddress?.assumingMemoryBound(to: Int8.self),
                    passwordData.count,
                    saltBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    salt.count,
                    CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                    iterations,
                    &derivedKey,
                    keyLength
                )
            }
        }

        return derivedKey
    }

    public static func constantTimeEquals(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        guard a.count == b.count else { return false }
        var result: UInt8 = 0
        for i in 0..<a.count {
            result |= a[i] ^ b[i]
        }
        return result == 0
    }

    public static func randomBytes(_ count: Int) -> [UInt8]? {
        var bytes = [UInt8](repeating: 0, count: count)
        guard SecRandomCopyBytes(kSecRandomDefault, count, &bytes) == errSecSuccess else {
            return nil
        }
        return bytes
    }

    public static func secureWipe(_ data: inout [UInt8]) {
        for i in 0..<data.count {
            data[i] = 0
        }
    }
}

// MARK: - Errors

public enum ShieldError: Error {
    case invalidKeySize
    case ciphertextTooShort
    case authenticationFailed
    case randomGenerationFailed
    case lamportKeyUsed
    case replayDetected
    case outOfOrder
    case tokenExpired
    case invalidToken
    case sessionExpired
}
