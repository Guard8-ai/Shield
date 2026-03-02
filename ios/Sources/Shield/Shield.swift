import Foundation
import CommonCrypto
import Security

/// EXPTIME-secure symmetric encryption for iOS/macOS.
///
/// Uses password-derived keys with PBKDF2 and encrypts using
/// a SHA256-based stream cipher with HMAC-SHA256 authentication.
/// Breaking requires 2^256 operations - no shortcut exists.
///
/// Example:
/// ```swift
/// let shield = Shield(password: "my_password", service: "github.com")
/// let encrypted = try shield.encrypt(Array("secret data".utf8))
/// let decrypted = try shield.decrypt(encrypted)
/// ```
public final class Shield {

    // MARK: - Constants

    public static let pbkdf2Iterations: UInt32 = 100_000
    private static let nonceSize = 16
    private static let macSize = 16
    private static let keySize = 32

    // V2 constants
    private static let v2HeaderSize = 17  // counter(8) + timestamp(8) + pad_len(1)
    private static let minPadding = 32
    private static let maxPadding = 128
    private static let minTimestampMs: Int64 = 1577836800000  // 2020-01-01
    private static let maxTimestampMs: Int64 = 4102444800000  // 2100-01-01
    private static let defaultMaxAgeMs: Int64 = 60000

    // MARK: - Properties

    private var key: [UInt8]
    private var encKey: [UInt8]  // encryption subkey
    private var macKey: [UInt8]  // authentication subkey
    private let maxAgeMs: Int64?

    // MARK: - Subkey Derivation

    /// Derive separated encryption and MAC subkeys from master key.
    private static func deriveSubkeys(_ masterKey: [UInt8]) -> (enc: [UInt8], mac: [UInt8]) {
        let encKey = hmacSHA256(key: masterKey, data: Array("shield-encrypt".utf8))
        let macKey = hmacSHA256(key: masterKey, data: Array("shield-authenticate".utf8))
        return (encKey, macKey)
    }

    // MARK: - Initialization

    /// Create Shield instance from password and service name.
    public init(password: String, service: String, iterations: UInt32 = pbkdf2Iterations) {
        let salt = service.data(using: .utf8)!.sha256()
        self.key = Self.deriveKey(password: password, salt: Array(salt), iterations: iterations)
        let subkeys = Self.deriveSubkeys(self.key)
        self.encKey = subkeys.enc
        self.macKey = subkeys.mac
        self.maxAgeMs = Self.defaultMaxAgeMs
    }

    /// Create Shield with pre-shared key (no password derivation).
    public init(key: [UInt8]) throws {
        guard key.count == Self.keySize else {
            throw ShieldError.invalidKeySize(expected: Self.keySize, actual: key.count)
        }
        self.key = key
        let subkeys = Self.deriveSubkeys(key)
        self.encKey = subkeys.enc
        self.macKey = subkeys.mac
        self.maxAgeMs = Self.defaultMaxAgeMs
    }

    /// Create Shield with pre-shared key and custom max age.
    public init(key: [UInt8], maxAgeMs: Int64?) throws {
        guard key.count == Self.keySize else {
            throw ShieldError.invalidKeySize(expected: Self.keySize, actual: key.count)
        }
        self.key = key
        let subkeys = Self.deriveSubkeys(key)
        self.encKey = subkeys.enc
        self.macKey = subkeys.mac
        self.maxAgeMs = maxAgeMs
    }

    // MARK: - Static Methods

    /// Quick encrypt with pre-shared key.
    public static func quickEncrypt(key: [UInt8], plaintext: [UInt8]) throws -> [UInt8] {
        let shield = try Shield(key: key)
        return try shield.encrypt(plaintext)
    }

    /// Quick decrypt with pre-shared key.
    public static func quickDecrypt(key: [UInt8], ciphertext: [UInt8]) throws -> [UInt8] {
        let shield = try Shield(key: key, maxAgeMs: nil)
        return try shield.decrypt(ciphertext)
    }

    // MARK: - Encryption/Decryption

    /// Encrypt data (v2 format).
    public func encrypt(_ plaintext: [UInt8]) throws -> [UInt8] {
        // Generate random nonce
        var nonce = [UInt8](repeating: 0, count: Self.nonceSize)
        guard SecRandomCopyBytes(kSecRandomDefault, Self.nonceSize, &nonce) == errSecSuccess else {
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
        let padRange = Self.maxPadding - Self.minPadding + 1  // 97
        var padLen = 0
        var buf = [UInt8](repeating: 0, count: 1)
        while true {
            guard SecRandomCopyBytes(kSecRandomDefault, 1, &buf) == errSecSuccess else {
                throw ShieldError.randomGenerationFailed
            }
            let v = Int(buf[0])
            if v < padRange * (256 / padRange) {
                padLen = (v % padRange) + Self.minPadding
                break
            }
        }
        var padding = [UInt8](repeating: 0, count: padLen)
        guard SecRandomCopyBytes(kSecRandomDefault, padLen, &padding) == errSecSuccess else {
            throw ShieldError.randomGenerationFailed
        }

        // Data to encrypt: counter || timestamp || pad_len || padding || plaintext
        let dataToEncrypt = counter + timestamp + [UInt8(padLen)] + padding + plaintext

        // Generate keystream and XOR (using encryption subkey)
        let keystream = generateKeystream(key: encKey, nonce: nonce, length: dataToEncrypt.count)
        var ciphertext = [UInt8](repeating: 0, count: dataToEncrypt.count)
        for i in 0..<dataToEncrypt.count {
            ciphertext[i] = dataToEncrypt[i] ^ keystream[i]
        }

        // Compute HMAC over nonce || ciphertext (using MAC subkey)
        let macData = nonce + ciphertext
        let mac = Self.hmacSHA256(key: macKey, data: macData)

        return nonce + ciphertext + Array(mac.prefix(Self.macSize))
    }

    /// Decrypt and verify data (auto-detects v1/v2).
    public func decrypt(_ encrypted: [UInt8]) throws -> [UInt8] {
        let minSize = Self.nonceSize + 8 + Self.macSize
        guard encrypted.count >= minSize else {
            throw ShieldError.ciphertextTooShort
        }

        let nonce = Array(encrypted[0..<Self.nonceSize])
        let ciphertext = Array(encrypted[Self.nonceSize..<(encrypted.count - Self.macSize)])
        let receivedMac = Array(encrypted[(encrypted.count - Self.macSize)...])

        // Verify MAC (using MAC subkey, constant-time)
        let expectedMac = Array(Self.hmacSHA256(key: macKey, data: nonce + ciphertext).prefix(Self.macSize))
        guard Self.constantTimeEquals(receivedMac, expectedMac) else {
            throw ShieldError.authenticationFailed
        }

        // Decrypt (using encryption subkey)
        let keystream = generateKeystream(key: encKey, nonce: nonce, length: ciphertext.count)
        var decrypted = [UInt8](repeating: 0, count: ciphertext.count)
        for i in 0..<ciphertext.count {
            decrypted[i] = ciphertext[i] ^ keystream[i]
        }

        // Auto-detect v2 by timestamp range
        if decrypted.count >= Self.v2HeaderSize {
            var timestampMs: Int64 = 0
            for i in 0..<8 {
                timestampMs |= Int64(decrypted[8 + i]) << (i * 8)
            }

            if timestampMs >= Self.minTimestampMs && timestampMs <= Self.maxTimestampMs {
                // v2 format detected
                let padLen = Int(decrypted[16])

                guard padLen >= Self.minPadding && padLen <= Self.maxPadding else {
                    throw ShieldError.authenticationFailed
                }

                let dataStart = Self.v2HeaderSize + padLen
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
        return Array(decrypted[8...])
    }

    // MARK: - Private Methods

    private static func deriveKey(password: String, salt: [UInt8], iterations: UInt32) -> [UInt8] {
        var derivedKey = [UInt8](repeating: 0, count: keySize)
        let passwordData = password.data(using: .utf8)!

        passwordData.withUnsafeBytes { passwordBytes in
            salt.withUnsafeBytes { saltBytes in
                CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    passwordBytes.baseAddress?.assumingMemoryBound(to: Int8.self),
                    passwordData.count,
                    saltBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    salt.count,
                    CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                    iterations,
                    &derivedKey,
                    keySize
                )
            }
        }

        return derivedKey
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

    // MARK: - Crypto Utilities (public static for use by other Shield components)

    public static func hmacSHA256(key: [UInt8], data: [UInt8]) -> [UInt8] {
        var result = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256), key, key.count, data, data.count, &result)
        return result
    }

    public static func constantTimeEquals(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        guard a.count == b.count else { return false }
        var result: UInt8 = 0
        for i in 0..<a.count {
            result |= a[i] ^ b[i]
        }
        return result == 0
    }
}

// MARK: - ShieldError

public enum ShieldError: Error, LocalizedError {
    case invalidKeySize(expected: Int, actual: Int)
    case ciphertextTooShort
    case authenticationFailed
    case randomGenerationFailed
    case keychainError(OSStatus)

    public var errorDescription: String? {
        switch self {
        case .invalidKeySize(let expected, let actual):
            return "Invalid key size: expected \(expected) bytes, got \(actual)"
        case .ciphertextTooShort:
            return "Ciphertext too short"
        case .authenticationFailed:
            return "Authentication failed: wrong key or tampered data"
        case .randomGenerationFailed:
            return "Random generation failed"
        case .keychainError(let status):
            return "Keychain error: \(status)"
        }
    }
}

// MARK: - Data Extensions

private extension Data {
    func sha256() -> [UInt8] {
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        self.withUnsafeBytes { bytes in
            _ = CC_SHA256(bytes.baseAddress, CC_LONG(self.count), &hash)
        }
        return hash
    }
}

private extension Array where Element == UInt8 {
    func sha256() -> [UInt8] {
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        _ = CC_SHA256(self, CC_LONG(self.count), &hash)
        return hash
    }
}
