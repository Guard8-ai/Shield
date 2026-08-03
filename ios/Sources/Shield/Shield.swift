import Foundation
import CommonCrypto
import CryptoKit
import Security

/// Authenticated symmetric encryption for iOS/macOS (wire format v4).
///
/// v4 replaces the previous custom SHA-256 keystream + HMAC construction with a
/// standard AEAD (AES-256-GCM by default, ChaCha20-Poly1305 optional) from Apple
/// CryptoKit. No cryptography is hand-rolled: key derivation uses PBKDF2-HMAC-SHA256
/// (CommonCrypto) + HKDF-SHA256-Expand (CryptoKit), and encryption uses CryptoKit's
/// AEAD primitives. The wire format matches every other Shield binding byte-for-byte
/// (see tests/v4_test_vectors.json).
///
/// Example:
/// ```swift
/// let shield = Shield(password: "my_password", service: "github.com")
/// let encrypted = try shield.encrypt(Array("secret data".utf8))
/// let decrypted = try shield.decrypt(encrypted)
/// ```
public final class Shield {

    // MARK: - Constants

    public static let pbkdf2Iterations: UInt32 = 600_000
    private static let keySize = 32
    private static let saltSize = 16

    // Authenticated leading version bytes (wire format v4).
    // Password mode: 0x03 || suite(1) || salt(16) || nonce(12) || ciphertext||tag
    // Key mode:      0x13 || suite(1) || nonce(12) || ciphertext||tag
    private static let versionPassword: UInt8 = 0x03
    private static let versionKey: UInt8 = 0x13

    // Cipher-suite identifiers.
    public static let suiteAesGcm: UInt8 = 0x01
    public static let suiteChaCha20Poly1305: UInt8 = 0x02

    // Base-AEAD constants.
    private static let aeadNonceSize = 12
    private static let tagSize = 16
    private static let innerHeaderSize = 9  // timestamp(8) + pad_len(1)
    private static let minPadding = 32
    private static let maxPadding = 128
    private static let defaultMaxAgeMs: Int64 = 60000
    private static let hkdfAeadInfo = "shield/aead/v4"

    // MARK: - Properties

    private var key: [UInt8]
    private var aeadKey: [UInt8]
    private let suite: UInt8
    private let maxAgeMs: Int64?

    // Password-mode fields (nil in pre-shared-key mode).
    private let password: String?
    private let service: String?
    private let iterations: UInt32
    private let salt: [UInt8]?
    private var keyCache: [[UInt8]: [UInt8]] = [:]

    // MARK: - AEAD key derivation

    /// AEAD key = HKDF-SHA256-Expand(master, "shield/aead/v4", 32).
    public static func deriveAeadKey(_ masterKey: [UInt8]) -> [UInt8] {
        let okm = HKDF<SHA256>.expand(
            pseudoRandomKey: SymmetricKey(data: Data(masterKey)),
            info: Data(hkdfAeadInfo.utf8),
            outputByteCount: keySize)
        return okm.withUnsafeBytes { Array($0) }
    }

    // MARK: - Initialization

    /// Create Shield instance from password and service name.
    public convenience init(password: String, service: String, iterations: UInt32 = pbkdf2Iterations) {
        // Fail closed on CSPRNG failure: never fall back to a predictable
        // (all-zero) salt, which would derive identical keys across instances.
        // fatalError is the unrecoverable-error analog of the Go (panic) and
        // Rust (RandomFailed) references.
        var randomSalt = [UInt8](repeating: 0, count: Self.saltSize)
        guard SecRandomCopyBytes(kSecRandomDefault, Self.saltSize, &randomSalt) == errSecSuccess else {
            fatalError("Shield: CSPRNG failure generating salt (fail-closed)")
        }
        self.init(password: password, service: service, salt: randomSalt, iterations: iterations)
    }

    /// Create Shield instance from password and service name with an explicit salt.
    public init(password: String, service: String, salt: [UInt8], iterations: UInt32) {
        self.password = password
        self.service = service
        self.iterations = iterations
        self.salt = salt
        self.suite = Self.suiteAesGcm
        self.maxAgeMs = Self.defaultMaxAgeMs

        let pbkdfSalt = salt + Array(service.utf8)
        let derived = Self.deriveKey(password: password, salt: pbkdfSalt, iterations: iterations)
        self.key = derived
        self.aeadKey = Self.deriveAeadKey(derived)
        self.keyCache[salt] = derived
    }

    /// Create Shield with pre-shared key (no password derivation).
    public init(key: [UInt8]) throws {
        guard key.count == Self.keySize else {
            throw ShieldError.invalidKeySize(expected: Self.keySize, actual: key.count)
        }
        self.key = key
        self.aeadKey = Self.deriveAeadKey(key)
        self.suite = Self.suiteAesGcm
        self.maxAgeMs = Self.defaultMaxAgeMs
        self.password = nil
        self.service = nil
        self.iterations = Self.pbkdf2Iterations
        self.salt = nil
    }

    /// Create Shield with pre-shared key and custom max age.
    public init(key: [UInt8], maxAgeMs: Int64?) throws {
        guard key.count == Self.keySize else {
            throw ShieldError.invalidKeySize(expected: Self.keySize, actual: key.count)
        }
        self.key = key
        self.aeadKey = Self.deriveAeadKey(key)
        self.suite = Self.suiteAesGcm
        self.maxAgeMs = maxAgeMs
        self.password = nil
        self.service = nil
        self.iterations = Self.pbkdf2Iterations
        self.salt = nil
    }

    // MARK: - Static Methods

    /// Quick encrypt with pre-shared key (pre-shared-key mode, AES-256-GCM, 0x13).
    public static func quickEncrypt(key: [UInt8], plaintext: [UInt8]) throws -> [UInt8] {
        let shield = try Shield(key: key)
        return try shield.encrypt(plaintext)
    }

    /// Quick decrypt with pre-shared key (pre-shared-key mode).
    public static func quickDecrypt(key: [UInt8], ciphertext: [UInt8]) throws -> [UInt8] {
        let shield = try Shield(key: key, maxAgeMs: nil)
        return try shield.decrypt(ciphertext)
    }

    // MARK: - Encryption/Decryption

    /// Encrypt data.
    ///
    /// Password mode output: 0x03 || suite || salt(16) || nonce(12) || ciphertext||tag.
    /// Key mode output:      0x13 || suite || nonce(12) || ciphertext||tag.
    public func encrypt(_ plaintext: [UInt8]) throws -> [UInt8] {
        return try Self.seal(aeadKey: aeadKey, suite: suite, salt: salt, plaintext: plaintext)
    }

    /// Decrypt and verify data, dispatching on the leading authenticated version byte.
    public func decrypt(_ encrypted: [UInt8]) throws -> [UInt8] {
        guard encrypted.count >= 1 else {
            throw ShieldError.ciphertextTooShort
        }

        let version = encrypted[0]
        if version == Self.versionPassword {
            guard salt != nil, let password = password, let service = service else {
                throw ShieldError.authenticationFailed
            }
            let aadLen = 2 + Self.saltSize
            guard encrypted.count >= aadLen + Self.aeadNonceSize + Self.tagSize else {
                throw ShieldError.ciphertextTooShort
            }
            let msgSuite = encrypted[1]
            let headerSalt = Array(encrypted[2..<(2 + Self.saltSize)])
            let derived = deriveKeyCaching(password: password, service: service, salt: headerSalt, iterations: iterations)
            let derivedAead = Self.deriveAeadKey(derived)
            return try Self.openCiphertext(aeadKey: derivedAead, suite: msgSuite,
                                           encrypted: encrypted, aadLen: aadLen, maxAgeMs: maxAgeMs)

        } else if version == Self.versionKey {
            guard encrypted.count >= 2 + Self.aeadNonceSize + Self.tagSize else {
                throw ShieldError.ciphertextTooShort
            }
            return try Self.openCiphertext(aeadKey: aeadKey, suite: encrypted[1],
                                           encrypted: encrypted, aadLen: 2, maxAgeMs: maxAgeMs)

        } else {
            throw ShieldError.invalidVersion
        }
    }

    // MARK: - Private Methods

    /// Derive the 32-byte master key for a header salt (cached by salt).
    private func deriveKeyCaching(password: String, service: String, salt: [UInt8], iterations: UInt32) -> [UInt8] {
        if let cached = keyCache[salt] {
            return cached
        }
        let pbkdfSalt = salt + Array(service.utf8)
        let derived = Self.deriveKey(password: password, salt: pbkdfSalt, iterations: iterations)
        keyCache[salt] = derived
        return derived
    }

    private static func deriveKey(password: String, salt: [UInt8], iterations: UInt32) -> [UInt8] {
        var derivedKey = [UInt8](repeating: 0, count: keySize)
        let passwordData = password.data(using: .utf8)!

        passwordData.withUnsafeBytes { passwordBytes in
            salt.withUnsafeBytes { saltBytes in
                _ = CCKeyDerivationPBKDF(
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

    /// Build the AEAD additional data (= wire prefix before the nonce).
    private static func buildAad(suite: UInt8, salt: [UInt8]?) -> [UInt8] {
        if let salt = salt {
            return [versionPassword, suite] + salt
        }
        return [versionKey, suite]
    }

    /// Seal with a fresh random nonce, timestamp and padding.
    private static func seal(aeadKey: [UInt8], suite: UInt8, salt: [UInt8]?, plaintext: [UInt8]) throws -> [UInt8] {
        var nonce = [UInt8](repeating: 0, count: aeadNonceSize)
        guard SecRandomCopyBytes(kSecRandomDefault, aeadNonceSize, &nonce) == errSecSuccess else {
            throw ShieldError.randomGenerationFailed
        }

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

        let timestampMs = Int64(Date().timeIntervalSince1970 * 1000)
        return try sealDeterministic(aeadKey: aeadKey, suite: suite, salt: salt, nonce: nonce,
                                     timestampMs: timestampMs, padLen: padLen, padding: padding,
                                     plaintext: plaintext)
    }

    /// Deterministic AEAD seal over fully specified inputs (used for conformance
    /// vectors and wrapped by the randomized `seal`).
    public static func sealDeterministic(aeadKey: [UInt8], suite: UInt8, salt: [UInt8]?, nonce: [UInt8],
                                         timestampMs: Int64, padLen: Int, padding: [UInt8],
                                         plaintext: [UInt8]) throws -> [UInt8] {
        let aad = buildAad(suite: suite, salt: salt)

        var timestamp = [UInt8](repeating: 0, count: 8)
        for i in 0..<8 {
            timestamp[i] = UInt8(truncatingIfNeeded: timestampMs >> (i * 8))
        }
        let inner = timestamp + [UInt8(padLen)] + padding + plaintext

        let ctTag = try aeadSeal(suite: suite, key: aeadKey, nonce: nonce, aad: aad, plaintext: inner)
        return aad + nonce + ctTag
    }

    /// Open an AEAD ciphertext, validate the inner layout and freshness window.
    public static func openCiphertext(aeadKey: [UInt8], suite: UInt8, encrypted: [UInt8],
                                      aadLen: Int, maxAgeMs: Int64?) throws -> [UInt8] {
        guard encrypted.count >= aadLen + aeadNonceSize + tagSize else {
            throw ShieldError.ciphertextTooShort
        }
        let aad = Array(encrypted[0..<aadLen])
        let nonce = Array(encrypted[aadLen..<(aadLen + aeadNonceSize)])
        let ctTag = Array(encrypted[(aadLen + aeadNonceSize)...])

        let inner = try aeadOpen(suite: suite, key: aeadKey, nonce: nonce, aad: aad, ctTag: ctTag)

        guard inner.count >= innerHeaderSize else {
            throw ShieldError.authenticationFailed
        }
        var timestampMs: Int64 = 0
        for i in 0..<8 {
            timestampMs |= Int64(inner[i]) << (i * 8)
        }
        let padLen = Int(inner[8])
        guard padLen >= minPadding && padLen <= maxPadding else {
            throw ShieldError.authenticationFailed
        }
        let dataStart = innerHeaderSize + padLen
        guard inner.count >= dataStart else {
            throw ShieldError.ciphertextTooShort
        }

        if let maxAge = maxAgeMs {
            let nowMs = Int64(Date().timeIntervalSince1970 * 1000)
            let age = nowMs - timestampMs
            if timestampMs > nowMs + 5000 || age > maxAge {
                throw ShieldError.authenticationFailed
            }
        }

        return Array(inner[dataStart...])
    }

    /// AEAD seal: returns ciphertext||tag.
    private static func aeadSeal(suite: UInt8, key: [UInt8], nonce: [UInt8], aad: [UInt8], plaintext: [UInt8]) throws -> [UInt8] {
        let symKey = SymmetricKey(data: Data(key))
        if suite == suiteAesGcm {
            let box = try AES.GCM.seal(Data(plaintext), using: symKey,
                                       nonce: try AES.GCM.Nonce(data: Data(nonce)),
                                       authenticating: Data(aad))
            return Array(box.ciphertext) + Array(box.tag)
        } else if suite == suiteChaCha20Poly1305 {
            let box = try ChaChaPoly.seal(Data(plaintext), using: symKey,
                                          nonce: try ChaChaPoly.Nonce(data: Data(nonce)),
                                          authenticating: Data(aad))
            return Array(box.ciphertext) + Array(box.tag)
        }
        throw ShieldError.invalidVersion
    }

    /// AEAD open: returns plaintext, throws on authentication failure.
    private static func aeadOpen(suite: UInt8, key: [UInt8], nonce: [UInt8], aad: [UInt8], ctTag: [UInt8]) throws -> [UInt8] {
        guard ctTag.count >= tagSize else {
            throw ShieldError.authenticationFailed
        }
        let ct = Array(ctTag[0..<(ctTag.count - tagSize)])
        let tag = Array(ctTag[(ctTag.count - tagSize)...])
        let symKey = SymmetricKey(data: Data(key))
        do {
            if suite == suiteAesGcm {
                let box = try AES.GCM.SealedBox(nonce: try AES.GCM.Nonce(data: Data(nonce)),
                                                ciphertext: Data(ct), tag: Data(tag))
                return Array(try AES.GCM.open(box, using: symKey, authenticating: Data(aad)))
            } else if suite == suiteChaCha20Poly1305 {
                let box = try ChaChaPoly.SealedBox(nonce: try ChaChaPoly.Nonce(data: Data(nonce)),
                                                   ciphertext: Data(ct), tag: Data(tag))
                return Array(try ChaChaPoly.open(box, using: symKey, authenticating: Data(aad)))
            }
        } catch {
            throw ShieldError.authenticationFailed
        }
        throw ShieldError.invalidVersion
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

public enum ShieldError: Error, LocalizedError, Equatable {
    case invalidKeySize(expected: Int, actual: Int)
    case ciphertextTooShort
    case authenticationFailed
    case invalidVersion
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
        case .invalidVersion:
            return "Invalid or unsupported version byte"
        case .randomGenerationFailed:
            return "Random generation failed"
        case .keychainError(let status):
            return "Keychain error: \(status)"
        }
    }
}
