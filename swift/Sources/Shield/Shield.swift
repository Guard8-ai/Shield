import Foundation
import CommonCrypto
import CryptoKit

/// Shield - Authenticated Symmetric Encryption Library (wire format v4).
///
/// v4 replaces the previous custom SHA-256 keystream + HMAC construction with a
/// standard AEAD (AES-256-GCM by default, ChaCha20-Poly1305 optional) from Apple
/// CryptoKit. No cryptography is hand-rolled: key derivation uses PBKDF2-HMAC-SHA256
/// (CommonCrypto) + HKDF-SHA256-Expand (CryptoKit), and encryption uses CryptoKit's
/// AEAD primitives. The wire format matches every other Shield binding byte-for-byte
/// (see tests/v4_test_vectors.json).
public class Shield {
    public static let keySize = 32
    // nonceSize/macSize are retained at 16 for the auxiliary keystream layers
    // (ratchet/stream). The base AEAD cipher uses its own 12-byte nonce.
    public static let nonceSize = 16
    public static let macSize = 16
    public static let saltSize = 16
    public static let iterations: UInt32 = 600_000

    // Authenticated leading version bytes (wire format v4).
    // Password mode: 0x03 || suite(1) || salt(16) || nonce(12) || ciphertext||tag
    // Key mode:      0x13 || suite(1) || nonce(12) || ciphertext||tag
    public static let versionPassword: UInt8 = 0x03
    public static let versionKey: UInt8 = 0x13

    // Cipher-suite identifiers.
    public static let suiteAesGcm: UInt8 = 0x01
    public static let suiteChaCha20Poly1305: UInt8 = 0x02

    // Base-AEAD constants.
    public static let aeadNonceSize = 12
    public static let tagSize = 16
    public static let innerHeaderSize = 9  // timestamp(8) + pad_len(1)
    public static let minPadding = 32
    public static let maxPadding = 128
    public static let defaultMaxAgeMs: Int64 = 60000
    public static let hkdfAeadInfo = "shield/aead/v4"

    private var key: [UInt8]
    private var aeadKey: [UInt8]
    private let suite: UInt8
    private let maxAgeMs: Int64?

    // Password-mode fields (nil in pre-shared-key mode).
    private let password: String?
    private let service: String?
    private let pbkdf2Iterations: UInt32
    private let salt: [UInt8]?
    private var keyCache: [[UInt8]: [UInt8]] = [:]

    /// AEAD key = HKDF-SHA256-Expand(master, "shield/aead/v4", 32).
    public static func deriveAeadKey(_ masterKey: [UInt8]) -> [UInt8] {
        let okm = HKDF<SHA256>.expand(
            pseudoRandomKey: SymmetricKey(data: Data(masterKey)),
            info: Data(hkdfAeadInfo.utf8),
            outputByteCount: keySize)
        return okm.withUnsafeBytes { Array($0) }
    }

    /// Create Shield from password and service name.
    ///
    /// A cryptographically secure random 16-byte salt is generated per instance.
    /// master = PBKDF2-HMAC-SHA256(password, salt || service, iterations, 32);
    /// aeadKey = HKDF-Expand(master, "shield/aead/v4", 32). The random salt is
    /// stored in the ciphertext header so a recipient with the same
    /// password+service can re-derive the key.
    public convenience init(password: String, service: String) {
        // Fail closed on CSPRNG failure: never fall back to a predictable
        // (all-zero) salt, which would derive identical keys across instances.
        // fatalError is the unrecoverable-error analog of the Go (panic) and
        // Rust (RandomFailed) references.
        guard let salt = Shield.randomBytes(Shield.saltSize) else {
            fatalError("Shield: CSPRNG failure generating salt (fail-closed)")
        }
        self.init(password: password, service: service, salt: salt, iterations: Shield.iterations)
    }

    /// Create Shield from password and service name with an explicit salt and iteration count.
    public init(password: String, service: String, salt: [UInt8], iterations: UInt32) {
        self.password = password
        self.service = service
        self.pbkdf2Iterations = iterations
        self.salt = salt
        self.suite = Shield.suiteAesGcm
        self.maxAgeMs = Shield.defaultMaxAgeMs

        let pbkdfSalt = salt + Array(service.utf8)
        let derived = Shield.pbkdf2(password: password, salt: pbkdfSalt, iterations: iterations, keyLength: Shield.keySize)
        self.key = derived
        self.aeadKey = Shield.deriveAeadKey(derived)
        self.keyCache[salt] = derived
    }

    /// Create Shield with pre-shared key.
    public init(key: [UInt8]) throws {
        guard key.count == Shield.keySize else {
            throw ShieldError.invalidKeySize
        }
        self.key = key
        self.aeadKey = Shield.deriveAeadKey(key)
        self.suite = Shield.suiteAesGcm
        self.maxAgeMs = Shield.defaultMaxAgeMs
        self.password = nil
        self.service = nil
        self.pbkdf2Iterations = Shield.iterations
        self.salt = nil
    }

    /// Create Shield with pre-shared key and custom max age.
    public init(key: [UInt8], maxAgeMs: Int64?) throws {
        guard key.count == Shield.keySize else {
            throw ShieldError.invalidKeySize
        }
        self.key = key
        self.aeadKey = Shield.deriveAeadKey(key)
        self.suite = Shield.suiteAesGcm
        self.maxAgeMs = maxAgeMs
        self.password = nil
        self.service = nil
        self.pbkdf2Iterations = Shield.iterations
        self.salt = nil
    }

    /// Derive the 32-byte master key for a given salt (cached by salt).
    private static func deriveKeyCaching(
        password: String, service: String, salt: [UInt8],
        iterations: UInt32, cache: inout [[UInt8]: [UInt8]]
    ) -> [UInt8] {
        if let cached = cache[salt] {
            return cached
        }
        let pbkdfSalt = salt + Array(service.utf8)
        let derived = pbkdf2(password: password, salt: pbkdfSalt, iterations: iterations, keyLength: keySize)
        cache[salt] = derived
        return derived
    }

    /// Encrypt plaintext.
    ///
    /// Password mode output: 0x03 || suite || salt(16) || nonce(12) || ciphertext||tag.
    /// Key mode output:      0x13 || suite || nonce(12) || ciphertext||tag.
    public func encrypt(_ plaintext: [UInt8]) throws -> [UInt8] {
        return try Shield.seal(aeadKey: aeadKey, suite: suite, salt: salt, plaintext: plaintext)
    }

    /// Decrypt ciphertext, dispatching on the leading authenticated version byte.
    public func decrypt(_ ciphertext: [UInt8]) throws -> [UInt8] {
        guard ciphertext.count >= 1 else {
            throw ShieldError.ciphertextTooShort
        }

        let version = ciphertext[0]
        if version == Shield.versionPassword {
            guard let _ = salt, let password = password, let service = service else {
                throw ShieldError.authenticationFailed
            }
            let aadLen = 2 + Shield.saltSize
            guard ciphertext.count >= aadLen + Shield.aeadNonceSize + Shield.tagSize else {
                throw ShieldError.ciphertextTooShort
            }
            let msgSuite = ciphertext[1]
            let headerSalt = Array(ciphertext[2..<(2 + Shield.saltSize)])
            let derived = Shield.deriveKeyCaching(
                password: password, service: service, salt: headerSalt,
                iterations: pbkdf2Iterations, cache: &keyCache)
            let derivedAead = Shield.deriveAeadKey(derived)
            return try Shield.openCiphertext(aeadKey: derivedAead, suite: msgSuite,
                                             encrypted: ciphertext, aadLen: aadLen, maxAgeMs: maxAgeMs)

        } else if version == Shield.versionKey {
            guard ciphertext.count >= 2 + Shield.aeadNonceSize + Shield.tagSize else {
                throw ShieldError.ciphertextTooShort
            }
            return try Shield.openCiphertext(aeadKey: aeadKey, suite: ciphertext[1],
                                             encrypted: ciphertext, aadLen: 2, maxAgeMs: maxAgeMs)

        } else {
            throw ShieldError.invalidVersion
        }
    }

    /// Get the derived master key.
    public func getKey() -> [UInt8] {
        return key
    }

    /// Wipe key material from memory.
    public func wipe() {
        for i in 0..<key.count { key[i] = 0 }
        for i in 0..<aeadKey.count { aeadKey[i] = 0 }
    }

    // MARK: - Static Methods

    /// Quick encrypt with explicit key (pre-shared-key mode, AES-256-GCM, 0x13).
    public static func quickEncrypt(key: [UInt8], plaintext: [UInt8]) throws -> [UInt8] {
        guard key.count == keySize else {
            throw ShieldError.invalidKeySize
        }
        return try seal(aeadKey: deriveAeadKey(key), suite: suiteAesGcm, salt: nil, plaintext: plaintext)
    }

    /// Quick decrypt with explicit key (pre-shared-key mode).
    public static func quickDecrypt(key: [UInt8], ciphertext: [UInt8]) throws -> [UInt8] {
        guard key.count == keySize else {
            throw ShieldError.invalidKeySize
        }
        guard ciphertext.count >= 1 else {
            throw ShieldError.ciphertextTooShort
        }
        guard ciphertext[0] == versionKey else {
            throw ShieldError.invalidVersion
        }
        guard ciphertext.count >= 2 + aeadNonceSize + tagSize else {
            throw ShieldError.ciphertextTooShort
        }
        return try openCiphertext(aeadKey: deriveAeadKey(key), suite: ciphertext[1],
                                  encrypted: ciphertext, aadLen: 2, maxAgeMs: nil)
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

        // Random padding: 32-128 bytes (rejection sampling to avoid modulo bias).
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
    /// `aadLen` is the offset of the nonce (= len(version||suite||[salt])).
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
            let box = try AES.GCM.seal(Data(plaintext),
                                       using: symKey,
                                       nonce: try AES.GCM.Nonce(data: Data(nonce)),
                                       authenticating: Data(aad))
            return Array(box.ciphertext) + Array(box.tag)
        } else if suite == suiteChaCha20Poly1305 {
            let box = try ChaChaPoly.seal(Data(plaintext),
                                          using: symKey,
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
                _ = CCKeyDerivationPBKDF(
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
    case streamTruncated
    case invalidVersion
    case randomGenerationFailed
    case lamportKeyUsed
    case replayDetected
    case outOfOrder
    case tokenExpired
    case invalidToken
    case sessionExpired
}
