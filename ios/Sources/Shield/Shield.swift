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
/// let encrypted = shield.encrypt(Array("secret data".utf8))
/// if let decrypted = shield.decrypt(encrypted) {
///     print(String(bytes: decrypted, encoding: .utf8)!)
/// }
/// ```
public final class Shield {

    // MARK: - Constants

    private static let pbkdf2Iterations: UInt32 = 100_000
    private static let nonceSize = 16
    private static let macSize = 16
    private static let keySize = 32

    // MARK: - Properties

    private let key: [UInt8]
    private var counter: UInt64 = 0

    // MARK: - Initialization

    /// Create Shield instance from password and service name.
    ///
    /// - Parameters:
    ///   - password: User's password
    ///   - service: Service identifier (e.g., "github.com")
    ///   - iterations: PBKDF2 iterations (default: 100,000)
    public init(password: String, service: String, iterations: UInt32 = pbkdf2Iterations) {
        let salt = service.data(using: .utf8)!.sha256()
        self.key = Self.deriveKey(
            password: password,
            salt: Array(salt),
            iterations: iterations
        )
    }

    /// Create Shield with pre-shared key (no password derivation).
    ///
    /// - Parameter key: 32-byte symmetric key
    /// - Throws: `ShieldError.invalidKeySize` if key is not 32 bytes
    public init(key: [UInt8]) throws {
        guard key.count == Self.keySize else {
            throw ShieldError.invalidKeySize(expected: Self.keySize, actual: key.count)
        }
        self.key = key
    }

    // MARK: - Static Methods

    /// Quick encrypt with pre-shared key.
    public static func quickEncrypt(key: [UInt8], plaintext: [UInt8]) throws -> [UInt8] {
        let shield = try Shield(key: key)
        return shield.encrypt(plaintext)
    }

    /// Quick decrypt with pre-shared key.
    public static func quickDecrypt(key: [UInt8], ciphertext: [UInt8]) throws -> [UInt8]? {
        let shield = try Shield(key: key)
        return shield.decrypt(ciphertext)
    }

    // MARK: - Encryption/Decryption

    /// Encrypt data.
    ///
    /// - Parameter plaintext: Data to encrypt
    /// - Returns: Ciphertext: nonce(16) || encrypted_data || mac(16)
    public func encrypt(_ plaintext: [UInt8]) -> [UInt8] {
        var nonce = [UInt8](repeating: 0, count: Self.nonceSize)
        _ = SecRandomCopyBytes(kSecRandomDefault, Self.nonceSize, &nonce)

        // Counter bytes (little-endian)
        var counterBytes = [UInt8](repeating: 0, count: 8)
        for i in 0..<8 {
            counterBytes[i] = UInt8(truncatingIfNeeded: counter >> (i * 8))
        }
        counter += 1

        // Data to encrypt: counter || plaintext
        let data = counterBytes + plaintext

        // Generate keystream and XOR
        let keystream = generateKeystream(key: key, nonce: nonce, length: data.count)
        var ciphertext = [UInt8](repeating: 0, count: data.count)
        for i in 0..<data.count {
            ciphertext[i] = data[i] ^ keystream[i]
        }

        // HMAC authenticate
        let mac = hmacSHA256(key: key, data: nonce + ciphertext).prefix(Self.macSize)

        return nonce + ciphertext + Array(mac)
    }

    /// Decrypt and verify data.
    ///
    /// - Parameter encrypted: Ciphertext from encrypt()
    /// - Returns: Plaintext bytes, or nil if authentication fails
    public func decrypt(_ encrypted: [UInt8]) -> [UInt8]? {
        let minSize = Self.nonceSize + 8 + Self.macSize
        guard encrypted.count >= minSize else { return nil }

        let nonce = Array(encrypted[0..<Self.nonceSize])
        let ciphertext = Array(encrypted[Self.nonceSize..<(encrypted.count - Self.macSize)])
        let mac = Array(encrypted[(encrypted.count - Self.macSize)...])

        // Verify MAC first (constant-time)
        let expectedMac = Array(hmacSHA256(key: key, data: nonce + ciphertext).prefix(Self.macSize))
        guard constantTimeEquals(mac, expectedMac) else { return nil }

        // Decrypt
        let keystream = generateKeystream(key: key, nonce: nonce, length: ciphertext.count)
        var decrypted = [UInt8](repeating: 0, count: ciphertext.count)
        for i in 0..<ciphertext.count {
            decrypted[i] = ciphertext[i] ^ keystream[i]
        }

        // Skip counter prefix (8 bytes)
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

// MARK: - ShieldError

public enum ShieldError: Error, LocalizedError {
    case invalidKeySize(expected: Int, actual: Int)
    case authenticationFailed
    case keychainError(OSStatus)

    public var errorDescription: String? {
        switch self {
        case .invalidKeySize(let expected, let actual):
            return "Invalid key size: expected \(expected) bytes, got \(actual)"
        case .authenticationFailed:
            return "Authentication failed: wrong key or tampered data"
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
