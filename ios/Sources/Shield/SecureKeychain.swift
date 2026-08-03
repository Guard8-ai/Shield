import Foundation
import Security
import CommonCrypto

/// Secure key storage using iOS Keychain.
///
/// Provides Secure Enclave-backed storage when available.
///
/// Example:
/// ```swift
/// let keychain = SecureKeychain()
///
/// // Store a key
/// try keychain.store(key: secretKey, for: "my_key")
///
/// // Retrieve a key
/// let key = try keychain.retrieve(for: "my_key")
///
/// // Create Shield with stored key
/// let shield = try keychain.getOrCreateShield(
///     alias: "user_key",
///     password: "password",
///     service: "myapp.com"
/// )
/// ```
public final class SecureKeychain {

    // MARK: - Properties

    private let serviceName: String
    private let accessGroup: String?

    // MARK: - Initialization

    /// Initialize SecureKeychain.
    ///
    /// - Parameters:
    ///   - serviceName: Keychain service name (default: bundle identifier)
    ///   - accessGroup: Optional keychain access group for sharing between apps
    public init(serviceName: String? = nil, accessGroup: String? = nil) {
        self.serviceName = serviceName ?? Bundle.main.bundleIdentifier ?? "ai.dikestra.shield"
        self.accessGroup = accessGroup
    }

    // MARK: - Key Storage

    /// Store a key in the Keychain.
    ///
    /// - Parameters:
    ///   - key: Key bytes to store
    ///   - alias: Unique identifier for the key
    ///   - biometricProtection: Require biometric authentication to access
    /// - Throws: `ShieldError.keychainError` if storage fails
    public func store(key: [UInt8], for alias: String, biometricProtection: Bool = false) throws {
        // Delete any existing key first
        try? delete(for: alias)

        // Note: kSecAttrAccessible and kSecAttrAccessControl are mutually exclusive.
        // We set one or the other below, never both.
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: alias,
            kSecValueData as String: Data(key)
        ]

        if let accessGroup = accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }

        if biometricProtection {
            guard let access = SecAccessControlCreateWithFlags(
                nil,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                .biometryCurrentSet,
                nil
            ) else {
                throw ShieldError.keychainError(errSecParam)
            }
            query[kSecAttrAccessControl as String] = access
        } else {
            query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        }

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw ShieldError.keychainError(status)
        }
    }

    /// Retrieve a key from the Keychain.
    ///
    /// - Parameter alias: Key identifier
    /// - Returns: Key bytes, or nil if not found
    /// - Throws: `ShieldError.keychainError` if retrieval fails
    public func retrieve(for alias: String) throws -> [UInt8]? {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: alias,
            kSecReturnData as String: true
        ]

        if let accessGroup = accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        if status == errSecItemNotFound {
            return nil
        }

        guard status == errSecSuccess, let data = result as? Data else {
            throw ShieldError.keychainError(status)
        }

        return Array(data)
    }

    /// Delete a key from the Keychain.
    ///
    /// - Parameter alias: Key identifier
    /// - Throws: `ShieldError.keychainError` if deletion fails
    public func delete(for alias: String) throws {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: alias
        ]

        if let accessGroup = accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }

        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw ShieldError.keychainError(status)
        }
    }

    /// Check if a key exists in the Keychain.
    ///
    /// - Parameter alias: Key identifier
    /// - Returns: true if key exists
    public func exists(for alias: String) -> Bool {
        do {
            return try retrieve(for: alias) != nil
        } catch {
            return false
        }
    }

    // MARK: - Shield Integration

    /// Create a Shield instance with a stored or new key.
    ///
    /// On first call a random 16-byte salt is generated, the PBKDF2 key is derived
    /// from `password + service + randomSalt`, and that key is stored in the Keychain
    /// under `alias`.  On every subsequent call the same stored key is retrieved and
    /// used directly — no re-derivation occurs, so the salt need not be persisted
    /// separately.
    ///
    /// Important: do not delete the Keychain entry while ciphertexts derived from it
    /// still exist — those ciphertexts will become permanently unreadable.
    ///
    /// - Parameters:
    ///   - alias: Key identifier
    ///   - password: Password for key derivation (if creating new)
    ///   - service: Service name for key derivation (if creating new)
    /// - Returns: Shield instance
    /// - Throws: `ShieldError` if key operations fail
    public func getOrCreateShield(
        alias: String,
        password: String,
        service: String
    ) throws -> Shield {
        if let existingKey = try retrieve(for: alias) {
            return try Shield(key: existingKey)
        }

        // Generate a random 16-byte salt for this key's lifetime.
        // The salt does not need to be stored separately — the derived key IS stored.
        var randomSalt = [UInt8](repeating: 0, count: 16)
        guard SecRandomCopyBytes(kSecRandomDefault, 16, &randomSalt) == errSecSuccess else {
            throw ShieldError.randomGenerationFailed
        }

        let key = deriveKey(password: password, service: service, salt: randomSalt)
        try store(key: key, for: alias)
        return try Shield(key: key)
    }

    /// Store a Shield key with biometric protection.
    ///
    /// - Parameters:
    ///   - alias: Key identifier
    ///   - password: Password for key derivation
    ///   - service: Service name for key derivation
    /// - Throws: `ShieldError` if storage fails
    public func storeWithBiometrics(
        alias: String,
        password: String,
        service: String
    ) throws {
        var randomSalt = [UInt8](repeating: 0, count: 16)
        guard SecRandomCopyBytes(kSecRandomDefault, 16, &randomSalt) == errSecSuccess else {
            throw ShieldError.randomGenerationFailed
        }
        let key = deriveKey(password: password, service: service, salt: randomSalt)
        try store(key: key, for: alias, biometricProtection: true)
    }

    // MARK: - Private Methods

    /// Derive a 32-byte key using PBKDF2-SHA256.
    ///
    /// The PBKDF2 input salt is `randomSalt + Array(service.utf8)` (random 16 bytes
    /// prepended to the service bytes).  600 000 iterations, 32-byte output.
    private func deriveKey(password: String, service: String, salt randomSalt: [UInt8]) -> [UInt8] {
        let salt = randomSalt + Array(service.utf8)
        var derivedKey = [UInt8](repeating: 0, count: 32)
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
                    600_000, // CR-2: OWASP 2023 floor
                    &derivedKey,
                    32
                )
            }
        }

        return derivedKey
    }
}

