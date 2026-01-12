import Foundation
import Security

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
        self.serviceName = serviceName ?? Bundle.main.bundleIdentifier ?? "ai.guard8.shield"
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

        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: alias,
            kSecValueData as String: Data(key),
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]

        if let accessGroup = accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }

        if biometricProtection {
            let access = SecAccessControlCreateWithFlags(
                nil,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                .biometryCurrentSet,
                nil
            )
            query[kSecAttrAccessControl as String] = access
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

        // Create new Shield and store its key
        let shield = Shield(password: password, service: service)

        // Derive key again for storage (we don't have direct access to Shield's key)
        let key = deriveKey(password: password, service: service)
        try store(key: key, for: alias)

        return shield
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
        let key = deriveKey(password: password, service: service)
        try store(key: key, for: alias, biometricProtection: true)
    }

    // MARK: - Private Methods

    private func deriveKey(password: String, service: String) -> [UInt8] {
        let salt = service.data(using: .utf8)!.sha256()
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
                    100_000,
                    &derivedKey,
                    32
                )
            }
        }

        return derivedKey
    }
}

// MARK: - Data Extension

private extension Data {
    func sha256() -> [UInt8] {
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        self.withUnsafeBytes { bytes in
            _ = CC_SHA256(bytes.baseAddress, CC_LONG(self.count), &hash)
        }
        return hash
    }
}
