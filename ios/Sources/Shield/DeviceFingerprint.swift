import Foundation
import UIKit
import CryptoKit

/// Device fingerprinting for iOS.
///
/// Uses iOS-specific device identifiers for hardware-bound encryption.
/// More secure than desktop fingerprinting due to Secure Enclave backing.
///
/// **Privacy**: identifierForVendor is app-scoped and resets on app deletion.
/// **Security**: Hardware-backed keys can be stored in Secure Enclave.
///
/// Example:
/// ```swift
/// let fingerprint = try DeviceFingerprint.collect(mode: .hardwareBacked)
/// let shield = try Shield.withFingerprint(password: "password", service: "myapp.com", mode: .hardwareBacked)
/// ```
public final class DeviceFingerprint {

    // MARK: - Fingerprint Modes

    public enum FingerprintMode {
        /// No fingerprinting (backward compatible)
        case none

        /// Vendor identifier (app-scoped, resets on app deletion)
        case vendorId

        /// Device model + system version (less unique, but stable)
        case deviceInfo

        /// Hardware-backed with Secure Enclave (recommended, requires Face ID/Touch ID device)
        case hardwareBacked

        /// Combined vendor ID + device info
        case combined
    }

    // MARK: - Errors

    public enum FingerprintError: Error {
        case unavailable
        case secureEnclaveNotAvailable
        case keychainError(OSStatus)
    }

    // MARK: - Public Methods

    /// Collect device fingerprint.
    ///
    /// - Parameter mode: Fingerprint mode
    /// - Returns: Fingerprint string (MD5 hex), or empty for .none
    /// - Throws: `FingerprintError` if fingerprint unavailable
    public static func collect(mode: FingerprintMode) throws -> String {
        switch mode {
        case .none:
            return ""

        case .vendorId:
            return try getVendorId()

        case .deviceInfo:
            return getDeviceInfo()

        case .hardwareBacked:
            return try getHardwareBackedFingerprint()

        case .combined:
            return try getCombinedFingerprint()
        }
    }

    // MARK: - Private Methods

    /// Get vendor identifier (identifierForVendor).
    ///
    /// **Privacy**: Unique per app vendor, resets on app deletion.
    /// **Stability**: Same across all apps from same vendor on this device.
    private static func getVendorId() throws -> String {
        guard let vendorId = UIDevice.current.identifierForVendor?.uuidString else {
            throw FingerprintError.unavailable
        }
        return vendorId
    }

    /// Get device model + system version info.
    ///
    /// **Privacy**: Public info, not unique (same for all devices of same model).
    /// **Stability**: Changes with iOS updates.
    private static func getDeviceInfo() -> String {
        let components = [
            UIDevice.current.model,
            UIDevice.current.systemName,
            UIDevice.current.systemVersion,
            getDeviceModel()
        ]
        let combined = components.joined(separator: "-")
        return md5(string: combined)
    }

    /// Get hardware model identifier (e.g., "iPhone14,2").
    private static func getDeviceModel() -> String {
        var systemInfo = utsname()
        uname(&systemInfo)
        let machineMirror = Mirror(reflecting: systemInfo.machine)
        let identifier = machineMirror.children.reduce("") { identifier, element in
            guard let value = element.value as? Int8, value != 0 else { return identifier }
            return identifier + String(UnicodeScalar(UInt8(value)))
        }
        return identifier
    }

    /// Get hardware-backed fingerprint using Secure Enclave.
    ///
    /// Creates a Secure Enclave-backed key that cannot be extracted.
    /// The key is bound to the device hardware.
    ///
    /// **Security**: Highest - keys stored in Secure Enclave.
    /// **Privacy**: Key never leaves Secure Enclave.
    /// **Requires**: Device with Face ID or Touch ID.
    private static func getHardwareBackedFingerprint() throws -> String {
        let keychain = SecureKeychain()
        let hardwareKeyAlias = "shield_hw_fingerprint"

        // Try to retrieve existing hardware key
        if let existingKey = try? keychain.retrieve(for: hardwareKeyAlias) {
            return Data(existingKey).hexString
        }

        // Generate new Secure Enclave-backed key
        do {
            let key = try generateSecureEnclaveKey(alias: hardwareKeyAlias)
            try keychain.store(key: Array(key), for: hardwareKeyAlias, biometricProtection: false)
            return key.hexString
        } catch {
            // Fallback to vendor ID if Secure Enclave unavailable
            return try getVendorId()
        }
    }

    /// Generate Secure Enclave-backed key.
    private static func generateSecureEnclaveKey(alias: String) throws -> Data {
        // Check if Secure Enclave is available
        guard SecureEnclave.isAvailable else {
            throw FingerprintError.secureEnclaveNotAvailable
        }

        do {
            // Generate P256 private key in Secure Enclave
            let privateKey = try SecureEnclave.P256.Signing.PrivateKey(compactRepresentable: true)

            // Get public key representation (can be used as device fingerprint)
            let publicKeyData = privateKey.publicKey.compactRepresentation ?? Data()

            // Hash the public key for consistent 32-byte output
            return Data(SHA256.hash(data: publicKeyData))
        } catch {
            throw FingerprintError.secureEnclaveNotAvailable
        }
    }

    /// Get combined fingerprint (vendor ID + device info).
    ///
    /// **Recommended for most use cases**: Balances security and stability.
    private static func getCombinedFingerprint() throws -> String {
        var components: [String] = []

        // Try vendor ID first
        if let vendorId = try? getVendorId() {
            components.append(vendorId)
        }

        // Add device info
        components.append(getDeviceInfo())

        guard !components.isEmpty else {
            throw FingerprintError.unavailable
        }

        let combined = components.joined(separator: "-")
        return md5(string: combined)
    }

    /// MD5 hash helper.
    private static func md5(string: String) -> String {
        let data = Data(string.utf8)
        let digest = Insecure.MD5.hash(data: data)
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}

// MARK: - Data Extension

private extension Data {
    /// Convert Data to hex string.
    var hexString: String {
        return self.map { String(format: "%02x", $0) }.joined()
    }
}

// MARK: - Shield Extension

public extension Shield {
    /// Create Shield with device fingerprinting.
    ///
    /// Derives keys from password + device identifier, binding encryption to the physical device.
    ///
    /// - Parameters:
    ///   - password: User's password
    ///   - service: Service identifier
    ///   - mode: Fingerprint mode (default: .hardwareBacked)
    /// - Returns: Shield instance with device-bound key
    /// - Throws: `DeviceFingerprint.FingerprintError` if fingerprint unavailable
    ///
    /// Example:
    /// ```swift
    /// let shield = try Shield.withFingerprint(
    ///     password: "password",
    ///     service: "github.com",
    ///     mode: .hardwareBacked
    /// )
    /// let encrypted = try shield.encrypt(data: Data("secret".utf8))
    /// ```
    static func withFingerprint(
        password: String,
        service: String,
        mode: DeviceFingerprint.FingerprintMode = .hardwareBacked
    ) throws -> Shield {
        let fingerprint = try DeviceFingerprint.collect(mode: mode)

        let combinedPassword: String
        if fingerprint.isEmpty {
            combinedPassword = password
        } else {
            combinedPassword = "\(password):\(fingerprint)"
        }

        return Shield(password: combinedPassword, service: service)
    }
}
