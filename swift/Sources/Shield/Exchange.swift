import Foundation
import CommonCrypto

/// Key Exchange - Key exchange without public-key crypto.
///
/// Methods:
/// 1. PAKE: Password-Authenticated Key Exchange
/// 2. QR: QR codes, base64 for manual exchange
/// 3. Key Splitting: XOR-based secret sharing

/// Password-Authenticated Key Exchange.
///
/// Both parties derive a shared key from a common password.
/// Uses role binding to prevent reflection attacks.
public enum PAKEExchange {
    public static let defaultIterations = 200000

    /// Derive key contribution from password.
    ///
    /// - Parameters:
    ///   - password: Shared password between parties
    ///   - salt: Public salt (can be exchanged openly)
    ///   - role: Role identifier ('alice', 'bob', 'initiator', etc.)
    ///   - iterations: PBKDF2 iterations (default: 200000)
    /// - Returns: 32-byte key contribution
    public static func derive(password: String, salt: [UInt8], role: String,
                              iterations: Int = 200000) -> [UInt8] {
        let baseKey = pbkdf2(password: password, salt: salt, iterations: iterations, keyLength: 32)

        var combined = baseKey
        combined.append(contentsOf: Array(role.utf8))
        return Shield.sha256(combined)
    }

    /// Combine key contributions into session key.
    ///
    /// - Parameter contributions: Key contributions from all parties
    /// - Returns: 32-byte shared session key
    public static func combine(_ contributions: [UInt8]...) -> [UInt8] {
        // Sort contributions for deterministic output
        let sorted = contributions.sorted { a, b in
            for i in 0..<min(a.count, b.count) {
                if a[i] != b[i] {
                    return a[i] < b[i]
                }
            }
            return a.count < b.count
        }

        var combined: [UInt8] = []
        for contrib in sorted {
            combined.append(contentsOf: contrib)
        }
        return Shield.sha256(combined)
    }

    /// Generate random salt for key exchange.
    public static func generateSalt() -> [UInt8]? {
        return Shield.randomBytes(16)
    }

    private static func pbkdf2(password: String, salt: [UInt8], iterations: Int, keyLength: Int) -> [UInt8] {
        var derivedKey = [UInt8](repeating: 0, count: keyLength)
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
                    UInt32(iterations),
                    &derivedKey,
                    keyLength
                )
            }
        }

        return derivedKey
    }
}

/// Key exchange via QR codes or manual transfer.
///
/// Encodes keys in URL-safe base64 for easy scanning/typing.
public enum QRExchange {
    /// Encode key for QR code or manual transfer.
    ///
    /// - Parameter key: Key bytes to encode
    /// - Returns: URL-safe base64 string
    public static func encode(_ key: [UInt8]) -> String {
        return Data(key).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// Decode key from QR code or manual input.
    ///
    /// - Parameter encoded: Base64 string from encode()
    /// - Returns: Key bytes
    public static func decode(_ encoded: String) -> [UInt8]? {
        var base64 = encoded
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")

        let remainder = base64.count % 4
        if remainder > 0 {
            base64 += String(repeating: "=", count: 4 - remainder)
        }

        guard let data = Data(base64Encoded: base64) else {
            return nil
        }
        return Array(data)
    }

    /// Generate complete exchange data with optional metadata.
    ///
    /// - Parameters:
    ///   - key: Key to exchange
    ///   - metadata: Optional metadata (issuer, expiry, etc.)
    /// - Returns: JSON-like string for QR code
    public static func generateExchangeData(key: [UInt8], metadata: [String: Any]? = nil) -> String? {
        var data: [String: Any] = [
            "v": 1,
            "k": encode(key)
        ]

        if let meta = metadata, !meta.isEmpty {
            data["m"] = meta
        }

        guard let jsonData = try? JSONSerialization.data(withJSONObject: data, options: []) else {
            return nil
        }
        return String(data: jsonData, encoding: .utf8)
    }

    /// Parse exchange data from QR code.
    ///
    /// - Parameter data: JSON string from generateExchangeData()
    /// - Returns: Tuple of (key, metadata)
    public static func parseExchangeData(_ data: String) -> (key: [UInt8], metadata: [String: Any]?)? {
        guard let jsonData = data.data(using: .utf8),
              let parsed = try? JSONSerialization.jsonObject(with: jsonData) as? [String: Any],
              let keyB64 = parsed["k"] as? String,
              let key = decode(keyB64) else {
            return nil
        }

        let metadata = parsed["m"] as? [String: Any]
        return (key, metadata)
    }
}

/// Split keys into shares for threshold recovery.
///
/// This is a simplified XOR-based scheme where ALL shares
/// are required for reconstruction.
public enum KeySplitter {
    /// Split key into shares (all required for reconstruction).
    ///
    /// - Parameters:
    ///   - key: Key to split
    ///   - numShares: Number of shares to create
    /// - Returns: List of shares
    /// - Throws: ShieldError if numShares < 2
    public static func split(_ key: [UInt8], numShares: Int) throws -> [[UInt8]] {
        guard numShares >= 2 else {
            throw ShieldError.invalidKeySize
        }

        var shares: [[UInt8]] = []

        // Generate random shares for all but the last
        for _ in 0..<(numShares - 1) {
            guard let share = Shield.randomBytes(key.count) else {
                throw ShieldError.randomGenerationFailed
            }
            shares.append(share)
        }

        // Final share = XOR of key with all other shares
        var finalShare = key
        for share in shares {
            for i in 0..<finalShare.count {
                finalShare[i] ^= share[i]
            }
        }
        shares.append(finalShare)

        return shares
    }

    /// Combine shares to recover key.
    ///
    /// - Parameter shares: All shares from split()
    /// - Returns: Original key
    /// - Throws: ShieldError if shares < 2
    public static func combine(_ shares: [[UInt8]]) throws -> [UInt8] {
        guard shares.count >= 2 else {
            throw ShieldError.invalidKeySize
        }

        var result = shares[0]
        for i in 1..<shares.count {
            for j in 0..<result.count {
                result[j] ^= shares[i][j]
            }
        }

        return result
    }
}
