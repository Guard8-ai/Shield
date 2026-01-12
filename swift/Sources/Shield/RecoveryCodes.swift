import Foundation
import Security

/// RecoveryCodes - Backup codes for 2FA.
///
/// Use when user loses access to their authenticator app.
/// Each code can only be used once.
public class RecoveryCodes {
    private static let hexChars = Array("0123456789ABCDEF")

    private var codes: Set<String>
    private var used: Set<String> = []

    /// Create with existing codes.
    public init(codes: [String]) {
        self.codes = Set(codes)
    }

    /// Create with newly generated codes.
    public convenience init() {
        self.init(codes: RecoveryCodes.generate(count: 10, length: 8))
    }

    /// Create with specified number of codes (backward compatibility).
    public convenience init(count: Int) {
        self.init(codes: RecoveryCodes.generate(count: count, length: 8))
    }

    /// Generate recovery codes.
    ///
    /// - Parameters:
    ///   - count: Number of codes to generate
    ///   - length: Length of each code (must be even)
    /// - Returns: List of formatted codes (XXXX-XXXX)
    public static func generate(count: Int = 10, length: Int = 8) -> [String] {
        var result: [String] = []
        let byteCount = length / 2

        for _ in 0..<count {
            var bytes = [UInt8](repeating: 0, count: byteCount)
            _ = SecRandomCopyBytes(kSecRandomDefault, byteCount, &bytes)

            var code = ""
            for byte in bytes {
                code.append(hexChars[Int((byte >> 4) & 0x0F)])
                code.append(hexChars[Int(byte & 0x0F)])
            }

            // Format as XXXX-XXXX
            let mid = code.index(code.startIndex, offsetBy: 4)
            let formatted = String(code[..<mid]) + "-" + String(code[mid...])
            result.append(formatted)
        }

        return result
    }

    /// Verify and consume a recovery code.
    ///
    /// - Parameter code: Code to verify
    /// - Returns: true if valid (code is now consumed)
    public func verify(_ code: String) -> Bool {
        // Normalize format (remove dashes, uppercase)
        let normalized = code.replacingOccurrences(of: "-", with: "").uppercased()
        guard normalized.count >= 8 else { return false }

        let mid = normalized.index(normalized.startIndex, offsetBy: 4)
        let formatted = String(normalized[..<mid]) + "-" + String(normalized[mid...])

        if used.contains(formatted) {
            return false
        }

        if codes.contains(formatted) {
            used.insert(formatted)
            codes.remove(formatted)
            return true
        }

        return false
    }

    /// Get remaining (unused) codes.
    public var remainingCodes: [String] {
        Array(codes)
    }

    /// Alias for backward compatibility.
    public var allCodes: [String] {
        remainingCodes
    }

    /// Get count of remaining codes.
    public var remainingCount: Int {
        codes.count
    }

    /// Alias for backward compatibility.
    public var remaining: Int {
        remainingCount
    }

    /// Get used codes.
    public var usedCodes: [String] {
        Array(used)
    }
}
