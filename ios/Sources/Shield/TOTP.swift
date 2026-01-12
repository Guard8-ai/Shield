import Foundation
import CommonCrypto

/// Time-based One-Time Password generator/verifier (RFC 6238).
///
/// Compatible with Google Authenticator, Authy, Microsoft Authenticator, etc.
///
/// Example:
/// ```swift
/// let secret = TOTP.generateSecret()
/// let totp = TOTP(secret: secret)
/// let code = totp.generate()
/// totp.verify(code) // true
/// ```
public final class TOTP {

    // MARK: - Types

    /// Supported HMAC algorithms.
    public enum Algorithm: String {
        case sha1 = "SHA1"
        case sha256 = "SHA256"

        var ccAlgorithm: CCHmacAlgorithm {
            switch self {
            case .sha1: return CCHmacAlgorithm(kCCHmacAlgSHA1)
            case .sha256: return CCHmacAlgorithm(kCCHmacAlgSHA256)
            }
        }

        var digestLength: Int {
            switch self {
            case .sha1: return Int(CC_SHA1_DIGEST_LENGTH)
            case .sha256: return Int(CC_SHA256_DIGEST_LENGTH)
            }
        }
    }

    // MARK: - Properties

    private let secret: [UInt8]
    private let digits: Int
    private let interval: Int
    private let algorithm: Algorithm

    // MARK: - Initialization

    /// Initialize TOTP generator.
    ///
    /// - Parameters:
    ///   - secret: Shared secret (typically 20 bytes)
    ///   - digits: OTP length (6 or 8)
    ///   - interval: Time step in seconds (default: 30)
    ///   - algorithm: `.sha1` (compatible) or `.sha256` (stronger)
    public init(
        secret: [UInt8],
        digits: Int = 6,
        interval: Int = 30,
        algorithm: Algorithm = .sha1
    ) {
        self.secret = secret
        self.digits = digits
        self.interval = interval
        self.algorithm = algorithm
    }

    // MARK: - Static Methods

    /// Generate random secret for new 2FA setup.
    ///
    /// - Parameter length: Secret length in bytes (default: 20)
    /// - Returns: Random secret bytes
    public static func generateSecret(length: Int = 20) -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: length)
        _ = SecRandomCopyBytes(kSecRandomDefault, length, &bytes)
        return bytes
    }

    /// Convert secret to base32 for QR codes.
    ///
    /// - Parameter secret: Secret bytes
    /// - Returns: Base32 encoded string (without padding)
    public static func secretToBase32(_ secret: [UInt8]) -> String {
        base32Encode(secret).trimmingCharacters(in: CharacterSet(charactersIn: "="))
    }

    /// Parse base32 secret from authenticator app.
    ///
    /// - Parameter b32: Base32 encoded secret
    /// - Returns: Secret bytes
    public static func secretFromBase32(_ b32: String) -> [UInt8] {
        // Add padding if needed
        var padded = b32.uppercased()
        let padding = (8 - (padded.count % 8)) % 8
        padded += String(repeating: "=", count: padding)
        return base32Decode(padded)
    }

    // MARK: - Public Methods

    /// Generate current TOTP code.
    ///
    /// - Parameter timestamp: Unix timestamp in seconds (default: current time)
    /// - Returns: OTP code as string (zero-padded)
    public func generate(timestamp: Int? = nil) -> String {
        let time = timestamp ?? Int(Date().timeIntervalSince1970)
        let counter = time / interval
        return hotp(counter: counter)
    }

    /// Verify TOTP code with time window.
    ///
    /// - Parameters:
    ///   - code: User-provided code
    ///   - timestamp: Time to verify against (default: now)
    ///   - window: Number of intervals to check before/after (default: 1)
    /// - Returns: True if code is valid
    public func verify(_ code: String, timestamp: Int? = nil, window: Int = 1) -> Bool {
        let time = timestamp ?? Int(Date().timeIntervalSince1970)
        let counter = time / interval

        // Check current and adjacent intervals (handles clock skew)
        for offset in -window...window {
            let expected = hotp(counter: counter + offset)
            if constantTimeEquals(code, expected) {
                return true
            }
        }
        return false
    }

    /// Generate URI for QR code (otpauth://).
    ///
    /// - Parameters:
    ///   - account: User account identifier (e.g., email)
    ///   - issuer: Service name (default: "Shield")
    /// - Returns: otpauth:// URI for QR code generation
    public func provisioningUri(account: String, issuer: String = "Shield") -> String {
        let secretB32 = Self.secretToBase32(secret)
        return "otpauth://totp/\(issuer):\(account)" +
               "?secret=\(secretB32)&issuer=\(issuer)" +
               "&algorithm=\(algorithm.rawValue)&digits=\(digits)"
    }

    // MARK: - Private Methods

    /// HOTP algorithm (RFC 4226).
    private func hotp(counter: Int) -> String {
        // Counter as 8-byte big-endian
        var counterValue = UInt64(counter).bigEndian
        let counterBytes = withUnsafeBytes(of: &counterValue) { Array($0) }

        // HMAC
        var hmacResult = [UInt8](repeating: 0, count: algorithm.digestLength)
        CCHmac(algorithm.ccAlgorithm, secret, secret.count, counterBytes, counterBytes.count, &hmacResult)

        // Dynamic truncation
        let offset = Int(hmacResult[hmacResult.count - 1] & 0x0F)
        let codeInt = (UInt32(hmacResult[offset] & 0x7F) << 24) |
                      (UInt32(hmacResult[offset + 1] & 0xFF) << 16) |
                      (UInt32(hmacResult[offset + 2] & 0xFF) << 8) |
                      UInt32(hmacResult[offset + 3] & 0xFF)

        // Modulo to get digits
        let divisor = UInt32(pow(10.0, Double(digits)))
        let code = codeInt % divisor

        return String(format: "%0\(digits)d", code)
    }

    private func constantTimeEquals(_ a: String, _ b: String) -> Bool {
        guard a.count == b.count else { return false }
        var result: UInt8 = 0
        for (charA, charB) in zip(a.utf8, b.utf8) {
            result |= charA ^ charB
        }
        return result == 0
    }

    // MARK: - Base32 Encoding

    private static let base32Alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")

    private static func base32Encode(_ data: [UInt8]) -> String {
        guard !data.isEmpty else { return "" }
        var result = ""
        var buffer = 0
        var bitsLeft = 0

        for byte in data {
            buffer = (buffer << 8) | Int(byte)
            bitsLeft += 8
            while bitsLeft >= 5 {
                let index = (buffer >> (bitsLeft - 5)) & 0x1F
                result.append(base32Alphabet[index])
                bitsLeft -= 5
            }
        }

        if bitsLeft > 0 {
            let index = (buffer << (5 - bitsLeft)) & 0x1F
            result.append(base32Alphabet[index])
        }

        // Add padding
        while result.count % 8 != 0 {
            result.append("=")
        }

        return result
    }

    private static func base32Decode(_ data: String) -> [UInt8] {
        let cleanData = data.uppercased().trimmingCharacters(in: CharacterSet(charactersIn: "="))
        guard !cleanData.isEmpty else { return [] }

        var result = [UInt8]()
        var buffer = 0
        var bitsLeft = 0

        for char in cleanData {
            guard let index = base32Alphabet.firstIndex(of: char) else { continue }
            buffer = (buffer << 5) | index
            bitsLeft += 5
            if bitsLeft >= 8 {
                result.append(UInt8(buffer >> (bitsLeft - 8)))
                bitsLeft -= 8
            }
        }

        return result
    }
}

// MARK: - RecoveryCodes

/// Recovery codes for 2FA backup.
///
/// Use when user loses access to their authenticator app.
/// Each code can only be used once.
///
/// Example:
/// ```swift
/// let recovery = RecoveryCodes()
/// print(recovery.codes) // Show codes to user
/// recovery.verify("ABCD-1234") // Consumes the code
/// ```
public final class RecoveryCodes {

    private var _codes: Set<String>
    private var _used: Set<String> = []

    /// Number of unused recovery codes.
    public var remaining: Int {
        _codes.count - _used.count
    }

    /// Get all recovery codes (for display to user).
    public var codes: [String] {
        _codes.sorted()
    }

    /// Initialize with existing codes or generate new ones.
    ///
    /// - Parameter codes: List of existing codes, or nil to generate new
    public init(codes: [String]? = nil) {
        _codes = Set(codes ?? Self.generateCodes())
    }

    /// Generate recovery codes.
    ///
    /// - Parameters:
    ///   - count: Number of codes to generate (default: 10)
    ///   - length: Length of each code in hex chars (default: 8)
    /// - Returns: List of recovery codes
    public static func generateCodes(count: Int = 10, length: Int = 8) -> [String] {
        (0..<count).map { _ in
            var bytes = [UInt8](repeating: 0, count: length / 2)
            _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
            let hex = bytes.map { String(format: "%02X", $0) }.joined()
            return "\(hex.prefix(4))-\(hex.suffix(4))"
        }
    }

    /// Verify and consume a recovery code.
    ///
    /// - Parameter code: Recovery code to verify
    /// - Returns: True if valid (code is now consumed)
    public func verify(_ code: String) -> Bool {
        // Normalize format
        let normalized = code.uppercased()
            .replacingOccurrences(of: "-", with: "")
            .replacingOccurrences(of: " ", with: "")

        let formatted: String
        if normalized.count == 8 {
            formatted = "\(normalized.prefix(4))-\(normalized.suffix(4))"
        } else {
            formatted = code.uppercased()
        }

        if _codes.contains(formatted) && !_used.contains(formatted) {
            _used.insert(formatted)
            return true
        }
        return false
    }
}
