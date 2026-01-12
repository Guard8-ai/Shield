import Foundation
import CommonCrypto

/// TOTP - Time-based One-Time Password (RFC 6238)
public class TOTP {
    public static let defaultDigits = 6
    public static let defaultInterval: Int64 = 30
    public static let defaultSecretSize = 20

    private var secret: [UInt8]
    private let digits: Int
    private let interval: Int64

    public init(secret: [UInt8], digits: Int = defaultDigits, interval: Int = Int(defaultInterval)) {
        self.secret = secret
        self.digits = digits > 0 ? digits : TOTP.defaultDigits
        self.interval = Int64(interval > 0 ? interval : Int(TOTP.defaultInterval))
    }

    public static func generateSecret() -> [UInt8]? {
        return Shield.randomBytes(defaultSecretSize)
    }

    public func generate(timestamp: Int64 = 0) -> String {
        let ts = timestamp == 0 ? Int64(Date().timeIntervalSince1970) : timestamp
        let counter = ts / interval
        return generateHOTP(counter: UInt64(counter))
    }

    public func verify(code: String, timestamp: Int64 = 0, window: Int = 1) -> Bool {
        let ts = timestamp == 0 ? Int64(Date().timeIntervalSince1970) : timestamp
        let w = window > 0 ? window : 1

        for i in 0...w {
            if generate(timestamp: ts - Int64(i) * interval) == code {
                return true
            }
            if i > 0 && generate(timestamp: ts + Int64(i) * interval) == code {
                return true
            }
        }
        return false
    }

    private func generateHOTP(counter: UInt64) -> String {
        var counterBytes = [UInt8](repeating: 0, count: 8)
        var c = counter.bigEndian
        withUnsafeBytes(of: &c) { buffer in
            for i in 0..<8 {
                counterBytes[i] = buffer[i]
            }
        }

        let hash = hmacSha1(key: secret, data: counterBytes)

        let offset = Int(hash[19] & 0x0f)
        let code = (Int(hash[offset] & 0x7f) << 24) |
                   (Int(hash[offset + 1]) << 16) |
                   (Int(hash[offset + 2]) << 8) |
                   Int(hash[offset + 3])

        var modulo = 1
        for _ in 0..<digits {
            modulo *= 10
        }

        return String(format: "%0\(digits)d", code % modulo)
    }

    private func hmacSha1(key: [UInt8], data: [UInt8]) -> [UInt8] {
        var mac = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        key.withUnsafeBytes { keyBuffer in
            data.withUnsafeBytes { dataBuffer in
                CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA1),
                       keyBuffer.baseAddress, key.count,
                       dataBuffer.baseAddress, data.count,
                       &mac)
            }
        }
        return mac
    }

    public func toBase32() -> String {
        return Base32.encode(secret)
    }

    public static func fromBase32(_ encoded: String) -> TOTP {
        return TOTP(secret: Base32.decode(encoded))
    }

    public func provisioningUri(account: String, issuer: String) -> String {
        let secretB32 = toBase32()
        return "otpauth://totp/\(issuer):\(account)?secret=\(secretB32)&issuer=\(issuer)&algorithm=SHA1&digits=\(digits)&period=\(interval)"
    }

    public func getSecret() -> [UInt8] {
        return secret
    }

    public func wipe() {
        Shield.secureWipe(&secret)
    }
}

// MARK: - Base32

private enum Base32 {
    private static let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")

    static func encode(_ data: [UInt8]) -> String {
        var result = ""
        var buffer = 0
        var bufferLength = 0

        for byte in data {
            buffer = (buffer << 8) | Int(byte)
            bufferLength += 8
            while bufferLength >= 5 {
                bufferLength -= 5
                result.append(alphabet[(buffer >> bufferLength) & 0x1f])
            }
        }
        if bufferLength > 0 {
            result.append(alphabet[(buffer << (5 - bufferLength)) & 0x1f])
        }
        return result
    }

    static func decode(_ encoded: String) -> [UInt8] {
        let clean = encoded.uppercased().replacingOccurrences(of: "=", with: "")
        var result = [UInt8]()
        var buffer = 0
        var bufferLength = 0

        for char in clean {
            guard let index = alphabet.firstIndex(of: char) else { continue }
            buffer = (buffer << 5) | index
            bufferLength += 5
            if bufferLength >= 8 {
                bufferLength -= 8
                result.append(UInt8((buffer >> bufferLength) & 0xff))
            }
        }
        return result
    }
}
