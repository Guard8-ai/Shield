import Foundation

/// SymmetricSignature provides HMAC-based signatures.
public class SymmetricSignature {
    private var signingKey: [UInt8]
    public private(set) var verificationKey: [UInt8]

    public init(signingKey: [UInt8]) throws {
        guard signingKey.count == Shield.keySize else {
            throw ShieldError.invalidKeySize
        }
        self.signingKey = signingKey

        // Derive verification key
        let data = Array("verify:".utf8) + signingKey
        self.verificationKey = Shield.sha256(data)
    }

    public static func generate() throws -> SymmetricSignature {
        guard let key = Shield.randomBytes(Shield.keySize) else {
            throw ShieldError.randomGenerationFailed
        }
        return try SymmetricSignature(signingKey: key)
    }

    public static func fromPassword(_ password: String, identity: String) -> SymmetricSignature {
        let salt = Shield.sha256(Array("sign:\(identity)".utf8))
        let key = Shield.pbkdf2(password: password, salt: salt, iterations: Shield.iterations, keyLength: Shield.keySize)
        return try! SymmetricSignature(signingKey: key)
    }

    public func sign(_ message: [UInt8], includeTimestamp: Bool = false) -> [UInt8] {
        if includeTimestamp {
            let timestamp = Int64(Date().timeIntervalSince1970)
            let tsBytes = withUnsafeBytes(of: timestamp.littleEndian) { Array($0) }

            let sigData = tsBytes + message
            let sig = Shield.hmacSha256(key: signingKey, data: sigData)

            return tsBytes + sig
        }

        return Shield.hmacSha256(key: signingKey, data: message)
    }

    public func verify(_ message: [UInt8], signature: [UInt8], verificationKey: [UInt8], maxAge: Int64 = 0) -> Bool {
        guard Shield.constantTimeEquals(verificationKey, self.verificationKey) else {
            return false
        }

        if signature.count == 40 {
            let timestamp = signature.prefix(8).withUnsafeBytes { $0.load(as: Int64.self).littleEndian }

            if maxAge > 0 {
                let now = Int64(Date().timeIntervalSince1970)
                let diff = abs(now - timestamp)
                if diff > maxAge {
                    return false
                }
            }

            let sigData = Array(signature.prefix(8)) + message
            let expected = Shield.hmacSha256(key: signingKey, data: sigData)

            return Shield.constantTimeEquals(Array(signature.suffix(32)), expected)
        }

        if signature.count == 32 {
            let expected = Shield.hmacSha256(key: signingKey, data: message)
            return Shield.constantTimeEquals(signature, expected)
        }

        return false
    }

    public func fingerprint() -> String {
        let hash = Shield.sha256(verificationKey)
        return hash.prefix(8).map { String(format: "%02x", $0) }.joined()
    }

    public func wipe() {
        Shield.secureWipe(&signingKey)
        Shield.secureWipe(&verificationKey)
    }
}

/// LamportSignature provides one-time post-quantum signatures.
public class LamportSignature {
    private var privateKey: [[[UInt8]]]  // [256][2][32]
    public private(set) var publicKey: [UInt8]  // [256 * 64]
    private var used: Bool = false

    private init() {
        self.privateKey = []
        self.publicKey = []
    }

    public static func generate() throws -> LamportSignature {
        let ls = LamportSignature()
        ls.privateKey = Array(repeating: Array(repeating: [UInt8](repeating: 0, count: Shield.keySize), count: 2), count: 256)
        ls.publicKey = [UInt8](repeating: 0, count: 256 * 64)

        for i in 0..<256 {
            guard let key0 = Shield.randomBytes(Shield.keySize),
                  let key1 = Shield.randomBytes(Shield.keySize) else {
                throw ShieldError.randomGenerationFailed
            }

            ls.privateKey[i][0] = key0
            ls.privateKey[i][1] = key1

            let h0 = Shield.sha256(key0)
            let h1 = Shield.sha256(key1)

            for j in 0..<32 {
                ls.publicKey[i * 64 + j] = h0[j]
                ls.publicKey[i * 64 + 32 + j] = h1[j]
            }
        }

        return ls
    }

    public func sign(_ message: [UInt8]) throws -> [UInt8] {
        if used {
            throw ShieldError.lamportKeyUsed
        }
        used = true

        let msgHash = Shield.sha256(message)
        var signature = [UInt8](repeating: 0, count: 256 * 32)

        for i in 0..<256 {
            let byteIdx = i / 8
            let bitIdx = i % 8
            let bit = Int((msgHash[byteIdx] >> bitIdx) & 1)

            for j in 0..<32 {
                signature[i * 32 + j] = privateKey[i][bit][j]
            }
        }

        return signature
    }

    public static func verify(_ message: [UInt8], signature: [UInt8], publicKey: [UInt8]) -> Bool {
        guard signature.count == 256 * 32, publicKey.count == 256 * 64 else {
            return false
        }

        let msgHash = Shield.sha256(message)

        for i in 0..<256 {
            let byteIdx = i / 8
            let bitIdx = i % 8
            let bit = Int((msgHash[byteIdx] >> bitIdx) & 1)

            let revealed = Array(signature[(i * 32)..<((i + 1) * 32)])
            let hashed = Shield.sha256(revealed)

            let expectedStart = bit == 1 ? i * 64 + 32 : i * 64
            let expected = Array(publicKey[expectedStart..<(expectedStart + 32)])

            if !Shield.constantTimeEquals(hashed, expected) {
                return false
            }
        }

        return true
    }

    public var isUsed: Bool { used }

    public func fingerprint() -> String {
        let hash = Shield.sha256(publicKey)
        return hash.prefix(8).map { String(format: "%02x", $0) }.joined()
    }

    public func wipe() {
        for i in 0..<privateKey.count {
            Shield.secureWipe(&privateKey[i][0])
            Shield.secureWipe(&privateKey[i][1])
        }
    }
}
