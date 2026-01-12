import Foundation
import CommonCrypto

/// User identity.
public struct Identity {
    public let userId: String
    public let displayName: String
    public let verificationKey: [UInt8]
    public let createdAt: Int64
    public var attributes: [String: Any]

    public init(userId: String, displayName: String, verificationKey: [UInt8],
                createdAt: Int64, attributes: [String: Any] = [:]) {
        self.userId = userId
        self.displayName = displayName
        self.verificationKey = verificationKey
        self.createdAt = createdAt
        self.attributes = attributes
    }
}

/// Session information from validated token.
public struct Session {
    public let userId: String
    public let created: Int64
    public let expires: Int64
    public let permissions: [String]
    public var metadata: [String: Any]

    public init(userId: String, created: Int64, expires: Int64,
                permissions: [String] = [], metadata: [String: Any] = [:]) {
        self.userId = userId
        self.created = created
        self.expires = expires
        self.permissions = permissions
        self.metadata = metadata
    }

    public var isExpired: Bool {
        return Int64(Date().timeIntervalSince1970) > expires
    }

    public var remainingTime: Int64 {
        return max(0, expires - Int64(Date().timeIntervalSince1970))
    }
}

/// IdentityProvider - SSO/Identity Provider using symmetric crypto.
///
/// Provides user registration, session management, and service tokens
/// using only symmetric cryptography (no public-key certificates).
public class IdentityProvider {
    private static let pbkdf2Iterations = 100000

    private let providerKey: [UInt8]
    private let tokenTtl: Int
    private var identities: [String: Identity] = [:]

    /// Create identity provider.
    ///
    /// - Parameters:
    ///   - providerKey: 32-byte provider secret key
    ///   - tokenTtl: Default token lifetime in seconds
    public init(providerKey: [UInt8], tokenTtl: Int = 3600) {
        self.providerKey = providerKey
        self.tokenTtl = tokenTtl > 0 ? tokenTtl : 3600
    }

    /// Register new user identity.
    ///
    /// - Parameters:
    ///   - userId: Unique user identifier
    ///   - password: User's password
    ///   - displayName: User's display name
    ///   - attributes: Optional user attributes
    /// - Returns: Created identity
    /// - Throws: ShieldError if userId already exists
    public func register(userId: String, password: String, displayName: String,
                         attributes: [String: Any] = [:]) throws -> Identity {
        if identities[userId] != nil {
            throw ShieldError.invalidToken
        }

        let verificationKey = deriveVerificationKey(userId: userId, password: password)
        let identity = Identity(
            userId: userId,
            displayName: displayName,
            verificationKey: verificationKey,
            createdAt: Int64(Date().timeIntervalSince1970),
            attributes: attributes
        )

        identities[userId] = identity
        return identity
    }

    /// Authenticate user and return session token.
    ///
    /// - Parameters:
    ///   - userId: User identifier
    ///   - password: User's password
    ///   - permissions: Optional permission list
    ///   - ttl: Token lifetime (or default if nil)
    /// - Returns: Session token, or nil if authentication fails
    public func authenticate(userId: String, password: String,
                             permissions: [String]? = nil, ttl: Int? = nil) -> String? {
        guard let identity = identities[userId] else {
            return nil
        }

        let verificationKey = deriveVerificationKey(userId: userId, password: password)
        guard Shield.constantTimeEquals(verificationKey, identity.verificationKey) else {
            return nil
        }

        let actualTtl = ttl ?? tokenTtl
        let now = Int64(Date().timeIntervalSince1970)

        var sessionData: [String: Any] = [
            "user_id": userId,
            "created": now,
            "expires": now + Int64(actualTtl),
            "permissions": permissions ?? [],
            "nonce": generateNonce()
        ]

        return signToken(data: sessionData)
    }

    /// Validate session token.
    ///
    /// - Parameter token: Session token from authenticate()
    /// - Returns: Session object, or nil if invalid/expired
    public func validateToken(_ token: String) -> Session? {
        guard let sessionData = verifyToken(token) else {
            return nil
        }

        guard let expires = sessionData["expires"] as? Int64 else {
            return nil
        }

        if expires < Int64(Date().timeIntervalSince1970) {
            return nil
        }

        let permissions = (sessionData["permissions"] as? [String]) ?? []
        let metadata = (sessionData["metadata"] as? [String: Any]) ?? [:]

        return Session(
            userId: sessionData["user_id"] as? String ?? "",
            created: sessionData["created"] as? Int64 ?? 0,
            expires: expires,
            permissions: permissions,
            metadata: metadata
        )
    }

    /// Create service-specific access token.
    ///
    /// - Parameters:
    ///   - sessionToken: Valid session token
    ///   - service: Target service identifier
    ///   - permissions: Scoped permissions for this service
    ///   - ttl: Token lifetime (default 300 seconds)
    /// - Returns: Service token, or nil if session invalid
    public func createServiceToken(sessionToken: String, service: String,
                                   permissions: [String]? = nil, ttl: Int = 300) -> String? {
        guard let session = validateToken(sessionToken) else {
            return nil
        }

        let now = Int64(Date().timeIntervalSince1970)
        let serviceData: [String: Any] = [
            "user_id": session.userId,
            "service": service,
            "created": now,
            "expires": now + Int64(ttl),
            "permissions": permissions ?? [],
            "parent_expires": session.expires
        ]

        return signToken(data: serviceData)
    }

    /// Validate service-specific token.
    ///
    /// - Parameters:
    ///   - token: Service token
    ///   - service: Expected service identifier
    /// - Returns: Session object, or nil if invalid
    public func validateServiceToken(_ token: String, service: String) -> Session? {
        guard let tokenData = verifyToken(token) else {
            return nil
        }

        guard tokenData["service"] as? String == service else {
            return nil
        }

        let now = Int64(Date().timeIntervalSince1970)
        guard let expires = tokenData["expires"] as? Int64, expires >= now else {
            return nil
        }

        if let parentExpires = tokenData["parent_expires"] as? Int64, parentExpires < now {
            return nil
        }

        let permissions = (tokenData["permissions"] as? [String]) ?? []
        let metadata: [String: Any] = ["service": service]

        return Session(
            userId: tokenData["user_id"] as? String ?? "",
            created: tokenData["created"] as? Int64 ?? 0,
            expires: expires,
            permissions: permissions,
            metadata: metadata
        )
    }

    /// Refresh session token.
    ///
    /// - Parameters:
    ///   - token: Current valid session token
    ///   - ttl: New lifetime (or default if nil)
    /// - Returns: New session token, or nil if current token invalid
    public func refreshToken(_ token: String, ttl: Int? = nil) -> String? {
        guard let session = validateToken(token) else {
            return nil
        }

        let actualTtl = ttl ?? tokenTtl
        let now = Int64(Date().timeIntervalSince1970)

        let sessionData: [String: Any] = [
            "user_id": session.userId,
            "created": now,
            "expires": now + Int64(actualTtl),
            "permissions": session.permissions,
            "nonce": generateNonce()
        ]

        return signToken(data: sessionData)
    }

    /// Revoke user identity.
    ///
    /// - Parameter userId: User to revoke
    /// - Returns: true if user was revoked
    @discardableResult
    public func revokeUser(_ userId: String) -> Bool {
        return identities.removeValue(forKey: userId) != nil
    }

    /// Get identity by user ID.
    public func getIdentity(_ userId: String) -> Identity? {
        return identities[userId]
    }

    // Private helpers

    private func deriveVerificationKey(userId: String, password: String) -> [UInt8] {
        let saltInput = "user:\(userId)".data(using: .utf8)!
        let salt = Shield.sha256(Array(saltInput))

        let userKey = pbkdf2(password: password, salt: salt, iterations: IdentityProvider.pbkdf2Iterations, keyLength: 32)

        var verifyInput = Array("verify:".utf8)
        verifyInput.append(contentsOf: userKey)
        return Shield.sha256(verifyInput)
    }

    private func pbkdf2(password: String, salt: [UInt8], iterations: Int, keyLength: Int) -> [UInt8] {
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

    private func signToken(data: [String: Any]) -> String? {
        guard let jsonData = try? JSONSerialization.data(withJSONObject: data, options: [.sortedKeys]) else {
            return nil
        }

        let tokenBytes = Array(jsonData)
        let mac = Shield.hmacSha256(key: providerKey, data: tokenBytes)
        let truncatedMac = Array(mac.prefix(16))

        var result = tokenBytes
        result.append(contentsOf: truncatedMac)

        return Data(result).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private func verifyToken(_ token: String) -> [String: Any]? {
        // Restore base64 standard chars and padding
        var base64 = token
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")

        let remainder = base64.count % 4
        if remainder > 0 {
            base64 += String(repeating: "=", count: 4 - remainder)
        }

        guard let decoded = Data(base64Encoded: base64) else {
            return nil
        }

        let bytes = Array(decoded)
        if bytes.count < 17 {
            return nil
        }

        let tokenBytes = Array(bytes.prefix(bytes.count - 16))
        let receivedMac = Array(bytes.suffix(16))

        let expectedMac = Array(Shield.hmacSha256(key: providerKey, data: tokenBytes).prefix(16))

        guard Shield.constantTimeEquals(receivedMac, expectedMac) else {
            return nil
        }

        guard let json = try? JSONSerialization.jsonObject(with: Data(tokenBytes), options: []) as? [String: Any] else {
            return nil
        }

        return json
    }

    private func generateNonce() -> String {
        guard let bytes = Shield.randomBytes(8) else {
            return ""
        }
        return bytes.map { String(format: "%02x", $0) }.joined()
    }
}
