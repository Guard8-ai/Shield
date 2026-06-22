import Foundation
import CryptoKit

/// Post-Quantum Hybrid Key Exchange (X25519 + ML-KEM-768).
///
/// Lets two parties who have never shared a secret agree on a 32-byte key over an
/// open network, safe even against an attacker who records the traffic today and owns
/// a quantum computer years from now ("harvest now, decrypt later").
///
/// It is a HYBRID exchange combining two independent key exchanges and mixing both
/// results, so an attacker must break BOTH to win:
///   - X25519     classical elliptic-curve Diffie-Hellman (battle-tested today)
///   - ML-KEM-768 NIST FIPS 203 lattice KEM (quantum-resistant), aka CRYSTALS-Kyber
///
/// Both primitives come from Apple CryptoKit (`MLKEM768`, `Curve25519`), not
/// hand-rolled math. The 32-byte output feeds straight into `Shield.withKey()`.
///
/// Byte-compatible with the Python, Go, Rust, JS, C#, Java, Kotlin and Android Shield
/// bindings: identical FIPS 203 / RFC 7748 encodings and the same KDF binding. The
/// shared conformance vectors in `tests/pq_kex_vectors.json` keep every implementation
/// byte-identical.
///
/// `MLKEM768` requires macOS 15 / iOS 18 (the first OSes to ship NIST FIPS 203 in
/// CryptoKit). On older OSes the symmetric Shield API remains fully available.
///
/// Security properties (and limits): confidential against a passive eavesdropper who
/// does not hold the recipient's private key (including a future quantum computer); the
/// shared key is bound to the recipient's exact public key and this handshake (no
/// unknown-key-share); the SENDER is anonymous (not authenticated); and there is NO
/// forward secrecy against compromise of the recipient's LONG-TERM key. For full
/// forward secrecy use an interactive ratchet, not this one-shot exchange. Rotate the
/// recipient keypair periodically to bound exposure.
@available(macOS 15.0, iOS 18.0, tvOS 18.0, watchOS 11.0, *)
public enum PqHybrid {
    static let mlkemPublicSize = 1184
    static let mlkemCiphertextSize = 1088
    static let mlkemSeedSize = 64 // portable FIPS 203 seed (d || z)
    static let x25519Size = 32

    /// Serialized public bundle size: ML-KEM public || X25519 public.
    public static let publicBundleSize = mlkemPublicSize + x25519Size // 1216
    /// Serialized handshake size: ephemeral X25519 public || ML-KEM ciphertext.
    public static let handshakeSize = x25519Size + mlkemCiphertextSize // 1120
    /// Serialized private key size: ML-KEM seed || X25519 scalar.
    public static let privateKeySize = mlkemSeedSize + x25519Size // 96
    /// Derived shared key size.
    public static let sharedKeySize = 32

    static let kdfSalt = Data("shield/pq-hybrid/v1".utf8)

    /// Errors raised by the hybrid key exchange.
    public enum PqError: Error {
        case invalidSize(expected: Int, actual: Int)
    }

    static func rawBytes(_ key: SymmetricKey) -> Data {
        key.withUnsafeBytes { Data($0) }
    }

    static func rawBytes(_ secret: SharedSecret) -> Data {
        secret.withUnsafeBytes { Data($0) }
    }

    // Mix the two exchange results into one 32-byte key. Concatenating the secrets and
    // running them through HKDF binds the result to BOTH exchanges (hybrid security)
    // and to the full transcript, preventing key-substitution attacks.
    static func deriveSharedKey(classicalSecret: Data, pqSecret: Data, transcript: Data) -> Data {
        let ikm = SymmetricKey(data: classicalSecret + pqSecret)
        let okm = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: ikm,
            salt: kdfSalt,
            info: transcript,
            outputByteCount: sharedKeySize
        )
        return rawBytes(okm)
    }

    /// Sender side: derive a shared key for `peer` and the handshake to send. Transmit
    /// the handshake to the recipient (who passes it to `HybridPrivateKey.accept`); use
    /// the shared key with `Shield.withKey()`.
    public static func initiate(peer: HybridPublicKey) throws -> (handshake: Data, sharedKey: Data) {
        // ML-KEM: lock a fresh secret inside the recipient's public padlock.
        let ek = try MLKEM768.PublicKey(rawRepresentation: peer.mlkemPublic)
        let encapsulation = ek.encapsulate()
        let pqSecret = rawBytes(encapsulation.sharedSecret)
        let kemCiphertext = encapsulation.encapsulated

        // X25519: a one-time ("ephemeral") classical exchange against the peer's key.
        let ephPriv = Curve25519.KeyAgreement.PrivateKey()
        let ephPublic = ephPriv.publicKey.rawRepresentation
        let peerX = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: peer.x25519Public)
        let classicalSecret = rawBytes(try ephPriv.sharedSecretFromKeyAgreement(with: peerX))

        let transcript = peer.toBytes() + ephPublic + kemCiphertext
        let sharedKey = deriveSharedKey(classicalSecret: classicalSecret, pqSecret: pqSecret, transcript: transcript)
        let handshake = ephPublic + kemCiphertext
        return (handshake, sharedKey)
    }
}

/// A recipient's published "address": an ML-KEM public key + an X25519 public key.
@available(macOS 15.0, iOS 18.0, tvOS 18.0, watchOS 11.0, *)
public struct HybridPublicKey {
    let mlkemPublic: Data
    let x25519Public: Data

    init(mlkemPublic: Data, x25519Public: Data) throws {
        guard mlkemPublic.count == PqHybrid.mlkemPublicSize else {
            throw PqHybrid.PqError.invalidSize(expected: PqHybrid.mlkemPublicSize, actual: mlkemPublic.count)
        }
        guard x25519Public.count == PqHybrid.x25519Size else {
            throw PqHybrid.PqError.invalidSize(expected: PqHybrid.x25519Size, actual: x25519Public.count)
        }
        self.mlkemPublic = mlkemPublic
        self.x25519Public = x25519Public
    }

    /// Serialize for publishing/transport (publicBundleSize bytes).
    public func toBytes() -> Data {
        mlkemPublic + x25519Public
    }

    /// Parse a bundle produced by `toBytes()`.
    public static func fromBytes(_ data: Data) throws -> HybridPublicKey {
        guard data.count == PqHybrid.publicBundleSize else {
            throw PqHybrid.PqError.invalidSize(expected: PqHybrid.publicBundleSize, actual: data.count)
        }
        let split = data.startIndex + PqHybrid.mlkemPublicSize
        return try HybridPublicKey(
            mlkemPublic: data[data.startIndex..<split],
            x25519Public: data[split...]
        )
    }
}

/// A recipient's private key. Generate once, keep secret, publish the public key.
@available(macOS 15.0, iOS 18.0, tvOS 18.0, watchOS 11.0, *)
public struct HybridPrivateKey {
    private let seed: Data
    private let scalar: Data
    private let mlkem: MLKEM768.PrivateKey
    private let x25519: Curve25519.KeyAgreement.PrivateKey

    private init(seed: Data, scalar: Data) throws {
        self.seed = seed
        self.scalar = scalar
        self.mlkem = try MLKEM768.PrivateKey(seedRepresentation: seed)
        self.x25519 = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: scalar)
    }

    /// Create a fresh keypair using the system CSPRNG.
    public static func generate() throws -> HybridPrivateKey {
        var seed = Data(count: PqHybrid.mlkemSeedSize)
        var scalar = Data(count: PqHybrid.x25519Size)
        _ = seed.withUnsafeMutableBytes { SecRandomCopyBytesCompat($0) }
        _ = scalar.withUnsafeMutableBytes { SecRandomCopyBytesCompat($0) }
        return try HybridPrivateKey(seed: seed, scalar: scalar)
    }

    /// Serialize the PRIVATE key for secure storage (privateKeySize bytes):
    /// ML-KEM-768 64-byte seed || X25519 32-byte scalar. Keep it secret.
    public func toBytes() -> Data {
        seed + scalar
    }

    /// Restore a keypair produced by `toBytes()`.
    public static func fromBytes(_ data: Data) throws -> HybridPrivateKey {
        guard data.count == PqHybrid.privateKeySize else {
            throw PqHybrid.PqError.invalidSize(expected: PqHybrid.privateKeySize, actual: data.count)
        }
        let split = data.startIndex + PqHybrid.mlkemSeedSize
        return try HybridPrivateKey(seed: data[data.startIndex..<split], scalar: data[split...])
    }

    /// The publishable public half of this keypair.
    public func publicKey() throws -> HybridPublicKey {
        try HybridPublicKey(
            mlkemPublic: mlkem.publicKey.rawRepresentation,
            x25519Public: x25519.publicKey.rawRepresentation
        )
    }

    /// Recipient side: turn a sender's handshake into the shared 32-byte key.
    public func accept(_ handshake: Data) throws -> Data {
        guard handshake.count == PqHybrid.handshakeSize else {
            throw PqHybrid.PqError.invalidSize(expected: PqHybrid.handshakeSize, actual: handshake.count)
        }
        let split = handshake.startIndex + PqHybrid.x25519Size
        let ephX25519Public = handshake[handshake.startIndex..<split]
        let kemCiphertext = handshake[split...]

        let pqSecret = PqHybrid.rawBytes(try mlkem.decapsulate(Data(kemCiphertext)))
        let ephPub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: ephX25519Public)
        let classicalSecret = PqHybrid.rawBytes(try x25519.sharedSecretFromKeyAgreement(with: ephPub))

        let transcript = try publicKey().toBytes() + Data(ephX25519Public) + Data(kemCiphertext)
        return PqHybrid.deriveSharedKey(classicalSecret: classicalSecret, pqSecret: pqSecret, transcript: transcript)
    }
}

/// Fill a buffer with CSPRNG bytes. `SecRandomCopyBytes` on Apple platforms; on other
/// platforms (Linux/Windows, used only for source checks) fall back to `SystemRandomNumberGenerator`.
@available(macOS 15.0, iOS 18.0, tvOS 18.0, watchOS 11.0, *)
@discardableResult
func SecRandomCopyBytesCompat(_ buffer: UnsafeMutableRawBufferPointer) -> Int32 {
    var rng = SystemRandomNumberGenerator()
    for i in 0..<buffer.count {
        buffer[i] = UInt8.random(in: 0...255, using: &rng)
    }
    return 0
}
