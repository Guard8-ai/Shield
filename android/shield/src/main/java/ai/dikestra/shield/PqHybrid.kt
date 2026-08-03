package ai.dikestra.shield

import java.security.SecureRandom
import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters

/**
 * Post-Quantum Hybrid Key Exchange (X25519 + ML-KEM-768).
 *
 * Lets two parties who have never shared a secret agree on a 32-byte key over an open
 * network, safe even against an attacker who records the traffic today and owns a
 * quantum computer years from now ("harvest now, decrypt later").
 *
 * It is a HYBRID exchange combining two independent key exchanges and mixing both
 * results, so an attacker must break BOTH to win:
 *  - X25519     classical elliptic-curve Diffie-Hellman (battle-tested today)
 *  - ML-KEM-768 NIST FIPS 203 lattice KEM (quantum-resistant), aka CRYSTALS-Kyber
 *
 * Both primitives come from the audited Bouncy Castle provider, not hand-rolled math.
 * The 32-byte output feeds straight into Shield.withKey().
 *
 * Byte-compatible with the Python, Go, Rust, JS, C#, Java and other Shield bindings:
 * identical FIPS 203 / RFC 7748 encodings and the same KDF binding. The shared
 * conformance vectors in tests/pq_kex_vectors.json keep every implementation
 * byte-identical.
 *
 * Security properties (and limits): confidential against a passive eavesdropper who
 * does not hold the recipient's private key (including a future quantum computer); the
 * shared key is bound to the recipient's exact public key and this handshake (no
 * unknown-key-share); the SENDER is anonymous (not authenticated); and there is NO
 * forward secrecy against compromise of the recipient's LONG-TERM key. For full
 * forward secrecy use an interactive ratchet, not this one-shot exchange. Rotate the
 * recipient keypair periodically to bound exposure.
 */
object PqHybrid {
    internal const val MLKEM_PUBLIC_SIZE = 1184
    internal const val MLKEM_CIPHERTEXT_SIZE = 1088
    internal const val MLKEM_SEED_SIZE = 64 // portable FIPS 203 seed (d || z)
    internal const val X25519_SIZE = 32

    /** Serialized public bundle size: ML-KEM public || X25519 public. */
    const val PUBLIC_BUNDLE_SIZE = MLKEM_PUBLIC_SIZE + X25519_SIZE // 1216
    /** Serialized handshake size: ephemeral X25519 public || ML-KEM ciphertext. */
    const val HANDSHAKE_SIZE = X25519_SIZE + MLKEM_CIPHERTEXT_SIZE // 1120
    /** Serialized private key size: ML-KEM seed || X25519 scalar. */
    const val PRIVATE_KEY_SIZE = MLKEM_SEED_SIZE + X25519_SIZE // 96
    /** Derived shared key size. */
    const val SHARED_KEY_SIZE = 32

    private val KDF_SALT = "shield/pq-hybrid/v1".toByteArray(Charsets.US_ASCII)
    private val rng = SecureRandom()

    /** The handshake and shared key returned by [initiate]. */
    data class InitiationResult(val handshake: ByteArray, val sharedKey: ByteArray)

    internal fun concat(vararg parts: ByteArray): ByteArray {
        val out = ByteArray(parts.sumOf { it.size })
        var offset = 0
        for (p in parts) {
            p.copyInto(out, offset)
            offset += p.size
        }
        return out
    }

    // Mix the two exchange results into one 32-byte key. Concatenating the secrets and
    // running them through HKDF binds the result to BOTH exchanges (hybrid security)
    // and to the full transcript, preventing key-substitution attacks.
    internal fun deriveSharedKey(classicalSecret: ByteArray, pqSecret: ByteArray, transcript: ByteArray): ByteArray {
        val hkdf = HKDFBytesGenerator(SHA256Digest())
        hkdf.init(HKDFParameters(concat(classicalSecret, pqSecret), KDF_SALT, transcript))
        val okm = ByteArray(SHARED_KEY_SIZE)
        hkdf.generateBytes(okm, 0, SHARED_KEY_SIZE)
        return okm
    }

    /**
     * Sender side: derive a shared key for [peer] and the handshake to send. Transmit
     * the handshake to the recipient (who passes it to [HybridPrivateKey.accept]); use
     * the shared key with Shield.withKey().
     */
    fun initiate(peer: HybridPublicKey): InitiationResult {
        // ML-KEM: lock a fresh secret inside the recipient's public padlock.
        val ek = MLKEMPublicKeyParameters(MLKEMParameters.ml_kem_768, peer.mlkemPublic)
        val enc = MLKEMGenerator(rng).generateEncapsulated(ek)
        val pqSecret = enc.secret
        val kemCiphertext = enc.encapsulation

        // X25519: a one-time ("ephemeral") classical exchange against the peer's key.
        val ephScalar = ByteArray(X25519_SIZE).also { rng.nextBytes(it) }
        val ephPriv = X25519PrivateKeyParameters(ephScalar, 0)
        val ephPublic = ephPriv.generatePublicKey().encoded
        val classicalSecret = ByteArray(X25519_SIZE)
        X25519Agreement().apply {
            init(ephPriv)
            calculateAgreement(X25519PublicKeyParameters(peer.x25519Public, 0), classicalSecret, 0)
        }

        val transcript = concat(peer.toBytes(), ephPublic, kemCiphertext)
        val sharedKey = deriveSharedKey(classicalSecret, pqSecret, transcript)
        val handshake = concat(ephPublic, kemCiphertext)
        return InitiationResult(handshake, sharedKey)
    }
}

/** A recipient's published "address": an ML-KEM public key + an X25519 public key. */
class HybridPublicKey internal constructor(
    internal val mlkemPublic: ByteArray,
    internal val x25519Public: ByteArray,
) {
    init {
        require(mlkemPublic.size == PqHybrid.MLKEM_PUBLIC_SIZE) {
            "ML-KEM public key must be ${PqHybrid.MLKEM_PUBLIC_SIZE} bytes"
        }
        require(x25519Public.size == PqHybrid.X25519_SIZE) {
            "X25519 public key must be ${PqHybrid.X25519_SIZE} bytes"
        }
    }

    /** Serialize for publishing/transport (PUBLIC_BUNDLE_SIZE bytes). */
    fun toBytes(): ByteArray = PqHybrid.concat(mlkemPublic, x25519Public)

    companion object {
        /** Parse a bundle produced by [toBytes]. */
        fun fromBytes(data: ByteArray): HybridPublicKey {
            require(data.size == PqHybrid.PUBLIC_BUNDLE_SIZE) {
                "Public bundle must be ${PqHybrid.PUBLIC_BUNDLE_SIZE} bytes, got ${data.size}"
            }
            return HybridPublicKey(
                data.copyOfRange(0, PqHybrid.MLKEM_PUBLIC_SIZE),
                data.copyOfRange(PqHybrid.MLKEM_PUBLIC_SIZE, PqHybrid.PUBLIC_BUNDLE_SIZE),
            )
        }
    }
}

/** A recipient's private key. Generate once, keep secret, publish the public key. */
class HybridPrivateKey private constructor(
    private val seed: ByteArray,
    private val scalar: ByteArray,
) {
    private val mlkem = MLKEMPrivateKeyParameters(MLKEMParameters.ml_kem_768, seed)
    private val x25519 = X25519PrivateKeyParameters(scalar, 0)

    /**
     * Serialize the PRIVATE key for secure storage (PRIVATE_KEY_SIZE bytes):
     * ML-KEM-768 64-byte seed || X25519 32-byte scalar. Keep it secret.
     */
    fun toBytes(): ByteArray = PqHybrid.concat(seed, scalar)

    /** The publishable public half of this keypair. */
    fun publicKey(): HybridPublicKey =
        HybridPublicKey(mlkem.publicKey, x25519.generatePublicKey().encoded)

    /** Recipient side: turn a sender's handshake into the shared 32-byte key. */
    fun accept(handshake: ByteArray): ByteArray {
        require(handshake.size == PqHybrid.HANDSHAKE_SIZE) {
            "Handshake must be ${PqHybrid.HANDSHAKE_SIZE} bytes, got ${handshake.size}"
        }
        val ephX25519Public = handshake.copyOfRange(0, PqHybrid.X25519_SIZE)
        val kemCiphertext = handshake.copyOfRange(PqHybrid.X25519_SIZE, PqHybrid.HANDSHAKE_SIZE)

        val pqSecret = MLKEMExtractor(mlkem).extractSecret(kemCiphertext)

        val classicalSecret = ByteArray(PqHybrid.X25519_SIZE)
        X25519Agreement().apply {
            init(x25519)
            calculateAgreement(X25519PublicKeyParameters(ephX25519Public, 0), classicalSecret, 0)
        }

        val transcript = PqHybrid.concat(publicKey().toBytes(), ephX25519Public, kemCiphertext)
        return PqHybrid.deriveSharedKey(classicalSecret, pqSecret, transcript)
    }

    companion object {
        /** Create a fresh keypair using the system CSPRNG. */
        fun generate(): HybridPrivateKey {
            val rng = SecureRandom()
            val seed = ByteArray(PqHybrid.MLKEM_SEED_SIZE).also { rng.nextBytes(it) }
            val scalar = ByteArray(PqHybrid.X25519_SIZE).also { rng.nextBytes(it) }
            return HybridPrivateKey(seed, scalar)
        }

        /** Restore a keypair produced by [toBytes]. */
        fun fromBytes(data: ByteArray): HybridPrivateKey {
            require(data.size == PqHybrid.PRIVATE_KEY_SIZE) {
                "Private key must be ${PqHybrid.PRIVATE_KEY_SIZE} bytes, got ${data.size}"
            }
            return HybridPrivateKey(
                data.copyOfRange(0, PqHybrid.MLKEM_SEED_SIZE),
                data.copyOfRange(PqHybrid.MLKEM_SEED_SIZE, PqHybrid.PRIVATE_KEY_SIZE),
            )
        }
    }
}
