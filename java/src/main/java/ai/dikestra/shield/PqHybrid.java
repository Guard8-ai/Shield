package ai.dikestra.shield;

import java.security.SecureRandom;

import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.agreement.X25519Agreement;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;

/**
 * Post-Quantum Hybrid Key Exchange (X25519 + ML-KEM-768).
 *
 * <p>Lets two parties who have never shared a secret agree on a 32-byte key over an
 * open network, safe even against an attacker who records the traffic today and owns
 * a quantum computer years from now ("harvest now, decrypt later").
 *
 * <p>It is a HYBRID exchange combining two independent key exchanges and mixing both
 * results, so an attacker must break BOTH to win:
 * <ul>
 *   <li>X25519     classical elliptic-curve Diffie-Hellman (battle-tested today)</li>
 *   <li>ML-KEM-768 NIST FIPS 203 lattice KEM (quantum-resistant), aka CRYSTALS-Kyber</li>
 * </ul>
 *
 * <p>Both primitives come from the audited Bouncy Castle provider, not hand-rolled
 * math. The 32-byte output feeds straight into {@code Shield.withKey()}.
 *
 * <p>Byte-compatible with the Python, Go, Rust, JS, C# and other Shield bindings:
 * identical FIPS 203 / RFC 7748 encodings and the same KDF binding. The shared
 * conformance vectors in {@code tests/pq_kex_vectors.json} keep every implementation
 * byte-identical.
 *
 * <p>Security properties (and limits): confidential against a passive eavesdropper who
 * does not hold the recipient's private key (including a future quantum computer); the
 * shared key is bound to the recipient's exact public key and this handshake (no
 * unknown-key-share); the SENDER is anonymous (not authenticated); and there is NO
 * forward secrecy against compromise of the recipient's LONG-TERM key. For full forward
 * secrecy use an interactive ratchet, not this one-shot exchange. Rotate the recipient
 * keypair periodically to bound exposure.
 */
public final class PqHybrid {

    static final int MLKEM_PUBLIC_SIZE = 1184;
    static final int MLKEM_CIPHERTEXT_SIZE = 1088;
    static final int MLKEM_SEED_SIZE = 64; // portable FIPS 203 seed (d || z)
    static final int X25519_SIZE = 32;

    /** Serialized public bundle size: ML-KEM public || X25519 public. */
    public static final int PUBLIC_BUNDLE_SIZE = MLKEM_PUBLIC_SIZE + X25519_SIZE; // 1216
    /** Serialized handshake size: ephemeral X25519 public || ML-KEM ciphertext. */
    public static final int HANDSHAKE_SIZE = X25519_SIZE + MLKEM_CIPHERTEXT_SIZE; // 1120
    /** Serialized private key size: ML-KEM seed || X25519 scalar. */
    public static final int PRIVATE_KEY_SIZE = MLKEM_SEED_SIZE + X25519_SIZE; // 96
    /** Derived shared key size. */
    public static final int SHARED_KEY_SIZE = 32;

    private static final byte[] KDF_SALT = "shield/pq-hybrid/v1".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    private static final SecureRandom RNG = new SecureRandom();

    private PqHybrid() {
    }

    /** The handshake-and-shared-key pair returned by {@link #initiate}. */
    public static final class InitiationResult {
        public final byte[] handshake;
        public final byte[] sharedKey;

        InitiationResult(byte[] handshake, byte[] sharedKey) {
            this.handshake = handshake;
            this.sharedKey = sharedKey;
        }
    }

    static byte[] concat(byte[]... parts) {
        int total = 0;
        for (byte[] p : parts) {
            total += p.length;
        }
        byte[] out = new byte[total];
        int offset = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, offset, p.length);
            offset += p.length;
        }
        return out;
    }

    static byte[] slice(byte[] src, int start, int len) {
        byte[] out = new byte[len];
        System.arraycopy(src, start, out, 0, len);
        return out;
    }

    // Mix the two exchange results into one 32-byte key. Concatenating the secrets and
    // running them through HKDF binds the result to BOTH exchanges (hybrid security)
    // and to the full transcript, preventing key-substitution attacks.
    static byte[] deriveSharedKey(byte[] classicalSecret, byte[] pqSecret, byte[] transcript) {
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
        hkdf.init(new HKDFParameters(concat(classicalSecret, pqSecret), KDF_SALT, transcript));
        byte[] okm = new byte[SHARED_KEY_SIZE];
        hkdf.generateBytes(okm, 0, SHARED_KEY_SIZE);
        return okm;
    }

    /**
     * Sender side: derive a shared key for {@code peer} and the handshake to send.
     * Transmit {@code handshake} to the recipient (who passes it to
     * {@link HybridPrivateKey#accept}); use {@code sharedKey} with {@code Shield.withKey()}.
     */
    public static InitiationResult initiate(HybridPublicKey peer) {
        // ML-KEM: lock a fresh secret inside the recipient's public padlock.
        MLKEMPublicKeyParameters ek = new MLKEMPublicKeyParameters(MLKEMParameters.ml_kem_768, peer.mlkemPublic);
        SecretWithEncapsulation enc = new MLKEMGenerator(RNG).generateEncapsulated(ek);
        byte[] pqSecret = enc.getSecret();
        byte[] kemCiphertext = enc.getEncapsulation();

        // X25519: a one-time ("ephemeral") classical exchange against the peer's key.
        byte[] ephScalar = new byte[X25519_SIZE];
        RNG.nextBytes(ephScalar);
        X25519PrivateKeyParameters ephPriv = new X25519PrivateKeyParameters(ephScalar, 0);
        byte[] ephPublic = ephPriv.generatePublicKey().getEncoded();
        byte[] classicalSecret = new byte[X25519_SIZE];
        X25519Agreement agreement = new X25519Agreement();
        agreement.init(ephPriv);
        agreement.calculateAgreement(new X25519PublicKeyParameters(peer.x25519Public, 0), classicalSecret, 0);

        byte[] transcript = concat(peer.toBytes(), ephPublic, kemCiphertext);
        byte[] sharedKey = deriveSharedKey(classicalSecret, pqSecret, transcript);
        byte[] handshake = concat(ephPublic, kemCiphertext);
        return new InitiationResult(handshake, sharedKey);
    }

    /** A recipient's published "address": an ML-KEM public key + an X25519 public key. */
    public static final class HybridPublicKey {
        final byte[] mlkemPublic;
        final byte[] x25519Public;

        HybridPublicKey(byte[] mlkemPublic, byte[] x25519Public) {
            if (mlkemPublic.length != MLKEM_PUBLIC_SIZE) {
                throw new IllegalArgumentException("ML-KEM public key must be " + MLKEM_PUBLIC_SIZE + " bytes");
            }
            if (x25519Public.length != X25519_SIZE) {
                throw new IllegalArgumentException("X25519 public key must be " + X25519_SIZE + " bytes");
            }
            this.mlkemPublic = mlkemPublic;
            this.x25519Public = x25519Public;
        }

        /** Serialize for publishing/transport (PUBLIC_BUNDLE_SIZE bytes). */
        public byte[] toBytes() {
            return concat(mlkemPublic, x25519Public);
        }

        /** Parse a bundle produced by {@link #toBytes()}. */
        public static HybridPublicKey fromBytes(byte[] data) {
            if (data.length != PUBLIC_BUNDLE_SIZE) {
                throw new IllegalArgumentException("Public bundle must be " + PUBLIC_BUNDLE_SIZE + " bytes, got " + data.length);
            }
            return new HybridPublicKey(slice(data, 0, MLKEM_PUBLIC_SIZE), slice(data, MLKEM_PUBLIC_SIZE, X25519_SIZE));
        }
    }

    /** A recipient's private key. Generate once, keep secret, publish the public key. */
    public static final class HybridPrivateKey {
        private final byte[] seed;
        private final byte[] scalar;
        private final MLKEMPrivateKeyParameters mlkem;
        private final X25519PrivateKeyParameters x25519;

        private HybridPrivateKey(byte[] seed, byte[] scalar) {
            this.seed = seed;
            this.scalar = scalar;
            this.mlkem = new MLKEMPrivateKeyParameters(MLKEMParameters.ml_kem_768, seed);
            this.x25519 = new X25519PrivateKeyParameters(scalar, 0);
        }

        /** Create a fresh keypair using the system CSPRNG. */
        public static HybridPrivateKey generate() {
            byte[] seed = new byte[MLKEM_SEED_SIZE];
            byte[] scalar = new byte[X25519_SIZE];
            RNG.nextBytes(seed);
            RNG.nextBytes(scalar);
            return new HybridPrivateKey(seed, scalar);
        }

        /**
         * Serialize the PRIVATE key for secure storage (PRIVATE_KEY_SIZE bytes):
         * ML-KEM-768 64-byte seed || X25519 32-byte scalar. Keep it secret.
         */
        public byte[] toBytes() {
            return concat(seed, scalar);
        }

        /** Restore a keypair produced by {@link #toBytes()}. */
        public static HybridPrivateKey fromBytes(byte[] data) {
            if (data.length != PRIVATE_KEY_SIZE) {
                throw new IllegalArgumentException("Private key must be " + PRIVATE_KEY_SIZE + " bytes, got " + data.length);
            }
            return new HybridPrivateKey(slice(data, 0, MLKEM_SEED_SIZE), slice(data, MLKEM_SEED_SIZE, X25519_SIZE));
        }

        /** The publishable public half of this keypair. */
        public HybridPublicKey publicKey() {
            return new HybridPublicKey(mlkem.getPublicKey(), x25519.generatePublicKey().getEncoded());
        }

        /** Recipient side: turn a sender's handshake into the shared 32-byte key. */
        public byte[] accept(byte[] handshake) {
            if (handshake.length != HANDSHAKE_SIZE) {
                throw new IllegalArgumentException("Handshake must be " + HANDSHAKE_SIZE + " bytes, got " + handshake.length);
            }
            byte[] ephX25519Public = slice(handshake, 0, X25519_SIZE);
            byte[] kemCiphertext = slice(handshake, X25519_SIZE, MLKEM_CIPHERTEXT_SIZE);

            byte[] pqSecret = new MLKEMExtractor(mlkem).extractSecret(kemCiphertext);

            byte[] classicalSecret = new byte[X25519_SIZE];
            X25519Agreement agreement = new X25519Agreement();
            agreement.init(x25519);
            agreement.calculateAgreement(new X25519PublicKeyParameters(ephX25519Public, 0), classicalSecret, 0);

            byte[] transcript = concat(publicKey().toBytes(), ephX25519Public, kemCiphertext);
            return deriveSharedKey(classicalSecret, pqSecret, transcript);
        }
    }
}
