using System;
using System.Text;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;

namespace Dikestra.Shield
{
    /// <summary>
    /// Post-Quantum Hybrid Key Exchange (X25519 + ML-KEM-768).
    ///
    /// Lets two parties who have never shared a secret agree on a 32-byte key over an
    /// open network, safe even against an attacker who records the traffic today and
    /// owns a quantum computer years from now ("harvest now, decrypt later").
    ///
    /// It is a HYBRID exchange combining two independent key exchanges and mixing both
    /// results, so an attacker must break BOTH to win:
    ///   - X25519     classical elliptic-curve Diffie-Hellman (battle-tested today)
    ///   - ML-KEM-768 NIST FIPS 203 lattice KEM (quantum-resistant), aka CRYSTALS-Kyber
    ///
    /// Both primitives come from the audited Bouncy Castle provider, not hand-rolled
    /// math. The 32-byte output feeds straight into Shield.WithKey().
    ///
    /// Byte-compatible with the Python, Go, Rust, JS and other Shield bindings:
    /// identical FIPS 203 / RFC 7748 encodings and the same KDF binding. The shared
    /// conformance vectors in tests/pq_kex_vectors.json keep every implementation
    /// byte-identical.
    ///
    /// Security properties (and limits): confidential against a passive eavesdropper
    /// who does not hold the recipient's private key (including a future quantum
    /// computer); the shared key is bound to the recipient's exact public key and this
    /// handshake (no unknown-key-share); the SENDER is anonymous (not authenticated);
    /// and there is NO forward secrecy against compromise of the recipient's LONG-TERM
    /// key. For full forward secrecy use an interactive ratchet, not this one-shot
    /// exchange. Rotate the recipient keypair periodically to bound exposure.
    /// </summary>
    public static class PqHybrid
    {
        internal const int MlKemPublicSize = 1184;
        internal const int MlKemCiphertextSize = 1088;
        internal const int MlKemSeedSize = 64; // portable FIPS 203 seed (d || z)
        internal const int X25519Size = 32;

        /// <summary>Serialized public bundle size: ML-KEM public || X25519 public.</summary>
        public const int PublicBundleSize = MlKemPublicSize + X25519Size; // 1216
        /// <summary>Serialized handshake size: ephemeral X25519 public || ML-KEM ciphertext.</summary>
        public const int HandshakeSize = X25519Size + MlKemCiphertextSize; // 1120
        /// <summary>Serialized private key size: ML-KEM seed || X25519 scalar.</summary>
        public const int PrivateKeySize = MlKemSeedSize + X25519Size; // 96
        /// <summary>Derived shared key size.</summary>
        public const int SharedKeySize = 32;

        private static readonly byte[] KdfSalt = Encoding.ASCII.GetBytes("shield/pq-hybrid/v1");

        // Mix the two exchange results into one 32-byte key. Concatenating the secrets
        // and running them through HKDF binds the result to BOTH exchanges (hybrid
        // security) and to the full transcript, preventing key-substitution attacks.
        internal static byte[] DeriveSharedKey(byte[] classicalSecret, byte[] pqSecret, byte[] transcript)
        {
            var ikm = new byte[classicalSecret.Length + pqSecret.Length];
            Buffer.BlockCopy(classicalSecret, 0, ikm, 0, classicalSecret.Length);
            Buffer.BlockCopy(pqSecret, 0, ikm, classicalSecret.Length, pqSecret.Length);
            var hkdf = new HkdfBytesGenerator(new Sha256Digest());
            hkdf.Init(new Org.BouncyCastle.Crypto.Parameters.HkdfParameters(ikm, KdfSalt, transcript));
            var okm = new byte[SharedKeySize];
            hkdf.GenerateBytes(okm, 0, SharedKeySize);
            return okm;
        }

        private static byte[] Concat(params byte[][] parts)
        {
            int total = 0;
            foreach (var p in parts) total += p.Length;
            var outBuf = new byte[total];
            int offset = 0;
            foreach (var p in parts)
            {
                Buffer.BlockCopy(p, 0, outBuf, 0 + offset, p.Length);
                offset += p.Length;
            }
            return outBuf;
        }

        /// <summary>
        /// Sender side: derive a shared key for <paramref name="peer"/> and the handshake to send.
        /// Returns (handshake, sharedKey): transmit handshake to the recipient (who passes it to
        /// <see cref="HybridPrivateKey.Accept"/>); use sharedKey with Shield.WithKey().
        /// </summary>
        public static (byte[] Handshake, byte[] SharedKey) Initiate(HybridPublicKey peer)
        {
            // ML-KEM: lock a fresh secret inside the recipient's public padlock.
            var ek = MLKemPublicKeyParameters.FromEncoding(MLKemParameters.ml_kem_768, peer.MlKemPublic);
            var enc = new MLKemEncapsulator(MLKemParameters.ml_kem_768);
            enc.Init(ek);
            var kemCiphertext = new byte[enc.EncapsulationLength];
            var pqSecret = new byte[enc.SecretLength];
            enc.Encapsulate(kemCiphertext, 0, kemCiphertext.Length, pqSecret, 0, pqSecret.Length);

            // X25519: a one-time ("ephemeral") classical exchange against the peer's key.
            var ephScalar = new byte[X25519Size];
            new Org.BouncyCastle.Security.SecureRandom().NextBytes(ephScalar);
            var ephPriv = new X25519PrivateKeyParameters(ephScalar, 0);
            var ephPublic = ephPriv.GeneratePublicKey().GetEncoded();
            var classicalSecret = new byte[X25519Size];
            var agreement = new X25519Agreement();
            agreement.Init(ephPriv);
            agreement.CalculateAgreement(new X25519PublicKeyParameters(peer.X25519Public, 0), classicalSecret, 0);

            var transcript = Concat(peer.ToBytes(), ephPublic, kemCiphertext);
            var sharedKey = DeriveSharedKey(classicalSecret, pqSecret, transcript);
            var handshake = Concat(ephPublic, kemCiphertext);
            return (handshake, sharedKey);
        }

        internal static byte[] Slice(byte[] src, int start, int len)
        {
            var outBuf = new byte[len];
            Buffer.BlockCopy(src, start, outBuf, 0, len);
            return outBuf;
        }

        internal static byte[] ConcatThree(byte[] a, byte[] b, byte[] c) => Concat(a, b, c);
    }

    /// <summary>A recipient's published "address": an ML-KEM public key + an X25519 public key.</summary>
    public sealed class HybridPublicKey
    {
        internal byte[] MlKemPublic;
        internal byte[] X25519Public;

        internal HybridPublicKey(byte[] mlkemPublic, byte[] x25519Public)
        {
            if (mlkemPublic.Length != PqHybrid.MlKemPublicSize)
                throw new ArgumentException($"ML-KEM public key must be {PqHybrid.MlKemPublicSize} bytes");
            if (x25519Public.Length != PqHybrid.X25519Size)
                throw new ArgumentException($"X25519 public key must be {PqHybrid.X25519Size} bytes");
            MlKemPublic = mlkemPublic;
            X25519Public = x25519Public;
        }

        /// <summary>Serialize for publishing/transport (PublicBundleSize bytes).</summary>
        public byte[] ToBytes() => PqHybrid.ConcatThree(MlKemPublic, X25519Public, Array.Empty<byte>());

        /// <summary>Parse a bundle produced by ToBytes().</summary>
        public static HybridPublicKey FromBytes(byte[] data)
        {
            if (data.Length != PqHybrid.PublicBundleSize)
                throw new ArgumentException($"Public bundle must be {PqHybrid.PublicBundleSize} bytes, got {data.Length}");
            return new HybridPublicKey(
                PqHybrid.Slice(data, 0, PqHybrid.MlKemPublicSize),
                PqHybrid.Slice(data, PqHybrid.MlKemPublicSize, PqHybrid.X25519Size));
        }
    }

    /// <summary>A recipient's private key. Generate once, keep secret, publish the public key.</summary>
    public sealed class HybridPrivateKey
    {
        private readonly byte[] _seed;
        private readonly byte[] _scalar;
        private readonly MLKemPrivateKeyParameters _mlkem;
        private readonly X25519PrivateKeyParameters _x25519;

        private HybridPrivateKey(byte[] seed, byte[] scalar)
        {
            _seed = seed;
            _scalar = scalar;
            _mlkem = MLKemPrivateKeyParameters.FromSeed(MLKemParameters.ml_kem_768, seed);
            _x25519 = new X25519PrivateKeyParameters(scalar, 0);
        }

        /// <summary>Create a fresh keypair using the system CSPRNG.</summary>
        public static HybridPrivateKey Generate()
        {
            var rng = new Org.BouncyCastle.Security.SecureRandom();
            var seed = new byte[PqHybrid.MlKemSeedSize];
            var scalar = new byte[PqHybrid.X25519Size];
            rng.NextBytes(seed);
            rng.NextBytes(scalar);
            return new HybridPrivateKey(seed, scalar);
        }

        /// <summary>
        /// Serialize the PRIVATE key for secure storage (PrivateKeySize bytes):
        /// ML-KEM-768 64-byte seed || X25519 32-byte scalar. Keep it secret.
        /// </summary>
        public byte[] ToBytes() => PqHybrid.ConcatThree(_seed, _scalar, Array.Empty<byte>());

        /// <summary>Restore a keypair produced by ToBytes().</summary>
        public static HybridPrivateKey FromBytes(byte[] data)
        {
            if (data.Length != PqHybrid.PrivateKeySize)
                throw new ArgumentException($"Private key must be {PqHybrid.PrivateKeySize} bytes, got {data.Length}");
            return new HybridPrivateKey(
                PqHybrid.Slice(data, 0, PqHybrid.MlKemSeedSize),
                PqHybrid.Slice(data, PqHybrid.MlKemSeedSize, PqHybrid.X25519Size));
        }

        /// <summary>The publishable public half of this keypair.</summary>
        public HybridPublicKey PublicKey() =>
            new HybridPublicKey(_mlkem.GetPublicKeyEncoded(), _x25519.GeneratePublicKey().GetEncoded());

        /// <summary>Recipient side: turn a sender's handshake into the shared 32-byte key.</summary>
        public byte[] Accept(byte[] handshake)
        {
            if (handshake.Length != PqHybrid.HandshakeSize)
                throw new ArgumentException($"Handshake must be {PqHybrid.HandshakeSize} bytes, got {handshake.Length}");
            var ephX25519Public = PqHybrid.Slice(handshake, 0, PqHybrid.X25519Size);
            var kemCiphertext = PqHybrid.Slice(handshake, PqHybrid.X25519Size, PqHybrid.MlKemCiphertextSize);

            var dec = new MLKemDecapsulator(MLKemParameters.ml_kem_768);
            dec.Init(_mlkem);
            var pqSecret = new byte[dec.SecretLength];
            dec.Decapsulate(kemCiphertext, 0, kemCiphertext.Length, pqSecret, 0, pqSecret.Length);

            var classicalSecret = new byte[PqHybrid.X25519Size];
            var agreement = new X25519Agreement();
            agreement.Init(_x25519);
            agreement.CalculateAgreement(new X25519PublicKeyParameters(ephX25519Public, 0), classicalSecret, 0);

            var transcript = PqHybrid.ConcatThree(PublicKey().ToBytes(), ephX25519Public, kemCiphertext);
            return PqHybrid.DeriveSharedKey(classicalSecret, pqSecret, transcript);
        }
    }
}
