// Post-Quantum Hybrid Key Exchange (X25519 + ML-KEM-768).
//
// Lets two parties who have never shared a secret agree on a 32-byte key over an
// open network, safe even against an attacker who records the traffic today and
// owns a quantum computer years from now ("harvest now, decrypt later").
//
// It is a HYBRID exchange combining two independent key exchanges and mixing both
// results, so an attacker must break BOTH to win:
//
//   - X25519     classical elliptic-curve Diffie-Hellman (battle-tested today)
//   - ML-KEM-768 NIST FIPS 203 lattice KEM (quantum-resistant), aka CRYSTALS-Kyber
//
// Both primitives come from the audited @noble/post-quantum and @noble/curves
// packages, not hand-rolled math. The 32-byte output feeds straight into
// Shield.withKey() / quickEncrypt().
//
// Byte-compatible with the Python (shield.pqhybrid), Go, Rust and other Shield
// bindings: identical FIPS 203 / RFC 7748 encodings and the same KDF binding (see
// deriveSharedKey). The shared conformance vectors in tests/pq_kex_vectors.json
// keep every implementation byte-identical.
//
// Security properties (and limits): confidential against a passive eavesdropper
// who does not hold the recipient's private key (including a future quantum
// computer); the shared key is bound to the recipient's exact public key and this
// handshake (no unknown-key-share); the SENDER is anonymous (not authenticated);
// and there is NO forward secrecy against compromise of the recipient's LONG-TERM
// key. For full forward secrecy use an interactive ratchet, not this one-shot
// exchange. Rotate the recipient keypair periodically to bound exposure.

import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { x25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { randomBytes } from 'node:crypto';

const MLKEM_PUBLIC_SIZE = 1184;
const MLKEM_CIPHERTEXT_SIZE = 1088;
const MLKEM_SEED_SIZE = 64; // portable FIPS 203 seed (d || z)
const X25519_SIZE = 32;

export const PUBLIC_BUNDLE_SIZE = MLKEM_PUBLIC_SIZE + X25519_SIZE; // 1216
export const HANDSHAKE_SIZE = X25519_SIZE + MLKEM_CIPHERTEXT_SIZE; // 1120
export const PRIVATE_KEY_SIZE = MLKEM_SEED_SIZE + X25519_SIZE; // 96
export const SHARED_KEY_SIZE = 32;

const KDF_SALT = new TextEncoder().encode('shield/pq-hybrid/v1');

function concatBytes(...arrays) {
  let total = 0;
  for (const a of arrays) total += a.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

// Mix the two exchange results into one 32-byte key. Concatenating the secrets and
// running them through HKDF binds the result to BOTH exchanges (hybrid security)
// and to the full transcript, preventing key-substitution attacks.
function deriveSharedKey(classicalSecret, pqSecret, transcript) {
  const ikm = concatBytes(classicalSecret, pqSecret);
  return hkdf(sha256, ikm, KDF_SALT, transcript, SHARED_KEY_SIZE);
}

/** A recipient's published "address": an ML-KEM public key + an X25519 public key. */
export class HybridPublicKey {
  constructor(mlkemPublic, x25519Public) {
    if (mlkemPublic.length !== MLKEM_PUBLIC_SIZE) {
      throw new Error(`ML-KEM public key must be ${MLKEM_PUBLIC_SIZE} bytes`);
    }
    if (x25519Public.length !== X25519_SIZE) {
      throw new Error(`X25519 public key must be ${X25519_SIZE} bytes`);
    }
    this.mlkemPublic = mlkemPublic;
    this.x25519Public = x25519Public;
  }

  /** Serialize for publishing/transport (PUBLIC_BUNDLE_SIZE bytes). */
  toBytes() {
    return concatBytes(this.mlkemPublic, this.x25519Public);
  }

  /** Parse a bundle produced by toBytes(). */
  static fromBytes(data) {
    if (data.length !== PUBLIC_BUNDLE_SIZE) {
      throw new Error(`Public bundle must be ${PUBLIC_BUNDLE_SIZE} bytes, got ${data.length}`);
    }
    return new HybridPublicKey(
      data.slice(0, MLKEM_PUBLIC_SIZE),
      data.slice(MLKEM_PUBLIC_SIZE),
    );
  }
}

/** A recipient's private key. Generate once, keep secret, publish the public key. */
export class HybridPrivateKey {
  constructor(seed, x25519Scalar) {
    this._seed = seed;
    this._scalar = x25519Scalar;
    this._mlkem = ml_kem768.keygen(seed); // { publicKey, secretKey }
  }

  /** Create a fresh keypair using the system CSPRNG. */
  static generate() {
    return new HybridPrivateKey(
      Uint8Array.from(randomBytes(MLKEM_SEED_SIZE)),
      Uint8Array.from(randomBytes(X25519_SIZE)),
    );
  }

  /**
   * Serialize the PRIVATE key for secure storage (PRIVATE_KEY_SIZE bytes):
   * ML-KEM-768 64-byte seed || X25519 32-byte scalar. Keep it secret.
   */
  toBytes() {
    return concatBytes(this._seed, this._scalar);
  }

  /** Restore a keypair produced by toBytes(). */
  static fromBytes(data) {
    if (data.length !== PRIVATE_KEY_SIZE) {
      throw new Error(`Private key must be ${PRIVATE_KEY_SIZE} bytes, got ${data.length}`);
    }
    return new HybridPrivateKey(
      data.slice(0, MLKEM_SEED_SIZE),
      data.slice(MLKEM_SEED_SIZE),
    );
  }

  /** The publishable public half of this keypair. */
  publicKey() {
    return new HybridPublicKey(this._mlkem.publicKey, x25519.getPublicKey(this._scalar));
  }

  /** Recipient side: turn a sender's handshake into the shared 32-byte key. */
  accept(handshake) {
    if (handshake.length !== HANDSHAKE_SIZE) {
      throw new Error(`Handshake must be ${HANDSHAKE_SIZE} bytes, got ${handshake.length}`);
    }
    const ephX25519Public = handshake.slice(0, X25519_SIZE);
    const kemCiphertext = handshake.slice(X25519_SIZE);

    const pqSecret = ml_kem768.decapsulate(kemCiphertext, this._mlkem.secretKey);
    const classicalSecret = x25519.getSharedSecret(this._scalar, ephX25519Public);

    const transcript = concatBytes(this.publicKey().toBytes(), ephX25519Public, kemCiphertext);
    return deriveSharedKey(classicalSecret, pqSecret, transcript);
  }
}

/**
 * Sender side: derive a shared key for peerPublic and the handshake to send.
 * Returns { handshake, sharedKey }: transmit handshake to the recipient (who
 * passes it to accept()); use sharedKey with Shield.withKey() / quickEncrypt().
 */
export function initiate(peerPublic) {
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(peerPublic.mlkemPublic);

  const ephScalar = Uint8Array.from(randomBytes(X25519_SIZE));
  const ephX25519Public = x25519.getPublicKey(ephScalar);
  const classicalSecret = x25519.getSharedSecret(ephScalar, peerPublic.x25519Public);

  const transcript = concatBytes(peerPublic.toBytes(), ephX25519Public, cipherText);
  const sharedKey = deriveSharedKey(classicalSecret, sharedSecret, transcript);
  const handshake = concatBytes(ephX25519Public, cipherText);
  return { handshake, sharedKey };
}
