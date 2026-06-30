//! Post-Quantum Hybrid Key Exchange (X25519 + ML-KEM-768).
//!
//! Lets two parties who have never shared a secret agree on a 32-byte key over an
//! open network, and stay safe even against an attacker who records the traffic
//! today and owns a quantum computer years from now ("harvest now, decrypt later").
//!
//! It is a *hybrid* exchange: it runs two independent key exchanges and mixes both
//! results, so an attacker must break **both** to win:
//!
//! * X25519     — classical elliptic-curve Diffie-Hellman (battle-tested today).
//! * ML-KEM-768 — NIST FIPS 203 lattice KEM (quantum-resistant), aka `CRYSTALS-Kyber`.
//!
//! Both primitives come from audited `RustCrypto` crates (`x25519-dalek`, `ml-kem`),
//! not from hand-rolled math. The 32-byte output feeds straight into
//! [`crate::Shield::with_key`] / [`crate::quick_encrypt`].
//!
//! This is byte-compatible with the Python (`shield.pqhybrid`), Go and other Shield
//! bindings: identical FIPS 203 / RFC 7748 encodings and the same KDF binding (see
//! [`derive_shared_key`]). The shared conformance vectors in
//! `tests/pq_kex_vectors.json` keep every implementation byte-identical.
//!
//! # Security properties (and limits)
//!
//! * Confidential against a passive eavesdropper who does NOT hold the recipient's
//!   private key, including a future quantum computer ("harvest now, decrypt later").
//! * Authenticated TO the recipient: the shared key is bound through the KDF
//!   transcript to the recipient's exact public key and to this specific handshake,
//!   so a captured handshake cannot be re-pointed at a different recipient (no
//!   unknown-key-share).
//! * Anonymous sender: the sender is NOT authenticated. To know who sent a message,
//!   sign it or run it over an authenticated channel.
//! * NO forward secrecy against compromise of the recipient's LONG-TERM key (its
//!   ML-KEM/X25519 keys are static). For full forward secrecy use an interactive
//!   ratchet ([`crate::RatchetSession`]), not this one-shot exchange. Rotate the
//!   recipient keypair periodically to bound exposure.

use crate::error::{Result, ShieldError};
use crate::random::random_bytes;

use hkdf::Hkdf;
use ml_kem::array::Array;
use ml_kem::kem::Decapsulate;
use ml_kem::{Ciphertext, EncapsulateDeterministic, Encoded, EncodedSizeUser, KemCore, MlKem768};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

type Dk = <MlKem768 as KemCore>::DecapsulationKey;
type Ek = <MlKem768 as KemCore>::EncapsulationKey;

/// Bytes of an ML-KEM-768 public (encapsulation) key.
const MLKEM_PUBLIC_SIZE: usize = 1184;
/// Bytes of an ML-KEM-768 encapsulation ciphertext.
const MLKEM_CIPHERTEXT_SIZE: usize = 1088;
/// Bytes of the portable FIPS 203 ML-KEM seed (`d || z`).
const MLKEM_SEED_SIZE: usize = 64;
/// Bytes of an X25519 public key / scalar.
const X25519_SIZE: usize = 32;

/// Serialized public bundle: `ML-KEM public || X25519 public` (1216 bytes).
pub const PUBLIC_BUNDLE_SIZE: usize = MLKEM_PUBLIC_SIZE + X25519_SIZE;
/// Serialized handshake: `ephemeral X25519 public || ML-KEM ciphertext` (1120 bytes).
pub const HANDSHAKE_SIZE: usize = X25519_SIZE + MLKEM_CIPHERTEXT_SIZE;
/// Serialized private key: `ML-KEM seed || X25519 scalar` (96 bytes).
pub const PRIVATE_KEY_SIZE: usize = MLKEM_SEED_SIZE + X25519_SIZE;
/// Size of the derived shared key.
pub const SHARED_KEY_SIZE: usize = 32;

/// Versioned domain-separation label for the hybrid KDF.
const KDF_SALT: &[u8] = b"shield/pq-hybrid/v1";

/// Mix the two exchange results into one 32-byte key.
///
/// Concatenating the secrets and running them through HKDF binds the result to
/// BOTH exchanges (hybrid security) and to the full transcript (the public keys
/// and ciphertext), preventing an attacker from substituting their own keys.
fn derive_shared_key(
    classical_secret: &[u8],
    pq_secret: &[u8],
    transcript: &[u8],
) -> [u8; SHARED_KEY_SIZE] {
    let mut ikm = Vec::with_capacity(classical_secret.len() + pq_secret.len());
    ikm.extend_from_slice(classical_secret);
    ikm.extend_from_slice(pq_secret);
    let hk = Hkdf::<Sha256>::new(Some(KDF_SALT), &ikm);
    let mut okm = [0u8; SHARED_KEY_SIZE];
    // `expand` only fails for absurd output lengths; 32 bytes never does.
    hk.expand(transcript, &mut okm)
        .expect("HKDF expand of 32 bytes is always valid");
    okm
}

/// A recipient's public "address": an ML-KEM public key plus an X25519 public key.
///
/// Safe to publish anywhere. A sender uses it with [`initiate`] to derive a shared key.
#[derive(Clone)]
pub struct HybridPublicKey {
    mlkem_public: Vec<u8>,
    x25519_public: [u8; X25519_SIZE],
}

impl HybridPublicKey {
    /// Serialize for publishing/transport (`PUBLIC_BUNDLE_SIZE` bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PUBLIC_BUNDLE_SIZE);
        out.extend_from_slice(&self.mlkem_public);
        out.extend_from_slice(&self.x25519_public);
        out
    }

    /// Parse a public bundle previously produced by [`HybridPublicKey::to_bytes`].
    ///
    /// # Errors
    /// Returns [`ShieldError::InvalidKeyLength`] if `data` is not `PUBLIC_BUNDLE_SIZE` bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() != PUBLIC_BUNDLE_SIZE {
            return Err(ShieldError::InvalidKeyLength {
                expected: PUBLIC_BUNDLE_SIZE,
                actual: data.len(),
            });
        }
        let mut x25519_public = [0u8; X25519_SIZE];
        x25519_public.copy_from_slice(&data[MLKEM_PUBLIC_SIZE..]);
        Ok(Self {
            mlkem_public: data[..MLKEM_PUBLIC_SIZE].to_vec(),
            x25519_public,
        })
    }
}

/// A recipient's private key. Generate once, keep secret, publish the public key.
pub struct HybridPrivateKey {
    mlkem_seed: [u8; MLKEM_SEED_SIZE],
    mlkem_dk: Dk,
    mlkem_ek: Ek,
    x25519: StaticSecret,
}

impl HybridPrivateKey {
    /// Create a fresh keypair using the system CSPRNG.
    ///
    /// # Errors
    /// Returns [`ShieldError::RandomFailed`] if the system RNG fails.
    pub fn generate() -> Result<Self> {
        let seed = random_bytes::<MLKEM_SEED_SIZE>()?;
        let scalar = random_bytes::<X25519_SIZE>()?;
        Ok(Self::from_components(seed, scalar))
    }

    /// Rebuild the keypair from its raw seed (`d || z`) and X25519 scalar.
    fn from_components(seed: [u8; MLKEM_SEED_SIZE], scalar: [u8; X25519_SIZE]) -> Self {
        let mut d = Array::default();
        let mut z = Array::default();
        d.copy_from_slice(&seed[..32]);
        z.copy_from_slice(&seed[32..]);
        let (mlkem_dk, mlkem_ek) = MlKem768::generate_deterministic(&d, &z);
        Self {
            mlkem_seed: seed,
            mlkem_dk,
            mlkem_ek,
            x25519: StaticSecret::from(scalar),
        }
    }

    /// Serialize the PRIVATE key for secure storage (`PRIVATE_KEY_SIZE` bytes):
    /// `ML-KEM-768 64-byte seed || X25519 32-byte scalar`. Keep it secret.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PRIVATE_KEY_SIZE);
        out.extend_from_slice(&self.mlkem_seed);
        out.extend_from_slice(&self.x25519.to_bytes());
        out
    }

    /// Restore a keypair previously produced by [`HybridPrivateKey::to_bytes`].
    ///
    /// # Errors
    /// Returns [`ShieldError::InvalidKeyLength`] if `data` is not `PRIVATE_KEY_SIZE` bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() != PRIVATE_KEY_SIZE {
            return Err(ShieldError::InvalidKeyLength {
                expected: PRIVATE_KEY_SIZE,
                actual: data.len(),
            });
        }
        let mut seed = [0u8; MLKEM_SEED_SIZE];
        let mut scalar = [0u8; X25519_SIZE];
        seed.copy_from_slice(&data[..MLKEM_SEED_SIZE]);
        scalar.copy_from_slice(&data[MLKEM_SEED_SIZE..]);
        Ok(Self::from_components(seed, scalar))
    }

    /// The publishable public half of this keypair.
    pub fn public_key(&self) -> HybridPublicKey {
        HybridPublicKey {
            mlkem_public: self.mlkem_ek.as_bytes().to_vec(),
            x25519_public: PublicKey::from(&self.x25519).to_bytes(),
        }
    }

    /// Recipient side: turn a sender's handshake into the shared 32-byte key.
    ///
    /// # Errors
    /// Returns [`ShieldError::InvalidKeyLength`] if `handshake` is the wrong size, or
    /// [`ShieldError::PostQuantum`] if ML-KEM decapsulation fails.
    pub fn accept(&self, handshake: &[u8]) -> Result<[u8; SHARED_KEY_SIZE]> {
        if handshake.len() != HANDSHAKE_SIZE {
            return Err(ShieldError::InvalidKeyLength {
                expected: HANDSHAKE_SIZE,
                actual: handshake.len(),
            });
        }
        let eph_x25519_public: [u8; X25519_SIZE] = handshake[..X25519_SIZE]
            .try_into()
            .expect("slice is exactly X25519_SIZE bytes");
        let kem_ciphertext = &handshake[X25519_SIZE..];

        // ML-KEM: open the padlock to recover the post-quantum secret.
        let ct = Ciphertext::<MlKem768>::try_from(kem_ciphertext)
            .map_err(|_| ShieldError::PostQuantum("invalid ML-KEM ciphertext".into()))?;
        let pq_secret = self
            .mlkem_dk
            .decapsulate(&ct)
            .map_err(|()| ShieldError::PostQuantum("ML-KEM decapsulation failed".into()))?;

        // X25519: classical Diffie-Hellman with the sender's ephemeral public key.
        let classical_secret = self
            .x25519
            .diffie_hellman(&PublicKey::from(eph_x25519_public));
        // Reject low-order peer keys (all-zero / non-contributory shared secret),
        // matching the Go/JS bindings. Prevents a forced known shared secret.
        if !classical_secret.was_contributory() {
            return Err(ShieldError::InvalidFormat);
        }

        let public = self.public_key();
        let mut transcript = public.to_bytes();
        transcript.extend_from_slice(&eph_x25519_public);
        transcript.extend_from_slice(kem_ciphertext);
        Ok(derive_shared_key(
            classical_secret.as_bytes(),
            &pq_secret,
            &transcript,
        ))
    }
}

/// Sender side: derive a shared key for `peer` and the handshake to send.
///
/// Returns `(handshake, shared_key)`: transmit `handshake` to the recipient (who
/// passes it to [`HybridPrivateKey::accept`]); use `shared_key` with
/// [`crate::Shield::with_key`].
///
/// # Errors
/// Returns [`ShieldError::PostQuantum`] if the peer's ML-KEM key is malformed or
/// encapsulation fails, or [`ShieldError::RandomFailed`] if the system RNG fails.
pub fn initiate(peer: &HybridPublicKey) -> Result<(Vec<u8>, [u8; SHARED_KEY_SIZE])> {
    // ML-KEM: lock a fresh secret inside the recipient's public padlock.
    let enc = Encoded::<Ek>::try_from(peer.mlkem_public.as_slice())
        .map_err(|_| ShieldError::PostQuantum("invalid ML-KEM public key".into()))?;
    let ek = Ek::from_bytes(&enc);
    let m = Array(random_bytes::<32>()?);
    let (kem_ciphertext, pq_secret) = ek
        .encapsulate_deterministic(&m)
        .map_err(|()| ShieldError::PostQuantum("ML-KEM encapsulation failed".into()))?;

    // X25519: a one-time ("ephemeral") classical exchange against the peer's key.
    let eph_secret = StaticSecret::from(random_bytes::<X25519_SIZE>()?);
    let eph_public = PublicKey::from(&eph_secret).to_bytes();
    let classical_secret = eph_secret.diffie_hellman(&PublicKey::from(peer.x25519_public));
    // Reject low-order peer keys (all-zero / non-contributory shared secret).
    if !classical_secret.was_contributory() {
        return Err(ShieldError::InvalidFormat);
    }

    let mut transcript = peer.to_bytes();
    transcript.extend_from_slice(&eph_public);
    transcript.extend_from_slice(&kem_ciphertext);
    let shared_key = derive_shared_key(classical_secret.as_bytes(), &pq_secret, &transcript);

    let mut handshake = Vec::with_capacity(HANDSHAKE_SIZE);
    handshake.extend_from_slice(&eph_public);
    handshake.extend_from_slice(&kem_ciphertext);
    Ok((handshake, shared_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_initiate_accept() {
        let bob = HybridPrivateKey::generate().unwrap();
        let (handshake, alice_key) = initiate(&bob.public_key()).unwrap();
        let bob_key = bob.accept(&handshake).unwrap();
        assert_eq!(alice_key, bob_key);
    }

    #[test]
    fn private_key_serialization_roundtrips() {
        let bob = HybridPrivateKey::generate().unwrap();
        let restored = HybridPrivateKey::from_bytes(&bob.to_bytes()).unwrap();
        assert_eq!(
            bob.public_key().to_bytes(),
            restored.public_key().to_bytes()
        );
        // A handshake accepted by the restored key must yield the same shared key.
        let (handshake, alice_key) = initiate(&bob.public_key()).unwrap();
        assert_eq!(restored.accept(&handshake).unwrap(), alice_key);
    }

    #[test]
    fn initiate_rejects_low_order_x25519_peer_key() {
        // An all-zero X25519 public key is a low-order point: the DH yields a
        // non-contributory (all-zero) shared secret. initiate() must reject it.
        let bob = HybridPrivateKey::generate().unwrap();
        let mut peer = bob.public_key();
        peer.x25519_public = [0u8; X25519_SIZE];
        assert!(initiate(&peer).is_err());
    }

    #[test]
    fn accept_rejects_low_order_x25519_ephemeral() {
        // Build a valid handshake, then zero its ephemeral X25519 public key.
        // ML-KEM decapsulation still succeeds, but the X25519 DH is now
        // non-contributory, so accept() must reject it.
        let bob = HybridPrivateKey::generate().unwrap();
        let (mut handshake, _key) = initiate(&bob.public_key()).unwrap();
        for b in handshake.iter_mut().take(X25519_SIZE) {
            *b = 0;
        }
        assert!(bob.accept(&handshake).is_err());
    }

    #[test]
    fn rejects_wrong_sizes() {
        let bob = HybridPrivateKey::generate().unwrap();
        assert!(bob.accept(&[0u8; 10]).is_err());
        assert!(HybridPublicKey::from_bytes(&[0u8; 10]).is_err());
        assert!(HybridPrivateKey::from_bytes(&[0u8; 10]).is_err());
    }

    #[test]
    fn matches_cross_language_vectors() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/pq_kex_vectors.json");
        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let vectors = doc["vectors"].as_array().unwrap();
        assert!(!vectors.is_empty());
        for v in vectors {
            let bob = HybridPrivateKey::from_bytes(
                &hex::decode(v["bob_private_hex"].as_str().unwrap()).unwrap(),
            )
            .unwrap();
            assert_eq!(
                hex::encode(bob.public_key().to_bytes()),
                v["bob_public_bundle_hex"].as_str().unwrap(),
                "public bundle mismatch for vector {}",
                v["name"]
            );
            let shared = bob
                .accept(&hex::decode(v["handshake_hex"].as_str().unwrap()).unwrap())
                .unwrap();
            assert_eq!(
                hex::encode(shared),
                v["expected_shared_key_hex"].as_str().unwrap(),
                "shared key mismatch for vector {}",
                v["name"]
            );
        }
    }
}
