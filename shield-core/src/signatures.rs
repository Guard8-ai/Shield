//! Digital signatures without public-key cryptography.
//!
//! Provides HMAC-based signatures and Lamport one-time signatures.

use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use std::num::NonZeroU32;
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Result, ShieldError};

/// HMAC-based symmetric signature.
///
/// Keys are securely zeroized from memory when dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SymmetricSignature {
    signing_key: [u8; 32],
    verification_key: [u8; 32],
}

impl SymmetricSignature {
    /// Create from signing key.
    #[must_use] 
    pub fn new(signing_key: [u8; 32]) -> Self {
        let verification_key = {
            let mut data = Vec::with_capacity(7 + 32);
            data.extend_from_slice(b"verify:");
            data.extend_from_slice(&signing_key);
            let hash = ring::digest::digest(&ring::digest::SHA256, &data);
            let mut key = [0u8; 32];
            key.copy_from_slice(hash.as_ref());
            key
        };

        Self {
            signing_key,
            verification_key,
        }
    }

    /// Generate new random signing identity.
    pub fn generate() -> Result<Self> {
        let rng = SystemRandom::new();
        let mut key = [0u8; 32];
        rng.fill(&mut key).map_err(|_| ShieldError::RandomFailed)?;
        Ok(Self::new(key))
    }

    /// Derive from password and identity.
    #[must_use] 
    pub fn from_password(password: &str, identity: &str) -> Self {
        let salt_data = format!("sign:{identity}");
        let salt = ring::digest::digest(&ring::digest::SHA256, salt_data.as_bytes());

        let mut key = [0u8; 32];
        ring::pbkdf2::derive(
            ring::pbkdf2::PBKDF2_HMAC_SHA256,
            NonZeroU32::new(100_000).unwrap(),
            salt.as_ref(),
            password.as_bytes(),
            &mut key,
        );

        Self::new(key)
    }

    /// Sign a message.
    #[must_use] 
    pub fn sign(&self, message: &[u8], include_timestamp: bool) -> Vec<u8> {
        if include_timestamp {
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let mut sig_data = Vec::with_capacity(8 + message.len());
            sig_data.extend_from_slice(&timestamp.to_le_bytes());
            sig_data.extend_from_slice(message);

            let key = hmac::Key::new(hmac::HMAC_SHA256, &self.signing_key);
            let tag = hmac::sign(&key, &sig_data);

            let mut result = Vec::with_capacity(8 + 32);
            result.extend_from_slice(&timestamp.to_le_bytes());
            result.extend_from_slice(tag.as_ref());
            result
        } else {
            let key = hmac::Key::new(hmac::HMAC_SHA256, &self.signing_key);
            let tag = hmac::sign(&key, message);
            tag.as_ref().to_vec()
        }
    }

    /// Verify a signature.
    #[must_use] 
    pub fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
        verification_key: &[u8; 32],
        max_age: u64,
    ) -> bool {
        if verification_key.ct_eq(&self.verification_key).unwrap_u8() != 1 {
            return false;
        }

        if signature.len() == 40 {
            // Timestamped signature
            let timestamp = u64::from_le_bytes(signature[..8].try_into().unwrap());
            let sig = &signature[8..];

            if max_age > 0 {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                if now.abs_diff(timestamp) > max_age {
                    return false;
                }
            }

            let mut sig_data = Vec::with_capacity(8 + message.len());
            sig_data.extend_from_slice(&timestamp.to_le_bytes());
            sig_data.extend_from_slice(message);

            let key = hmac::Key::new(hmac::HMAC_SHA256, &self.signing_key);
            let expected = hmac::sign(&key, &sig_data);
            sig.ct_eq(expected.as_ref()).unwrap_u8() == 1
        } else if signature.len() == 32 {
            let key = hmac::Key::new(hmac::HMAC_SHA256, &self.signing_key);
            let expected = hmac::sign(&key, message);
            signature.ct_eq(expected.as_ref()).unwrap_u8() == 1
        } else {
            false
        }
    }

    /// Get verification key.
    #[must_use] 
    pub fn verification_key(&self) -> &[u8; 32] {
        &self.verification_key
    }

    /// Get key fingerprint.
    #[must_use] 
    pub fn fingerprint(&self) -> String {
        let hash = ring::digest::digest(&ring::digest::SHA256, &self.verification_key);
        hex::encode(&hash.as_ref()[..8])
    }
}

/// Lamport one-time signature (post-quantum secure).
///
/// Private key material is securely zeroized from memory when dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct LamportSignature {
    private_key: Vec<([u8; 32], [u8; 32])>,
    #[zeroize(skip)]
    public_key: Vec<u8>,
    #[zeroize(skip)]
    used: bool,
}

impl LamportSignature {
    const BITS: usize = 256;

    /// Generate new Lamport key pair.
    pub fn generate() -> Result<Self> {
        let rng = SystemRandom::new();
        let mut private_key = Vec::with_capacity(Self::BITS);
        let mut public_key = Vec::with_capacity(Self::BITS * 64);

        for _ in 0..Self::BITS {
            let mut key0 = [0u8; 32];
            let mut key1 = [0u8; 32];
            rng.fill(&mut key0).map_err(|_| ShieldError::RandomFailed)?;
            rng.fill(&mut key1).map_err(|_| ShieldError::RandomFailed)?;

            let hash0 = ring::digest::digest(&ring::digest::SHA256, &key0);
            let hash1 = ring::digest::digest(&ring::digest::SHA256, &key1);

            public_key.extend_from_slice(hash0.as_ref());
            public_key.extend_from_slice(hash1.as_ref());
            private_key.push((key0, key1));
        }

        Ok(Self {
            private_key,
            public_key,
            used: false,
        })
    }

    /// Sign message (ONE TIME ONLY).
    pub fn sign(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        if self.used {
            return Err(ShieldError::LamportKeyUsed);
        }
        self.used = true;

        let msg_hash = ring::digest::digest(&ring::digest::SHA256, message);
        let hash_bytes = msg_hash.as_ref();
        let mut signature = Vec::with_capacity(Self::BITS * 32);

        for i in 0..Self::BITS {
            let byte_idx = i / 8;
            let bit_idx = i % 8;
            let bit = (hash_bytes[byte_idx] >> bit_idx) & 1;

            let (key0, key1) = &self.private_key[i];
            if bit == 1 {
                signature.extend_from_slice(key1);
            } else {
                signature.extend_from_slice(key0);
            }
        }

        Ok(signature)
    }

    /// Verify a Lamport signature.
    #[must_use] 
    pub fn verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
        if signature.len() != 256 * 32 || public_key.len() != 256 * 64 {
            return false;
        }

        let msg_hash = ring::digest::digest(&ring::digest::SHA256, message);
        let hash_bytes = msg_hash.as_ref();

        for i in 0..256 {
            let byte_idx = i / 8;
            let bit_idx = i % 8;
            let bit = (hash_bytes[byte_idx] >> bit_idx) & 1;

            let revealed = &signature[i * 32..(i + 1) * 32];
            let hashed = ring::digest::digest(&ring::digest::SHA256, revealed);

            let expected = if bit == 1 {
                &public_key[i * 64 + 32..i * 64 + 64]
            } else {
                &public_key[i * 64..i * 64 + 32]
            };

            if hashed.as_ref().ct_eq(expected).unwrap_u8() != 1 {
                return false;
            }
        }

        true
    }

    /// Check if key has been used.
    #[must_use] 
    pub fn is_used(&self) -> bool {
        self.used
    }

    /// Get public key.
    #[must_use] 
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Get key fingerprint.
    #[must_use] 
    pub fn fingerprint(&self) -> String {
        let hash = ring::digest::digest(&ring::digest::SHA256, &self.public_key);
        hex::encode(&hash.as_ref()[..8])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symmetric_sign_verify() {
        let signer = SymmetricSignature::generate().unwrap();
        let message = b"Hello, World!";
        let signature = signer.sign(message, true);
        assert!(signer.verify(message, &signature, signer.verification_key(), 300));
    }

    #[test]
    fn test_symmetric_wrong_key() {
        let signer1 = SymmetricSignature::generate().unwrap();
        let signer2 = SymmetricSignature::generate().unwrap();
        let message = b"test";
        let signature = signer1.sign(message, true);
        assert!(!signer2.verify(message, &signature, signer2.verification_key(), 300));
    }

    #[test]
    fn test_symmetric_from_password() {
        let signer1 = SymmetricSignature::from_password("password", "user@example.com");
        let signer2 = SymmetricSignature::from_password("password", "user@example.com");
        assert_eq!(signer1.verification_key(), signer2.verification_key());
    }

    #[test]
    fn test_lamport_sign_verify() {
        let mut lamport = LamportSignature::generate().unwrap();
        let message = b"Test message";
        let signature = lamport.sign(message).unwrap();
        assert!(LamportSignature::verify(message, &signature, lamport.public_key()));
    }

    #[test]
    fn test_lamport_one_time() {
        let mut lamport = LamportSignature::generate().unwrap();
        lamport.sign(b"first").unwrap();
        assert!(lamport.sign(b"second").is_err());
    }

    #[test]
    fn test_lamport_is_used() {
        let mut lamport = LamportSignature::generate().unwrap();
        assert!(!lamport.is_used());
        lamport.sign(b"message").unwrap();
        assert!(lamport.is_used());
    }
}
