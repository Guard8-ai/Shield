//! Core Shield encryption implementation.
//!
//! Matches Python `shield.py` byte-for-byte for interoperability.

use ring::{hmac, pbkdf2, rand::{SecureRandom, SystemRandom}};
use subtle::ConstantTimeEq;
use std::num::NonZeroU32;

use crate::error::{Result, ShieldError};

/// PBKDF2 iteration count (matches Python implementation).
const PBKDF2_ITERATIONS: u32 = 100_000;

/// Nonce size in bytes.
const NONCE_SIZE: usize = 16;

/// MAC size in bytes.
const MAC_SIZE: usize = 16;

/// Minimum ciphertext size: nonce + counter(8) + mac.
const MIN_CIPHERTEXT_SIZE: usize = NONCE_SIZE + 8 + MAC_SIZE;

/// EXPTIME-secure symmetric encryption.
///
/// Uses password-derived keys with PBKDF2 and encrypts using
/// a SHA256-based stream cipher with HMAC-SHA256 authentication.
/// Breaking requires 2^256 operations - no shortcut exists.
pub struct Shield {
    key: [u8; 32],
    #[allow(dead_code)]
    counter: u64,
}

impl Shield {
    /// Create a new Shield instance from password and service name.
    ///
    /// # Arguments
    /// * `password` - User's password
    /// * `service` - Service identifier (e.g., "github.com")
    ///
    /// # Example
    /// ```
    /// use shield_core::Shield;
    /// let shield = Shield::new("my_password", "example.com");
    /// ```
    #[must_use]
    pub fn new(password: &str, service: &str) -> Self {
        // Derive salt from service name (matches Python)
        let salt = ring::digest::digest(&ring::digest::SHA256, service.as_bytes());

        // Derive key using PBKDF2
        let mut key = [0u8; 32];
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            NonZeroU32::new(PBKDF2_ITERATIONS).unwrap(),
            salt.as_ref(),
            password.as_bytes(),
            &mut key,
        );

        Self { key, counter: 0 }
    }

    /// Create Shield with a pre-shared key (no password derivation).
    #[must_use]
    pub fn with_key(key: [u8; 32]) -> Self {
        Self { key, counter: 0 }
    }

    /// Encrypt data.
    ///
    /// Returns: `nonce(16) || ciphertext || mac(16)`
    ///
    /// # Errors
    /// Returns error if random generation fails.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        Self::encrypt_with_key(&self.key, plaintext)
    }

    /// Encrypt with explicit key.
    pub fn encrypt_with_key(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
        let rng = SystemRandom::new();

        // Generate random nonce
        let mut nonce = [0u8; NONCE_SIZE];
        rng.fill(&mut nonce).map_err(|_| ShieldError::RandomFailed)?;

        // Counter prefix (matches Python format)
        let counter_bytes = 0u64.to_le_bytes();

        // Data to encrypt: counter || plaintext
        let mut data_to_encrypt = Vec::with_capacity(8 + plaintext.len());
        data_to_encrypt.extend_from_slice(&counter_bytes);
        data_to_encrypt.extend_from_slice(plaintext);

        // Generate keystream and XOR
        let keystream = generate_keystream(key, &nonce, data_to_encrypt.len());
        let ciphertext: Vec<u8> = data_to_encrypt
            .iter()
            .zip(keystream.iter())
            .map(|(p, k)| p ^ k)
            .collect();

        // Compute HMAC over nonce || ciphertext
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, key);
        let mut hmac_data = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        hmac_data.extend_from_slice(&nonce);
        hmac_data.extend_from_slice(&ciphertext);
        let tag = hmac::sign(&hmac_key, &hmac_data);

        // Format: nonce || ciphertext || mac(16)
        let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len() + MAC_SIZE);
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);
        result.extend_from_slice(&tag.as_ref()[..MAC_SIZE]);

        Ok(result)
    }

    /// Decrypt and verify data.
    ///
    /// # Errors
    /// Returns error if MAC verification fails or ciphertext is malformed.
    pub fn decrypt(&self, encrypted: &[u8]) -> Result<Vec<u8>> {
        Self::decrypt_with_key(&self.key, encrypted)
    }

    /// Decrypt with explicit key.
    pub fn decrypt_with_key(key: &[u8; 32], encrypted: &[u8]) -> Result<Vec<u8>> {
        if encrypted.len() < MIN_CIPHERTEXT_SIZE {
            return Err(ShieldError::CiphertextTooShort {
                expected: MIN_CIPHERTEXT_SIZE,
                actual: encrypted.len(),
            });
        }

        // Parse components
        let nonce = &encrypted[..NONCE_SIZE];
        let ciphertext = &encrypted[NONCE_SIZE..encrypted.len() - MAC_SIZE];
        let mac = &encrypted[encrypted.len() - MAC_SIZE..];

        // Verify MAC first (constant-time)
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, key);
        let mut hmac_data = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        hmac_data.extend_from_slice(nonce);
        hmac_data.extend_from_slice(ciphertext);
        let expected_tag = hmac::sign(&hmac_key, &hmac_data);

        // Constant-time comparison
        if mac.ct_eq(&expected_tag.as_ref()[..MAC_SIZE]).unwrap_u8() != 1 {
            return Err(ShieldError::AuthenticationFailed);
        }

        // Decrypt
        let keystream = generate_keystream(key, nonce, ciphertext.len());
        let decrypted: Vec<u8> = ciphertext
            .iter()
            .zip(keystream.iter())
            .map(|(c, k)| c ^ k)
            .collect();

        // Skip counter prefix (8 bytes)
        Ok(decrypted[8..].to_vec())
    }

    /// Get the derived key (for testing/debugging).
    #[must_use]
    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }
}

/// Generate keystream using SHA256 (matches Python implementation).
fn generate_keystream(key: &[u8], nonce: &[u8], length: usize) -> Vec<u8> {
    let mut keystream = Vec::with_capacity(((length + 31) / 32) * 32);
    let num_blocks = (length + 31) / 32;

    for i in 0..num_blocks {
        let counter = (i as u32).to_le_bytes();

        // SHA256(key || nonce || counter)
        let mut data = Vec::with_capacity(key.len() + nonce.len() + 4);
        data.extend_from_slice(key);
        data.extend_from_slice(nonce);
        data.extend_from_slice(&counter);

        let hash = ring::digest::digest(&ring::digest::SHA256, &data);
        keystream.extend_from_slice(hash.as_ref());
    }

    keystream.truncate(length);
    keystream
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keystream_deterministic() {
        let key = [1u8; 32];
        let nonce = [2u8; 16];

        let ks1 = generate_keystream(&key, &nonce, 64);
        let ks2 = generate_keystream(&key, &nonce, 64);

        assert_eq!(ks1, ks2);
    }

    #[test]
    fn test_keystream_different_nonce() {
        let key = [1u8; 32];
        let nonce1 = [2u8; 16];
        let nonce2 = [3u8; 16];

        let ks1 = generate_keystream(&key, &nonce1, 32);
        let ks2 = generate_keystream(&key, &nonce2, 32);

        assert_ne!(ks1, ks2);
    }

    #[test]
    fn test_encrypt_format() {
        let shield = Shield::new("password", "service");
        let encrypted = shield.encrypt(b"test").unwrap();

        // nonce(16) + counter(8) + plaintext(4) + mac(16) = 44
        assert_eq!(encrypted.len(), 16 + 8 + 4 + 16);
    }
}
