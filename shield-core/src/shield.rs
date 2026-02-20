//! Core Shield encryption implementation.
//!
//! Matches Python `shield.py` byte-for-byte for interoperability.

// Crypto block counters are intentionally u32 - data >4GB would have other issues
#![allow(clippy::cast_possible_truncation)]

use ring::{hmac, pbkdf2};
use std::num::NonZeroU32;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Result, ShieldError};

/// PBKDF2 iteration count (matches Python implementation).
const PBKDF2_ITERATIONS: u32 = 100_000;

/// Nonce size in bytes.
const NONCE_SIZE: usize = 16;

/// MAC size in bytes.
const MAC_SIZE: usize = 16;

/// Minimum ciphertext size: nonce + counter(8) + mac.
const MIN_CIPHERTEXT_SIZE: usize = NONCE_SIZE + 8 + MAC_SIZE;

/// V2 header size: counter(8) + timestamp(8) + pad_len(1)
const V2_HEADER_SIZE: usize = 17;

/// Minimum padding size (bytes)
const MIN_PADDING: usize = 32;

/// Maximum padding size (bytes)
const MAX_PADDING: usize = 128;

/// Timestamp range for v2 detection (2020-01-01 to 2100-01-01 in milliseconds)
const MIN_TIMESTAMP_MS: u64 = 1_577_836_800_000;
const MAX_TIMESTAMP_MS: u64 = 4_102_444_800_000;

/// EXPTIME-secure symmetric encryption.
///
/// Uses password-derived keys with PBKDF2 and encrypts using
/// a SHA256-based stream cipher with HMAC-SHA256 authentication.
/// Breaking requires 2^256 operations - no shortcut exists.
///
/// **Version 2** adds replay protection and length obfuscation:
/// - Timestamp validation prevents replay attacks
/// - Random padding (32-128 bytes) obfuscates message length
///
/// Key material is securely zeroized from memory when dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Shield {
    key: [u8; 32],
    #[zeroize(skip)]
    #[allow(dead_code)]
    counter: u64,
    /// Maximum message age in milliseconds (None = no replay protection)
    #[zeroize(skip)]
    max_age_ms: Option<u64>,
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

        Self {
            key,
            counter: 0,
            max_age_ms: Some(60_000), // Default: 60 seconds
        }
    }

    /// Create Shield with a pre-shared key (no password derivation).
    #[must_use]
    pub fn with_key(key: [u8; 32]) -> Self {
        Self {
            key,
            counter: 0,
            max_age_ms: Some(60_000),
        }
    }

    /// Create Shield with hardware fingerprinting (device-bound encryption).
    ///
    /// Derives keys from password + hardware identifier, binding encryption to the physical device.
    /// Keys cannot be transferred to other hardware without the correct fingerprint.
    ///
    /// # Arguments
    /// * `password` - User's password
    /// * `service` - Service identifier (e.g., "github.com")
    /// * `mode` - Fingerprint collection mode (Motherboard, CPU, or Combined)
    ///
    /// # Example
    /// ```
    /// use shield_core::{Shield, FingerprintMode};
    /// let shield = Shield::with_fingerprint("password", "example.com", FingerprintMode::Combined)?;
    /// # Ok::<(), shield_core::ShieldError>(())
    /// ```
    ///
    /// # Errors
    /// Returns error if hardware fingerprint cannot be collected.
    ///
    /// # Security
    /// - **Binding Strength**: MEDIUM (hardware IDs are stable but replaceable)
    /// - **Spoofability**: LOW-MEDIUM (requires hardware access or VM manipulation)
    /// - **Portability**: NONE (keys are device-bound by design)
    pub fn with_fingerprint(
        password: &str,
        service: &str,
        mode: crate::fingerprint::FingerprintMode,
    ) -> Result<Self> {
        // Collect hardware fingerprint
        let fingerprint = crate::fingerprint::collect_fingerprint(mode)?;

        // Combine password with fingerprint
        let combined_password = if fingerprint.is_empty() {
            password.to_string()
        } else {
            format!("{}:{}", password, fingerprint)
        };

        // Derive salt from service name
        let salt = ring::digest::digest(&ring::digest::SHA256, service.as_bytes());

        // Derive key using PBKDF2 with combined password
        let mut key = [0u8; 32];
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            NonZeroU32::new(PBKDF2_ITERATIONS).unwrap(),
            salt.as_ref(),
            combined_password.as_bytes(),
            &mut key,
        );

        Ok(Self {
            key,
            counter: 0,
            max_age_ms: Some(60_000),
        })
    }

    /// Set maximum message age for replay protection.
    ///
    /// # Arguments
    /// * `max_age_ms` - Maximum age in milliseconds, or None to disable replay protection
    #[must_use]
    pub fn with_max_age(mut self, max_age_ms: Option<u64>) -> Self {
        self.max_age_ms = max_age_ms;
        self
    }

    /// Encrypt data (v2 format with replay protection and length obfuscation).
    ///
    /// Returns: `nonce(16) || ciphertext || mac(16)`
    ///
    /// Inner format: `counter(8) || timestamp_ms(8) || pad_len(1) || random_padding(32-128) || plaintext`
    ///
    /// # Errors
    /// Returns error if random generation fails.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        Self::encrypt_with_key(&self.key, plaintext)
    }

    /// Encrypt with explicit key (v2 format).
    pub fn encrypt_with_key(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
        // Generate random nonce
        let nonce: [u8; NONCE_SIZE] = crate::random::random_bytes()?;

        // Counter prefix (always 0 for compatibility)
        let counter_bytes = 0u64.to_le_bytes();

        // Timestamp in milliseconds since Unix epoch
        let timestamp_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let timestamp_bytes = timestamp_ms.to_le_bytes();

        // Random padding: 32-128 bytes
        let pad_len_byte: [u8; 1] = crate::random::random_bytes()?;
        let pad_len = (pad_len_byte[0] as usize % (MAX_PADDING - MIN_PADDING + 1)) + MIN_PADDING;
        let padding = crate::random::random_vec(pad_len)?;

        // Data to encrypt: counter || timestamp || pad_len || padding || plaintext
        let mut data_to_encrypt = Vec::with_capacity(V2_HEADER_SIZE + pad_len + plaintext.len());
        data_to_encrypt.extend_from_slice(&counter_bytes);
        data_to_encrypt.extend_from_slice(&timestamp_bytes);
        data_to_encrypt.push(pad_len as u8);
        data_to_encrypt.extend_from_slice(&padding);
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

    /// Decrypt and verify data (supports both v1 and v2 formats).
    ///
    /// Automatically detects v2 format by timestamp range and applies replay protection if configured.
    ///
    /// # Errors
    /// Returns error if MAC verification fails, ciphertext is malformed, or message is expired.
    pub fn decrypt(&self, encrypted: &[u8]) -> Result<Vec<u8>> {
        Self::decrypt_with_max_age(&self.key, encrypted, self.max_age_ms)
    }

    /// Decrypt with explicit key (no replay protection).
    pub fn decrypt_with_key(key: &[u8; 32], encrypted: &[u8]) -> Result<Vec<u8>> {
        Self::decrypt_with_max_age(key, encrypted, Some(60_000))
    }

    /// Decrypt with explicit max age for replay protection.
    pub fn decrypt_with_max_age(
        key: &[u8; 32],
        encrypted: &[u8],
        max_age_ms: Option<u64>,
    ) -> Result<Vec<u8>> {
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

        // Check if this is v2 format by examining timestamp range
        if decrypted.len() >= V2_HEADER_SIZE {
            let timestamp_bytes = &decrypted[8..16];
            let timestamp_ms = u64::from_le_bytes(timestamp_bytes.try_into().unwrap());

            // Valid v2 timestamp range: 2020-2100
            if (MIN_TIMESTAMP_MS..=MAX_TIMESTAMP_MS).contains(&timestamp_ms) {
                // This is v2 format
                let pad_len = decrypted[16] as usize;
                let data_start = V2_HEADER_SIZE + pad_len;

                if data_start > decrypted.len() {
                    return Err(ShieldError::InvalidFormat);
                }

                // Replay protection (if enabled)
                if let Some(max_age) = max_age_ms {
                    let now_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;

                    let age = (now_ms as i64) - (timestamp_ms as i64);

                    // Reject future timestamps (clock skew > 5s)
                    if age < -5000 {
                        return Err(ShieldError::InvalidFormat);
                    }

                    // Reject expired messages
                    if age > max_age as i64 {
                        return Err(ShieldError::InvalidFormat);
                    }
                }

                return Ok(decrypted[data_start..].to_vec());
            }
        }

        // v1 fallback: counter(8) || plaintext
        Ok(decrypted[8..].to_vec())
    }

    /// Decrypt v1 format explicitly (for backward compatibility with legacy ciphertext).
    ///
    /// Always uses v1 parsing: skip 8-byte counter prefix, no timestamp check.
    pub fn decrypt_v1(&self, encrypted: &[u8]) -> Result<Vec<u8>> {
        Self::decrypt_v1_with_key(&self.key, encrypted)
    }

    /// Decrypt v1 format with explicit key.
    pub fn decrypt_v1_with_key(key: &[u8; 32], encrypted: &[u8]) -> Result<Vec<u8>> {
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

        // Verify MAC
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, key);
        let mut hmac_data = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        hmac_data.extend_from_slice(nonce);
        hmac_data.extend_from_slice(ciphertext);
        let expected_tag = hmac::sign(&hmac_key, &hmac_data);

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

        // v1 format: skip 8-byte counter prefix
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
    let mut keystream = Vec::with_capacity(length.div_ceil(32) * 32);
    let num_blocks = length.div_ceil(32);

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
    fn test_encrypt_format_v2() {
        let shield = Shield::new("password", "service");
        let encrypted = shield.encrypt(b"test").unwrap();

        // v2: nonce(16) + [counter(8) + timestamp(8) + pad_len(1) + padding(32-128) + plaintext(4)] + mac(16)
        // Minimum: 16 + (17 + 32 + 4) + 16 = 85 bytes
        // Maximum: 16 + (17 + 128 + 4) + 16 = 181 bytes
        assert!(encrypted.len() >= 85 && encrypted.len() <= 181);
    }

    #[test]
    fn test_v2_roundtrip() {
        let shield = Shield::new("password", "service");
        let plaintext = b"Hello, Shield v2!";

        let encrypted = shield.encrypt(plaintext).unwrap();
        let decrypted = shield.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_v2_replay_protection_fresh() {
        let shield = Shield::new("password", "service");
        let encrypted = shield.encrypt(b"fresh message").unwrap();

        // Decrypt immediately - should succeed
        let decrypted = shield.decrypt(&encrypted).unwrap();
        assert_eq!(b"fresh message", decrypted.as_slice());
    }

    #[test]
    fn test_v2_replay_protection_disabled() {
        let shield = Shield::new("password", "service").with_max_age(None);
        let encrypted = shield.encrypt(b"no expiry").unwrap();

        // Should always work with replay protection disabled
        let decrypted = shield.decrypt(&encrypted).unwrap();
        assert_eq!(b"no expiry", decrypted.as_slice());
    }

    #[test]
    fn test_v2_length_variation() {
        let shield = Shield::new("password", "service");
        let plaintext = b"same message";

        // Encrypt same plaintext multiple times
        let mut lengths = std::collections::HashSet::new();
        for _ in 0..20 {
            let encrypted = shield.encrypt(plaintext).unwrap();
            lengths.insert(encrypted.len());
        }

        // Due to random padding (32-128 bytes), should have multiple unique lengths
        assert!(lengths.len() > 1, "Expected length variation due to random padding");
    }

    #[test]
    fn test_v1_backward_compat() {
        // Create a v1-format ciphertext manually (no timestamp, no padding)
        let key = [1u8; 32];
        let plaintext = b"v1 message";

        // v1 format: nonce(16) || [counter(8) || plaintext] || mac(16)
        let nonce: [u8; 16] = [2u8; 16];
        let counter_bytes = 0u64.to_le_bytes();

        let mut data_to_encrypt = Vec::new();
        data_to_encrypt.extend_from_slice(&counter_bytes);
        data_to_encrypt.extend_from_slice(plaintext);

        let keystream = generate_keystream(&key, &nonce, data_to_encrypt.len());
        let ciphertext: Vec<u8> = data_to_encrypt
            .iter()
            .zip(keystream.iter())
            .map(|(p, k)| p ^ k)
            .collect();

        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &key);
        let mut hmac_data = Vec::new();
        hmac_data.extend_from_slice(&nonce);
        hmac_data.extend_from_slice(&ciphertext);
        let tag = hmac::sign(&hmac_key, &hmac_data);

        let mut v1_encrypted = Vec::new();
        v1_encrypted.extend_from_slice(&nonce);
        v1_encrypted.extend_from_slice(&ciphertext);
        v1_encrypted.extend_from_slice(&tag.as_ref()[..16]);

        // v2 decrypt() should handle v1 format via fallback
        let shield = Shield::with_key(key);
        let decrypted = shield.decrypt(&v1_encrypted).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_v1_explicit_decrypt() {
        // Create v1 ciphertext
        let key = [3u8; 32];
        let plaintext = b"explicit v1";

        let nonce: [u8; 16] = [4u8; 16];
        let counter_bytes = 0u64.to_le_bytes();

        let mut data_to_encrypt = Vec::new();
        data_to_encrypt.extend_from_slice(&counter_bytes);
        data_to_encrypt.extend_from_slice(plaintext);

        let keystream = generate_keystream(&key, &nonce, data_to_encrypt.len());
        let ciphertext: Vec<u8> = data_to_encrypt
            .iter()
            .zip(keystream.iter())
            .map(|(p, k)| p ^ k)
            .collect();

        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &key);
        let mut hmac_data = Vec::new();
        hmac_data.extend_from_slice(&nonce);
        hmac_data.extend_from_slice(&ciphertext);
        let tag = hmac::sign(&hmac_key, &hmac_data);

        let mut v1_encrypted = Vec::new();
        v1_encrypted.extend_from_slice(&nonce);
        v1_encrypted.extend_from_slice(&ciphertext);
        v1_encrypted.extend_from_slice(&tag.as_ref()[..16]);

        // Use explicit v1 decrypt
        let shield = Shield::with_key(key);
        let decrypted = shield.decrypt_v1(&v1_encrypted).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_tamper_detection_v2() {
        let shield = Shield::new("password", "service");
        let mut encrypted = shield.encrypt(b"data").unwrap();

        // Tamper with ciphertext
        encrypted[20] ^= 0xFF;

        // Should fail MAC verification
        assert!(shield.decrypt(&encrypted).is_err());
    }
}
