//! Key rotation with version tagging.
//!
//! Manages multiple key versions for seamless rotation.

// Crypto block counters are intentionally u32 - data >4GB would have other issues
#![allow(clippy::cast_possible_truncation)]

use ring::hmac;
use std::collections::HashMap;
use subtle::ConstantTimeEq;

use crate::error::{Result, ShieldError};

/// Key rotation manager.
pub struct KeyRotationManager {
    keys: HashMap<u32, [u8; 32]>,
    current_version: u32,
}

impl KeyRotationManager {
    /// Create new manager with initial key.
    #[must_use]
    pub fn new(key: [u8; 32], version: u32) -> Self {
        let mut keys = HashMap::new();
        keys.insert(version, key);

        Self {
            keys,
            current_version: version,
        }
    }

    /// Get current key version.
    #[must_use]
    pub fn current_version(&self) -> u32 {
        self.current_version
    }

    /// Get all available versions.
    #[must_use]
    pub fn versions(&self) -> Vec<u32> {
        let mut v: Vec<u32> = self.keys.keys().copied().collect();
        v.sort_unstable();
        v
    }

    /// Add a historical key.
    pub fn add_key(&mut self, key: [u8; 32], version: u32) -> Result<()> {
        if self.keys.contains_key(&version) {
            return Err(ShieldError::VersionExists(version));
        }
        self.keys.insert(version, key);
        Ok(())
    }

    /// Rotate to new key.
    pub fn rotate(&mut self, new_key: [u8; 32], new_version: Option<u32>) -> Result<u32> {
        let version = new_version.unwrap_or(self.current_version + 1);
        if version <= self.current_version {
            return Err(ShieldError::InvalidVersion);
        }

        self.keys.insert(version, new_key);
        self.current_version = version;
        Ok(version)
    }

    /// Encrypt with current key.
    ///
    /// Format: version(4) || nonce(16) || ciphertext || mac(16)
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let key = self.keys.get(&self.current_version).unwrap();
        let nonce: [u8; 16] = crate::random::random_bytes()?;

        // Generate keystream
        let keystream = generate_keystream(key, &nonce, plaintext.len());
        let ciphertext: Vec<u8> = plaintext
            .iter()
            .zip(keystream.iter())
            .map(|(p, k)| p ^ k)
            .collect();

        // Version bytes
        let version_bytes = self.current_version.to_le_bytes();

        // HMAC over version || nonce || ciphertext
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, key);
        let mut hmac_data = Vec::with_capacity(4 + 16 + ciphertext.len());
        hmac_data.extend_from_slice(&version_bytes);
        hmac_data.extend_from_slice(&nonce);
        hmac_data.extend_from_slice(&ciphertext);
        let tag = hmac::sign(&hmac_key, &hmac_data);

        // Result: version || nonce || ciphertext || mac
        let mut result = Vec::with_capacity(4 + 16 + ciphertext.len() + 16);
        result.extend_from_slice(&version_bytes);
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);
        result.extend_from_slice(&tag.as_ref()[..16]);

        Ok(result)
    }

    /// Decrypt with appropriate key version.
    pub fn decrypt(&self, encrypted: &[u8]) -> Result<Vec<u8>> {
        if encrypted.len() < 36 {
            return Err(ShieldError::CiphertextTooShort {
                expected: 36,
                actual: encrypted.len(),
            });
        }

        // Parse components
        let version = u32::from_le_bytes(encrypted[..4].try_into().unwrap());
        let nonce = &encrypted[4..20];
        let ciphertext = &encrypted[20..encrypted.len() - 16];
        let mac = &encrypted[encrypted.len() - 16..];

        // Get key for version
        let key = self
            .keys
            .get(&version)
            .ok_or(ShieldError::UnknownVersion(version))?;

        // Verify MAC
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, key);
        let expected_tag = hmac::sign(&hmac_key, &encrypted[..encrypted.len() - 16]);

        if mac.ct_eq(&expected_tag.as_ref()[..16]).unwrap_u8() != 1 {
            return Err(ShieldError::AuthenticationFailed);
        }

        // Decrypt
        let keystream = generate_keystream(key, nonce, ciphertext.len());
        let plaintext: Vec<u8> = ciphertext
            .iter()
            .zip(keystream.iter())
            .map(|(c, k)| c ^ k)
            .collect();

        Ok(plaintext)
    }

    /// Prune old keys, keeping specified number of most recent.
    pub fn prune_old_keys(&mut self, keep_versions: usize) -> Vec<u32> {
        let mut versions = self.versions();
        versions.reverse(); // Most recent first

        let mut to_keep: std::collections::HashSet<u32> =
            versions.iter().take(keep_versions).copied().collect();
        to_keep.insert(self.current_version);

        let mut pruned = Vec::new();
        for v in self.keys.keys().copied().collect::<Vec<_>>() {
            if !to_keep.contains(&v) {
                self.keys.remove(&v);
                pruned.push(v);
            }
        }

        pruned
    }

    /// Re-encrypt data with current key.
    pub fn re_encrypt(&self, encrypted: &[u8]) -> Result<Vec<u8>> {
        let plaintext = self.decrypt(encrypted)?;
        self.encrypt(&plaintext)
    }
}

/// Generate keystream using SHA256.
fn generate_keystream(key: &[u8], nonce: &[u8], length: usize) -> Vec<u8> {
    let mut keystream = Vec::with_capacity(length.div_ceil(32) * 32);
    let num_blocks = length.div_ceil(32);

    for i in 0..num_blocks {
        let counter = (i as u32).to_le_bytes();
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
    fn test_encrypt_decrypt() {
        let key = [42u8; 32];
        let manager = KeyRotationManager::new(key, 1);
        let plaintext = b"Hello, Rotation!";

        let encrypted = manager.encrypt(plaintext).unwrap();
        let decrypted = manager.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_version_embedded() {
        let key = [42u8; 32];
        let manager = KeyRotationManager::new(key, 5);
        let encrypted = manager.encrypt(b"test").unwrap();

        let version = u32::from_le_bytes(encrypted[..4].try_into().unwrap());
        assert_eq!(version, 5);
    }

    #[test]
    fn test_rotate() {
        let key1 = [1u8; 32];
        let mut manager = KeyRotationManager::new(key1, 1);
        let encrypted1 = manager.encrypt(b"message 1").unwrap();

        let key2 = [2u8; 32];
        manager.rotate(key2, None).unwrap();
        assert_eq!(manager.current_version(), 2);

        let encrypted2 = manager.encrypt(b"message 2").unwrap();

        // Both decrypt
        assert_eq!(manager.decrypt(&encrypted1).unwrap(), b"message 1");
        assert_eq!(manager.decrypt(&encrypted2).unwrap(), b"message 2");
    }

    #[test]
    fn test_prune_old_keys() {
        let mut manager = KeyRotationManager::new([1u8; 32], 1);
        manager.rotate([2u8; 32], None).unwrap();
        manager.rotate([3u8; 32], None).unwrap();
        manager.rotate([4u8; 32], None).unwrap();

        let encrypted = manager.encrypt(b"test").unwrap();
        let pruned = manager.prune_old_keys(2);

        assert!(!pruned.is_empty());
        assert_eq!(manager.decrypt(&encrypted).unwrap(), b"test");
    }

    #[test]
    fn test_re_encrypt() {
        let mut manager = KeyRotationManager::new([1u8; 32], 1);
        let encrypted = manager.encrypt(b"original").unwrap();

        manager.rotate([2u8; 32], None).unwrap();
        let re_encrypted = manager.re_encrypt(&encrypted).unwrap();

        let version = u32::from_le_bytes(re_encrypted[..4].try_into().unwrap());
        assert_eq!(version, 2);
        assert_eq!(manager.decrypt(&re_encrypted).unwrap(), b"original");
    }

    #[test]
    fn test_unknown_version() {
        let manager = KeyRotationManager::new([1u8; 32], 1);
        let mut encrypted = manager.encrypt(b"test").unwrap();

        // Corrupt version
        encrypted[0] = 99;
        assert!(manager.decrypt(&encrypted).is_err());
    }
}
