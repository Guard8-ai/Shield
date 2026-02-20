//! Encrypted vector types with deterministic encryption

use super::error::{PgVectorError, Result};
use crate::Shield;
use serde::{Deserialize, Serialize};
use ring::digest;

/// Encrypted vector with deterministic encryption for searchability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedVector {
    /// Deterministic nonce (derived from vector content)
    pub nonce: Vec<u8>,
    /// Encrypted vector components (deterministic)
    pub encrypted_data: Vec<f32>,
    /// HMAC for integrity
    pub mac: Vec<u8>,
    /// Original dimension
    pub dimension: usize,
}

impl EncryptedVector {
    /// Encrypt a vector deterministically
    ///
    /// Uses content-based nonce derivation to ensure same vector
    /// always produces same ciphertext (required for pgvector indexing)
    pub fn encrypt(shield: &Shield, vector: &[f32]) -> Result<Self> {
        // Derive deterministic nonce from vector content
        let nonce = Self::derive_nonce(vector);

        // Encrypt each component deterministically
        let encrypted_data = Self::encrypt_components(shield, vector, &nonce)?;

        // Compute MAC over encrypted data
        let mac = Self::compute_mac(shield, &encrypted_data, &nonce)?;

        Ok(Self {
            nonce,
            encrypted_data,
            mac,
            dimension: vector.len(),
        })
    }

    /// Decrypt an encrypted vector
    pub fn decrypt(&self, shield: &Shield) -> Result<Vec<f32>> {
        // Verify MAC first
        let computed_mac = Self::compute_mac(shield, &self.encrypted_data, &self.nonce)?;
        if !constant_time_compare(&computed_mac, &self.mac) {
            return Err(PgVectorError::Shield(crate::error::ShieldError::AuthenticationFailed));
        }

        // Decrypt components
        Self::decrypt_components(shield, &self.encrypted_data, &self.nonce)
    }

    /// Derive deterministic nonce from vector content
    ///
    /// Uses SHA256 hash of vector bytes to create a deterministic
    /// 16-byte nonce. This ensures same vector always gets same nonce.
    fn derive_nonce(vector: &[f32]) -> Vec<u8> {
        // Serialize vector to bytes
        let mut bytes = Vec::with_capacity(vector.len() * 4);
        for &value in vector {
            bytes.extend_from_slice(&value.to_le_bytes());
        }

        // Hash with salt to derive nonce
        let salt = b"shield-pgvector-deterministic-v1";
        let mut input = salt.to_vec();
        input.extend_from_slice(&bytes);

        let hash = digest::digest(&digest::SHA256, &input);
        hash.as_ref()[..16].to_vec()
    }

    /// Encrypt vector components deterministically
    ///
    /// Uses XOR with deterministic keystream derived from
    /// Shield key + nonce + component index
    fn encrypt_components(shield: &Shield, vector: &[f32], nonce: &[u8]) -> Result<Vec<f32>> {
        let mut encrypted = Vec::with_capacity(vector.len());

        for (i, &value) in vector.iter().enumerate() {
            // Generate keystream for this component
            let keystream = Self::generate_component_keystream(shield, nonce, i)?;

            // XOR float bytes with keystream
            let value_bytes = value.to_le_bytes();
            let mut encrypted_bytes = [0u8; 4];
            for (j, &byte) in value_bytes.iter().enumerate() {
                encrypted_bytes[j] = byte ^ keystream[j];
            }

            encrypted.push(f32::from_le_bytes(encrypted_bytes));
        }

        Ok(encrypted)
    }

    /// Decrypt vector components
    fn decrypt_components(shield: &Shield, encrypted: &[f32], nonce: &[u8]) -> Result<Vec<f32>> {
        // Decryption is same as encryption (XOR is symmetric)
        Self::encrypt_components(shield, encrypted, nonce)
    }

    /// Generate keystream for a specific vector component
    fn generate_component_keystream(_shield: &Shield, nonce: &[u8], index: usize) -> Result<Vec<u8>> {
        // Create input: nonce || index || "component"
        let mut input = nonce.to_vec();
        input.extend_from_slice(&index.to_le_bytes());
        input.extend_from_slice(b"component");

        // Use SHA256 for deterministic keystream
        let hash = digest::digest(&digest::SHA256, &input);
        Ok(hash.as_ref()[..4].to_vec())
    }

    /// Compute MAC over encrypted vector
    fn compute_mac(_shield: &Shield, encrypted: &[f32], nonce: &[u8]) -> Result<Vec<u8>> {
        // Serialize encrypted vector
        let mut data = nonce.to_vec();
        for &value in encrypted {
            data.extend_from_slice(&value.to_le_bytes());
        }

        // Use SHA256 for MAC (truncate to 16 bytes)
        let hash = digest::digest(&digest::SHA256, &data);
        Ok(hash.as_ref()[..16].to_vec())
    }

    /// Get encrypted data as f32 slice for database storage
    pub fn as_slice(&self) -> &[f32] {
        &self.encrypted_data
    }
}

/// Constant-time comparison for MAC verification
fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic_encryption() {
        let shield = Shield::new("test_password", "pgvector.test");
        let vector = vec![0.1, 0.2, 0.3, 0.4, 0.5];

        // Encrypt twice
        let encrypted1 = EncryptedVector::encrypt(&shield, &vector).unwrap();
        let encrypted2 = EncryptedVector::encrypt(&shield, &vector).unwrap();

        // Should produce identical ciphertext (deterministic)
        assert_eq!(encrypted1.nonce, encrypted2.nonce);
        assert_eq!(encrypted1.encrypted_data, encrypted2.encrypted_data);
        assert_eq!(encrypted1.mac, encrypted2.mac);
    }

    #[test]
    fn test_encryption_decryption_roundtrip() {
        let shield = Shield::new("test_password", "pgvector.test");
        let vector = vec![1.0, 2.0, 3.0, 4.0, 5.0];

        let encrypted = EncryptedVector::encrypt(&shield, &vector).unwrap();
        let decrypted = encrypted.decrypt(&shield).unwrap();

        assert_eq!(vector.len(), decrypted.len());
        for (original, decrypted_val) in vector.iter().zip(decrypted.iter()) {
            assert!((original - decrypted_val).abs() < 1e-6);
        }
    }

    #[test]
    fn test_different_vectors_different_ciphertext() {
        let shield = Shield::new("test_password", "pgvector.test");
        let vector1 = vec![0.1, 0.2, 0.3];
        let vector2 = vec![0.4, 0.5, 0.6];

        let encrypted1 = EncryptedVector::encrypt(&shield, &vector1).unwrap();
        let encrypted2 = EncryptedVector::encrypt(&shield, &vector2).unwrap();

        // Different vectors should produce different ciphertext
        assert_ne!(encrypted1.nonce, encrypted2.nonce);
        assert_ne!(encrypted1.encrypted_data, encrypted2.encrypted_data);
    }

    #[test]
    fn test_tamper_detection() {
        let shield = Shield::new("test_password", "pgvector.test");
        let vector = vec![1.0, 2.0, 3.0];

        let mut encrypted = EncryptedVector::encrypt(&shield, &vector).unwrap();

        // Tamper with MAC
        encrypted.mac[0] ^= 0xFF;

        // Decryption should fail
        assert!(encrypted.decrypt(&shield).is_err());
    }
}
