//! Key exchange without public-key cryptography.
//!
//! Provides PAKE, QR exchange, and key splitting.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use std::num::NonZeroU32;

use crate::error::{Result, ShieldError};

/// Password-Authenticated Key Exchange.
pub struct PAKEExchange;

impl PAKEExchange {
    /// Default PBKDF2 iterations.
    pub const ITERATIONS: u32 = 200_000;

    /// Derive key contribution from password.
    #[must_use]
    pub fn derive(password: &str, salt: &[u8], role: &str, iterations: Option<u32>) -> [u8; 32] {
        let iters = iterations.unwrap_or(Self::ITERATIONS);

        let mut base_key = [0u8; 32];
        ring::pbkdf2::derive(
            ring::pbkdf2::PBKDF2_HMAC_SHA256,
            NonZeroU32::new(iters).unwrap(),
            salt,
            password.as_bytes(),
            &mut base_key,
        );

        let mut data = Vec::with_capacity(32 + role.len());
        data.extend_from_slice(&base_key);
        data.extend_from_slice(role.as_bytes());

        let hash = ring::digest::digest(&ring::digest::SHA256, &data);
        let mut result = [0u8; 32];
        result.copy_from_slice(hash.as_ref());
        result
    }

    /// Combine key contributions into session key.
    #[must_use]
    pub fn combine(contributions: &[[u8; 32]]) -> [u8; 32] {
        let mut sorted: Vec<&[u8; 32]> = contributions.iter().collect();
        sorted.sort();

        let mut combined = Vec::with_capacity(contributions.len() * 32);
        for c in sorted {
            combined.extend_from_slice(c);
        }

        let hash = ring::digest::digest(&ring::digest::SHA256, &combined);
        let mut result = [0u8; 32];
        result.copy_from_slice(hash.as_ref());
        result
    }

    /// Generate random salt.
    pub fn generate_salt() -> Result<[u8; 16]> {
        crate::random::random_bytes()
    }
}

/// Key exchange via QR codes or manual transfer.
pub struct QRExchange;

#[derive(Serialize, Deserialize)]
struct ExchangeData {
    v: u8,
    k: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    m: Option<serde_json::Value>,
}

impl QRExchange {
    /// Encode key for QR code.
    #[must_use]
    pub fn encode(key: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(key)
    }

    /// Decode key from QR code.
    pub fn decode(encoded: &str) -> Result<Vec<u8>> {
        URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| ShieldError::InvalidFormat)
    }

    /// Generate complete exchange data with metadata.
    #[must_use]
    pub fn generate_exchange_data(key: &[u8], metadata: Option<serde_json::Value>) -> String {
        let data = ExchangeData {
            v: 1,
            k: URL_SAFE_NO_PAD.encode(key),
            m: metadata,
        };
        serde_json::to_string(&data).unwrap()
    }

    /// Parse exchange data.
    pub fn parse_exchange_data(data: &str) -> Result<(Vec<u8>, Option<serde_json::Value>)> {
        let parsed: ExchangeData =
            serde_json::from_str(data).map_err(|_| ShieldError::InvalidFormat)?;
        let key = URL_SAFE_NO_PAD
            .decode(&parsed.k)
            .map_err(|_| ShieldError::InvalidFormat)?;
        Ok((key, parsed.m))
    }
}

/// Split keys into shares (all required to reconstruct).
pub struct KeySplitter;

impl KeySplitter {
    /// Split key into shares.
    pub fn split(key: &[u8], num_shares: usize) -> Result<Vec<Vec<u8>>> {
        if num_shares < 2 {
            return Err(ShieldError::InvalidShareCount);
        }

        let mut shares = Vec::with_capacity(num_shares);

        for _ in 0..num_shares - 1 {
            let share = crate::random::random_vec(key.len())?;
            shares.push(share);
        }

        // Final share = XOR of key with all others
        let mut final_share = key.to_vec();
        for share in &shares {
            for (i, &b) in share.iter().enumerate() {
                final_share[i] ^= b;
            }
        }
        shares.push(final_share);

        Ok(shares)
    }

    /// Combine shares to recover key.
    pub fn combine(shares: &[Vec<u8>]) -> Result<Vec<u8>> {
        if shares.len() < 2 {
            return Err(ShieldError::InvalidShareCount);
        }

        let len = shares[0].len();
        let mut result = vec![0u8; len];

        for share in shares {
            if share.len() != len {
                return Err(ShieldError::InvalidFormat);
            }
            for (i, &b) in share.iter().enumerate() {
                result[i] ^= b;
            }
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pake_derive() {
        let salt = PAKEExchange::generate_salt().unwrap();
        let key = PAKEExchange::derive("password", &salt, "client", None);
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_pake_deterministic() {
        let salt = PAKEExchange::generate_salt().unwrap();
        let key1 = PAKEExchange::derive("password", &salt, "client", None);
        let key2 = PAKEExchange::derive("password", &salt, "client", None);
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_pake_combine_order_independent() {
        let salt = PAKEExchange::generate_salt().unwrap();
        let client = PAKEExchange::derive("password", &salt, "client", None);
        let server = PAKEExchange::derive("password", &salt, "server", None);

        let shared1 = PAKEExchange::combine(&[client, server]);
        let shared2 = PAKEExchange::combine(&[server, client]);
        assert_eq!(shared1, shared2);
    }

    #[test]
    fn test_qr_roundtrip() {
        let key = [42u8; 32];
        let encoded = QRExchange::encode(&key);
        let decoded = QRExchange::decode(&encoded).unwrap();
        assert_eq!(key.as_slice(), decoded.as_slice());
    }

    #[test]
    fn test_qr_exchange_data() {
        let key = [1u8; 32];
        let metadata = serde_json::json!({"name": "test"});
        let data = QRExchange::generate_exchange_data(&key, Some(metadata.clone()));
        let (parsed_key, parsed_meta) = QRExchange::parse_exchange_data(&data).unwrap();
        assert_eq!(key.as_slice(), parsed_key.as_slice());
        assert_eq!(parsed_meta, Some(metadata));
    }

    #[test]
    fn test_key_splitter() {
        let key = [42u8; 32];
        let shares = KeySplitter::split(&key, 3).unwrap();
        assert_eq!(shares.len(), 3);

        let recovered = KeySplitter::combine(&shares).unwrap();
        assert_eq!(key.as_slice(), recovered.as_slice());
    }

    #[test]
    fn test_key_splitter_partial() {
        let key = [42u8; 32];
        let shares = KeySplitter::split(&key, 3).unwrap();

        // Partial shares don't recover key
        let partial = KeySplitter::combine(&shares[..2]).unwrap();
        assert_ne!(key.as_slice(), partial.as_slice());
    }

    #[test]
    fn test_key_splitter_min_shares() {
        let key = [42u8; 32];
        assert!(KeySplitter::split(&key, 1).is_err());
    }
}
