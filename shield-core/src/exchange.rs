//! Key exchange without public-key cryptography.
//!
//! Provides a pre-shared-key handshake helper ([`PAKEExchange`]), QR exchange,
//! and key splitting.
//!
//! # Security note: this is NOT a true PAKE
//!
//! The type [`PAKEExchange`] is named for historical/API-compatibility reasons,
//! but it does **not** provide the security guarantee of a real
//! Password-Authenticated Key Exchange (such as `SPAKE2`, `CPace`, or `OPAQUE`). A true
//! PAKE leaks *no* offline-checkable function of the password to a network
//! observer, so a weak password stays safe even if the entire handshake is
//! recorded.
//!
//! This helper instead derives each party's contribution as a *deterministic*
//! function of the shared secret and a salt:
//! `contribution = HMAC(PBKDF2(secret, salt), role)`. Both the salt and the
//! contribution travel on the wire (see [`crate::channel`]). An eavesdropper who
//! records a handshake can therefore mount an **offline dictionary attack**: for
//! each guessed password they recompute the contribution and compare. PBKDF2
//! (600 000 iterations) raises the cost per guess but does not remove the
//! attack — it is fundamentally not preventable in a symmetric-only design.
//!
//! ## When this is safe to use
//!
//! Use [`PAKEExchange`] / [`crate::channel::ShieldChannel`] **only with a
//! high-entropy shared secret** (for example a 256-bit random key, or a
//! diceware passphrase with ≥128 bits of entropy). With a high-entropy secret
//! the offline search is computationally infeasible and the handshake is sound.
//!
//! ## When NOT to use it
//!
//! Do **not** use it to bootstrap a session from a low-entropy human password,
//! and do not rely on it for forward secrecy against compromise of the shared
//! secret. For those cases use the X25519 + ML-KEM-768 hybrid key exchange
//! (`pqhybrid`, behind the `pq` feature), which is a real asymmetric KEX and
//! does not expose a password to offline guessing.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ring::hmac;
use serde::{Deserialize, Serialize};
use std::num::NonZeroU32;

use crate::error::{Result, ShieldError};

/// Pre-shared-key handshake helper.
///
/// **Not a true PAKE** despite the name. The contribution it derives,
/// `HMAC(PBKDF2(secret, salt), role)`, is sent on the wire together with the
/// salt, so a recorded handshake permits an offline dictionary attack against a
/// low-entropy secret. Safe **only** with a high-entropy pre-shared secret. See
/// the [module-level security note](crate::exchange) and use the `pqhybrid`
/// X25519+ML-KEM KEX for the password / forward-secret case.
pub struct PAKEExchange;

impl PAKEExchange {
    /// Default PBKDF2 iterations (CR-2: OWASP 2023 floor).
    pub const ITERATIONS: u32 = 600_000;

    /// Derive key contribution from password.
    #[must_use]
    pub fn derive(password: &str, salt: &[u8], role: &str, iterations: Option<u32>) -> [u8; 32] {
        let iters = iterations.unwrap_or(Self::ITERATIONS);

        let mut base_key = [0u8; 32];
        ring::pbkdf2::derive(
            ring::pbkdf2::PBKDF2_HMAC_SHA256,
            NonZeroU32::new(iters).unwrap_or(NonZeroU32::new(Self::ITERATIONS).unwrap()),
            salt,
            password.as_bytes(),
            &mut base_key,
        );

        // Derive role-specific key using HMAC-SHA256 (keyed PRF)
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &base_key);
        let tag = hmac::sign(&hmac_key, role.as_bytes());
        let mut result = [0u8; 32];
        result.copy_from_slice(&tag.as_ref()[..32]);
        result
    }

    /// Combine key contributions into a session key using HMAC-SHA256.
    ///
    /// # Errors
    ///
    /// Returns [`ShieldError::InvalidFormat`] if fewer than two contributions
    /// are supplied: a combine of zero or one contribution is meaningless, and
    /// indexing an empty list would otherwise panic (a denial-of-service risk
    /// for a caller that passes an externally-influenced list).
    pub fn combine(contributions: &[[u8; 32]]) -> Result<[u8; 32]> {
        if contributions.len() < 2 {
            return Err(ShieldError::InvalidFormat);
        }

        let mut sorted: Vec<&[u8; 32]> = contributions.iter().collect();
        sorted.sort();

        // Use first contribution as HMAC key, remaining as data
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, sorted[0]);
        let mut data = Vec::with_capacity((sorted.len() - 1) * 32);
        for c in &sorted[1..] {
            data.extend_from_slice(*c);
        }

        let tag = hmac::sign(&hmac_key, &data);
        let mut result = [0u8; 32];
        result.copy_from_slice(&tag.as_ref()[..32]);
        Ok(result)
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
        serde_json::to_string(&data).unwrap_or_default()
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

        let shared1 = PAKEExchange::combine(&[client, server]).unwrap();
        let shared2 = PAKEExchange::combine(&[server, client]).unwrap();
        assert_eq!(shared1, shared2);
    }

    #[test]
    fn test_pake_combine_empty_is_error_not_panic() {
        // RT2-10: combine() previously indexed sorted[0] unconditionally and
        // panicked (DoS) on empty input. It must now return an error.
        assert!(PAKEExchange::combine(&[]).is_err());
    }

    #[test]
    fn test_pake_combine_single_is_error() {
        // A single contribution is meaningless to "combine" and must be rejected
        // rather than returning HMAC(c, "").
        let salt = PAKEExchange::generate_salt().unwrap();
        let only = PAKEExchange::derive("password", &salt, "client", None);
        assert!(PAKEExchange::combine(&[only]).is_err());
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
