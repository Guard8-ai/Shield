//! # Shield Core
//!
//! EXPTIME-secure encryption library - Rust implementation.
//!
//! ## Security Model
//!
//! Shield uses only symmetric primitives with proven exponential-time security.
//! Breaking requires 2^256 operations - no shortcut exists.
//! - PBKDF2-SHA256 for key derivation
//! - AES-256-CTR-like stream cipher (SHA256-based keystream)
//! - HMAC-SHA256 for authentication
//!
//! ## Usage
//!
//! ```rust
//! use shield_core::Shield;
//!
//! let shield = Shield::new("password", "service.com");
//! let ciphertext = shield.encrypt(b"secret data").unwrap();
//! let plaintext = shield.decrypt(&ciphertext).unwrap();
//! ```
//!
//! ## Error Handling
//!
//! All fallible operations return `Result<T, ShieldError>`. Common errors:
//! - [`ShieldError::AuthenticationFailed`] - MAC verification failed (tampered/wrong key)
//! - [`ShieldError::CiphertextTooShort`] - Input too small to be valid ciphertext
//! - [`ShieldError::RandomFailed`] - System RNG failure (extremely rare)
//! - [`ShieldError::InvalidFormat`] - Malformed input data
//!
//! ## Panics
//!
//! Functions that may panic are documented, but panics are rare and indicate:
//! - Internal invariant violations (should never happen in correct usage)
//! - System-level failures (e.g., time going backwards)

#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
// Error/panic docs are centralized above; individual function docs are concise
#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

pub mod channel;
#[cfg(feature = "async")]
pub mod channel_async;
#[cfg(feature = "confidential")]
pub mod confidential;
mod error;
mod exchange;
#[cfg(feature = "fido2")]
pub mod fido2;
pub mod fingerprint;
mod random;
mod group;
mod identity;
pub mod password;
#[cfg(feature = "pgvector")]
pub mod pgvector;
mod ratchet;
mod rotation;
mod shield;
mod signatures;
mod stream;
mod totp;
#[cfg(feature = "wasm")]
mod wasm;

pub use channel::{ChannelConfig, ShieldChannel, ShieldListener};
#[cfg(feature = "async")]
pub use channel_async::AsyncShieldChannel;
pub use error::{Result, ShieldError};
pub use exchange::{KeySplitter, PAKEExchange, QRExchange};
pub use fingerprint::FingerprintMode;
pub use group::{BroadcastEncryption, EncryptedBroadcast, EncryptedGroupMessage, GroupEncryption};
pub use identity::{Identity, IdentityProvider, SecureSession, Session};
pub use ratchet::RatchetSession;
pub use rotation::KeyRotationManager;
pub use shield::Shield;
pub use signatures::{LamportSignature, SymmetricSignature};
pub use stream::StreamCipher;
pub use totp::{RecoveryCodes, TOTP};

#[cfg(feature = "wasm")]
pub use wasm::*;

/// Quick encrypt with pre-shared key (no password derivation)
pub fn quick_encrypt(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
    Shield::encrypt_with_key(key, data)
}

/// Quick decrypt with pre-shared key
pub fn quick_decrypt(key: &[u8; 32], encrypted: &[u8]) -> Result<Vec<u8>> {
    Shield::decrypt_with_key(key, encrypted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        let shield = Shield::new("test_password", "test.service");
        let plaintext = b"Hello, EXPTIME-secure world!";

        let encrypted = shield.encrypt(plaintext).unwrap();
        let decrypted = shield.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_quick_functions() {
        let key = [0x42u8; 32];
        let data = b"Quick test message";

        let encrypted = quick_encrypt(&key, data).unwrap();
        let decrypted = quick_decrypt(&key, &encrypted).unwrap();

        assert_eq!(data.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_tamper_detection() {
        let shield = Shield::new("password", "service");
        let mut encrypted = shield.encrypt(b"data").unwrap();

        // Tamper with ciphertext
        encrypted[20] ^= 0xFF;

        assert!(shield.decrypt(&encrypted).is_err());
    }

    #[test]
    fn test_wrong_password() {
        let shield1 = Shield::new("password1", "service");
        let shield2 = Shield::new("password2", "service");

        let encrypted = shield1.encrypt(b"secret").unwrap();

        assert!(shield2.decrypt(&encrypted).is_err());
    }

    #[test]
    fn test_different_services() {
        let shield1 = Shield::new("password", "service1");
        let shield2 = Shield::new("password", "service2");

        let encrypted = shield1.encrypt(b"secret").unwrap();

        assert!(shield2.decrypt(&encrypted).is_err());
    }
}
