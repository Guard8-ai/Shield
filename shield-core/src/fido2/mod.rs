//! FIDO2/WebAuthn passwordless authentication module
//!
//! This module provides FIDO2/WebAuthn support with Shield-encrypted credential storage.
//! It enables passwordless authentication using hardware security keys, platform authenticators
//! (Face ID, Touch ID, Windows Hello), and biometrics.
//!
//! # Features
//!
//! - **Registration**: Create and store FIDO2 credentials
//! - **Authentication**: Verify users with stored credentials
//! - **Shield Integration**: Credentials encrypted with EXPTIME-secure encryption
//! - **Replay Protection**: Signature counter validation prevents replay attacks
//! - **Challenge Management**: Secure challenge generation and validation
//!
//! # Example
//!
//! ```rust
//! use shield_core::{Shield, fido2::{Fido2Manager, WebAuthnConfig}};
//!
//! let config = WebAuthnConfig::new("example.com", "My App", "https://example.com");
//! let shield = Shield::new("master_password", "fido2.myapp");
//! let mut manager = Fido2Manager::new_with_shield(config, shield);
//!
//! // Registration: generate challenge, then verify with credential
//! let challenge = manager.generate_registration_challenge(
//!     b"user123", "alice", "Alice",
//! ).unwrap();
//! let cred_id = b"credential_123".to_vec();
//! let pubkey = b"public_key_data".to_vec();
//! let _credential = manager.verify_registration(
//!     &challenge.challenge, cred_id, pubkey,
//! ).unwrap();
//! ```

pub mod config;
pub mod credential;
pub mod error;
pub mod manager;

pub use config::{CredentialStore, WebAuthnConfig};
pub use credential::{ShieldCredentialStore, StoredCredential};
pub use error::{Fido2Error, Result};
pub use manager::{
    AllowedCredential, AuthenticationChallenge, AuthenticationResult,
    Fido2Manager, RegistrationChallenge,
};
