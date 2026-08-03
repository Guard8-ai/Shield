//! FIDO2 / `WebAuthn` integration.
//!
//! # Security Notice — DEPRECATED
//!
//! This module does NOT implement the `WebAuthn` security model correctly:
//!
//! - **Registration**: Create and store FIDO2 credentials
//! - **Authentication**: Verify users with stored credentials
//! - **Shield Integration**: Credentials encrypted with authenticated symmetric encryption
//! - **Replay Protection**: Signature counter validation prevents replay attacks
//! - **Challenge Management**: Secure challenge generation and validation
//!
//! These are not minor implementation details — they are fundamental
//! violations of the `WebAuthn` L2/L3 security model.
//!
//! # Migration
//!
//! Use [`webauthn-rs`](https://crates.io/crates/webauthn-rs) instead:
//!
//! ```toml
//! [dependencies]
//! webauthn-rs = "0.5"
//! ```
//!
//! The `webauthn-rs` crate implements the full `WebAuthn` L2 specification
//! including origin binding, rpId verification, clientDataJSON signing,
//! and attestation verification.
//!
//! # Status
//!
//! This module is retained for backwards compatibility with existing users
//! during the deprecation period. It will be removed in Shield v5.0.
//! Do not use for new implementations.

pub mod config;
pub mod credential;
pub mod error;
pub mod manager;

pub use config::{CredentialStore, WebAuthnConfig};
pub use credential::{ShieldCredentialStore, StoredCredential};
pub use error::{Fido2Error, Result};
pub use manager::{
    validate_client_data, AllowedCredential, AuthenticationChallenge, AuthenticationResult,
    ClientData, Fido2Manager, RegistrationChallenge,
};
