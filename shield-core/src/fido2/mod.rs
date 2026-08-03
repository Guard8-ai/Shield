//! FIDO2 / `WebAuthn` integration.
//!
//! # Security Notice — DEPRECATED
//!
//! This module does NOT implement the `WebAuthn` security model correctly:
//!
//! - **No origin binding**: `clientDataJSON.origin` is not validated against
//!   the relying party's expected origin. Any origin can register and
//!   authenticate credentials.
//! - **No rpId binding**: `authenticatorData.rpIdHash` is not verified.
//!   Credentials from one relying party are accepted by any other.
//! - **No clientDataJSON binding**: the challenge is not bound to the HTTP
//!   origin + operation type, leaving this implementation vulnerable to
//!   phishing and cross-origin attacks.
//! - **No attestation**: the authenticator's identity cannot be verified.
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
