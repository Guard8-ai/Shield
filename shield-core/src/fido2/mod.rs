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
//! ```no_run
//! use shield_core::{Shield, fido2::{Fido2Manager, WebAuthnConfig}};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Configure WebAuthn
//! let config = WebAuthnConfig::new("example.com", "My App", "https://example.com");
//! let shield = Shield::new("master_password", "fido2.myapp")?;
//!
//! // Create manager with encrypted storage
//! let mut manager = Fido2Manager::new_with_shield(config, shield);
//!
//! // Registration flow
//! let user_id = b"user123";
//! let challenge = manager.generate_registration_challenge(
//!     user_id,
//!     "alice@example.com",
//!     "Alice",
//! )?;
//!
//! // ... client creates credential ...
//!
//! // Verify and store credential
//! let credential = manager.verify_registration(
//!     &challenge.challenge,
//!     credential_id,
//!     public_key,
//! )?;
//!
//! // Authentication flow
//! let auth_challenge = manager.generate_authentication_challenge(user_id)?;
//!
//! // ... client signs challenge ...
//!
//! // Verify authentication
//! let result = manager.verify_authentication(
//!     &auth_challenge.challenge,
//!     &credential_id,
//!     &signature,
//!     counter,
//! )?;
//! # Ok(())
//! # }
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
