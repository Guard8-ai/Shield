//! FIDO2/WebAuthn configuration
//!
//! # DEPRECATED — Non-Conformant Implementation
//!
//! This configuration is part of a non-conformant FIDO2 implementation.
//! Fields `rp_id` and `allowed_origins` are present for structural
//! completeness and future migration but are **not currently enforced**
//! during registration or authentication.  See `backend-065`.
//!
//! Migrate to [`webauthn-rs`](https://crates.io/crates/webauthn-rs) `0.5`.

use super::credential::StoredCredential;
use super::error::Result;

/// `WebAuthn` relying party configuration.
///
/// # Warning
///
/// The fields `rp_id` and `allowed_origins` are stored in challenges and
/// credentials but are **not validated** during the current implementation.
/// This means origin binding and rpId binding are absent — a critical
/// `WebAuthn` security property.  See `backend-065` and module-level docs.
#[derive(Clone, Debug)]
pub struct WebAuthnConfig {
    /// Relying party ID (e.g., "example.com").
    ///
    /// TODO(backend-065): hash and compare against `authenticatorData.rpIdHash`
    /// during registration and authentication to prevent cross-RP credential reuse.
    pub rp_id: String,
    /// Relying party name (e.g., "Shield Demo")
    pub rp_name: String,
    /// Primary expected origin (e.g., `https://example.com`).
    ///
    /// Kept for API compatibility. Use `allowed_origins` for the full list.
    /// TODO(backend-065): enforce during `clientDataJSON` parsing.
    pub origin: String,
    /// All origins permitted to register/authenticate with this relying party.
    ///
    /// TODO(backend-065): validated by `validate_client_data` once that
    /// function is wired into `verify_registration` and `verify_authentication`.
    pub allowed_origins: Vec<String>,
    /// Challenge timeout in milliseconds (default: 60000)
    pub timeout_ms: u32,
}

impl WebAuthnConfig {
    /// Create a new `WebAuthn` configuration.
    ///
    /// `origin` is also added to `allowed_origins` automatically.
    pub fn new(
        rp_id: impl Into<String>,
        rp_name: impl Into<String>,
        origin: impl Into<String>,
    ) -> Self {
        let origin = origin.into();
        let allowed_origins = vec![origin.clone()];
        Self {
            rp_id: rp_id.into(),
            rp_name: rp_name.into(),
            origin,
            allowed_origins,
            timeout_ms: 60000, // 60 seconds
        }
    }

    /// Add an additional allowed origin.
    ///
    /// TODO(backend-065): used by `validate_client_data` once wired in.
    #[must_use]
    pub fn with_allowed_origin(mut self, origin: impl Into<String>) -> Self {
        self.allowed_origins.push(origin.into());
        self
    }

    /// Set timeout in milliseconds
    #[must_use]
    pub fn with_timeout(mut self, timeout_ms: u32) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }
}

/// Trait for credential storage backends
pub trait CredentialStore: Send + Sync {
    /// Store a credential for a user
    fn store(&mut self, user_id: &[u8], credential: &StoredCredential) -> Result<()>;

    /// Get all credentials for a user
    fn get(&self, user_id: &[u8]) -> Result<Vec<StoredCredential>>;

    /// Delete a specific credential
    fn delete(&mut self, user_id: &[u8], credential_id: &[u8]) -> Result<()>;

    /// Update credential counter
    fn update_counter(&mut self, user_id: &[u8], credential_id: &[u8], counter: u32) -> Result<()>;
}
