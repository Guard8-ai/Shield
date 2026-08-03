//! FIDO2/WebAuthn configuration

use super::credential::StoredCredential;
use super::error::Result;

/// `WebAuthn` relying party configuration.
#[derive(Clone, Debug)]
pub struct WebAuthnConfig {
    /// Relying party ID (e.g., `"example.com"`). Hashed and compared against
    /// `authenticatorData.rpIdHash` during registration and authentication.
    pub rp_id: String,
    /// Relying party name (e.g., "Shield Demo")
    pub rp_name: String,
    /// Primary expected origin (e.g., `"https://example.com"`).
    pub origin: String,
    /// All origins permitted to register/authenticate with this relying party.
    /// Validated against `clientDataJSON.origin` during every ceremony.
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
