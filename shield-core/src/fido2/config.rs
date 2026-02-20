//! FIDO2/WebAuthn configuration

use super::error::Result;
use super::credential::StoredCredential;

/// WebAuthn relying party configuration
#[derive(Clone, Debug)]
pub struct WebAuthnConfig {
    /// Relying party ID (e.g., "example.com")
    pub rp_id: String,
    /// Relying party name (e.g., "Shield Demo")
    pub rp_name: String,
    /// Expected origin (e.g., "https://example.com")
    pub origin: String,
    /// Challenge timeout in milliseconds (default: 60000)
    pub timeout_ms: u32,
}

impl WebAuthnConfig {
    /// Create a new WebAuthn configuration
    pub fn new(rp_id: impl Into<String>, rp_name: impl Into<String>, origin: impl Into<String>) -> Self {
        Self {
            rp_id: rp_id.into(),
            rp_name: rp_name.into(),
            origin: origin.into(),
            timeout_ms: 60000, // 60 seconds
        }
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
