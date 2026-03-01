//! FIDO2 Manager - Main API for `WebAuthn` operations

use super::config::{CredentialStore, WebAuthnConfig};
use super::credential::{ShieldCredentialStore, StoredCredential};
use super::error::{Fido2Error, Result};
use crate::Shield;
use base64::Engine;
use ring::hmac;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Base64 engine for FIDO2 challenge/credential encoding.
fn b64_encode(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn b64_decode(data: &str) -> std::result::Result<Vec<u8>, base64::DecodeError> {
    base64::engine::general_purpose::STANDARD.decode(data)
}

/// Challenge data for registration or authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeData {
    /// Random challenge bytes
    pub challenge: Vec<u8>,
    /// Challenge timeout timestamp
    pub expires_at: u64,
    /// Associated user ID (for authentication)
    pub user_id: Option<Vec<u8>>,
}

/// FIDO2 Manager for `WebAuthn` operations
pub struct Fido2Manager<S: CredentialStore> {
    config: WebAuthnConfig,
    store: S,
    challenges: HashMap<Vec<u8>, ChallengeData>,
}

impl Fido2Manager<ShieldCredentialStore> {
    /// Create a new FIDO2 manager with Shield-encrypted storage
    pub fn new_with_shield(config: WebAuthnConfig, shield: Shield) -> Self {
        Self {
            config,
            store: ShieldCredentialStore::new(shield),
            challenges: HashMap::new(),
        }
    }
}

impl<S: CredentialStore> Fido2Manager<S> {
    /// Create a new FIDO2 manager with custom storage
    pub fn new(config: WebAuthnConfig, store: S) -> Self {
        Self {
            config,
            store,
            challenges: HashMap::new(),
        }
    }

    /// Generate a registration challenge
    pub fn generate_registration_challenge(
        &mut self,
        user_id: &[u8],
        username: &str,
        display_name: &str,
    ) -> Result<RegistrationChallenge> {
        // Generate cryptographically secure random challenge
        let challenge = crate::random::random_vec(32)?;

        let expires_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + (u64::from(self.config.timeout_ms) / 1000);

        // Store challenge for verification
        self.challenges.insert(
            challenge.clone(),
            ChallengeData {
                challenge: challenge.clone(),
                expires_at,
                user_id: Some(user_id.to_vec()),
            },
        );

        Ok(RegistrationChallenge {
            challenge: b64_encode(&challenge),
            user_id: b64_encode(user_id),
            username: username.to_string(),
            display_name: display_name.to_string(),
            rp_id: self.config.rp_id.clone(),
            rp_name: self.config.rp_name.clone(),
            timeout_ms: self.config.timeout_ms,
        })
    }

    /// Verify registration response and store credential
    pub fn verify_registration(
        &mut self,
        challenge_b64: &str,
        credential_id: Vec<u8>,
        public_key: Vec<u8>,
    ) -> Result<StoredCredential> {
        // Decode challenge
        let challenge = b64_decode(challenge_b64).map_err(|_| Fido2Error::InvalidChallenge)?;

        // Verify challenge exists and not expired
        let challenge_data = self
            .challenges
            .get(&challenge)
            .ok_or(Fido2Error::InvalidChallenge)?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if now > challenge_data.expires_at {
            self.challenges.remove(&challenge);
            return Err(Fido2Error::InvalidChallenge);
        }

        let user_id = challenge_data
            .user_id
            .clone()
            .ok_or(Fido2Error::InvalidChallenge)?;

        // Create and store credential
        let credential = StoredCredential::new(
            credential_id,
            public_key,
            user_id.clone(),
            self.config.rp_id.clone(),
        );

        self.store.store(&user_id, &credential)?;

        // Remove used challenge
        self.challenges.remove(&challenge);

        Ok(credential)
    }

    /// Generate an authentication challenge
    pub fn generate_authentication_challenge(
        &mut self,
        user_id: &[u8],
    ) -> Result<AuthenticationChallenge> {
        // Get user's credentials
        let credentials = self.store.get(user_id)?;

        if credentials.is_empty() {
            return Err(Fido2Error::CredentialNotFound);
        }

        // Generate challenge
        let challenge = crate::random::random_vec(32)?;

        let expires_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + (u64::from(self.config.timeout_ms) / 1000);

        // Store challenge
        self.challenges.insert(
            challenge.clone(),
            ChallengeData {
                challenge: challenge.clone(),
                expires_at,
                user_id: Some(user_id.to_vec()),
            },
        );

        // Build allowed credentials list
        let allowed_credentials: Vec<_> = credentials
            .iter()
            .map(|c| AllowedCredential {
                id: b64_encode(&c.credential_id),
                credential_type: "public-key".to_string(),
            })
            .collect();

        Ok(AuthenticationChallenge {
            challenge: b64_encode(&challenge),
            allowed_credentials,
            timeout_ms: self.config.timeout_ms,
            rp_id: self.config.rp_id.clone(),
        })
    }

    /// Verify authentication response
    pub fn verify_authentication(
        &mut self,
        challenge_b64: &str,
        credential_id: &[u8],
        signature: &[u8],
        counter: u32,
    ) -> Result<AuthenticationResult> {
        // Decode challenge
        let challenge = b64_decode(challenge_b64).map_err(|_| Fido2Error::InvalidChallenge)?;

        // Verify challenge exists and not expired
        let challenge_data = self
            .challenges
            .get(&challenge)
            .ok_or(Fido2Error::InvalidChallenge)?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if now > challenge_data.expires_at {
            self.challenges.remove(&challenge);
            return Err(Fido2Error::InvalidChallenge);
        }

        let user_id = challenge_data
            .user_id
            .clone()
            .ok_or(Fido2Error::InvalidChallenge)?;

        // Get stored credential
        let credentials = self.store.get(&user_id)?;
        let stored_cred = credentials
            .iter()
            .find(|c| c.credential_id == credential_id)
            .ok_or(Fido2Error::CredentialNotFound)?;

        // Verify counter increased (replay protection)
        if counter <= stored_cred.counter {
            return Err(Fido2Error::CounterDecreased);
        }

        // Verify HMAC-SHA256 signature using stored credential's public_key
        // Signature covers: challenge || credential_id || counter (domain separation)
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &stored_cred.public_key);
        let mut sign_data = Vec::with_capacity(challenge.len() + credential_id.len() + 4);
        sign_data.extend_from_slice(&challenge);
        sign_data.extend_from_slice(credential_id);
        sign_data.extend_from_slice(&counter.to_le_bytes());
        hmac::verify(&hmac_key, &sign_data, signature).map_err(|_| Fido2Error::InvalidSignature)?;

        // Update counter
        self.store
            .update_counter(&user_id, credential_id, counter)?;

        // Remove used challenge
        self.challenges.remove(&challenge);

        Ok(AuthenticationResult {
            user_id,
            credential_id: credential_id.to_vec(),
            counter,
            success: true,
        })
    }

    /// List all credentials for a user
    pub fn list_credentials(&self, user_id: &[u8]) -> Result<Vec<StoredCredential>> {
        self.store.get(user_id)
    }

    /// Delete a credential
    pub fn delete_credential(&mut self, user_id: &[u8], credential_id: &[u8]) -> Result<()> {
        self.store.delete(user_id, credential_id)
    }
}

/// Registration challenge sent to client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationChallenge {
    pub challenge: String, // base64-encoded
    pub user_id: String,   // base64-encoded
    pub username: String,
    pub display_name: String,
    pub rp_id: String,
    pub rp_name: String,
    pub timeout_ms: u32,
}

/// Authentication challenge sent to client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationChallenge {
    pub challenge: String, // base64-encoded
    pub allowed_credentials: Vec<AllowedCredential>,
    pub timeout_ms: u32,
    pub rp_id: String,
}

/// Allowed credential descriptor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowedCredential {
    pub id: String, // base64-encoded credential ID
    #[serde(rename = "type")]
    pub credential_type: String, // "public-key"
}

/// Authentication result
#[derive(Debug, Clone)]
pub struct AuthenticationResult {
    pub user_id: Vec<u8>,
    pub credential_id: Vec<u8>,
    pub counter: u32,
    pub success: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_manager() -> Fido2Manager<ShieldCredentialStore> {
        let config = WebAuthnConfig::new("example.com", "Test App", "https://example.com");
        let shield = Shield::new("test_password", "fido2.test");
        Fido2Manager::new_with_shield(config, shield)
    }

    /// Compute a valid HMAC-SHA256 signature for FIDO2 authentication.
    fn compute_test_signature(
        public_key: &[u8],
        challenge_b64: &str,
        credential_id: &[u8],
        counter: u32,
    ) -> Vec<u8> {
        let challenge = b64_decode(challenge_b64).unwrap();
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, public_key);
        let mut sign_data = Vec::new();
        sign_data.extend_from_slice(&challenge);
        sign_data.extend_from_slice(credential_id);
        sign_data.extend_from_slice(&counter.to_le_bytes());
        hmac::sign(&hmac_key, &sign_data).as_ref().to_vec()
    }

    #[test]
    fn test_registration_flow() {
        let mut manager = create_test_manager();
        let user_id = b"user123";

        // Generate challenge
        let challenge = manager
            .generate_registration_challenge(user_id, "testuser", "Test User")
            .unwrap();

        assert!(!challenge.challenge.is_empty());
        assert_eq!(challenge.username, "testuser");

        // Simulate registration
        let credential_id = b"cred_id_123".to_vec();
        let public_key = b"public_key_data".to_vec();

        let stored = manager
            .verify_registration(&challenge.challenge, credential_id.clone(), public_key)
            .unwrap();

        assert_eq!(stored.credential_id, credential_id);
        assert_eq!(stored.user_id, user_id);
    }

    #[test]
    fn test_authentication_flow() {
        let mut manager = create_test_manager();
        let user_id = b"user123";
        let credential_id = b"cred_id_123".to_vec();
        let public_key = b"public_key_data".to_vec();

        // Register first
        let reg_challenge = manager
            .generate_registration_challenge(user_id, "testuser", "Test User")
            .unwrap();
        manager
            .verify_registration(
                &reg_challenge.challenge,
                credential_id.clone(),
                public_key.clone(),
            )
            .unwrap();

        // Generate auth challenge
        let auth_challenge = manager.generate_authentication_challenge(user_id).unwrap();
        assert!(!auth_challenge.challenge.is_empty());
        assert_eq!(auth_challenge.allowed_credentials.len(), 1);

        // Compute valid HMAC signature
        let signature =
            compute_test_signature(&public_key, &auth_challenge.challenge, &credential_id, 1);

        let result = manager
            .verify_authentication(&auth_challenge.challenge, &credential_id, &signature, 1)
            .unwrap();

        assert!(result.success);
        assert_eq!(result.user_id, user_id);
        assert_eq!(result.counter, 1);
    }

    #[test]
    fn test_authentication_invalid_signature() {
        let mut manager = create_test_manager();
        let user_id = b"user123";
        let credential_id = b"cred_id_123".to_vec();

        // Register
        let reg_challenge = manager
            .generate_registration_challenge(user_id, "testuser", "Test User")
            .unwrap();
        manager
            .verify_registration(
                &reg_challenge.challenge,
                credential_id.clone(),
                b"public_key_data".to_vec(),
            )
            .unwrap();

        // Generate auth challenge
        let auth_challenge = manager.generate_authentication_challenge(user_id).unwrap();

        // Use an invalid signature
        let result = manager.verify_authentication(
            &auth_challenge.challenge,
            &credential_id,
            b"invalid_signature",
            1,
        );
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Fido2Error::InvalidSignature));
    }

    #[test]
    fn test_counter_replay_protection() {
        let mut manager = create_test_manager();
        let user_id = b"user123";
        let credential_id = b"cred_id_123".to_vec();
        let public_key = b"public_key_data".to_vec();

        // Register
        let reg_challenge = manager
            .generate_registration_challenge(user_id, "testuser", "Test User")
            .unwrap();
        manager
            .verify_registration(
                &reg_challenge.challenge,
                credential_id.clone(),
                public_key.clone(),
            )
            .unwrap();

        // First authentication with valid signature
        let auth_challenge = manager.generate_authentication_challenge(user_id).unwrap();
        let sig1 =
            compute_test_signature(&public_key, &auth_challenge.challenge, &credential_id, 1);
        manager
            .verify_authentication(&auth_challenge.challenge, &credential_id, &sig1, 1)
            .unwrap();

        // Second authentication with same counter should fail (replay)
        let auth_challenge2 = manager.generate_authentication_challenge(user_id).unwrap();
        let sig2 =
            compute_test_signature(&public_key, &auth_challenge2.challenge, &credential_id, 1);
        let result =
            manager.verify_authentication(&auth_challenge2.challenge, &credential_id, &sig2, 1);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Fido2Error::CounterDecreased));
    }
}
