//! FIDO2 credential types and Shield-encrypted storage

use super::config::CredentialStore;
use super::error::{Fido2Error, Result};
use crate::Shield;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Stored FIDO2 credential with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCredential {
    /// Credential ID (unique identifier)
    pub credential_id: Vec<u8>,
    /// COSE-encoded public key
    pub public_key: Vec<u8>,
    /// Signature counter (for replay detection)
    pub counter: u32,
    /// User ID
    pub user_id: Vec<u8>,
    /// Relying party ID
    pub rp_id: String,
    /// Creation timestamp (Unix epoch)
    pub created_at: u64,
}

impl StoredCredential {
    /// Create a new stored credential
    pub fn new(
        credential_id: Vec<u8>,
        public_key: Vec<u8>,
        user_id: Vec<u8>,
        rp_id: String,
    ) -> Self {
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            credential_id,
            public_key,
            counter: 0,
            user_id,
            rp_id,
            created_at,
        }
    }
}

/// Shield-encrypted credential storage
pub struct ShieldCredentialStore {
    shield: Shield,
    storage: HashMap<Vec<u8>, Vec<u8>>, // user_id -> encrypted credentials list
}

impl ShieldCredentialStore {
    /// Create a new Shield-encrypted credential store
    pub fn new(shield: Shield) -> Self {
        Self {
            shield,
            storage: HashMap::new(),
        }
    }

    /// Encrypt credentials for storage
    fn encrypt_credentials(&self, credentials: &[StoredCredential]) -> Result<Vec<u8>> {
        let json = serde_json::to_vec(credentials)?;
        Ok(self.shield.encrypt(&json)?)
    }

    /// Decrypt credentials from storage
    fn decrypt_credentials(&self, encrypted: &[u8]) -> Result<Vec<StoredCredential>> {
        let json = self.shield.decrypt(encrypted)?;
        Ok(serde_json::from_slice(&json)?)
    }
}

impl CredentialStore for ShieldCredentialStore {
    fn store(&mut self, user_id: &[u8], credential: &StoredCredential) -> Result<()> {
        // Get existing credentials
        let mut credentials = self.get(user_id).unwrap_or_default();

        // Add new credential
        credentials.push(credential.clone());

        // Encrypt and store
        let encrypted = self.encrypt_credentials(&credentials)?;
        self.storage.insert(user_id.to_vec(), encrypted);

        Ok(())
    }

    fn get(&self, user_id: &[u8]) -> Result<Vec<StoredCredential>> {
        match self.storage.get(user_id) {
            Some(encrypted) => self.decrypt_credentials(encrypted),
            None => Ok(Vec::new()),
        }
    }

    fn delete(&mut self, user_id: &[u8], credential_id: &[u8]) -> Result<()> {
        let mut credentials = self.get(user_id)?;
        credentials.retain(|c| c.credential_id != credential_id);

        if credentials.is_empty() {
            self.storage.remove(user_id);
        } else {
            let encrypted = self.encrypt_credentials(&credentials)?;
            self.storage.insert(user_id.to_vec(), encrypted);
        }

        Ok(())
    }

    fn update_counter(&mut self, user_id: &[u8], credential_id: &[u8], counter: u32) -> Result<()> {
        let mut credentials = self.get(user_id)?;

        let credential = credentials
            .iter_mut()
            .find(|c| c.credential_id == credential_id)
            .ok_or(Fido2Error::CredentialNotFound)?;

        credential.counter = counter;

        let encrypted = self.encrypt_credentials(&credentials)?;
        self.storage.insert(user_id.to_vec(), encrypted);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_store_roundtrip() {
        let shield = Shield::new("test_password", "fido2.test");
        let mut store = ShieldCredentialStore::new(shield);

        let user_id = b"user123";
        let credential = StoredCredential::new(
            b"cred_id_1".to_vec(),
            b"public_key_data".to_vec(),
            user_id.to_vec(),
            "example.com".to_string(),
        );

        // Store credential
        store.store(user_id, &credential).unwrap();

        // Retrieve credential
        let retrieved = store.get(user_id).unwrap();
        assert_eq!(retrieved.len(), 1);
        assert_eq!(retrieved[0].credential_id, credential.credential_id);
        assert_eq!(retrieved[0].public_key, credential.public_key);
    }

    #[test]
    fn test_credential_update_counter() {
        let shield = Shield::new("test_password", "fido2.test");
        let mut store = ShieldCredentialStore::new(shield);

        let user_id = b"user123";
        let credential = StoredCredential::new(
            b"cred_id_1".to_vec(),
            b"public_key_data".to_vec(),
            user_id.to_vec(),
            "example.com".to_string(),
        );

        store.store(user_id, &credential).unwrap();
        store.update_counter(user_id, &credential.credential_id, 5).unwrap();

        let retrieved = store.get(user_id).unwrap();
        assert_eq!(retrieved[0].counter, 5);
    }

    #[test]
    fn test_credential_delete() {
        let shield = Shield::new("test_password", "fido2.test");
        let mut store = ShieldCredentialStore::new(shield);

        let user_id = b"user123";
        let credential = StoredCredential::new(
            b"cred_id_1".to_vec(),
            b"public_key_data".to_vec(),
            user_id.to_vec(),
            "example.com".to_string(),
        );

        store.store(user_id, &credential).unwrap();
        store.delete(user_id, &credential.credential_id).unwrap();

        let retrieved = store.get(user_id).unwrap();
        assert_eq!(retrieved.len(), 0);
    }
}
