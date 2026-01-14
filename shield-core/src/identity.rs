//! Identity and SSO without public-key cryptography.
//!
//! Provides identity management, session tokens, and service tokens.

// Token timestamps and indices use intentional truncation for compact encoding
#![allow(clippy::cast_possible_truncation)]

use base64::Engine;
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use std::collections::HashMap;
use std::num::NonZeroU32;
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

use crate::error::{Result, ShieldError};

/// Generate keystream using SHA256.
fn generate_keystream(key: &[u8], nonce: &[u8], length: usize) -> Vec<u8> {
    let mut keystream = Vec::with_capacity(length.div_ceil(32) * 32);
    let num_blocks = length.div_ceil(32);

    for i in 0..num_blocks {
        let counter = (i as u32).to_le_bytes();
        let mut data = Vec::with_capacity(key.len() + nonce.len() + 4);
        data.extend_from_slice(key);
        data.extend_from_slice(nonce);
        data.extend_from_slice(&counter);

        let hash = ring::digest::digest(&ring::digest::SHA256, &data);
        keystream.extend_from_slice(hash.as_ref());
    }

    keystream.truncate(length);
    keystream
}

/// User identity.
#[derive(Clone)]
pub struct Identity {
    pub user_id: String,
    pub display_name: String,
    pub verification_key: [u8; 32],
    pub attributes: HashMap<String, String>,
    pub created_at: u64,
}

/// Session information.
#[derive(Clone)]
pub struct Session {
    pub user_id: String,
    pub permissions: Vec<String>,
    pub expires_at: Option<u64>,
    pub attributes: HashMap<String, String>,
}

impl Session {
    /// Check if session is expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        match self.expires_at {
            None => false,
            Some(expires) => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                now > expires
            }
        }
    }

    /// Check if session has permission.
    #[must_use]
    pub fn has_permission(&self, permission: &str) -> bool {
        self.permissions.contains(&permission.to_string())
    }
}

/// Stored user data.
struct UserData {
    password_hash: [u8; 32],
    salt: [u8; 16],
    identity: Identity,
}

/// Identity provider for managing users and sessions.
pub struct IdentityProvider {
    master_key: [u8; 32],
    token_ttl: u64,
    users: HashMap<String, UserData>,
}

impl IdentityProvider {
    const ITERATIONS: u32 = 100_000;

    /// Create new identity provider.
    #[must_use]
    pub fn new(master_key: [u8; 32], token_ttl: u64) -> Self {
        Self {
            master_key,
            token_ttl: if token_ttl == 0 { 3600 } else { token_ttl },
            users: HashMap::new(),
        }
    }

    /// Derive key for specific purpose.
    fn derive_key(&self, purpose: &str) -> [u8; 32] {
        let mut data = Vec::with_capacity(32 + purpose.len());
        data.extend_from_slice(&self.master_key);
        data.extend_from_slice(purpose.as_bytes());
        let hash = ring::digest::digest(&ring::digest::SHA256, &data);
        let mut key = [0u8; 32];
        key.copy_from_slice(hash.as_ref());
        key
    }

    /// Register a new user.
    pub fn register(
        &mut self,
        user_id: &str,
        password: &str,
        display_name: Option<&str>,
        attributes: HashMap<String, String>,
    ) -> Result<Identity> {
        if self.users.contains_key(user_id) {
            return Err(ShieldError::UserExists(user_id.to_string()));
        }

        let rng = SystemRandom::new();
        let mut salt = [0u8; 16];
        rng.fill(&mut salt).map_err(|_| ShieldError::RandomFailed)?;

        let mut password_hash = [0u8; 32];
        ring::pbkdf2::derive(
            ring::pbkdf2::PBKDF2_HMAC_SHA256,
            NonZeroU32::new(Self::ITERATIONS).unwrap(),
            &salt,
            password.as_bytes(),
            &mut password_hash,
        );

        // Generate verification key
        let verify_key = self.derive_key("verify");
        let mut vk_data = Vec::with_capacity(32 + user_id.len());
        vk_data.extend_from_slice(&verify_key);
        vk_data.extend_from_slice(user_id.as_bytes());
        let vk_hash = ring::digest::digest(&ring::digest::SHA256, &vk_data);
        let mut verification_key = [0u8; 32];
        verification_key.copy_from_slice(vk_hash.as_ref());

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let identity = Identity {
            user_id: user_id.to_string(),
            display_name: display_name.unwrap_or(user_id).to_string(),
            verification_key,
            attributes, // Consume owned value, no clone needed
            created_at: now,
        };

        self.users.insert(
            user_id.to_string(),
            UserData {
                password_hash,
                salt,
                identity: identity.clone(),
            },
        );

        Ok(identity)
    }

    /// Authenticate user and return session token.
    #[must_use]
    pub fn authenticate(
        &self,
        user_id: &str,
        password: &str,
        permissions: &[String],
        ttl: Option<u64>,
    ) -> Option<String> {
        let user = self.users.get(user_id)?;

        let mut password_hash = [0u8; 32];
        ring::pbkdf2::derive(
            ring::pbkdf2::PBKDF2_HMAC_SHA256,
            NonZeroU32::new(Self::ITERATIONS).unwrap(),
            &user.salt,
            password.as_bytes(),
            &mut password_hash,
        );

        if password_hash.ct_eq(&user.password_hash).unwrap_u8() != 1 {
            return None;
        }

        Some(self.create_token(user_id, permissions, ttl.unwrap_or(self.token_ttl)))
    }

    /// Create session token.
    fn create_token(&self, user_id: &str, permissions: &[String], ttl: u64) -> String {
        let rng = SystemRandom::new();
        let mut nonce = [0u8; 16];
        rng.fill(&mut nonce).unwrap();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let expires_at = now + ttl;

        // Serialize token data
        let user_id_bytes = user_id.as_bytes();
        let perms_json = serde_json::to_string(permissions).unwrap();
        let perms_bytes = perms_json.as_bytes();

        let mut token_data = Vec::new();
        token_data.extend_from_slice(&(user_id_bytes.len() as u16).to_le_bytes());
        token_data.extend_from_slice(user_id_bytes);
        token_data.extend_from_slice(&(perms_bytes.len() as u16).to_le_bytes());
        token_data.extend_from_slice(perms_bytes);
        token_data.extend_from_slice(&expires_at.to_le_bytes());

        // Encrypt
        let key = self.derive_key("session");
        let keystream = generate_keystream(&key, &nonce, token_data.len());
        let encrypted: Vec<u8> = token_data
            .iter()
            .zip(keystream.iter())
            .map(|(p, k)| p ^ k)
            .collect();

        // MAC
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &key);
        let mut hmac_data = Vec::with_capacity(16 + encrypted.len());
        hmac_data.extend_from_slice(&nonce);
        hmac_data.extend_from_slice(&encrypted);
        let tag = hmac::sign(&hmac_key, &hmac_data);

        let mut result = Vec::with_capacity(16 + encrypted.len() + 16);
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&encrypted);
        result.extend_from_slice(&tag.as_ref()[..16]);

        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&result)
    }

    /// Validate session token.
    #[must_use]
    pub fn validate_token(&self, token: &str) -> Option<Session> {
        let data = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(token)
            .ok()?;

        if data.len() < 34 {
            return None;
        }

        let nonce = &data[..16];
        let encrypted = &data[16..data.len() - 16];
        let mac = &data[data.len() - 16..];

        let key = self.derive_key("session");

        // Verify MAC
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &key);
        let mut hmac_data = Vec::with_capacity(16 + encrypted.len());
        hmac_data.extend_from_slice(nonce);
        hmac_data.extend_from_slice(encrypted);
        let expected_tag = hmac::sign(&hmac_key, &hmac_data);

        if mac.ct_eq(&expected_tag.as_ref()[..16]).unwrap_u8() != 1 {
            return None;
        }

        // Decrypt
        let keystream = generate_keystream(&key, nonce, encrypted.len());
        let token_data: Vec<u8> = encrypted
            .iter()
            .zip(keystream.iter())
            .map(|(c, k)| c ^ k)
            .collect();

        // Parse
        let user_id_len = u16::from_le_bytes([token_data[0], token_data[1]]) as usize;
        let user_id = String::from_utf8(token_data[2..2 + user_id_len].to_vec()).ok()?;

        let offset = 2 + user_id_len;
        let perms_len = u16::from_le_bytes([token_data[offset], token_data[offset + 1]]) as usize;
        let perms_json =
            String::from_utf8(token_data[offset + 2..offset + 2 + perms_len].to_vec()).ok()?;
        let permissions: Vec<String> = serde_json::from_str(&perms_json).ok()?;

        let exp_offset = offset + 2 + perms_len;
        let expires_at =
            u64::from_le_bytes(token_data[exp_offset..exp_offset + 8].try_into().ok()?);

        let session = Session {
            user_id,
            permissions,
            expires_at: Some(expires_at),
            attributes: HashMap::new(),
        };

        if session.is_expired() {
            return None;
        }

        Some(session)
    }

    /// Create service-specific token.
    #[must_use]
    pub fn create_service_token(
        &self,
        session_token: &str,
        service: &str,
        permissions: &[String],
        ttl: u64,
    ) -> Option<String> {
        let session = self.validate_token(session_token)?;

        let rng = SystemRandom::new();
        let mut nonce = [0u8; 16];
        rng.fill(&mut nonce).ok()?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let expires_at = now + ttl;

        // Serialize
        let user_id_bytes = session.user_id.as_bytes();
        let service_bytes = service.as_bytes();
        let perms_json = serde_json::to_string(permissions).unwrap();
        let perms_bytes = perms_json.as_bytes();

        let mut token_data = Vec::new();
        token_data.extend_from_slice(&(user_id_bytes.len() as u16).to_le_bytes());
        token_data.extend_from_slice(user_id_bytes);
        token_data.extend_from_slice(&(service_bytes.len() as u16).to_le_bytes());
        token_data.extend_from_slice(service_bytes);
        token_data.extend_from_slice(&(perms_bytes.len() as u16).to_le_bytes());
        token_data.extend_from_slice(perms_bytes);
        token_data.extend_from_slice(&expires_at.to_le_bytes());

        // Encrypt with service-specific key
        let key = self.derive_key(&format!("service:{service}"));
        let keystream = generate_keystream(&key, &nonce, token_data.len());
        let encrypted: Vec<u8> = token_data
            .iter()
            .zip(keystream.iter())
            .map(|(p, k)| p ^ k)
            .collect();

        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &key);
        let mut hmac_data = Vec::with_capacity(16 + encrypted.len());
        hmac_data.extend_from_slice(&nonce);
        hmac_data.extend_from_slice(&encrypted);
        let tag = hmac::sign(&hmac_key, &hmac_data);

        let mut result = Vec::with_capacity(16 + encrypted.len() + 16);
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&encrypted);
        result.extend_from_slice(&tag.as_ref()[..16]);

        Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&result))
    }

    /// Validate service token.
    #[must_use]
    pub fn validate_service_token(&self, token: &str, service: &str) -> Option<Session> {
        let data = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(token)
            .ok()?;

        if data.len() < 34 {
            return None;
        }

        let nonce = &data[..16];
        let encrypted = &data[16..data.len() - 16];
        let mac = &data[data.len() - 16..];

        let key = self.derive_key(&format!("service:{service}"));

        // Verify MAC
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &key);
        let mut hmac_data = Vec::with_capacity(16 + encrypted.len());
        hmac_data.extend_from_slice(nonce);
        hmac_data.extend_from_slice(encrypted);
        let expected_tag = hmac::sign(&hmac_key, &hmac_data);

        if mac.ct_eq(&expected_tag.as_ref()[..16]).unwrap_u8() != 1 {
            return None;
        }

        // Decrypt
        let keystream = generate_keystream(&key, nonce, encrypted.len());
        let token_data: Vec<u8> = encrypted
            .iter()
            .zip(keystream.iter())
            .map(|(c, k)| c ^ k)
            .collect();

        // Parse
        let mut offset = 0;
        let user_id_len = u16::from_le_bytes([token_data[offset], token_data[offset + 1]]) as usize;
        offset += 2;
        let user_id = String::from_utf8(token_data[offset..offset + user_id_len].to_vec()).ok()?;
        offset += user_id_len;

        let service_len = u16::from_le_bytes([token_data[offset], token_data[offset + 1]]) as usize;
        offset += 2;
        let token_service =
            String::from_utf8(token_data[offset..offset + service_len].to_vec()).ok()?;
        offset += service_len;

        if token_service != service {
            return None;
        }

        let perms_len = u16::from_le_bytes([token_data[offset], token_data[offset + 1]]) as usize;
        offset += 2;
        let perms_json = String::from_utf8(token_data[offset..offset + perms_len].to_vec()).ok()?;
        let permissions: Vec<String> = serde_json::from_str(&perms_json).ok()?;
        offset += perms_len;

        let expires_at = u64::from_le_bytes(token_data[offset..offset + 8].try_into().ok()?);

        let session = Session {
            user_id,
            permissions,
            expires_at: Some(expires_at),
            attributes: HashMap::new(),
        };

        if session.is_expired() {
            return None;
        }

        Some(session)
    }

    /// Refresh session token.
    #[must_use]
    pub fn refresh_token(&self, token: &str) -> Option<String> {
        let session = self.validate_token(token)?;
        Some(self.create_token(&session.user_id, &session.permissions, self.token_ttl))
    }

    /// Get user identity.
    #[must_use]
    pub fn get_identity(&self, user_id: &str) -> Option<&Identity> {
        self.users.get(user_id).map(|u| &u.identity)
    }

    /// Revoke user.
    pub fn revoke_user(&mut self, user_id: &str) {
        self.users.remove(user_id);
    }
}

/// Secure session with automatic key rotation.
pub struct SecureSession {
    master_key: [u8; 32],
    rotation_interval: u64,
    max_old_keys: usize,
    key_version: u32,
    keys: HashMap<u32, [u8; 32]>,
    last_rotation: u64,
}

impl SecureSession {
    /// Create new secure session.
    #[must_use]
    pub fn new(master_key: [u8; 32], rotation_interval: u64, max_old_keys: usize) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let key = Self::derive_session_key(&master_key, 1);
        let mut keys = HashMap::new();
        keys.insert(1, key);

        Self {
            master_key,
            rotation_interval: if rotation_interval == 0 {
                3600
            } else {
                rotation_interval
            },
            max_old_keys: if max_old_keys == 0 { 3 } else { max_old_keys },
            key_version: 1,
            keys,
            last_rotation: now,
        }
    }

    fn derive_session_key(master_key: &[u8; 32], version: u32) -> [u8; 32] {
        let mut data = Vec::with_capacity(32 + 16);
        data.extend_from_slice(master_key);
        data.extend_from_slice(format!("session:{version}").as_bytes());
        let hash = ring::digest::digest(&ring::digest::SHA256, &data);
        let mut key = [0u8; 32];
        key.copy_from_slice(hash.as_ref());
        key
    }

    fn maybe_rotate(&mut self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if now - self.last_rotation >= self.rotation_interval {
            self.key_version += 1;
            let new_key = Self::derive_session_key(&self.master_key, self.key_version);
            self.keys.insert(self.key_version, new_key);
            self.last_rotation = now;

            // Prune old keys
            let mut versions: Vec<u32> = self.keys.keys().copied().collect();
            versions.sort_by(|a, b| b.cmp(a));
            for v in versions.into_iter().skip(self.max_old_keys + 1) {
                self.keys.remove(&v);
            }
        }
    }

    /// Encrypt session data.
    pub fn encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        self.maybe_rotate();

        let key = self.keys.get(&self.key_version).unwrap();
        let rng = SystemRandom::new();
        let mut nonce = [0u8; 16];
        rng.fill(&mut nonce)
            .map_err(|_| ShieldError::RandomFailed)?;

        let keystream = generate_keystream(key, &nonce, data.len());
        let ciphertext: Vec<u8> = data
            .iter()
            .zip(keystream.iter())
            .map(|(p, k)| p ^ k)
            .collect();

        let version_bytes = self.key_version.to_le_bytes();

        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, key);
        let mut hmac_data = Vec::with_capacity(4 + 16 + ciphertext.len());
        hmac_data.extend_from_slice(&version_bytes);
        hmac_data.extend_from_slice(&nonce);
        hmac_data.extend_from_slice(&ciphertext);
        let tag = hmac::sign(&hmac_key, &hmac_data);

        let mut result = Vec::with_capacity(4 + 16 + ciphertext.len() + 16);
        result.extend_from_slice(&version_bytes);
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);
        result.extend_from_slice(&tag.as_ref()[..16]);

        Ok(result)
    }

    /// Decrypt session data.
    pub fn decrypt(&mut self, encrypted: &[u8]) -> Option<Vec<u8>> {
        self.maybe_rotate();

        if encrypted.len() < 36 {
            return None;
        }

        let version = u32::from_le_bytes(encrypted[..4].try_into().ok()?);
        let nonce = &encrypted[4..20];
        let ciphertext = &encrypted[20..encrypted.len() - 16];
        let mac = &encrypted[encrypted.len() - 16..];

        let key = self.keys.get(&version)?;

        // Verify MAC
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, key);
        let expected_tag = hmac::sign(&hmac_key, &encrypted[..encrypted.len() - 16]);

        if mac.ct_eq(&expected_tag.as_ref()[..16]).unwrap_u8() != 1 {
            return None;
        }

        let keystream = generate_keystream(key, nonce, ciphertext.len());
        let plaintext: Vec<u8> = ciphertext
            .iter()
            .zip(keystream.iter())
            .map(|(c, k)| c ^ k)
            .collect();

        Some(plaintext)
    }

    /// Get current key version (for testing).
    #[must_use]
    pub fn key_version(&self) -> u32 {
        self.key_version
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_user() {
        let mut provider = IdentityProvider::new([0u8; 32], 3600);
        let identity = provider
            .register("alice", "password123", Some("Alice Smith"), HashMap::new())
            .unwrap();

        assert_eq!(identity.user_id, "alice");
        assert_eq!(identity.display_name, "Alice Smith");
    }

    #[test]
    fn test_register_duplicate() {
        let mut provider = IdentityProvider::new([0u8; 32], 3600);
        provider
            .register("alice", "password", None, HashMap::new())
            .unwrap();
        assert!(provider
            .register("alice", "password2", None, HashMap::new())
            .is_err());
    }

    #[test]
    fn test_authenticate() {
        let mut provider = IdentityProvider::new([0u8; 32], 3600);
        provider
            .register("alice", "password123", None, HashMap::new())
            .unwrap();

        let token = provider.authenticate("alice", "password123", &[], None);
        assert!(token.is_some());
    }

    #[test]
    fn test_authenticate_wrong_password() {
        let mut provider = IdentityProvider::new([0u8; 32], 3600);
        provider
            .register("alice", "password123", None, HashMap::new())
            .unwrap();

        let token = provider.authenticate("alice", "wrongpassword", &[], None);
        assert!(token.is_none());
    }

    #[test]
    fn test_validate_token() {
        let mut provider = IdentityProvider::new([0u8; 32], 3600);
        provider
            .register("alice", "password", None, HashMap::new())
            .unwrap();
        let token = provider
            .authenticate("alice", "password", &[], None)
            .unwrap();

        let session = provider.validate_token(&token);
        assert!(session.is_some());
        assert_eq!(session.unwrap().user_id, "alice");
    }

    #[test]
    fn test_service_token() {
        let mut provider = IdentityProvider::new([0u8; 32], 3600);
        provider
            .register("alice", "password", None, HashMap::new())
            .unwrap();
        let session_token = provider
            .authenticate("alice", "password", &[], None)
            .unwrap();

        let service_token = provider
            .create_service_token(
                &session_token,
                "api.example.com",
                &["read".to_string()],
                300,
            )
            .unwrap();

        let session = provider.validate_service_token(&service_token, "api.example.com");
        assert!(session.is_some());
        assert_eq!(session.as_ref().unwrap().user_id, "alice");
        assert!(session.unwrap().has_permission("read"));
    }

    #[test]
    fn test_service_token_wrong_service() {
        let mut provider = IdentityProvider::new([0u8; 32], 3600);
        provider
            .register("alice", "password", None, HashMap::new())
            .unwrap();
        let session_token = provider
            .authenticate("alice", "password", &[], None)
            .unwrap();
        let service_token = provider
            .create_service_token(&session_token, "api.example.com", &[], 300)
            .unwrap();

        let session = provider.validate_service_token(&service_token, "other.example.com");
        assert!(session.is_none());
    }

    #[test]
    fn test_secure_session() {
        let mut session = SecureSession::new([0u8; 32], 3600, 3);
        let plaintext = b"session data";
        let encrypted = session.encrypt(plaintext).unwrap();
        let decrypted = session.decrypt(&encrypted).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_secure_session_tampered() {
        let mut session = SecureSession::new([0u8; 32], 3600, 3);
        let mut encrypted = session.encrypt(b"data").unwrap();
        encrypted[20] ^= 0xFF;
        assert!(session.decrypt(&encrypted).is_none());
    }
}
