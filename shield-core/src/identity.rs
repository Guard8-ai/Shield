//! Identity and SSO without public-key cryptography.
//!
//! Provides identity management, session tokens, and service tokens.

// Token timestamps and indices use intentional truncation for compact encoding
#![allow(clippy::cast_possible_truncation)]

use base64::Engine;
use ring::hmac;
use std::collections::HashMap;
use std::num::NonZeroU32;
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::error::{Result, ShieldError};

/// Generate keystream using HMAC-SHA256 (keyed PRF).
fn generate_keystream(key: &[u8], nonce: &[u8], length: usize) -> Vec<u8> {
    let mut keystream = Vec::with_capacity(length.div_ceil(32) * 32);
    let num_blocks = length.div_ceil(32);
    let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, key);

    for i in 0..num_blocks {
        let counter = (i as u32).to_le_bytes();
        let mut data = Vec::with_capacity(nonce.len() + 4);
        data.extend_from_slice(nonce);
        data.extend_from_slice(&counter);

        let tag = hmac::sign(&hmac_key, &data);
        keystream.extend_from_slice(tag.as_ref());
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
                    .map_or(0, |d| d.as_secs());
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

    /// Derive key for specific purpose using HMAC-SHA256 (keyed PRF).
    fn derive_key(&self, purpose: &str) -> [u8; 32] {
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &self.master_key);
        let tag = hmac::sign(&hmac_key, purpose.as_bytes());
        let mut key = [0u8; 32];
        key.copy_from_slice(&tag.as_ref()[..32]);
        key
    }

    /// Derive separated encryption and MAC subkeys for token operations.
    /// Prevents key reuse between encryption and authentication.
    fn derive_token_subkeys(&self, purpose: &str) -> ([u8; 32], [u8; 32]) {
        let base_key = self.derive_key(purpose);
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &base_key);

        let enc_tag = hmac::sign(&hmac_key, b"shield-token-encrypt");
        let mut enc_key = [0u8; 32];
        enc_key.copy_from_slice(&enc_tag.as_ref()[..32]);

        let mac_tag = hmac::sign(&hmac_key, b"shield-token-authenticate");
        let mut mac_key = [0u8; 32];
        mac_key.copy_from_slice(&mac_tag.as_ref()[..32]);

        (enc_key, mac_key)
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

        let salt: [u8; 16] = crate::random::random_bytes()?;

        let mut password_hash = [0u8; 32];
        ring::pbkdf2::derive(
            ring::pbkdf2::PBKDF2_HMAC_SHA256,
            NonZeroU32::new(Self::ITERATIONS).unwrap(),
            &salt,
            password.as_bytes(),
            &mut password_hash,
        );

        // Generate verification key using HMAC-SHA256 (keyed PRF)
        let verify_key = self.derive_key("verify");
        let vk_hmac = hmac::Key::new(hmac::HMAC_SHA256, &verify_key);
        let vk_tag = hmac::sign(&vk_hmac, user_id.as_bytes());
        let mut verification_key = [0u8; 32];
        verification_key.copy_from_slice(&vk_tag.as_ref()[..32]);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());

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
    ///
    /// Runs PBKDF2 even for non-existent users to prevent timing-based
    /// user enumeration (CWE-203).
    #[must_use]
    pub fn authenticate(
        &self,
        user_id: &str,
        password: &str,
        permissions: &[String],
        ttl: Option<u64>,
    ) -> Option<String> {
        // Use real salt if user exists, otherwise derive a stable dummy salt
        // to ensure constant-time behavior regardless of user existence.
        let dummy_salt = self.derive_key("dummy-salt");
        let (salt, expected_hash, user_exists) = match self.users.get(user_id) {
            Some(user) => (user.salt, user.password_hash, true),
            None => {
                let mut dummy = [0u8; 16];
                dummy.copy_from_slice(&dummy_salt[..16]);
                (dummy, [0u8; 32], false)
            }
        };

        let mut password_hash = [0u8; 32];
        ring::pbkdf2::derive(
            ring::pbkdf2::PBKDF2_HMAC_SHA256,
            NonZeroU32::new(Self::ITERATIONS).unwrap(),
            &salt,
            password.as_bytes(),
            &mut password_hash,
        );

        if !user_exists || password_hash.ct_eq(&expected_hash).unwrap_u8() != 1 {
            return None;
        }

        Some(self.create_token(user_id, permissions, ttl.unwrap_or(self.token_ttl)))
    }

    /// Create session token.
    fn create_token(&self, user_id: &str, permissions: &[String], ttl: u64) -> String {
        let nonce: [u8; 16] = crate::random::random_bytes().unwrap_or([0u8; 16]);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let expires_at = now + ttl;

        // Serialize token data
        let user_id_bytes = user_id.as_bytes();
        let perms_json = serde_json::to_string(permissions).unwrap_or_default();
        let perms_bytes = perms_json.as_bytes();

        let mut token_data = Vec::new();
        token_data.extend_from_slice(&(user_id_bytes.len() as u16).to_le_bytes());
        token_data.extend_from_slice(user_id_bytes);
        token_data.extend_from_slice(&(perms_bytes.len() as u16).to_le_bytes());
        token_data.extend_from_slice(perms_bytes);
        token_data.extend_from_slice(&expires_at.to_le_bytes());

        // Derive separate encryption and MAC keys
        let (enc_key, mac_key) = self.derive_token_subkeys("session");

        // Encrypt with enc_key
        let keystream = generate_keystream(&enc_key, &nonce, token_data.len());
        let encrypted: Vec<u8> = token_data
            .iter()
            .zip(keystream.iter())
            .map(|(p, k)| p ^ k)
            .collect();

        // MAC with mac_key
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &mac_key);
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

        // Derive separate encryption and MAC keys
        let (enc_key, mac_key) = self.derive_token_subkeys("session");

        // Verify MAC with mac_key
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &mac_key);
        let mut hmac_data = Vec::with_capacity(16 + encrypted.len());
        hmac_data.extend_from_slice(nonce);
        hmac_data.extend_from_slice(encrypted);
        let expected_tag = hmac::sign(&hmac_key, &hmac_data);

        if mac.ct_eq(&expected_tag.as_ref()[..16]).unwrap_u8() != 1 {
            return None;
        }

        // Decrypt with enc_key
        let keystream = generate_keystream(&enc_key, nonce, encrypted.len());
        let token_data: Vec<u8> = encrypted
            .iter()
            .zip(keystream.iter())
            .map(|(c, k)| c ^ k)
            .collect();

        // Parse with bounds checks to prevent panics on malformed data
        if token_data.len() < 2 {
            return None;
        }
        let user_id_len = u16::from_le_bytes([token_data[0], token_data[1]]) as usize;
        if token_data.len() < 2 + user_id_len + 2 {
            return None;
        }
        let user_id = String::from_utf8(token_data[2..2 + user_id_len].to_vec()).ok()?;

        let offset = 2 + user_id_len;
        let perms_len = u16::from_le_bytes([token_data[offset], token_data[offset + 1]]) as usize;
        if token_data.len() < offset + 2 + perms_len + 8 {
            return None;
        }
        let perms_json =
            String::from_utf8(token_data[offset + 2..offset + 2 + perms_len].to_vec()).ok()?;
        let permissions: Vec<String> = serde_json::from_str(&perms_json).ok()?;

        let exp_offset = offset + 2 + perms_len;
        let expires_at =
            u64::from_le_bytes(token_data[exp_offset..exp_offset + 8].try_into().ok()?);

        // Reject tokens for revoked/unregistered users
        if !self.users.contains_key(&user_id) {
            return None;
        }

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

        let nonce: [u8; 16] = crate::random::random_bytes().ok()?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let expires_at = now + ttl;

        // Serialize
        let user_id_bytes = session.user_id.as_bytes();
        let service_bytes = service.as_bytes();
        let perms_json = serde_json::to_string(permissions).unwrap_or_default();
        let perms_bytes = perms_json.as_bytes();

        let mut token_data = Vec::new();
        token_data.extend_from_slice(&(user_id_bytes.len() as u16).to_le_bytes());
        token_data.extend_from_slice(user_id_bytes);
        token_data.extend_from_slice(&(service_bytes.len() as u16).to_le_bytes());
        token_data.extend_from_slice(service_bytes);
        token_data.extend_from_slice(&(perms_bytes.len() as u16).to_le_bytes());
        token_data.extend_from_slice(perms_bytes);
        token_data.extend_from_slice(&expires_at.to_le_bytes());

        // Derive separate enc/mac keys for service-specific token
        let (enc_key, mac_key) = self.derive_token_subkeys(&format!("service:{service}"));
        let keystream = generate_keystream(&enc_key, &nonce, token_data.len());
        let encrypted: Vec<u8> = token_data
            .iter()
            .zip(keystream.iter())
            .map(|(p, k)| p ^ k)
            .collect();

        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &mac_key);
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

        // Derive separate enc/mac keys for service token
        let (enc_key, mac_key) = self.derive_token_subkeys(&format!("service:{service}"));

        // Verify MAC with mac_key
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &mac_key);
        let mut hmac_data = Vec::with_capacity(16 + encrypted.len());
        hmac_data.extend_from_slice(nonce);
        hmac_data.extend_from_slice(encrypted);
        let expected_tag = hmac::sign(&hmac_key, &hmac_data);

        if mac.ct_eq(&expected_tag.as_ref()[..16]).unwrap_u8() != 1 {
            return None;
        }

        // Decrypt with enc_key
        let keystream = generate_keystream(&enc_key, nonce, encrypted.len());
        let token_data: Vec<u8> = encrypted
            .iter()
            .zip(keystream.iter())
            .map(|(c, k)| c ^ k)
            .collect();

        // Parse with bounds checks
        let mut offset = 0;
        if token_data.len() < offset + 2 {
            return None;
        }
        let user_id_len = u16::from_le_bytes([token_data[offset], token_data[offset + 1]]) as usize;
        offset += 2;
        if token_data.len() < offset + user_id_len + 2 {
            return None;
        }
        let user_id = String::from_utf8(token_data[offset..offset + user_id_len].to_vec()).ok()?;
        offset += user_id_len;

        let service_len = u16::from_le_bytes([token_data[offset], token_data[offset + 1]]) as usize;
        offset += 2;
        if token_data.len() < offset + service_len + 2 {
            return None;
        }
        let token_service =
            String::from_utf8(token_data[offset..offset + service_len].to_vec()).ok()?;
        offset += service_len;

        if token_service != service {
            return None;
        }

        let perms_len = u16::from_le_bytes([token_data[offset], token_data[offset + 1]]) as usize;
        offset += 2;
        if token_data.len() < offset + perms_len + 8 {
            return None;
        }
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
            .map_or(0, |d| d.as_secs());

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
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, master_key);
        let tag = hmac::sign(&hmac_key, format!("session:{version}").as_bytes());
        let mut key = [0u8; 32];
        key.copy_from_slice(&tag.as_ref()[..32]);
        key
    }

    fn maybe_rotate(&mut self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());

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

        let key = self
            .keys
            .get(&self.key_version)
            .ok_or(ShieldError::UnknownVersion(self.key_version))?;
        let nonce: [u8; 16] = crate::random::random_bytes()?;

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

impl Drop for IdentityProvider {
    fn drop(&mut self) {
        self.master_key.zeroize();
        for user in self.users.values_mut() {
            user.password_hash.zeroize();
            user.salt.zeroize();
        }
    }
}

impl Drop for SecureSession {
    fn drop(&mut self) {
        self.master_key.zeroize();
        for key in self.keys.values_mut() {
            key.zeroize();
        }
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
