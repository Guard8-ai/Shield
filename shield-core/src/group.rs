//! Multi-recipient encryption.
//!
//! Encrypt once for multiple recipients, each can decrypt with their own key.

// Member indices fit in u16 for practical group sizes (<65k members)
#![allow(clippy::cast_possible_truncation)]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ring::hmac;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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

/// Encrypt a block with HMAC authentication.
fn encrypt_block(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
    let nonce: [u8; 16] = crate::random::random_bytes()?;

    let keystream = generate_keystream(key, &nonce, data.len());
    let ciphertext: Vec<u8> = data
        .iter()
        .zip(keystream.iter())
        .map(|(p, k)| p ^ k)
        .collect();

    let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let mut hmac_data = Vec::with_capacity(16 + ciphertext.len());
    hmac_data.extend_from_slice(&nonce);
    hmac_data.extend_from_slice(&ciphertext);
    let tag = hmac::sign(&hmac_key, &hmac_data);

    let mut result = Vec::with_capacity(16 + ciphertext.len() + 16);
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);
    result.extend_from_slice(&tag.as_ref()[..16]);

    Ok(result)
}

/// Decrypt a block with HMAC verification.
fn decrypt_block(key: &[u8; 32], encrypted: &[u8]) -> Result<Vec<u8>> {
    if encrypted.len() < 32 {
        return Err(ShieldError::CiphertextTooShort {
            expected: 32,
            actual: encrypted.len(),
        });
    }

    let nonce = &encrypted[..16];
    let ciphertext = &encrypted[16..encrypted.len() - 16];
    let mac = &encrypted[encrypted.len() - 16..];

    let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let mut hmac_data = Vec::with_capacity(16 + ciphertext.len());
    hmac_data.extend_from_slice(nonce);
    hmac_data.extend_from_slice(ciphertext);
    let expected_tag = hmac::sign(&hmac_key, &hmac_data);

    if mac.ct_eq(&expected_tag.as_ref()[..16]).unwrap_u8() != 1 {
        return Err(ShieldError::AuthenticationFailed);
    }

    let keystream = generate_keystream(key, nonce, ciphertext.len());
    let plaintext: Vec<u8> = ciphertext
        .iter()
        .zip(keystream.iter())
        .map(|(c, k)| c ^ k)
        .collect();

    Ok(plaintext)
}

/// Encrypted group message format.
#[derive(Serialize, Deserialize)]
pub struct EncryptedGroupMessage {
    pub version: u8,
    pub ciphertext: String,
    pub keys: HashMap<String, String>,
}

/// Multi-recipient encryption.
pub struct GroupEncryption {
    group_key: [u8; 32],
    members: HashMap<String, [u8; 32]>,
}

impl GroupEncryption {
    /// Create new group encryption.
    pub fn new(group_key: Option<[u8; 32]>) -> Result<Self> {
        let key = if let Some(k) = group_key {
            k
        } else {
            crate::random::random_bytes()?
        };

        Ok(Self {
            group_key: key,
            members: HashMap::new(),
        })
    }

    /// Add member to group.
    pub fn add_member(&mut self, member_id: &str, shared_key: [u8; 32]) {
        self.members.insert(member_id.to_string(), shared_key);
    }

    /// Remove member from group.
    pub fn remove_member(&mut self, member_id: &str) -> bool {
        self.members.remove(member_id).is_some()
    }

    /// Get member list.
    pub fn members(&self) -> Vec<&str> {
        self.members.keys().map(String::as_str).collect()
    }

    /// Encrypt for all group members.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedGroupMessage> {
        let ciphertext = encrypt_block(&self.group_key, plaintext)?;

        let mut keys = HashMap::new();
        for (member_id, member_key) in &self.members {
            let encrypted_key = encrypt_block(member_key, &self.group_key)?;
            keys.insert(member_id.clone(), URL_SAFE_NO_PAD.encode(&encrypted_key));
        }

        Ok(EncryptedGroupMessage {
            version: 1,
            ciphertext: URL_SAFE_NO_PAD.encode(&ciphertext),
            keys,
        })
    }

    /// Decrypt as group member.
    pub fn decrypt_as_member(
        encrypted: &EncryptedGroupMessage,
        member_id: &str,
        member_key: &[u8; 32],
    ) -> Result<Vec<u8>> {
        let encrypted_group_key = encrypted
            .keys
            .get(member_id)
            .ok_or(ShieldError::MemberNotFound)?;

        let encrypted_key_bytes = URL_SAFE_NO_PAD
            .decode(encrypted_group_key)
            .map_err(|_| ShieldError::InvalidFormat)?;

        let group_key_vec = decrypt_block(member_key, &encrypted_key_bytes)?;
        let mut group_key = [0u8; 32];
        group_key.copy_from_slice(&group_key_vec);

        let ciphertext = URL_SAFE_NO_PAD
            .decode(&encrypted.ciphertext)
            .map_err(|_| ShieldError::InvalidFormat)?;

        decrypt_block(&group_key, &ciphertext)
    }

    /// Rotate the group key.
    pub fn rotate_key(&mut self) -> Result<[u8; 32]> {
        let old_key = self.group_key;
        self.group_key = crate::random::random_bytes()?;
        Ok(old_key)
    }

    /// Get the group key.
    #[must_use]
    pub fn group_key(&self) -> &[u8; 32] {
        &self.group_key
    }
}

/// Encrypted broadcast message format.
#[derive(Serialize, Deserialize)]
pub struct EncryptedBroadcast {
    pub version: u8,
    pub ciphertext: String,
    pub subgroups: HashMap<String, String>,
    pub members: HashMap<String, MemberKeyData>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct MemberKeyData {
    pub sg: u32,
    pub key: String,
}

/// Efficient broadcast encryption for large groups.
pub struct BroadcastEncryption {
    #[allow(dead_code)]
    master_key: [u8; 32],
    subgroup_size: usize,
    members: HashMap<String, (u32, [u8; 32])>,
    subgroup_keys: HashMap<u32, [u8; 32]>,
    next_subgroup: u32,
}

impl BroadcastEncryption {
    /// Create new broadcast encryption.
    pub fn new(master_key: Option<[u8; 32]>, subgroup_size: usize) -> Result<Self> {
        let key = if let Some(k) = master_key {
            k
        } else {
            crate::random::random_bytes()?
        };

        Ok(Self {
            master_key: key,
            subgroup_size: if subgroup_size == 0 {
                16
            } else {
                subgroup_size
            },
            members: HashMap::new(),
            subgroup_keys: HashMap::new(),
            next_subgroup: 0,
        })
    }

    /// Add member to broadcast group.
    pub fn add_member(&mut self, member_id: &str, member_key: [u8; 32]) -> Result<u32> {
        // Find subgroup with space
        let mut subgroup_id = None;
        for sg_id in self.subgroup_keys.keys() {
            let count = self.members.values().filter(|(sg, _)| sg == sg_id).count();
            if count < self.subgroup_size {
                subgroup_id = Some(*sg_id);
                break;
            }
        }

        let sg_id = if let Some(id) = subgroup_id {
            id
        } else {
            let id = self.next_subgroup;
            let sg_key: [u8; 32] = crate::random::random_bytes()?;
            self.subgroup_keys.insert(id, sg_key);
            self.next_subgroup += 1;
            id
        };

        self.members
            .insert(member_id.to_string(), (sg_id, member_key));
        Ok(sg_id)
    }

    /// Encrypt for broadcast.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedBroadcast> {
        let message_key: [u8; 32] = crate::random::random_bytes()?;

        // Encrypt message
        let ciphertext = encrypt_block(&message_key, plaintext)?;

        // Encrypt message key for each subgroup
        let mut subgroups = HashMap::new();
        for (sg_id, sg_key) in &self.subgroup_keys {
            let encrypted_msg_key = encrypt_block(sg_key, &message_key)?;
            subgroups.insert(
                sg_id.to_string(),
                URL_SAFE_NO_PAD.encode(&encrypted_msg_key),
            );
        }

        // Encrypt subgroup keys for each member
        let mut members = HashMap::new();
        for (member_id, (sg_id, member_key)) in &self.members {
            let sg_key = self.subgroup_keys.get(sg_id).unwrap();
            let encrypted_sg_key = encrypt_block(member_key, sg_key)?;
            members.insert(
                member_id.clone(),
                MemberKeyData {
                    sg: *sg_id,
                    key: URL_SAFE_NO_PAD.encode(&encrypted_sg_key),
                },
            );
        }

        Ok(EncryptedBroadcast {
            version: 1,
            ciphertext: URL_SAFE_NO_PAD.encode(&ciphertext),
            subgroups,
            members,
        })
    }

    /// Decrypt broadcast as member.
    pub fn decrypt_as_member(
        encrypted: &EncryptedBroadcast,
        member_id: &str,
        member_key: &[u8; 32],
    ) -> Result<Vec<u8>> {
        let member_data = encrypted
            .members
            .get(member_id)
            .ok_or(ShieldError::MemberNotFound)?;

        // Decrypt subgroup key
        let sg_key_enc = URL_SAFE_NO_PAD
            .decode(&member_data.key)
            .map_err(|_| ShieldError::InvalidFormat)?;
        let sg_key_vec = decrypt_block(member_key, &sg_key_enc)?;
        let mut sg_key = [0u8; 32];
        sg_key.copy_from_slice(&sg_key_vec);

        // Decrypt message key
        let msg_key_enc = URL_SAFE_NO_PAD
            .decode(
                encrypted
                    .subgroups
                    .get(&member_data.sg.to_string())
                    .ok_or(ShieldError::InvalidFormat)?,
            )
            .map_err(|_| ShieldError::InvalidFormat)?;
        let msg_key_vec = decrypt_block(&sg_key, &msg_key_enc)?;
        let mut msg_key = [0u8; 32];
        msg_key.copy_from_slice(&msg_key_vec);

        // Decrypt message
        let ciphertext = URL_SAFE_NO_PAD
            .decode(&encrypted.ciphertext)
            .map_err(|_| ShieldError::InvalidFormat)?;
        decrypt_block(&msg_key, &ciphertext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_group_encrypt_decrypt() {
        let mut group = GroupEncryption::new(None).unwrap();
        let alice_key = [1u8; 32];
        let bob_key = [2u8; 32];

        group.add_member("alice", alice_key);
        group.add_member("bob", bob_key);

        let plaintext = b"Group message!";
        let encrypted = group.encrypt(plaintext).unwrap();

        let alice_decrypted =
            GroupEncryption::decrypt_as_member(&encrypted, "alice", &alice_key).unwrap();
        let bob_decrypted =
            GroupEncryption::decrypt_as_member(&encrypted, "bob", &bob_key).unwrap();

        assert_eq!(plaintext.as_slice(), alice_decrypted.as_slice());
        assert_eq!(plaintext.as_slice(), bob_decrypted.as_slice());
    }

    #[test]
    fn test_group_non_member() {
        let mut group = GroupEncryption::new(None).unwrap();
        group.add_member("alice", [1u8; 32]);

        let encrypted = group.encrypt(b"secret").unwrap();
        let result = GroupEncryption::decrypt_as_member(&encrypted, "eve", &[3u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn test_group_remove_member() {
        let mut group = GroupEncryption::new(None).unwrap();
        group.add_member("alice", [1u8; 32]);
        group.add_member("bob", [2u8; 32]);

        assert_eq!(group.members().len(), 2);
        group.remove_member("bob");
        assert_eq!(group.members().len(), 1);
    }

    #[test]
    fn test_broadcast_encrypt_decrypt() {
        let mut broadcast = BroadcastEncryption::new(None, 2).unwrap();
        let alice_key = [1u8; 32];
        let bob_key = [2u8; 32];

        broadcast.add_member("alice", alice_key).unwrap();
        broadcast.add_member("bob", bob_key).unwrap();

        let plaintext = b"Broadcast message!";
        let encrypted = broadcast.encrypt(plaintext).unwrap();

        let alice_decrypted =
            BroadcastEncryption::decrypt_as_member(&encrypted, "alice", &alice_key).unwrap();
        let bob_decrypted =
            BroadcastEncryption::decrypt_as_member(&encrypted, "bob", &bob_key).unwrap();

        assert_eq!(plaintext.as_slice(), alice_decrypted.as_slice());
        assert_eq!(plaintext.as_slice(), bob_decrypted.as_slice());
    }

    #[test]
    fn test_broadcast_subgroups() {
        let mut broadcast = BroadcastEncryption::new(None, 2).unwrap();

        let sg1 = broadcast.add_member("alice", [1u8; 32]).unwrap();
        let sg2 = broadcast.add_member("bob", [2u8; 32]).unwrap();
        let sg3 = broadcast.add_member("carol", [3u8; 32]).unwrap();

        // First two in same subgroup
        assert_eq!(sg1, 0);
        assert_eq!(sg2, 0);
        // Third in new subgroup
        assert_eq!(sg3, 1);
    }
}
