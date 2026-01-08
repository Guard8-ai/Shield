//! Forward secrecy through key ratcheting.
//!
//! Each message uses a new key derived from previous.
//! Compromise of current key doesn't reveal past messages.
//!
//! Based on Signal's Double Ratchet (simplified symmetric version).

// Crypto block counters are intentionally u32 - data >4GB would have other issues
#![allow(clippy::cast_possible_truncation)]

use ring::{digest, hmac, rand::{SecureRandom, SystemRandom}};
use subtle::ConstantTimeEq;

use crate::error::{Result, ShieldError};

/// Ratcheting session for forward secrecy.
///
/// Each encrypt/decrypt advances the key chain,
/// destroying previous keys automatically.
pub struct RatchetSession {
    send_chain: [u8; 32],
    recv_chain: [u8; 32],
    send_counter: u64,
    recv_counter: u64,
}

impl RatchetSession {
    /// Create a new ratchet session from shared root key.
    ///
    /// # Arguments
    /// * `root_key` - Shared secret from key exchange
    /// * `is_initiator` - True if this party initiated the session
    #[must_use]
    pub fn new(root_key: &[u8; 32], is_initiator: bool) -> Self {
        // Derive separate send/receive chains
        let (send_label, recv_label) = if is_initiator {
            (b"send", b"recv")
        } else {
            (b"recv", b"send")
        };

        let send_chain = derive_chain_key(root_key, send_label);
        let recv_chain = derive_chain_key(root_key, recv_label);

        Self {
            send_chain,
            recv_chain,
            send_counter: 0,
            recv_counter: 0,
        }
    }

    /// Encrypt a message with forward secrecy.
    ///
    /// Advances the send chain - previous keys are destroyed.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        // Ratchet send chain
        let (new_chain, msg_key) = ratchet_chain(&self.send_chain);
        self.send_chain = new_chain;

        // Counter for ordering
        let counter = self.send_counter;
        self.send_counter += 1;

        // Encrypt with message key
        encrypt_with_key(&msg_key, plaintext, counter)
    }

    /// Decrypt a message with forward secrecy.
    ///
    /// Advances the receive chain - previous keys are destroyed.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        // Ratchet receive chain
        let (new_chain, msg_key) = ratchet_chain(&self.recv_chain);
        self.recv_chain = new_chain;

        // Decrypt with message key
        let (plaintext, counter) = decrypt_with_key(&msg_key, ciphertext)?;

        // Verify counter (replay protection)
        if counter != self.recv_counter {
            return Err(ShieldError::RatchetError(format!(
                "out of order message: expected {}, got {}",
                self.recv_counter, counter
            )));
        }
        self.recv_counter += 1;

        Ok(plaintext)
    }

    /// Get send counter (for diagnostics).
    #[must_use]
    pub fn send_counter(&self) -> u64 {
        self.send_counter
    }

    /// Get receive counter (for diagnostics).
    #[must_use]
    pub fn recv_counter(&self) -> u64 {
        self.recv_counter
    }
}

/// Derive chain key from root and label.
fn derive_chain_key(root: &[u8; 32], label: &[u8]) -> [u8; 32] {
    let mut data = Vec::with_capacity(root.len() + label.len());
    data.extend_from_slice(root);
    data.extend_from_slice(label);

    let hash = digest::digest(&digest::SHA256, &data);
    let mut result = [0u8; 32];
    result.copy_from_slice(hash.as_ref());
    result
}

/// Ratchet chain forward, returning (`new_chain`, `message_key`).
fn ratchet_chain(chain_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    // New chain key
    let mut chain_data = Vec::with_capacity(chain_key.len() + 5);
    chain_data.extend_from_slice(chain_key);
    chain_data.extend_from_slice(b"chain");
    let new_chain_hash = digest::digest(&digest::SHA256, &chain_data);
    let mut new_chain = [0u8; 32];
    new_chain.copy_from_slice(new_chain_hash.as_ref());

    // Message key
    let mut msg_data = Vec::with_capacity(chain_key.len() + 7);
    msg_data.extend_from_slice(chain_key);
    msg_data.extend_from_slice(b"message");
    let msg_hash = digest::digest(&digest::SHA256, &msg_data);
    let mut msg_key = [0u8; 32];
    msg_key.copy_from_slice(msg_hash.as_ref());

    (new_chain, msg_key)
}

/// Encrypt with message key (includes counter).
fn encrypt_with_key(key: &[u8; 32], plaintext: &[u8], counter: u64) -> Result<Vec<u8>> {
    let rng = SystemRandom::new();

    // Generate nonce
    let mut nonce = [0u8; 16];
    rng.fill(&mut nonce).map_err(|_| ShieldError::RandomFailed)?;

    // Counter header
    let counter_bytes = counter.to_le_bytes();

    // Data: counter || plaintext
    let mut data = Vec::with_capacity(8 + plaintext.len());
    data.extend_from_slice(&counter_bytes);
    data.extend_from_slice(plaintext);

    // Generate keystream
    let mut keystream = Vec::with_capacity(data.len().div_ceil(32) * 32);
    for i in 0..data.len().div_ceil(32) {
        let block_counter = (i as u32).to_le_bytes();
        let mut hash_input = Vec::with_capacity(key.len() + nonce.len() + 4);
        hash_input.extend_from_slice(key);
        hash_input.extend_from_slice(&nonce);
        hash_input.extend_from_slice(&block_counter);
        let hash = digest::digest(&digest::SHA256, &hash_input);
        keystream.extend_from_slice(hash.as_ref());
    }

    // XOR encrypt
    let ciphertext: Vec<u8> = data
        .iter()
        .zip(keystream.iter())
        .map(|(p, k)| p ^ k)
        .collect();

    // HMAC
    let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let mut hmac_data = Vec::with_capacity(16 + ciphertext.len());
    hmac_data.extend_from_slice(&nonce);
    hmac_data.extend_from_slice(&ciphertext);
    let tag = hmac::sign(&hmac_key, &hmac_data);

    // Format: nonce(16) || ciphertext || mac(16)
    let mut result = Vec::with_capacity(16 + ciphertext.len() + 16);
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);
    result.extend_from_slice(&tag.as_ref()[..16]);

    Ok(result)
}

/// Decrypt with message key, returns (plaintext, counter).
fn decrypt_with_key(key: &[u8; 32], encrypted: &[u8]) -> Result<(Vec<u8>, u64)> {
    if encrypted.len() < 40 {
        return Err(ShieldError::RatchetError("ciphertext too short".into()));
    }

    let nonce = &encrypted[..16];
    let ciphertext = &encrypted[16..encrypted.len() - 16];
    let mac = &encrypted[encrypted.len() - 16..];

    // Verify MAC
    let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let mut hmac_data = Vec::with_capacity(16 + ciphertext.len());
    hmac_data.extend_from_slice(nonce);
    hmac_data.extend_from_slice(ciphertext);
    let expected = hmac::sign(&hmac_key, &hmac_data);

    if mac.ct_eq(&expected.as_ref()[..16]).unwrap_u8() != 1 {
        return Err(ShieldError::AuthenticationFailed);
    }

    // Generate keystream
    let mut keystream = Vec::with_capacity(ciphertext.len().div_ceil(32) * 32);
    for i in 0..ciphertext.len().div_ceil(32) {
        let block_counter = (i as u32).to_le_bytes();
        let mut hash_input = Vec::with_capacity(key.len() + nonce.len() + 4);
        hash_input.extend_from_slice(key);
        hash_input.extend_from_slice(nonce);
        hash_input.extend_from_slice(&block_counter);
        let hash = digest::digest(&digest::SHA256, &hash_input);
        keystream.extend_from_slice(hash.as_ref());
    }

    // XOR decrypt
    let decrypted: Vec<u8> = ciphertext
        .iter()
        .zip(keystream.iter())
        .map(|(c, k)| c ^ k)
        .collect();

    // Parse counter
    let counter = u64::from_le_bytes([
        decrypted[0], decrypted[1], decrypted[2], decrypted[3],
        decrypted[4], decrypted[5], decrypted[6], decrypted[7],
    ]);

    Ok((decrypted[8..].to_vec(), counter))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ratchet_roundtrip() {
        let root = [0x42u8; 32];
        let mut alice = RatchetSession::new(&root, true);
        let mut bob = RatchetSession::new(&root, false);

        let msg1 = b"Hello Bob!";
        let enc1 = alice.encrypt(msg1).unwrap();
        let dec1 = bob.decrypt(&enc1).unwrap();
        assert_eq!(msg1.as_slice(), dec1.as_slice());

        let msg2 = b"Second message";
        let enc2 = alice.encrypt(msg2).unwrap();
        let dec2 = bob.decrypt(&enc2).unwrap();
        assert_eq!(msg2.as_slice(), dec2.as_slice());
    }

    #[test]
    fn test_ratchet_counters() {
        let root = [0x42u8; 32];
        let mut alice = RatchetSession::new(&root, true);
        let mut bob = RatchetSession::new(&root, false);

        assert_eq!(alice.send_counter(), 0);
        assert_eq!(bob.recv_counter(), 0);

        let enc = alice.encrypt(b"test").unwrap();
        assert_eq!(alice.send_counter(), 1);

        bob.decrypt(&enc).unwrap();
        assert_eq!(bob.recv_counter(), 1);
    }

    #[test]
    fn test_ratchet_different_ciphertexts() {
        let root = [0x42u8; 32];
        let mut alice = RatchetSession::new(&root, true);

        let enc1 = alice.encrypt(b"same message").unwrap();
        let enc2 = alice.encrypt(b"same message").unwrap();

        // Different ciphertext for same plaintext (forward secrecy)
        assert_ne!(enc1, enc2);
    }

    #[test]
    fn test_ratchet_replay_detection() {
        let root = [0x42u8; 32];
        let mut alice = RatchetSession::new(&root, true);
        let mut bob = RatchetSession::new(&root, false);

        // Send two messages
        let _enc1 = alice.encrypt(b"first").unwrap();
        let enc2 = alice.encrypt(b"second").unwrap();

        // Try to decrypt second message first (out of order)
        // This should fail because Bob expects counter 0, but gets counter 1
        assert!(bob.decrypt(&enc2).is_err());
    }
}
