//! Forward secrecy through key ratcheting.
//!
//! Each message uses a new key derived from previous.
//! Compromise of current key doesn't reveal past messages.
//!
//! Based on Signal's Double Ratchet (simplified symmetric version).

// Crypto block counters are intentionally u32 - data >4GB would have other issues
#![allow(clippy::cast_possible_truncation)]

use ring::hmac;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Result, ShieldError};

/// Ratcheting session for forward secrecy.
///
/// Each encrypt/decrypt advances the key chain,
/// destroying previous keys automatically.
///
/// Chain keys are securely zeroized from memory when dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RatchetSession {
    send_chain: [u8; 32],
    recv_chain: [u8; 32],
    #[zeroize(skip)]
    send_counter: u64,
    #[zeroize(skip)]
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

/// Derive chain key from root and label using HMAC-SHA256 (keyed PRF).
fn derive_chain_key(root: &[u8; 32], label: &[u8]) -> [u8; 32] {
    let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, root);
    let tag = hmac::sign(&hmac_key, label);
    let mut result = [0u8; 32];
    result.copy_from_slice(&tag.as_ref()[..32]);
    result
}

/// Ratchet chain forward using HMAC-SHA256, returning (`new_chain`, `message_key`).
fn ratchet_chain(chain_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, chain_key);

    // New chain key = HMAC(chain_key, "chain")
    let new_chain_tag = hmac::sign(&hmac_key, b"chain");
    let mut new_chain = [0u8; 32];
    new_chain.copy_from_slice(&new_chain_tag.as_ref()[..32]);

    // Message key = HMAC(chain_key, "message")
    let msg_tag = hmac::sign(&hmac_key, b"message");
    let mut msg_key = [0u8; 32];
    msg_key.copy_from_slice(&msg_tag.as_ref()[..32]);

    (new_chain, msg_key)
}

/// Encrypt with message key (includes counter).
fn encrypt_with_key(key: &[u8; 32], plaintext: &[u8], counter: u64) -> Result<Vec<u8>> {
    // Generate nonce
    let nonce: [u8; 16] = crate::random::random_bytes()?;

    // Counter header
    let counter_bytes = counter.to_le_bytes();

    // Data: counter || plaintext
    let mut data = Vec::with_capacity(8 + plaintext.len());
    data.extend_from_slice(&counter_bytes);
    data.extend_from_slice(plaintext);

    // Generate keystream using HMAC-SHA256 (keyed PRF)
    let num_blocks = data.len().div_ceil(32);
    assert!(u32::try_from(num_blocks).is_ok(), "keystream too long: counter overflow");
    let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let mut keystream = Vec::with_capacity(num_blocks * 32);
    for i in 0..num_blocks {
        let block_counter = (i as u32).to_le_bytes();
        let mut block_data = Vec::with_capacity(nonce.len() + 4);
        block_data.extend_from_slice(&nonce);
        block_data.extend_from_slice(&block_counter);
        let tag = hmac::sign(&hmac_key, &block_data);
        keystream.extend_from_slice(tag.as_ref());
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

    // Generate keystream using HMAC-SHA256 (keyed PRF)
    let num_blocks = ciphertext.len().div_ceil(32);
    assert!(u32::try_from(num_blocks).is_ok(), "keystream too long: counter overflow");
    let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let mut keystream = Vec::with_capacity(num_blocks * 32);
    for i in 0..num_blocks {
        let block_counter = (i as u32).to_le_bytes();
        let mut block_data = Vec::with_capacity(nonce.len() + 4);
        block_data.extend_from_slice(nonce);
        block_data.extend_from_slice(&block_counter);
        let tag = hmac::sign(&hmac_key, &block_data);
        keystream.extend_from_slice(tag.as_ref());
    }

    // XOR decrypt
    let decrypted: Vec<u8> = ciphertext
        .iter()
        .zip(keystream.iter())
        .map(|(c, k)| c ^ k)
        .collect();

    // Parse counter
    let counter = u64::from_le_bytes([
        decrypted[0],
        decrypted[1],
        decrypted[2],
        decrypted[3],
        decrypted[4],
        decrypted[5],
        decrypted[6],
        decrypted[7],
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
