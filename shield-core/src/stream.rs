//! Streaming encryption for large files.
//!
//! Processes data in chunks with per-chunk authentication.
//! Matches Python `StreamCipher` from `shield_enterprise.py`.

// Crypto block/chunk counters are intentionally u32 - data >4GB would have other issues
#![allow(clippy::cast_possible_truncation)]

use ring::{digest, hmac};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Result, ShieldError};

/// Default chunk size: 64KB
const DEFAULT_CHUNK_SIZE: usize = 64 * 1024;

/// Stream cipher for large file encryption.
///
/// Each chunk is independently authenticated, allowing:
/// - Constant memory usage regardless of file size
/// - Early detection of tampering
/// - Potential for parallel processing
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct StreamCipher {
    key: [u8; 32],
    #[zeroize(skip)]
    chunk_size: usize,
}

impl StreamCipher {
    /// Create a new stream cipher with the given key.
    #[must_use]
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            key,
            chunk_size: DEFAULT_CHUNK_SIZE,
        }
    }

    /// Create with custom chunk size.
    #[must_use]
    pub fn with_chunk_size(key: [u8; 32], chunk_size: usize) -> Self {
        Self { key, chunk_size }
    }

    /// Get the chunk size.
    #[must_use]
    pub fn chunk_size(&self) -> usize {
        self.chunk_size
    }

    /// Encrypt a stream of data.
    ///
    /// Returns an iterator over encrypted chunks.
    /// First chunk is the header containing stream salt.
    pub fn encrypt_stream<'a>(&'a self, data: &'a [u8]) -> Result<StreamEncryptor<'a>> {
        StreamEncryptor::new(&self.key, data, self.chunk_size)
    }

    /// Decrypt a stream of encrypted chunks.
    pub fn decrypt_stream(&self, encrypted: &[u8]) -> Result<Vec<u8>> {
        if encrypted.len() < 20 {
            return Err(ShieldError::StreamError("encrypted data too short".into()));
        }

        // Parse header: chunk_size(4) || stream_salt(16)
        let _chunk_size =
            u32::from_le_bytes([encrypted[0], encrypted[1], encrypted[2], encrypted[3]]) as usize;
        let stream_salt = &encrypted[4..20];

        let mut output = Vec::new();
        let mut pos = 20;
        let mut chunk_num: u64 = 0;
        let mut saw_end_marker = false;

        while pos < encrypted.len() {
            // Read chunk length
            if pos + 4 > encrypted.len() {
                return Err(ShieldError::StreamError("truncated chunk length".into()));
            }

            let chunk_len = u32::from_le_bytes([
                encrypted[pos],
                encrypted[pos + 1],
                encrypted[pos + 2],
                encrypted[pos + 3],
            ]) as usize;
            pos += 4;

            // Authenticated end-of-stream marker: the zero-length sentinel is
            // followed by a tag that commits to the number of chunks actually
            // seen, so a stream truncated at a chunk boundary (even with a
            // re-appended zero marker) fails verification here.
            if chunk_len == 0 {
                if pos + 32 > encrypted.len() {
                    return Err(ShieldError::StreamError("missing end-of-stream tag".into()));
                }
                let tag = &encrypted[pos..pos + 32];
                let expected = compute_eof_tag(&self.key, stream_salt, chunk_num);
                if tag.ct_eq(expected.as_ref()).unwrap_u8() != 1 {
                    return Err(ShieldError::AuthenticationFailed);
                }
                saw_end_marker = true;
                break;
            }

            if pos + chunk_len > encrypted.len() {
                return Err(ShieldError::StreamError("truncated chunk data".into()));
            }

            let chunk_data = &encrypted[pos..pos + chunk_len];
            pos += chunk_len;

            // Derive chunk key
            let chunk_key = derive_chunk_key(&self.key, stream_salt, chunk_num);

            // Decrypt chunk
            let decrypted = decrypt_chunk(&chunk_key, chunk_data)?;
            output.extend_from_slice(&decrypted);

            chunk_num += 1;
        }

        // A stream that ends without the authenticated marker has been
        // truncated (the trailing chunks and the end-of-stream tag were
        // dropped).
        if !saw_end_marker {
            return Err(ShieldError::StreamError(
                "stream truncated: missing end-of-stream marker".into(),
            ));
        }

        Ok(output)
    }

    /// Encrypt entire data at once (convenience method).
    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let encryptor = self.encrypt_stream(data)?;
        let mut result = Vec::new();

        for chunk in encryptor {
            result.extend_from_slice(&chunk?);
        }

        Ok(result)
    }

    /// Decrypt entire data at once (convenience method).
    pub fn decrypt(&self, encrypted: &[u8]) -> Result<Vec<u8>> {
        self.decrypt_stream(encrypted)
    }
}

/// Iterator over encrypted chunks.
pub struct StreamEncryptor<'a> {
    key: &'a [u8; 32],
    data: &'a [u8],
    stream_salt: [u8; 16],
    chunk_size: usize,
    position: usize,
    chunk_num: u64,
    header_sent: bool,
    finished: bool,
}

impl<'a> StreamEncryptor<'a> {
    fn new(key: &'a [u8; 32], data: &'a [u8], chunk_size: usize) -> Result<Self> {
        let stream_salt: [u8; 16] = crate::random::random_bytes()?;

        Ok(Self {
            key,
            data,
            stream_salt,
            chunk_size,
            position: 0,
            chunk_num: 0,
            header_sent: false,
            finished: false,
        })
    }
}

impl Iterator for StreamEncryptor<'_> {
    type Item = Result<Vec<u8>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }

        // First, send header
        if !self.header_sent {
            self.header_sent = true;
            let mut header = Vec::with_capacity(20);
            header.extend_from_slice(&(self.chunk_size as u32).to_le_bytes());
            header.extend_from_slice(&self.stream_salt);
            return Some(Ok(header));
        }

        // Check if we have more data
        if self.position >= self.data.len() {
            self.finished = true;
            // Send authenticated end-of-stream trailer: the zero-length marker
            // followed by a tag committing to the total chunk count, so a
            // truncated stream (with or without a forged marker) is detectable.
            let eof_tag = compute_eof_tag(self.key, &self.stream_salt, self.chunk_num);
            let mut trailer = Vec::with_capacity(4 + 32);
            trailer.extend_from_slice(&0u32.to_le_bytes());
            trailer.extend_from_slice(&eof_tag);
            return Some(Ok(trailer));
        }

        // Get next chunk
        let end = std::cmp::min(self.position + self.chunk_size, self.data.len());
        let chunk_data = &self.data[self.position..end];
        self.position = end;

        // Derive chunk key
        let chunk_key = derive_chunk_key(self.key, &self.stream_salt, self.chunk_num);
        self.chunk_num += 1;

        // Encrypt chunk
        match encrypt_chunk(&chunk_key, chunk_data) {
            Ok(encrypted) => {
                let mut result = Vec::with_capacity(4 + encrypted.len());
                result.extend_from_slice(&(encrypted.len() as u32).to_le_bytes());
                result.extend_from_slice(&encrypted);
                Some(Ok(result))
            }
            Err(e) => Some(Err(e)),
        }
    }
}

/// Derive per-chunk key from master key and stream salt.
fn derive_chunk_key(key: &[u8], stream_salt: &[u8], chunk_num: u64) -> [u8; 32] {
    let mut data = Vec::with_capacity(key.len() + stream_salt.len() + 8);
    data.extend_from_slice(key);
    data.extend_from_slice(stream_salt);
    data.extend_from_slice(&chunk_num.to_le_bytes());

    let hash = digest::digest(&digest::SHA256, &data);
    let mut result = [0u8; 32];
    result.copy_from_slice(hash.as_ref());
    result
}

/// Derive the domain-separated end-of-stream key from the master key.
fn derive_eof_key(key: &[u8; 32]) -> [u8; 32] {
    let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let tag = hmac::sign(&hmac_key, b"shield-stream-eof");
    let mut result = [0u8; 32];
    result.copy_from_slice(tag.as_ref());
    result
}

/// Compute the authenticated end-of-stream tag.
///
/// The tag commits to the stream salt and the total number of chunks (a length
/// commitment). A stream that is truncated at a chunk boundary has a different
/// chunk count, and an attacker cannot forge a matching tag without the master
/// key, so truncation — including re-appending a zero-length end marker — is
/// detected.
fn compute_eof_tag(key: &[u8; 32], stream_salt: &[u8], chunk_count: u64) -> [u8; 32] {
    let eof_key = derive_eof_key(key);
    let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &eof_key);
    let mut input = Vec::with_capacity(stream_salt.len() + 8);
    input.extend_from_slice(stream_salt);
    input.extend_from_slice(&chunk_count.to_le_bytes());
    let tag = hmac::sign(&hmac_key, &input);
    let mut result = [0u8; 32];
    result.copy_from_slice(tag.as_ref());
    result
}

/// Derive separated encryption and MAC subkeys from a chunk key using HMAC-SHA256.
fn derive_chunk_subkeys(key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, key);

    let enc_tag = hmac::sign(&hmac_key, b"shield-stream-encrypt");
    let mut enc_key = [0u8; 32];
    enc_key.copy_from_slice(&enc_tag.as_ref()[..32]);

    let mac_tag = hmac::sign(&hmac_key, b"shield-stream-authenticate");
    let mut mac_key = [0u8; 32];
    mac_key.copy_from_slice(&mac_tag.as_ref()[..32]);

    (enc_key, mac_key)
}

/// Encrypt a single chunk.
fn encrypt_chunk(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
    let (enc_key, mac_key) = derive_chunk_subkeys(key);

    // Generate nonce
    let nonce: [u8; 16] = crate::random::random_bytes()?;

    // Generate keystream with enc_key
    let num_blocks = data.len().div_ceil(32);
    if u32::try_from(num_blocks).is_err() {
        return Err(ShieldError::StreamError(
            "keystream too long: counter overflow".into(),
        ));
    }
    let mut keystream = Vec::with_capacity(num_blocks * 32);
    for i in 0..num_blocks {
        let counter = (i as u32).to_le_bytes();
        let mut hash_input = Vec::with_capacity(enc_key.len() + nonce.len() + 4);
        hash_input.extend_from_slice(&enc_key);
        hash_input.extend_from_slice(&nonce);
        hash_input.extend_from_slice(&counter);
        let hash = digest::digest(&digest::SHA256, &hash_input);
        keystream.extend_from_slice(hash.as_ref());
    }

    // XOR encrypt
    let ciphertext: Vec<u8> = data
        .iter()
        .zip(keystream.iter())
        .map(|(p, k)| p ^ k)
        .collect();

    // HMAC with mac_key
    let hmac_signing_key = hmac::Key::new(hmac::HMAC_SHA256, &mac_key);
    let mut hmac_data = Vec::with_capacity(16 + ciphertext.len());
    hmac_data.extend_from_slice(&nonce);
    hmac_data.extend_from_slice(&ciphertext);
    let tag = hmac::sign(&hmac_signing_key, &hmac_data);

    // Format: nonce || ciphertext || mac(16)
    let mut result = Vec::with_capacity(16 + ciphertext.len() + 16);
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);
    result.extend_from_slice(&tag.as_ref()[..16]);

    Ok(result)
}

/// Decrypt a single chunk.
fn decrypt_chunk(key: &[u8; 32], encrypted: &[u8]) -> Result<Vec<u8>> {
    if encrypted.len() < 32 {
        return Err(ShieldError::StreamError("chunk too short".into()));
    }

    let (enc_key, mac_key) = derive_chunk_subkeys(key);

    let nonce = &encrypted[..16];
    let ciphertext = &encrypted[16..encrypted.len() - 16];
    let mac = &encrypted[encrypted.len() - 16..];

    // Verify MAC with mac_key
    let hmac_signing_key = hmac::Key::new(hmac::HMAC_SHA256, &mac_key);
    let mut hmac_data = Vec::with_capacity(16 + ciphertext.len());
    hmac_data.extend_from_slice(nonce);
    hmac_data.extend_from_slice(ciphertext);
    let expected = hmac::sign(&hmac_signing_key, &hmac_data);

    if mac.ct_eq(&expected.as_ref()[..16]).unwrap_u8() != 1 {
        return Err(ShieldError::AuthenticationFailed);
    }

    // Generate keystream with enc_key
    let num_blocks = ciphertext.len().div_ceil(32);
    if u32::try_from(num_blocks).is_err() {
        return Err(ShieldError::StreamError(
            "keystream too long: counter overflow".into(),
        ));
    }
    let mut keystream = Vec::with_capacity(num_blocks * 32);
    for i in 0..num_blocks {
        let counter = (i as u32).to_le_bytes();
        let mut hash_input = Vec::with_capacity(enc_key.len() + nonce.len() + 4);
        hash_input.extend_from_slice(&enc_key);
        hash_input.extend_from_slice(nonce);
        hash_input.extend_from_slice(&counter);
        let hash = digest::digest(&digest::SHA256, &hash_input);
        keystream.extend_from_slice(hash.as_ref());
    }

    // XOR decrypt
    Ok(ciphertext
        .iter()
        .zip(keystream.iter())
        .map(|(c, k)| c ^ k)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_roundtrip() {
        let key = [0x42u8; 32];
        let cipher = StreamCipher::new(key);

        let data = b"Hello, streaming world!";
        let encrypted = cipher.encrypt(data).unwrap();
        let decrypted = cipher.decrypt(&encrypted).unwrap();

        assert_eq!(data.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_stream_large_data() {
        let key = [0x42u8; 32];
        let cipher = StreamCipher::with_chunk_size(key, 1024);

        let data: Vec<u8> = (0..10000_u32).map(|i| (i % 256) as u8).collect();
        let encrypted = cipher.encrypt(&data).unwrap();
        let decrypted = cipher.decrypt(&encrypted).unwrap();

        assert_eq!(data, decrypted);
    }

    #[test]
    fn test_eof_tag_conformance_vector() {
        // Cross-language golden vector for the authenticated end-of-stream tag.
        // Every binding must derive this exact tag so a stream finalized by one
        // language is accepted by another.
        //   master_key  = 32 x 0x42
        //   stream_salt = 16 x 0x01
        //   chunk_count = 3
        let tag = compute_eof_tag(&[0x42u8; 32], &[0x01u8; 16], 3);
        // 52d4dfbeccc364bd69a2f232aa460bd1eb79b0c93903f344dd7b937703918431
        let expected: [u8; 32] = [
            0x52, 0xd4, 0xdf, 0xbe, 0xcc, 0xc3, 0x64, 0xbd, 0x69, 0xa2, 0xf2, 0x32, 0xaa, 0x46,
            0x0b, 0xd1, 0xeb, 0x79, 0xb0, 0xc9, 0x39, 0x03, 0xf3, 0x44, 0xdd, 0x7b, 0x93, 0x77,
            0x03, 0x91, 0x84, 0x31,
        ];
        assert_eq!(tag, expected, "EOF tag conformance vector mismatch");
    }

    #[test]
    fn test_stream_truncation_at_chunk_boundary_rejected() {
        let key = [0x42u8; 32];
        let cipher = StreamCipher::with_chunk_size(key, 16);
        let data: Vec<u8> = (0..64u8).collect(); // 4 chunks of 16 bytes

        // Framed output: [header, chunk0, chunk1, chunk2, chunk3, trailer].
        let frames: Vec<Vec<u8>> = cipher
            .encrypt_stream(&data)
            .unwrap()
            .map(std::result::Result::unwrap)
            .collect();
        assert!(frames.len() >= 4);

        // Attacker keeps header + first two chunks, drops the rest and the
        // authenticated trailer. Each retained chunk is individually valid, so
        // per-chunk MACs do not catch this; the end-of-stream tag must.
        let mut truncated = Vec::new();
        truncated.extend_from_slice(&frames[0]);
        truncated.extend_from_slice(&frames[1]);
        truncated.extend_from_slice(&frames[2]);

        assert!(
            cipher.decrypt(&truncated).is_err(),
            "stream truncated at a chunk boundary must be rejected"
        );
    }

    #[test]
    fn test_stream_forged_end_marker_rejected() {
        let key = [0x42u8; 32];
        let cipher = StreamCipher::with_chunk_size(key, 16);
        let data: Vec<u8> = (0..64u8).collect();

        let frames: Vec<Vec<u8>> = cipher
            .encrypt_stream(&data)
            .unwrap()
            .map(std::result::Result::unwrap)
            .collect();

        // Attacker keeps header + first two chunks and appends a forged
        // zero-length end marker (without a valid end-of-stream tag) to make the
        // truncated stream look complete.
        let mut forged = Vec::new();
        forged.extend_from_slice(&frames[0]);
        forged.extend_from_slice(&frames[1]);
        forged.extend_from_slice(&frames[2]);
        forged.extend_from_slice(&[0, 0, 0, 0]);

        assert!(
            cipher.decrypt(&forged).is_err(),
            "forged end marker without a valid end-of-stream tag must be rejected"
        );
    }

    #[test]
    fn test_stream_tamper_detection() {
        let key = [0x42u8; 32];
        let cipher = StreamCipher::new(key);

        let mut encrypted = cipher.encrypt(b"test data").unwrap();
        // Tamper with a chunk
        if encrypted.len() > 30 {
            encrypted[30] ^= 0xFF;
        }

        assert!(cipher.decrypt(&encrypted).is_err());
    }
}
