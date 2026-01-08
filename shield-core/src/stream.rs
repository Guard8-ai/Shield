//! Streaming encryption for large files.
//!
//! Processes data in chunks with per-chunk authentication.
//! Matches Python `StreamCipher` from `shield_enterprise.py`.

// Crypto block/chunk counters are intentionally u32 - data >4GB would have other issues
#![allow(clippy::cast_possible_truncation)]

use ring::{hmac, digest, rand::{SecureRandom, SystemRandom}};
use subtle::ConstantTimeEq;

use crate::error::{Result, ShieldError};

/// Default chunk size: 64KB
const DEFAULT_CHUNK_SIZE: usize = 64 * 1024;

/// Stream cipher for large file encryption.
///
/// Each chunk is independently authenticated, allowing:
/// - Constant memory usage regardless of file size
/// - Early detection of tampering
/// - Potential for parallel processing
pub struct StreamCipher {
    key: [u8; 32],
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
    pub fn encrypt_stream<'a>(
        &'a self,
        data: &'a [u8],
    ) -> Result<StreamEncryptor<'a>> {
        StreamEncryptor::new(&self.key, data, self.chunk_size)
    }

    /// Decrypt a stream of encrypted chunks.
    pub fn decrypt_stream(&self, encrypted: &[u8]) -> Result<Vec<u8>> {
        if encrypted.len() < 20 {
            return Err(ShieldError::StreamError("encrypted data too short".into()));
        }

        // Parse header: chunk_size(4) || stream_salt(16)
        let _chunk_size = u32::from_le_bytes([
            encrypted[0], encrypted[1], encrypted[2], encrypted[3],
        ]) as usize;
        let stream_salt = &encrypted[4..20];

        let mut output = Vec::new();
        let mut pos = 20;
        let mut chunk_num: u64 = 0;

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

            // End marker
            if chunk_len == 0 {
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
        let rng = SystemRandom::new();
        let mut stream_salt = [0u8; 16];
        rng.fill(&mut stream_salt).map_err(|_| ShieldError::RandomFailed)?;

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
            // Send end marker
            return Some(Ok(vec![0, 0, 0, 0]));
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

/// Encrypt a single chunk.
fn encrypt_chunk(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
    let rng = SystemRandom::new();

    // Generate nonce
    let mut nonce = [0u8; 16];
    rng.fill(&mut nonce).map_err(|_| ShieldError::RandomFailed)?;

    // Generate keystream
    let mut keystream = Vec::with_capacity(data.len().div_ceil(32) * 32);
    for i in 0..data.len().div_ceil(32) {
        let counter = (i as u32).to_le_bytes();
        let mut hash_input = Vec::with_capacity(key.len() + nonce.len() + 4);
        hash_input.extend_from_slice(key);
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

    // HMAC
    let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let mut hmac_data = Vec::with_capacity(16 + ciphertext.len());
    hmac_data.extend_from_slice(&nonce);
    hmac_data.extend_from_slice(&ciphertext);
    let tag = hmac::sign(&hmac_key, &hmac_data);

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
        let counter = (i as u32).to_le_bytes();
        let mut hash_input = Vec::with_capacity(key.len() + nonce.len() + 4);
        hash_input.extend_from_slice(key);
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

        let data: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();
        let encrypted = cipher.encrypt(&data).unwrap();
        let decrypted = cipher.decrypt(&encrypted).unwrap();

        assert_eq!(data, decrypted);
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
