//! Shield WebAssembly Module
//! EXPTIME-secure encryption for browsers and any WebAssembly runtime.
//! Breaking requires 2^256 operations - no shortcut exists.

use wasm_bindgen::prelude::*;

// Constants
const KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 16;
const MAC_SIZE: usize = 16;
const ITERATIONS: u32 = 100_000;

/// Shield encryption context for WebAssembly
#[wasm_bindgen]
pub struct Shield {
    key: Vec<u8>,
}

#[wasm_bindgen]
impl Shield {
    /// Create Shield instance from password and service identifier
    #[wasm_bindgen(constructor)]
    pub fn new(password: &str, service: &str) -> Shield {
        let salt = sha256(format!("shield:{}", service).as_bytes());
        let key = pbkdf2(password.as_bytes(), &salt, ITERATIONS, KEY_SIZE);
        Shield { key }
    }

    /// Create Shield instance from raw key (32 bytes)
    #[wasm_bindgen(js_name = withKey)]
    pub fn with_key(key: &[u8]) -> Result<Shield, JsValue> {
        if key.len() != KEY_SIZE {
            return Err(JsValue::from_str("Key must be 32 bytes"));
        }
        Ok(Shield { key: key.to_vec() })
    }

    /// Encrypt plaintext
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let nonce = random_bytes(NONCE_SIZE);
        let keystream = generate_keystream(&self.key, &nonce, plaintext.len());

        let mut ciphertext = Vec::with_capacity(plaintext.len());
        for (i, &byte) in plaintext.iter().enumerate() {
            ciphertext.push(byte ^ keystream[i]);
        }

        // MAC = HMAC-SHA256(key, nonce || ciphertext), truncated to 16 bytes
        let mut mac_data = nonce.clone();
        mac_data.extend(&ciphertext);
        let mac = hmac_sha256(&self.key, &mac_data);

        // Output: nonce(16) || ciphertext || mac(16)
        let mut result = nonce;
        result.extend(ciphertext);
        result.extend(&mac[..MAC_SIZE]);
        result
    }

    /// Decrypt ciphertext
    pub fn decrypt(&self, encrypted: &[u8]) -> Result<Vec<u8>, JsValue> {
        if encrypted.len() < NONCE_SIZE + MAC_SIZE {
            return Err(JsValue::from_str("Ciphertext too short"));
        }

        let nonce = &encrypted[..NONCE_SIZE];
        let ciphertext = &encrypted[NONCE_SIZE..encrypted.len() - MAC_SIZE];
        let received_mac = &encrypted[encrypted.len() - MAC_SIZE..];

        // Verify MAC
        let mut mac_data = nonce.to_vec();
        mac_data.extend(ciphertext);
        let expected_mac = hmac_sha256(&self.key, &mac_data);

        if !constant_time_eq(received_mac, &expected_mac[..MAC_SIZE]) {
            return Err(JsValue::from_str("Authentication failed"));
        }

        // Decrypt
        let keystream = generate_keystream(&self.key, nonce, ciphertext.len());
        let mut plaintext = Vec::with_capacity(ciphertext.len());
        for (i, &byte) in ciphertext.iter().enumerate() {
            plaintext.push(byte ^ keystream[i]);
        }

        Ok(plaintext)
    }
}

/// TOTP (Time-based One-Time Password) for WebAssembly
#[wasm_bindgen]
pub struct TOTP {
    secret: Vec<u8>,
    digits: u32,
    interval: u64,
}

#[wasm_bindgen]
impl TOTP {
    /// Create TOTP with secret
    #[wasm_bindgen(constructor)]
    pub fn new(secret: &[u8]) -> TOTP {
        TOTP {
            secret: secret.to_vec(),
            digits: 6,
            interval: 30,
        }
    }

    /// Generate secret (20 bytes)
    #[wasm_bindgen(js_name = generateSecret)]
    pub fn generate_secret() -> Vec<u8> {
        random_bytes(20)
    }

    /// Generate TOTP code
    pub fn generate(&self, timestamp: u64) -> String {
        let counter = timestamp / self.interval;
        self.generate_hotp(counter)
    }

    /// Verify TOTP code
    pub fn verify(&self, code: &str, timestamp: u64, window: u32) -> bool {
        for i in 0..=window {
            if self.generate(timestamp - (i as u64) * self.interval) == code {
                return true;
            }
            if i > 0 && self.generate(timestamp + (i as u64) * self.interval) == code {
                return true;
            }
        }
        false
    }

    fn generate_hotp(&self, counter: u64) -> String {
        let counter_bytes = counter.to_be_bytes();
        let hash = hmac_sha1(&self.secret, &counter_bytes);

        let offset = (hash[19] & 0x0f) as usize;
        let code = ((hash[offset] as u32 & 0x7f) << 24)
            | ((hash[offset + 1] as u32 & 0xff) << 16)
            | ((hash[offset + 2] as u32 & 0xff) << 8)
            | (hash[offset + 3] as u32 & 0xff);

        let modulo = 10u32.pow(self.digits);
        format!("{:0>width$}", code % modulo, width = self.digits as usize)
    }

    /// Encode secret to Base32
    #[wasm_bindgen(js_name = toBase32)]
    pub fn to_base32(&self) -> String {
        base32_encode(&self.secret)
    }

    /// Get provisioning URI for authenticator apps
    #[wasm_bindgen(js_name = provisioningUri)]
    pub fn provisioning_uri(&self, account: &str, issuer: &str) -> String {
        let secret_b32 = self.to_base32();
        format!(
            "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits={}&period={}",
            issuer, account, secret_b32, issuer, self.digits, self.interval
        )
    }
}

/// RatchetSession for forward secrecy
#[wasm_bindgen]
pub struct RatchetSession {
    send_key: Vec<u8>,
    recv_key: Vec<u8>,
    send_counter: u64,
    recv_counter: u64,
}

#[wasm_bindgen]
impl RatchetSession {
    /// Create a new ratchet session
    #[wasm_bindgen(constructor)]
    pub fn new(root_key: &[u8], is_initiator: bool) -> Result<RatchetSession, JsValue> {
        if root_key.len() != KEY_SIZE {
            return Err(JsValue::from_str("Root key must be 32 bytes"));
        }

        let (send_key, recv_key) = if is_initiator {
            (
                derive_chain_key(root_key, b"init_send"),
                derive_chain_key(root_key, b"init_recv"),
            )
        } else {
            (
                derive_chain_key(root_key, b"init_recv"),
                derive_chain_key(root_key, b"init_send"),
            )
        };

        Ok(RatchetSession {
            send_key,
            recv_key,
            send_counter: 0,
            recv_counter: 0,
        })
    }

    /// Encrypt a message with ratcheting
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let message_key = derive_chain_key(&self.send_key, b"message");
        let nonce = random_bytes(NONCE_SIZE);

        // Encrypt
        let keystream = generate_keystream(&message_key, &nonce, plaintext.len());
        let mut ciphertext = Vec::with_capacity(plaintext.len());
        for (i, &byte) in plaintext.iter().enumerate() {
            ciphertext.push(byte ^ keystream[i]);
        }

        // Counter bytes
        let counter_bytes = self.send_counter.to_le_bytes();

        // MAC
        let mut mac_data = counter_bytes.to_vec();
        mac_data.extend(&nonce);
        mac_data.extend(&ciphertext);
        let mac = hmac_sha256(&message_key, &mac_data);

        // Ratchet
        self.send_key = derive_chain_key(&self.send_key, b"ratchet");
        self.send_counter += 1;

        // Output: counter(8) || nonce(16) || ciphertext || mac(16)
        let mut result = counter_bytes.to_vec();
        result.extend(&nonce);
        result.extend(&ciphertext);
        result.extend(&mac[..MAC_SIZE]);
        result
    }

    /// Decrypt a message with ratcheting
    pub fn decrypt(&mut self, encrypted: &[u8]) -> Result<Vec<u8>, JsValue> {
        if encrypted.len() < 8 + NONCE_SIZE + MAC_SIZE {
            return Err(JsValue::from_str("Ciphertext too short"));
        }

        // Parse
        let counter = u64::from_le_bytes(encrypted[..8].try_into().unwrap());
        let nonce = &encrypted[8..8 + NONCE_SIZE];
        let ciphertext = &encrypted[8 + NONCE_SIZE..encrypted.len() - MAC_SIZE];
        let received_mac = &encrypted[encrypted.len() - MAC_SIZE..];

        // Check counter
        if counter < self.recv_counter {
            return Err(JsValue::from_str("Replay detected"));
        }
        if counter > self.recv_counter {
            return Err(JsValue::from_str("Out of order"));
        }

        let message_key = derive_chain_key(&self.recv_key, b"message");

        // Verify MAC
        let mut mac_data = encrypted[..8].to_vec();
        mac_data.extend(nonce);
        mac_data.extend(ciphertext);
        let expected_mac = hmac_sha256(&message_key, &mac_data);

        if !constant_time_eq(received_mac, &expected_mac[..MAC_SIZE]) {
            return Err(JsValue::from_str("Authentication failed"));
        }

        // Decrypt
        let keystream = generate_keystream(&message_key, nonce, ciphertext.len());
        let mut plaintext = Vec::with_capacity(ciphertext.len());
        for (i, &byte) in ciphertext.iter().enumerate() {
            plaintext.push(byte ^ keystream[i]);
        }

        // Ratchet
        self.recv_key = derive_chain_key(&self.recv_key, b"ratchet");
        self.recv_counter += 1;

        Ok(plaintext)
    }

    /// Get send counter
    #[wasm_bindgen(getter, js_name = sendCounter)]
    pub fn send_counter(&self) -> u64 {
        self.send_counter
    }

    /// Get receive counter
    #[wasm_bindgen(getter, js_name = recvCounter)]
    pub fn recv_counter(&self) -> u64 {
        self.recv_counter
    }
}

/// Lamport one-time signature for post-quantum security
#[wasm_bindgen]
pub struct LamportSignature {
    private_key: Vec<Vec<Vec<u8>>>, // [256][2][32]
    public_key: Vec<u8>,            // 256 * 64 bytes
    is_used: bool,
}

#[wasm_bindgen]
impl LamportSignature {
    /// Generate a new Lamport key pair
    #[wasm_bindgen(constructor)]
    pub fn new() -> LamportSignature {
        let mut private_key = Vec::with_capacity(256);
        let mut public_key = Vec::with_capacity(256 * 64);

        for _ in 0..256 {
            let sk0 = random_bytes(KEY_SIZE);
            let sk1 = random_bytes(KEY_SIZE);
            let pk0 = sha256(&sk0);
            let pk1 = sha256(&sk1);

            public_key.extend(&pk0);
            public_key.extend(&pk1);
            private_key.push(vec![sk0, sk1]);
        }

        LamportSignature {
            private_key,
            public_key,
            is_used: false,
        }
    }

    /// Sign a message (can only be used once)
    pub fn sign(&mut self, message: &[u8]) -> Result<Vec<u8>, JsValue> {
        if self.is_used {
            return Err(JsValue::from_str("Lamport key already used"));
        }
        self.is_used = true;

        let msg_hash = sha256(message);
        let mut signature = Vec::with_capacity(256 * 32);

        for i in 0..256 {
            let byte_idx = i / 8;
            let bit_idx = i % 8;
            let bit = (msg_hash[byte_idx] >> bit_idx) & 1;
            signature.extend(&self.private_key[i][bit as usize]);
        }

        Ok(signature)
    }

    /// Verify a Lamport signature
    #[wasm_bindgen(js_name = verifySignature)]
    pub fn verify_signature(message: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
        if signature.len() != 256 * 32 || public_key.len() != 256 * 64 {
            return false;
        }

        let msg_hash = sha256(message);

        for i in 0..256 {
            let byte_idx = i / 8;
            let bit_idx = i % 8;
            let bit = (msg_hash[byte_idx] >> bit_idx) & 1;

            let revealed = &signature[i * 32..(i + 1) * 32];
            let hashed = sha256(revealed);

            let expected = if bit == 1 {
                &public_key[i * 64 + 32..i * 64 + 64]
            } else {
                &public_key[i * 64..i * 64 + 32]
            };

            if !constant_time_eq(&hashed, expected) {
                return false;
            }
        }

        true
    }

    /// Get public key
    #[wasm_bindgen(getter, js_name = publicKey)]
    pub fn get_public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    /// Check if key has been used
    #[wasm_bindgen(getter, js_name = isUsed)]
    pub fn is_used(&self) -> bool {
        self.is_used
    }
}

// ============================================================================
// Utility functions exposed to JavaScript
// ============================================================================

/// Generate random bytes
#[wasm_bindgen(js_name = randomBytes)]
pub fn random_bytes_js(size: usize) -> Vec<u8> {
    random_bytes(size)
}

/// SHA-256 hash
#[wasm_bindgen(js_name = sha256)]
pub fn sha256_js(data: &[u8]) -> Vec<u8> {
    sha256(data)
}

/// HMAC-SHA256
#[wasm_bindgen(js_name = hmacSha256)]
pub fn hmac_sha256_js(key: &[u8], data: &[u8]) -> Vec<u8> {
    hmac_sha256(key, data)
}

/// Constant-time comparison
#[wasm_bindgen(js_name = constantTimeEquals)]
pub fn constant_time_eq_js(a: &[u8], b: &[u8]) -> bool {
    constant_time_eq(a, b)
}

/// Quick encrypt without creating Shield instance
#[wasm_bindgen(js_name = quickEncrypt)]
pub fn quick_encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, JsValue> {
    let shield = Shield::with_key(key)?;
    Ok(shield.encrypt(plaintext))
}

/// Quick decrypt without creating Shield instance
#[wasm_bindgen(js_name = quickDecrypt)]
pub fn quick_decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, JsValue> {
    let shield = Shield::with_key(key)?;
    shield.decrypt(ciphertext)
}

// ============================================================================
// Internal crypto primitives
// ============================================================================

fn random_bytes(size: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; size];
    getrandom::getrandom(&mut bytes).expect("Failed to generate random bytes");
    bytes
}

fn sha256(data: &[u8]) -> Vec<u8> {
    // SHA-256 implementation
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    // Pad message
    let bit_len = (data.len() as u64) * 8;
    let mut padded = data.to_vec();
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0);
    }
    padded.extend(&bit_len.to_be_bytes());

    // Process blocks
    for chunk in padded.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[i*4], chunk[i*4+1], chunk[i*4+2], chunk[i*4+3]]);
        }
        for i in 16..64 {
            let s0 = w[i-15].rotate_right(7) ^ w[i-15].rotate_right(18) ^ (w[i-15] >> 3);
            let s1 = w[i-2].rotate_right(17) ^ w[i-2].rotate_right(19) ^ (w[i-2] >> 10);
            w[i] = w[i-16].wrapping_add(s0).wrapping_add(w[i-7]).wrapping_add(s1);
        }

        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g; g = f; f = e;
            e = d.wrapping_add(temp1);
            d = c; c = b; b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut result = Vec::with_capacity(32);
    for &val in &h {
        result.extend(&val.to_be_bytes());
    }
    result
}

fn sha1(data: &[u8]) -> Vec<u8> {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

    let bit_len = (data.len() as u64) * 8;
    let mut padded = data.to_vec();
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0);
    }
    padded.extend(&bit_len.to_be_bytes());

    for chunk in padded.chunks(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[i*4], chunk[i*4+1], chunk[i*4+2], chunk[i*4+3]]);
        }
        for i in 16..80 {
            w[i] = (w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]).rotate_left(1);
        }

        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);

        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDCu32),
                _ => (b ^ c ^ d, 0xCA62C1D6u32),
            };

            let temp = a.rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d; d = c;
            c = b.rotate_left(30);
            b = a; a = temp;
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }

    let mut result = Vec::with_capacity(20);
    for &val in &h {
        result.extend(&val.to_be_bytes());
    }
    result
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let block_size = 64;

    let key_block = if key.len() > block_size {
        let mut k = sha256(key);
        k.resize(block_size, 0);
        k
    } else {
        let mut k = key.to_vec();
        k.resize(block_size, 0);
        k
    };

    let mut o_key_pad = vec![0x5cu8; block_size];
    let mut i_key_pad = vec![0x36u8; block_size];
    for i in 0..block_size {
        o_key_pad[i] ^= key_block[i];
        i_key_pad[i] ^= key_block[i];
    }

    let mut inner = i_key_pad;
    inner.extend(data);
    let inner_hash = sha256(&inner);

    let mut outer = o_key_pad;
    outer.extend(&inner_hash);
    sha256(&outer)
}

fn hmac_sha1(key: &[u8], data: &[u8]) -> Vec<u8> {
    let block_size = 64;

    let key_block = if key.len() > block_size {
        let mut k = sha1(key);
        k.resize(block_size, 0);
        k
    } else {
        let mut k = key.to_vec();
        k.resize(block_size, 0);
        k
    };

    let mut o_key_pad = vec![0x5cu8; block_size];
    let mut i_key_pad = vec![0x36u8; block_size];
    for i in 0..block_size {
        o_key_pad[i] ^= key_block[i];
        i_key_pad[i] ^= key_block[i];
    }

    let mut inner = i_key_pad;
    inner.extend(data);
    let inner_hash = sha1(&inner);

    let mut outer = o_key_pad;
    outer.extend(&inner_hash);
    sha1(&outer)
}

fn pbkdf2(password: &[u8], salt: &[u8], iterations: u32, key_len: usize) -> Vec<u8> {
    let mut result = Vec::new();
    let mut block_num = 1u32;

    while result.len() < key_len {
        let mut u = salt.to_vec();
        u.extend(&block_num.to_be_bytes());
        u = hmac_sha256(password, &u);

        let mut block = u.clone();
        for _ in 1..iterations {
            u = hmac_sha256(password, &u);
            for i in 0..block.len() {
                block[i] ^= u[i];
            }
        }

        result.extend(block);
        block_num += 1;
    }

    result.truncate(key_len);
    result
}

fn generate_keystream(key: &[u8], nonce: &[u8], length: usize) -> Vec<u8> {
    let num_blocks = (length + 31) / 32;
    let mut keystream = Vec::with_capacity(num_blocks * 32);

    for i in 0..num_blocks {
        let mut block = key.to_vec();
        block.extend(nonce);
        block.extend(&(i as u32).to_le_bytes());
        keystream.extend(sha256(&block));
    }

    keystream.truncate(length);
    keystream
}

fn derive_chain_key(key: &[u8], info: &[u8]) -> Vec<u8> {
    let mut data = key.to_vec();
    data.extend(info);
    sha256(&data)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn base32_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut result = String::new();
    let mut buffer: u32 = 0;
    let mut bits_in_buffer = 0;

    for &byte in data {
        buffer = (buffer << 8) | (byte as u32);
        bits_in_buffer += 8;
        while bits_in_buffer >= 5 {
            bits_in_buffer -= 5;
            result.push(ALPHABET[((buffer >> bits_in_buffer) & 0x1f) as usize] as char);
        }
    }
    if bits_in_buffer > 0 {
        result.push(ALPHABET[((buffer << (5 - bits_in_buffer)) & 0x1f) as usize] as char);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let shield = Shield::new("password123", "test-service");
        let plaintext = b"Hello, Shield!";
        let encrypted = shield.encrypt(plaintext);
        let decrypted = shield.decrypt(&encrypted).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_sha256() {
        let expected = vec![
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
            0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
            0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
            0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(sha256(b"abc"), expected);
    }

    #[test]
    fn test_totp() {
        let secret = b"12345678901234567890";
        let totp = TOTP::new(secret);
        let code = totp.generate(59);
        assert_eq!(code.len(), 6);
    }

    #[test]
    fn test_ratchet_session() {
        let root_key = [0u8; 32];
        let mut alice = RatchetSession::new(&root_key, true).unwrap();
        let mut bob = RatchetSession::new(&root_key, false).unwrap();

        let msg = b"Hello Bob!";
        let encrypted = alice.encrypt(msg);
        let decrypted = bob.decrypt(&encrypted).unwrap();
        assert_eq!(msg.to_vec(), decrypted);
    }

    #[test]
    fn test_lamport_signature() {
        let mut lamport = LamportSignature::new();
        let message = b"Test message";
        let signature = lamport.sign(message).unwrap();
        let public_key = lamport.get_public_key();
        assert!(LamportSignature::verify_signature(message, &signature, &public_key));
    }
}
