//! WebAssembly bindings for Shield.
//!
//! Enables Shield to run in browsers and Node.js via WASM.
//!
//! ## Usage in JavaScript
//!
//! ```javascript
//! import init, { WasmShield, WasmTOTP, WasmRatchetSession, WasmLamportSignature } from './shield_core.js';
//!
//! await init();
//!
//! // Shield encryption
//! const shield = new WasmShield("password", "service.com");
//! const encrypted = shield.encrypt(new TextEncoder().encode("secret"));
//! const decrypted = shield.decrypt(encrypted);
//!
//! // TOTP (2FA)
//! const secret = WasmTOTP.generateSecret();
//! const totp = new WasmTOTP(secret);
//! const code = totp.generate(Date.now() / 1000);
//!
//! // Ratchet session (forward secrecy)
//! const rootKey = new Uint8Array(32);
//! const alice = new WasmRatchetSession(rootKey, true);
//! const bob = new WasmRatchetSession(rootKey, false);
//!
//! // Lamport signature (post-quantum)
//! const lamport = new WasmLamportSignature();
//! const sig = lamport.sign(message);
//! ```

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

#[cfg(feature = "wasm")]
use crate::{Shield, quick_encrypt, quick_decrypt, TOTP, RatchetSession, LamportSignature};

// ============================================================================
// Shield - Core encryption
// ============================================================================

/// WASM-compatible Shield wrapper.
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub struct WasmShield {
    inner: Shield,
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl WasmShield {
    /// Create a new Shield instance from password and service.
    #[wasm_bindgen(constructor)]
    #[must_use] 
    pub fn new(password: &str, service: &str) -> Self {
        Self {
            inner: Shield::new(password, service),
        }
    }

    /// Create Shield instance from raw key (32 bytes).
    #[wasm_bindgen(js_name = withKey)]
    pub fn with_key(key: &[u8]) -> Result<WasmShield, JsError> {
        if key.len() != 32 {
            return Err(JsError::new("Key must be 32 bytes"));
        }
        let key_array: [u8; 32] = key.try_into().unwrap();
        Ok(Self {
            inner: Shield::with_key(key_array),
        })
    }

    /// Encrypt data.
    #[wasm_bindgen]
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, JsError> {
        self.inner.encrypt(plaintext).map_err(|e| JsError::new(&e.to_string()))
    }

    /// Decrypt data.
    #[wasm_bindgen]
    pub fn decrypt(&self, encrypted: &[u8]) -> Result<Vec<u8>, JsError> {
        self.inner.decrypt(encrypted).map_err(|e| JsError::new(&e.to_string()))
    }

    /// Get the derived key (for interop testing).
    #[wasm_bindgen]
    #[must_use] 
    pub fn key(&self) -> Vec<u8> {
        self.inner.key().to_vec()
    }
}

/// Quick encrypt with pre-shared key (WASM export).
#[cfg(feature = "wasm")]
#[wasm_bindgen(js_name = quickEncrypt)]
pub fn wasm_encrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, JsError> {
    if key.len() != 32 {
        return Err(JsError::new("key must be 32 bytes"));
    }
    let key_array: [u8; 32] = key.try_into().unwrap();
    quick_encrypt(&key_array, data).map_err(|e| JsError::new(&e.to_string()))
}

/// Quick decrypt with pre-shared key (WASM export).
#[cfg(feature = "wasm")]
#[wasm_bindgen(js_name = quickDecrypt)]
pub fn wasm_decrypt(key: &[u8], encrypted: &[u8]) -> Result<Vec<u8>, JsError> {
    if key.len() != 32 {
        return Err(JsError::new("key must be 32 bytes"));
    }
    let key_array: [u8; 32] = key.try_into().unwrap();
    quick_decrypt(&key_array, encrypted).map_err(|e| JsError::new(&e.to_string()))
}

// ============================================================================
// TOTP - Time-based One-Time Password
// ============================================================================

/// WASM-compatible TOTP wrapper.
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub struct WasmTOTP {
    inner: TOTP,
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl WasmTOTP {
    /// Create TOTP with secret (default: 6 digits, 30 second interval).
    #[wasm_bindgen(constructor)]
    #[must_use] 
    pub fn new(secret: &[u8]) -> Self {
        Self {
            inner: TOTP::with_secret(secret.to_vec()),
        }
    }

    /// Create TOTP with custom settings.
    #[wasm_bindgen(js_name = withSettings)]
    #[must_use] 
    pub fn with_settings(secret: &[u8], digits: usize, interval: u64) -> Self {
        Self {
            inner: TOTP::new(secret.to_vec(), digits, interval),
        }
    }

    /// Generate a random secret (20 bytes).
    #[wasm_bindgen(js_name = generateSecret)]
    pub fn generate_secret() -> Result<Vec<u8>, JsError> {
        TOTP::generate_secret().map_err(|e| JsError::new(&e.to_string()))
    }

    /// Generate TOTP code for given timestamp (seconds since epoch).
    #[wasm_bindgen]
    #[must_use] 
    pub fn generate(&self, timestamp: u64) -> String {
        self.inner.generate(Some(timestamp))
    }

    /// Generate TOTP code for current time.
    #[wasm_bindgen(js_name = generateNow)]
    #[must_use] 
    pub fn generate_now(&self) -> String {
        self.inner.generate(None)
    }

    /// Verify TOTP code with time window.
    #[wasm_bindgen]
    #[must_use] 
    pub fn verify(&self, code: &str, timestamp: u64, window: u32) -> bool {
        self.inner.verify(code, Some(timestamp), window)
    }

    /// Verify TOTP code for current time.
    #[wasm_bindgen(js_name = verifyNow)]
    #[must_use] 
    pub fn verify_now(&self, code: &str, window: u32) -> bool {
        self.inner.verify(code, None, window)
    }

    /// Encode secret to Base32.
    #[wasm_bindgen(js_name = toBase32)]
    #[must_use] 
    pub fn to_base32(&self) -> String {
        TOTP::secret_to_base32(self.inner.secret())
    }

    /// Decode Base32 secret.
    #[wasm_bindgen(js_name = fromBase32)]
    pub fn from_base32(encoded: &str) -> Result<Vec<u8>, JsError> {
        TOTP::secret_from_base32(encoded).map_err(|e| JsError::new(&e.to_string()))
    }

    /// Get provisioning URI for authenticator apps.
    #[wasm_bindgen(js_name = provisioningUri)]
    #[must_use] 
    pub fn provisioning_uri(&self, account: &str, issuer: &str) -> String {
        self.inner.provisioning_uri(account, issuer)
    }
}

// ============================================================================
// RatchetSession - Forward secrecy
// ============================================================================

/// WASM-compatible `RatchetSession` wrapper.
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub struct WasmRatchetSession {
    inner: RatchetSession,
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl WasmRatchetSession {
    /// Create a new ratchet session from shared root key.
    #[wasm_bindgen(constructor)]
    pub fn new(root_key: &[u8], is_initiator: bool) -> Result<WasmRatchetSession, JsError> {
        if root_key.len() != 32 {
            return Err(JsError::new("Root key must be 32 bytes"));
        }
        let key_array: [u8; 32] = root_key.try_into().unwrap();
        Ok(Self {
            inner: RatchetSession::new(&key_array, is_initiator),
        })
    }

    /// Encrypt a message with forward secrecy.
    #[wasm_bindgen]
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, JsError> {
        self.inner.encrypt(plaintext).map_err(|e| JsError::new(&e.to_string()))
    }

    /// Decrypt a message with forward secrecy.
    #[wasm_bindgen]
    pub fn decrypt(&mut self, encrypted: &[u8]) -> Result<Vec<u8>, JsError> {
        self.inner.decrypt(encrypted).map_err(|e| JsError::new(&e.to_string()))
    }

    /// Get send counter.
    #[wasm_bindgen(getter, js_name = sendCounter)]
    #[must_use] 
    pub fn send_counter(&self) -> u64 {
        self.inner.send_counter()
    }

    /// Get receive counter.
    #[wasm_bindgen(getter, js_name = recvCounter)]
    #[must_use] 
    pub fn recv_counter(&self) -> u64 {
        self.inner.recv_counter()
    }
}

// ============================================================================
// LamportSignature - Post-quantum one-time signatures
// ============================================================================

/// WASM-compatible Lamport signature wrapper.
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub struct WasmLamportSignature {
    inner: LamportSignature,
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl WasmLamportSignature {
    /// Generate a new Lamport key pair.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<WasmLamportSignature, JsError> {
        LamportSignature::generate()
            .map(|inner| Self { inner })
            .map_err(|e| JsError::new(&e.to_string()))
    }

    /// Sign a message (ONE TIME ONLY - key becomes invalid after use).
    #[wasm_bindgen]
    pub fn sign(&mut self, message: &[u8]) -> Result<Vec<u8>, JsError> {
        self.inner.sign(message).map_err(|e| JsError::new(&e.to_string()))
    }

    /// Verify a Lamport signature (static method).
    #[wasm_bindgen(js_name = verifySignature)]
    #[must_use] 
    pub fn verify_signature(message: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
        LamportSignature::verify(message, signature, public_key)
    }

    /// Get public key.
    #[wasm_bindgen(getter, js_name = publicKey)]
    #[must_use] 
    pub fn public_key(&self) -> Vec<u8> {
        self.inner.public_key().to_vec()
    }

    /// Check if key has been used.
    #[wasm_bindgen(getter, js_name = isUsed)]
    #[must_use] 
    pub fn is_used(&self) -> bool {
        self.inner.is_used()
    }

    /// Get key fingerprint.
    #[wasm_bindgen]
    #[must_use] 
    pub fn fingerprint(&self) -> String {
        self.inner.fingerprint()
    }
}

// ============================================================================
// Utility functions
// ============================================================================

/// Generate random bytes.
#[cfg(feature = "wasm")]
#[wasm_bindgen(js_name = randomBytes)]
pub fn wasm_random_bytes(size: usize) -> Result<Vec<u8>, JsError> {
    use ring::rand::{SecureRandom, SystemRandom};
    let rng = SystemRandom::new();
    let mut bytes = vec![0u8; size];
    rng.fill(&mut bytes).map_err(|_| JsError::new("Failed to generate random bytes"))?;
    Ok(bytes)
}

/// SHA-256 hash.
#[cfg(feature = "wasm")]
#[wasm_bindgen(js_name = sha256)]
#[must_use] 
pub fn wasm_sha256(data: &[u8]) -> Vec<u8> {
    use ring::digest;
    digest::digest(&digest::SHA256, data).as_ref().to_vec()
}

/// HMAC-SHA256.
#[cfg(feature = "wasm")]
#[wasm_bindgen(js_name = hmacSha256)]
#[must_use] 
pub fn wasm_hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    use ring::hmac;
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    hmac::sign(&key, data).as_ref().to_vec()
}

/// Constant-time comparison.
#[cfg(feature = "wasm")]
#[wasm_bindgen(js_name = constantTimeEquals)]
#[must_use] 
pub fn wasm_constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).unwrap_u8() == 1
}
