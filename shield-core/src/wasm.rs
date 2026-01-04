//! WebAssembly bindings for Shield.
//!
//! Enables Shield to run in browsers and Node.js via WASM.
//!
//! ## Usage in JavaScript
//!
//! ```javascript
//! import init, { WasmShield, wasm_encrypt, wasm_decrypt } from './shield_core.js';
//!
//! await init();
//!
//! // Using the Shield class
//! const shield = new WasmShield("password", "service.com");
//! const encrypted = shield.encrypt(new TextEncoder().encode("secret"));
//! const decrypted = shield.decrypt(encrypted);
//!
//! // Or quick functions
//! const key = new Uint8Array(32); // Your 32-byte key
//! crypto.getRandomValues(key);
//! const ct = wasm_encrypt(key, new TextEncoder().encode("data"));
//! const pt = wasm_decrypt(key, ct);
//! ```

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

#[cfg(feature = "wasm")]
use crate::{Shield, quick_encrypt, quick_decrypt};

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
    pub fn new(password: &str, service: &str) -> Self {
        Self {
            inner: Shield::new(password, service),
        }
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
    pub fn key(&self) -> Vec<u8> {
        self.inner.key().to_vec()
    }
}

/// Quick encrypt with pre-shared key (WASM export).
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn wasm_encrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, JsError> {
    if key.len() != 32 {
        return Err(JsError::new("key must be 32 bytes"));
    }
    let key_array: [u8; 32] = key.try_into().unwrap();
    quick_encrypt(&key_array, data).map_err(|e| JsError::new(&e.to_string()))
}

/// Quick decrypt with pre-shared key (WASM export).
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn wasm_decrypt(key: &[u8], encrypted: &[u8]) -> Result<Vec<u8>, JsError> {
    if key.len() != 32 {
        return Err(JsError::new("key must be 32 bytes"));
    }
    let key_array: [u8; 32] = key.try_into().unwrap();
    quick_decrypt(&key_array, encrypted).map_err(|e| JsError::new(&e.to_string()))
}
