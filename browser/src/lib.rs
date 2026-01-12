//! Shield Browser SDK - Transparent auto-decryption for web applications.
//!
//! This crate provides a browser-side client that automatically decrypts
//! Shield-encrypted API responses, making encryption transparent to application code.
//!
//! # Usage (JavaScript)
//!
//! ```javascript
//! import init, { ShieldClient } from '@guard8/shield-browser';
//!
//! // Initialize once
//! await init();
//! const client = new ShieldClient();
//! await client.fetchKey('/api/shield-key');
//!
//! // Decrypt responses
//! const encrypted = await fetch('/api/data').then(r => r.json());
//! if (encrypted.encrypted) {
//!     const decrypted = client.decryptEnvelope(JSON.stringify(encrypted));
//!     console.log(decrypted);
//! }
//! ```

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use wasm_bindgen::prelude::*;

/// Browser client for Shield decryption.
///
/// Stores session key and provides decryption methods for use with
/// the fetch interceptor or manual decryption.
#[wasm_bindgen]
pub struct ShieldClient {
    /// 32-byte decryption key (from BrowserBridge)
    key: Option<Vec<u8>>,
    /// Session identifier
    session_id: Option<String>,
    /// Expiration timestamp (Unix seconds)
    expires_at: Option<u64>,
    /// Service name for verification
    service: Option<String>,
}

#[wasm_bindgen]
impl ShieldClient {
    /// Create a new ShieldClient (without key).
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            key: None,
            session_id: None,
            expires_at: None,
            service: None,
        }
    }

    /// Set the session key from BrowserBridge response.
    ///
    /// # Arguments
    /// * `key_b64` - Base64-encoded 32-byte key
    /// * `session_id` - Session identifier
    /// * `expires_at` - Expiration timestamp (Unix seconds)
    /// * `service` - Service name
    #[wasm_bindgen(js_name = setKey)]
    pub fn set_key(
        &mut self,
        key_b64: &str,
        session_id: &str,
        expires_at: u64,
        service: &str,
    ) -> Result<(), JsError> {
        let key = BASE64
            .decode(key_b64)
            .map_err(|e| JsError::new(&format!("Invalid base64 key: {}", e)))?;

        if key.len() != 32 {
            return Err(JsError::new(&format!(
                "Key must be 32 bytes, got {}",
                key.len()
            )));
        }

        self.key = Some(key);
        self.session_id = Some(session_id.to_string());
        self.expires_at = Some(expires_at);
        self.service = Some(service.to_string());

        Ok(())
    }

    /// Check if the client has a valid (non-expired) key.
    #[wasm_bindgen(js_name = isValid)]
    pub fn is_valid(&self) -> bool {
        match (&self.key, self.expires_at) {
            (Some(_), Some(exp)) => {
                let now = js_sys::Date::now() as u64 / 1000;
                now < exp
            }
            _ => false,
        }
    }

    /// Get the current session ID.
    #[wasm_bindgen(js_name = getSessionId)]
    pub fn get_session_id(&self) -> Option<String> {
        self.session_id.clone()
    }

    /// Get expiration timestamp.
    #[wasm_bindgen(js_name = getExpiresAt)]
    pub fn get_expires_at(&self) -> Option<u64> {
        self.expires_at
    }

    /// Decrypt base64-encoded ciphertext.
    ///
    /// # Arguments
    /// * `encrypted_b64` - Base64-encoded ciphertext (nonce || ct || mac)
    ///
    /// # Returns
    /// Decrypted bytes as Uint8Array
    pub fn decrypt(&self, encrypted_b64: &str) -> Result<Vec<u8>, JsError> {
        let key = self
            .key
            .as_ref()
            .ok_or_else(|| JsError::new("No key set. Call setKey() first."))?;

        if !self.is_valid() {
            return Err(JsError::new("Key has expired. Refresh required."));
        }

        let encrypted = BASE64
            .decode(encrypted_b64)
            .map_err(|e| JsError::new(&format!("Invalid base64 ciphertext: {}", e)))?;

        let key_array: [u8; 32] = key
            .as_slice()
            .try_into()
            .map_err(|_| JsError::new("Invalid key length"))?;

        shield_core::quick_decrypt(&key_array, &encrypted)
            .map_err(|e| JsError::new(&format!("Decryption failed: {}", e)))
    }

    /// Decrypt a JSON envelope `{"encrypted": true, "data": "base64..."}`.
    ///
    /// # Arguments
    /// * `envelope_json` - JSON string with encrypted envelope
    ///
    /// # Returns
    /// Decrypted string (typically JSON)
    #[wasm_bindgen(js_name = decryptEnvelope)]
    pub fn decrypt_envelope(&self, envelope_json: &str) -> Result<String, JsError> {
        // Parse the envelope
        let envelope: serde_json::Value = serde_json::from_str(envelope_json)
            .map_err(|e| JsError::new(&format!("Invalid JSON: {}", e)))?;

        // Check if encrypted
        let is_encrypted = envelope
            .get("encrypted")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if !is_encrypted {
            // Not encrypted, return as-is
            return Ok(envelope_json.to_string());
        }

        // Get the data field
        let data = envelope
            .get("data")
            .and_then(|v| v.as_str())
            .ok_or_else(|| JsError::new("Missing 'data' field in envelope"))?;

        // Decrypt
        let decrypted = self.decrypt(data)?;

        // Convert to string
        String::from_utf8(decrypted)
            .map_err(|e| JsError::new(&format!("Decrypted data is not valid UTF-8: {}", e)))
    }

    /// Check if a JSON string is an encrypted envelope.
    #[wasm_bindgen(js_name = isEncryptedEnvelope)]
    pub fn is_encrypted_envelope(&self, json_str: &str) -> bool {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(json_str) {
            v.get("encrypted")
                .and_then(|e| e.as_bool())
                .unwrap_or(false)
                && v.get("data").is_some()
        } else {
            false
        }
    }

    /// Clear the stored key (for logout).
    pub fn clear(&mut self) {
        self.key = None;
        self.session_id = None;
        self.expires_at = None;
        self.service = None;
    }
}

impl Default for ShieldClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Get current Unix timestamp in seconds.
#[wasm_bindgen(js_name = getCurrentTimestamp)]
pub fn get_current_timestamp() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = ShieldClient::new();
        assert!(!client.is_valid());
        assert!(client.get_session_id().is_none());
    }
}
