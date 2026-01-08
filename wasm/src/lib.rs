//! Shield WebAssembly Module
//!
//! EXPTIME-secure encryption for browsers and any WebAssembly runtime.
//! Breaking requires 2^256 operations - no shortcut exists.
//!
//! This crate re-exports the WASM bindings from `shield-core`, providing
//! a single source of truth for all Shield cryptographic implementations.
//!
//! ## Usage in JavaScript
//!
//! ```javascript
//! import init, { WasmShield, WasmTOTP, WasmRatchetSession, WasmLamportSignature } from './shield_wasm.js';
//!
//! await init();
//!
//! // Core encryption
//! const shield = new WasmShield("password", "service.com");
//! const encrypted = shield.encrypt(new TextEncoder().encode("secret"));
//! const decrypted = shield.decrypt(encrypted);
//!
//! // TOTP (2FA)
//! const secret = WasmTOTP.generateSecret();
//! const totp = new WasmTOTP(secret);
//! const code = totp.generate(Math.floor(Date.now() / 1000));
//!
//! // Ratchet session (forward secrecy)
//! const rootKey = randomBytes(32);
//! const alice = new WasmRatchetSession(rootKey, true);
//! const bob = new WasmRatchetSession(rootKey, false);
//! const encrypted = alice.encrypt(message);
//! const decrypted = bob.decrypt(encrypted);
//!
//! // Lamport signature (post-quantum secure)
//! const lamport = new WasmLamportSignature();
//! const signature = lamport.sign(message);
//! const valid = WasmLamportSignature.verifySignature(message, signature, lamport.publicKey);
//!
//! // Utility functions
//! const bytes = randomBytes(32);
//! const hash = sha256(data);
//! const mac = hmacSha256(key, data);
//! const equal = constantTimeEquals(a, b);
//! ```

// Re-export all WASM bindings from shield-core
pub use shield_core::{
    // Core encryption
    WasmShield,
    wasm_encrypt as quickEncrypt,
    wasm_decrypt as quickDecrypt,

    // TOTP (2FA)
    WasmTOTP,

    // Forward secrecy
    WasmRatchetSession,

    // Post-quantum signatures
    WasmLamportSignature,

    // Utility functions
    wasm_random_bytes as randomBytes,
    wasm_sha256 as sha256,
    wasm_hmac_sha256 as hmacSha256,
    wasm_constant_time_eq as constantTimeEquals,
};

// Also provide Shield as an alias for backwards compatibility with existing code
// that uses `Shield` instead of `WasmShield`
pub use shield_core::WasmShield as Shield;
pub use shield_core::WasmTOTP as TOTP;
pub use shield_core::WasmRatchetSession as RatchetSession;
pub use shield_core::WasmLamportSignature as LamportSignature;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reexports_available() {
        // Just verify that all re-exports compile
        let _ = std::any::type_name::<WasmShield>();
        let _ = std::any::type_name::<WasmTOTP>();
        let _ = std::any::type_name::<WasmRatchetSession>();
        let _ = std::any::type_name::<WasmLamportSignature>();
    }
}
