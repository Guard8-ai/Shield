# shield-core

[![Crates.io](https://img.shields.io/crates/v/shield-core.svg)](https://crates.io/crates/shield-core)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

EXPTIME-secure encryption library for Rust - symmetric cryptography with proven exponential-time security.

## Why Shield?

Shield uses only symmetric primitives with EXPTIME-hard security guarantees. Breaking requires 2^256 operations - no shortcut exists:

- **PBKDF2-SHA256** for key derivation (100,000 iterations)
- **SHA256-based stream cipher** (AES-256-CTR equivalent)
- **HMAC-SHA256** for authentication

## Installation

```toml
[dependencies]
shield-core = "0.1"
```

For WebAssembly:

```toml
[dependencies]
shield-core = { version = "0.1", features = ["wasm"] }
```

## Quick Start

### Basic Encryption

```rust
use shield_core::Shield;

// Password-based encryption
let shield = Shield::new("my_password", "github.com");
let encrypted = shield.encrypt(b"secret data")?;
let decrypted = shield.decrypt(&encrypted)?;
```

### Pre-shared Key

```rust
use shield_core::{quick_encrypt, quick_decrypt};

let key = [0u8; 32]; // Your 32-byte key
let encrypted = quick_encrypt(&key, b"data")?;
let decrypted = quick_decrypt(&key, &encrypted)?;
```

### Large File Encryption

```rust
use shield_core::StreamCipher;

let cipher = StreamCipher::from_password("password", b"salt");
let data = vec![0u8; 1024 * 1024]; // 1MB
let encrypted = cipher.encrypt(&data)?;
let decrypted = cipher.decrypt(&encrypted)?;
```

### Forward Secrecy (Ratchet)

```rust
use shield_core::RatchetSession;

let root_key = [0u8; 32]; // Exchanged via secure channel

let mut alice = RatchetSession::new(&root_key, true);
let mut bob = RatchetSession::new(&root_key, false);

// Each message uses a new key
let encrypted = alice.encrypt(b"Hello Bob!")?;
let decrypted = bob.decrypt(&encrypted)?;
```

## Features

- `std` (default): Standard library support
- `wasm`: WebAssembly support via wasm-bindgen

## API Reference

### Shield

Main encryption struct with password-derived keys.

```rust
impl Shield {
    fn new(password: &str, service: &str) -> Self;
    fn with_key(key: &[u8; 32]) -> Self;
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>>;
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>>;
}
```

### StreamCipher

Streaming encryption for large files.

```rust
impl StreamCipher {
    fn new(key: &[u8; 32]) -> Self;
    fn from_password(password: &str, salt: &[u8]) -> Self;
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>>;
    fn decrypt(&self, encrypted: &[u8]) -> Result<Vec<u8>>;
}
```

### RatchetSession

Forward secrecy with key ratcheting.

```rust
impl RatchetSession {
    fn new(root_key: &[u8; 32], is_initiator: bool) -> Self;
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>>;
    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>>;
}
```

## Interoperability

Shield produces byte-identical output across all implementations:

- Python: `pip install shield-crypto`
- Rust: `cargo add shield-core`
- JavaScript: `npm install @guard8/shield`

## Security Model

Shield uses only symmetric primitives with unconditional security:

- **Symmetric encryption** (AES-256 equivalent)
- **Hash functions** (SHA-256)
- **HMAC authentication**
- **Key derivation** (PBKDF2)

Breaking requires 2^256 operations - no shortcut exists.

## Safety

This crate uses `#![forbid(unsafe_code)]` and relies on audited cryptographic libraries:

- `ring` for PBKDF2, HMAC-SHA256, and random number generation
- `subtle` for constant-time operations

## License

CC0-1.0 (Public Domain) - Use freely, no attribution required.

## See Also

- [Shield Python Package](https://pypi.org/project/shield-crypto/)
- [Shield npm Package](https://npmjs.com/package/@guard8/shield)
- [GitHub Repository](https://github.com/Guard8-ai/Shield)
