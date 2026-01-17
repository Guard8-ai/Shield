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
shield-core = "1.1"
```

For WebAssembly:

```toml
[dependencies]
shield-core = { version = "1.1", features = ["wasm"] }
```

For Confidential Computing (TEE attestation):

```toml
[dependencies]
shield-core = { version = "1.1", features = ["confidential"] }
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
- `cli` (default): Command-line interface (`shield` binary)
- `wasm`: WebAssembly support via wasm-bindgen
- `async`: Async runtime support (Tokio)
- `confidential`: Confidential Computing with TEE attestation
- `openapi`: OpenAPI/Swagger schema generation for APIs

## CLI Tool

```bash
# Install
cargo install shield-core

# Encrypt/decrypt files
shield encrypt secret.txt -o secret.enc
shield decrypt secret.enc -o secret.txt

# Check password strength
shield check "MyP@ssw0rd123"

# Encrypt text directly
shield text encrypt "hello" -p password -s service

# Generate random key
shield keygen

# Show info
shield info
```

## Password Strength

```rust
use shield_core::password::{check_password, StrengthLevel};

let result = check_password("MyP@ssw0rd123");
println!("Entropy: {:.1} bits", result.entropy);
println!("Level: {:?}", result.level);  // Strong
println!("Crack time: {}", result.crack_time_display());

if !result.is_acceptable() {
    for suggestion in &result.suggestions {
        println!("Suggestion: {}", suggestion);
    }
}
```

## Confidential Computing

Hardware-based attestation for Trusted Execution Environments (requires `confidential` feature).

### Supported Platforms

| Platform | Provider | Attestation |
|----------|----------|-------------|
| AWS Nitro Enclaves | `NitroAttestationProvider` | COSE-signed PCR measurements |
| GCP Confidential VMs | `SEVAttestationProvider` | AMD SEV-SNP + vTPM |
| Azure Confidential | `MAAAttestationProvider` | Microsoft Azure Attestation |
| Intel SGX | `SGXAttestationProvider` | DCAP quotes (MRENCLAVE/MRSIGNER) |

### Usage

```rust
use shield_core::confidential::{
    AttestationProvider, NitroAttestationProvider,
    TEEKeyManager, KeyReleasePolicy,
};
use std::sync::Arc;

// Create provider for your platform
let provider = Arc::new(NitroAttestationProvider::new()
    .with_expected_pcr(0, "expected_pcr0_hash")
    .with_max_age(300));

// Key manager with attestation gating
let key_manager = TEEKeyManager::new(
    "master_password",
    "my-service",
    provider,
);

// Get keys only after attestation verification
let key = key_manager.derive_key(&attestation_evidence).await?;
```

### SGX Sealed Storage

```rust
use shield_core::confidential::{SealedStorage, SGXSealPolicy};

let storage = SealedStorage::new(SGXSealPolicy::MRENCLAVE);
storage.store("my_key", &secret_data).await?;
let data = storage.load("my_key").await?;
```

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

### PasswordStrength

Password strength analysis.

```rust
impl PasswordStrength {
    fn length: usize;           // Password length
    fn entropy: f64;            // Bits of entropy
    fn level: StrengthLevel;    // Critical/Weak/Fair/Strong/VeryStrong
    fn crack_time_seconds: f64; // Estimated crack time
    fn suggestions: Vec<String>;// Improvement suggestions
    fn is_acceptable(&self) -> bool;
    fn is_recommended(&self) -> bool;
    fn crack_time_display(&self) -> String;
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
- [BENCHMARKS.md](../BENCHMARKS.md) - Performance comparison vs AES-GCM
- [MIGRATION.md](../MIGRATION.md) - Migration from Fernet, NaCl, etc.
