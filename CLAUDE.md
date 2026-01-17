# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SHIELD is an EXPTIME-secure encryption library providing symmetric cryptography with proven exponential-time security guarantees. Breaking Shield requires 2^256 operations - no mathematical shortcut exists or can exist.

**Core principle**: Shield uses only symmetric primitives (SHA-256, HMAC, PBKDF2) with unconditional EXPTIME security. Keys are bootstrapped from passwords or pre-shared secrets.

## Repository Structure

| Directory | Focus |
|-----------|-------|
| `shield-core/` | **Rust core library + CLI** - Single source of truth for Rust/WASM |
| `browser/` | Browser SDK - Auto-decrypt fetch() with WASM |
| `android/` | Android SDK (Keystore + biometric integration) |
| `ios/` | iOS SDK (Keychain + Face ID/Touch ID integration) |
| `python/` | Python package (pip install shield-crypto) |
| `javascript/` | JavaScript/Node.js package (@guard8/shield) |
| `go/` | Go module (github.com/Guard8-ai/shield) |
| `c/` | C library (libshield) |
| `java/` | Java/Gradle project |
| `csharp/` | C#/.NET project |
| `swift/` | Swift Package |
| `kotlin/` | Kotlin/JVM project |
| `wasm/` | WebAssembly module (re-exports shield-core with wasm feature) |
| `examples/` | Usage examples (browser-integration, hsm, confidential-computing) |
| `tests/` | Cross-language interoperability tests |
| `BENCHMARKS.md` | Performance benchmarks vs AES-GCM, ChaCha20 |
| `MIGRATION.md` | Migration guides from Fernet, NaCl, PyCryptodome |

## Key Components

### Core Encryption
- `Shield`: Password-based encryption (PBKDF2-SHA256 + SHA256-CTR + HMAC-SHA256)
- `quickEncrypt/quickDecrypt`: Pre-shared key encryption

### Advanced Features
- `StreamCipher`: Large file encryption with per-chunk authentication
- `RatchetSession`: Forward secrecy with key ratcheting
- `TOTP/RecoveryCodes`: Two-factor authentication (RFC 6238)
- `SymmetricSignature`: HMAC-based signatures
- `LamportSignature`: Quantum-safe one-time signatures
- `GroupEncryption`: Multi-recipient encryption
- `KeyRotationManager`: Zero-downtime key rotation
- `IdentityProvider`: Token-based authentication/SSO
- `password`: Password strength checker with entropy calculation

### Secure Transport (Rust-only)
- `ShieldChannel`: TLS-like encrypted channel using PAKE + RatchetSession
- `AsyncShieldChannel`: Tokio-based async version for high-performance networking
- `ChannelConfig`: Configuration for password, service, iterations, timeout

### CLI Tool (shield-core)
- `shield encrypt/decrypt`: File encryption/decryption
- `shield check`: Password strength analysis
- `shield text`: Encrypt/decrypt text directly
- `shield keygen`: Generate random keys
- `shield info`: Show algorithm information

### Browser SDK (`browser/`)
- `ShieldBrowser.init()`: Initialize with key endpoint
- Auto-intercepts `fetch()` and decrypts encrypted responses
- Works with Python `BrowserBridge` for key exchange
- Transparent encryption for web applications

### Mobile SDKs
- **Android** (`android/`): Native Android SDK with Keystore integration
  - `Shield`: Core encryption (same API as other platforms)
  - `SecureKeyStore`: Android Keystore + EncryptedSharedPreferences
  - Hardware-backed storage (TEE/StrongBox) when available
  - Biometric protection support
- **iOS** (`ios/`): Native iOS SDK with Keychain integration
  - `Shield`: Core encryption (same API as other platforms)
  - `SecureKeychain`: iOS Keychain with biometric protection
  - Face ID / Touch ID integration
  - CocoaPods + Swift Package Manager support

### Python Web Integrations (`shield.integrations`)
- `ShieldMiddleware`: FastAPI middleware for automatic response encryption
- `ShieldFlask`: Flask extension with request/response encryption
- `shield_protected`/`shield_required`: Decorators for protected endpoints
- `ShieldTokenAuth`/`ShieldAPIKeyAuth`: Token and API key authentication
- `RateLimiter`/`TokenBucket`: Rate limiting with encrypted state
- `APIProtector`: Combined rate limiting, IP filtering, and audit logging
- `BrowserBridge`: Secure key exchange with browser clients
- `EncryptedCookie`: Tamper-proof encrypted cookies
- `SecureCORS`: CORS with signed request validation

### Confidential Computing (Rust + Python)
Hardware-based attestation and encryption for Trusted Execution Environments (TEEs).

**Rust** (`shield-core/src/confidential/` with `confidential` feature):
- `AttestationProvider` trait: Common interface for all TEE providers
- `NitroAttestationProvider`: AWS Nitro Enclaves (COSE-signed PCR measurements)
- `SEVAttestationProvider`: GCP Confidential VMs (AMD SEV-SNP + vTPM)
- `MAAAttestationProvider`: Azure MAA (Microsoft Attestation, Secure Key Release)
- `SGXAttestationProvider`: Intel SGX (DCAP quotes, MRENCLAVE/MRSIGNER)
- `TEEKeyManager`: Attestation-gated key release with policy enforcement
- `SealedStorage`: SGX-specific encrypted storage bound to enclave identity
- OpenAPI schemas via `utoipa` (`openapi` feature)

**Python** (`shield.integrations.confidential`):
- Same provider classes with async support
- `AttestationMiddleware`: FastAPI middleware for client attestation
- `@requires_attestation`: Decorator for attestation-protected endpoints
- Platform-specific integrations (AWS KMS, GCP Secret Manager, Azure Key Vault)

## Architecture

### Encryption Flow
```
Password → PBKDF2 (100k rounds) → Key → SHA256-CTR + HMAC-SHA256 → Ciphertext
```

Format: `nonce(16 bytes) || ciphertext || MAC(16 bytes)`

### Security Parameters
| Parameter | Value |
|-----------|-------|
| Key derivation | PBKDF2-SHA256, 100,000 iterations |
| Key size | 256 bits |
| Nonce | 128 bits (random per message) |
| MAC | HMAC-SHA256 (128-bit truncated) |

## Running Tests

```bash
# Rust core (95 tests with confidential computing)
cd shield-core && cargo test --features confidential

# Rust with OpenAPI support
cd shield-core && cargo test --features openapi

# Python (153 tests - includes 33 integration tests)
cd python && python -m pytest

# JavaScript (81 tests)
cd javascript && npm test

# Go (31 tests)
cd go && go test ./...

# C (16 tests)
cd c && make test

# Java (19 tests)
cd java && gradle test

# WebAssembly (uses shield-core)
cd wasm && cargo test
```

## Cross-Language Interoperability

All 10 implementations produce byte-identical output. Encrypt in any language, decrypt in any other. See `CHEATSHEET.md` for examples.

## Security Model

**EXPTIME Security Guarantees:**
- 256-bit symmetric keys require 2^256 brute-force operations
- No polynomial-time shortcut exists (this is a mathematical fact)
- Quantum computers only reduce to 2^128 (Grover's algorithm)
- All primitives are NIST-approved and battle-tested

**Protected against:**
- Brute force attacks
- Quantum computers
- Tampering (HMAC authentication)
- Replay attacks (ratcheting with counters)

**Requirements:**
- Strong passwords (use `check_password()` to enforce)
- Secure key storage
- Protected endpoints

## License

MIT License - use freely.
