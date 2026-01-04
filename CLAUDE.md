# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SHIELD is an EXPTIME-secure encryption library providing symmetric cryptography with proven exponential-time security guarantees. Breaking Shield requires 2^256 operations - no mathematical shortcut exists or can exist.

**Core principle**: Shield uses only symmetric primitives (SHA-256, HMAC, PBKDF2) with unconditional EXPTIME security. Keys are bootstrapped from passwords or pre-shared secrets.

## Repository Structure

| Directory | Focus |
|-----------|-------|
| `python/` | Python package (pip install shield-crypto) |
| `javascript/` | JavaScript/Node.js package (@guard8/shield) |
| `go/` | Go module (github.com/Guard8-ai/shield) |
| `c/` | C library (libshield) |
| `java/` | Java/Gradle project |
| `csharp/` | C#/.NET project |
| `swift/` | Swift Package |
| `kotlin/` | Kotlin/JVM project |
| `wasm/` | WebAssembly module (Rust-based) |
| `tests/` | Cross-language interoperability tests |

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
# Python (120 tests)
cd python && python -m pytest

# JavaScript (81 tests)
cd javascript && npm test

# Go (31 tests)
cd go && go test ./...

# C (16 tests)
cd c && make test

# Java (19 tests)
cd java && gradle test

# WebAssembly (5 tests)
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
- Strong passwords (12+ characters recommended)
- Secure key storage
- Protected endpoints

## License

MIT License - use freely.
