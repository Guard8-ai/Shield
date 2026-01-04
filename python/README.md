# Shield - EXPTIME-Secure Encryption

[![PyPI version](https://badge.fury.io/py/shield-crypto.svg)](https://pypi.org/project/shield-crypto/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Symmetric cryptography with proven exponential-time security.

## Why Shield?

Shield uses only symmetric primitives with EXPTIME-hard security guarantees. Breaking requires 2^256 operations - no shortcut exists:

- **PBKDF2-SHA256** for key derivation (100,000 iterations)
- **SHA256-based stream cipher** (AES-256-CTR equivalent)
- **HMAC-SHA256** for authentication

## Installation

```bash
pip install shield-crypto
```

## Quick Start

### Basic Encryption

```python
from shield import Shield

# Password-based encryption
s = Shield("my_password", "github.com")
encrypted = s.encrypt(b"secret data")
decrypted = s.decrypt(encrypted)  # b"secret data"
```

### Pre-shared Key

```python
from shield import quick_encrypt, quick_decrypt
import os

key = os.urandom(32)
encrypted = quick_encrypt(key, b"data")
decrypted = quick_decrypt(key, encrypted)
```

### Large File Encryption

```python
from shield import StreamCipher

cipher = StreamCipher.from_password("password", b"salt")
cipher.encrypt_file("large.bin", "large.bin.enc")
cipher.decrypt_file("large.bin.enc", "large.bin.dec")
```

### Forward Secrecy (Ratchet)

```python
from shield import RatchetSession
import os

root_key = os.urandom(32)  # Exchanged via secure channel

alice = RatchetSession(root_key, is_initiator=True)
bob = RatchetSession(root_key, is_initiator=False)

# Each message uses a new key
encrypted = alice.encrypt(b"Hello!")
decrypted = bob.decrypt(encrypted)  # b"Hello!"
```

### TOTP (2FA)

```python
from shield import TOTP

# Setup
secret = TOTP.generate_secret()
totp = TOTP(secret)

# Get QR code URI for authenticator apps
uri = totp.provisioning_uri("user@example.com", "MyApp")

# Generate/verify codes
code = totp.generate()
is_valid = totp.verify(code)  # True
```

## CLI Usage

```bash
# Encrypt a file
shield encrypt secret.txt -o secret.enc

# Decrypt a file
shield decrypt secret.enc -o secret.txt

# Generate random key
shield keygen

# Setup TOTP
shield totp-setup --account user@example.com

# Generate TOTP code
shield totp-code JBSWY3DPEHPK3PXP
```

## API Reference

### Shield

Main encryption class with password-derived keys.

```python
Shield(password: str, service: str, salt: bytes = None, iterations: int = 100_000)
Shield.with_key(key: bytes)  # Create from raw 32-byte key
.encrypt(plaintext: bytes) -> bytes
.decrypt(ciphertext: bytes) -> Optional[bytes]
```

### StreamCipher

Streaming encryption for large files.

```python
StreamCipher(key: bytes, chunk_size: int = 65536)
StreamCipher.from_password(password: str, salt: bytes)
.encrypt_file(in_path: str, out_path: str)
.decrypt_file(in_path: str, out_path: str)
.encrypt(data: bytes) -> bytes
.decrypt(data: bytes) -> bytes
```

### RatchetSession

Forward secrecy with key ratcheting.

```python
RatchetSession(root_key: bytes, is_initiator: bool)
.encrypt(plaintext: bytes) -> bytes
.decrypt(ciphertext: bytes) -> Optional[bytes]
```

### TOTP

Time-based One-Time Passwords (RFC 6238).

```python
TOTP(secret: bytes, digits: int = 6, interval: int = 30, algorithm: str = "sha1")
TOTP.generate_secret() -> bytes
TOTP.secret_to_base32(secret: bytes) -> str
TOTP.secret_from_base32(b32: str) -> bytes
.generate(timestamp: int = None) -> str
.verify(code: str, timestamp: int = None, window: int = 1) -> bool
.provisioning_uri(account: str, issuer: str = "Shield") -> str
```

## Security Model

### What P=NP Would Break

- RSA, ECDSA, ECDH (factoring, discrete log)
- Most key exchange protocols
- Certificate authorities

### What Remains Secure

- **Symmetric encryption** (AES, ChaCha20)
- **Hash functions** (SHA-256, SHA-3)
- **HMAC authentication**
- **Key derivation** (PBKDF2, Argon2)

Shield uses **only** primitives from the "remains secure" category.

## License

CC0-1.0 (Public Domain) - Use freely, no attribution required.

## See Also

- [Shield Rust Crate](https://crates.io/crates/shield-core)
- [Shield npm Package](https://npmjs.com/package/@guard8/shield)
- [GitHub Repository](https://github.com/Guard8-ai/Shield)
