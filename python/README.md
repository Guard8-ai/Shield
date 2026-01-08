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

## Web Framework Integrations

### FastAPI

```python
from fastapi import FastAPI, Depends
from shield.integrations import ShieldMiddleware, ShieldTokenAuth

app = FastAPI()

# Encrypt all JSON responses automatically
app.add_middleware(ShieldMiddleware, password="secret", service="api.example.com")

# Token-based authentication
auth = ShieldTokenAuth(password="secret", service="api.example.com")

@app.post("/login")
async def login(username: str, password: str):
    # Verify credentials...
    token = auth.create_token(user_id=username, roles=["user"])
    return {"token": token}

@app.get("/protected")
async def protected(user: dict = Depends(auth)):
    return {"user_id": user["sub"], "roles": user["roles"]}
```

### Flask

```python
from flask import Flask
from shield.integrations import ShieldFlask, shield_required

app = Flask(__name__)
shield = ShieldFlask(app, password="secret", service="api.example.com")

@app.route("/protected")
@shield_required(password="secret", service="api.example.com")
def protected():
    from flask import g
    return {"user_id": g.shield_user["sub"]}
```

### Rate Limiting

```python
from shield.integrations import RateLimiter, APIProtector

# Simple rate limiter
limiter = RateLimiter(password="secret", service="api", max_requests=100, window=60)

if limiter.is_allowed(user_id):
    process_request()
else:
    return "Rate limit exceeded", 429

# Full API protection
protector = APIProtector(password="secret", service="api")
protector.add_rate_limit(max_requests=100, window=60)
protector.add_ip_blacklist(["1.2.3.0/24"])

result = protector.check_request(client_ip=request.remote_addr, user_id=user_id)
if not result.allowed:
    return {"error": result.reason}, 403
```

### Encrypted Cookies

```python
from shield.integrations import EncryptedCookie

cookie = EncryptedCookie(password="secret", service="api.example.com")

# Encode session data
session_value = cookie.encode({"user_id": "123", "role": "admin"})

# Set cookie header
header = cookie.make_header("session", {"user_id": "123"})
# "session=...; Secure; HttpOnly; SameSite=Strict"

# Decode from request
data = cookie.decode(request.cookies.get("session"))
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

Shield uses only symmetric primitives with unconditional security:

- **Symmetric encryption** (AES-256 equivalent)
- **Hash functions** (SHA-256)
- **HMAC authentication**
- **Key derivation** (PBKDF2)

Breaking requires 2^256 operations - no shortcut exists.

## License

CC0-1.0 (Public Domain) - Use freely, no attribution required.

## See Also

- [Shield Rust Crate](https://crates.io/crates/shield-core)
- [Shield npm Package](https://npmjs.com/package/@guard8/shield)
- [GitHub Repository](https://github.com/Guard8-ai/Shield)
