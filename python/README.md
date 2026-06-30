# Shield - Authenticated Symmetric Encryption

[![PyPI version](https://badge.fury.io/py/shield-crypto.svg)](https://pypi.org/project/shield-crypto/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Symmetric authenticated encryption with 256-bit keys (~128-bit post-quantum security).

## Why Shield?

Shield builds on well-established symmetric primitives (SHA-256, HMAC-SHA256, PBKDF2). A 256-bit key gives 256-bit classical and ~128-bit post-quantum brute-force resistance, assuming these primitives are secure:

- **PBKDF2-SHA256** for key derivation (600,000 iterations)
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

### Post-Quantum Hybrid Key Exchange

For two parties who have **never shared a secret**, derive a session key over an
open network that stays safe even against a future quantum computer ("harvest now,
decrypt later"). It runs a classical (X25519) and a quantum-safe (ML-KEM-768)
exchange and mixes both — an attacker must break *both* to win.

Requires the optional extra: `pip install shield-crypto[pq]`.

```python
from shield import Shield
from shield.pqhybrid import HybridPrivateKey, HybridPublicKey, initiate

# Recipient (Bob): generate a keypair, publish the public key anywhere.
bob = HybridPrivateKey.generate()
bob_public = bob.public_key().to_bytes()

# Sender (Alice): derive a shared key + a handshake to send.
handshake, key = initiate(HybridPublicKey.from_bytes(bob_public))
ciphertext = Shield.with_key(key).encrypt(b"hello bob")     # send handshake + ciphertext

# Recipient (Bob): recover the same key and decrypt.
bob_key = bob.accept(handshake)
Shield.with_key(bob_key).decrypt(ciphertext)                # b"hello bob"
```

See `examples/pq_hybrid_demo.py` for a narrated run.

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
Shield(password: str, service: str, salt: bytes = None, iterations: int = 600_000)
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

Shield builds on well-established symmetric primitives. Like all practical ciphers, their security is conjectural (it relies on standard assumptions), not unconditional:

- **Symmetric encryption** (AES-256 equivalent)
- **Hash functions** (SHA-256)
- **HMAC authentication**
- **Key derivation** (PBKDF2)

Brute-forcing a full 256-bit key requires 2^256 operations; this relies on the standard assumption that SHA-256/HMAC have no exploitable structure (an assumption, not a mathematical proof).

## License

MIT License - Use freely.

## See Also

- [Shield Rust Crate](https://crates.io/crates/shield-core)
- [Shield npm Package](https://npmjs.com/package/@dikestra/shield)
- [GitHub Repository](https://github.com/Dikestra-ai/Shield)
