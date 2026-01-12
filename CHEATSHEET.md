# Shield Multi-Language Cheatsheet

Quick reference for using Shield across Python, JavaScript, Rust, Go, C, Java, C#, Swift, Kotlin, and WebAssembly.

## Installation

| Language | Package | Command |
|----------|---------|---------|
| Python | shield-crypto | `pip install shield-crypto` |
| JavaScript | @guard8/shield | `npm install @guard8/shield` |
| Rust | shield-core | `cargo add shield-core` |
| Go | github.com/Guard8-ai/shield | `go get github.com/Guard8-ai/shield` |
| C | libshield | Build from source |
| Java | ai.guard8:shield | Maven/Gradle |
| C# | Guard8.Shield | NuGet |
| Swift | Guard8Shield | Swift Package |
| Kotlin | ai.guard8:shield | Gradle |
| WebAssembly | shield-wasm | `wasm-pack build` |

## Basic Encryption

### Python
```python
from shield import Shield

s = Shield("password", "service.com")
encrypted = s.encrypt(b"secret data")
decrypted = s.decrypt(encrypted)
```

### JavaScript
```javascript
const { Shield } = require('@guard8/shield');

const s = new Shield('password', 'service.com');
const encrypted = s.encrypt(Buffer.from('secret data'));
const decrypted = s.decrypt(encrypted);
```

### Rust
```rust
use shield_core::Shield;

let s = Shield::new("password", "service.com");
let encrypted = s.encrypt(b"secret data")?;
let decrypted = s.decrypt(&encrypted)?;
```

### Go
```go
import "github.com/Guard8-ai/shield/shield"

s := shield.New("password", "service.com")
encrypted, _ := s.Encrypt([]byte("secret data"))
decrypted, _ := s.Decrypt(encrypted)
```

### C
```c
#include "shield.h"

shield_t ctx;
shield_init(&ctx, "password", "service.com");
size_t len;
uint8_t *encrypted = shield_encrypt(&ctx, data, data_len, &len);
uint8_t *decrypted = shield_decrypt(&ctx, encrypted, len, &len, NULL);
```

### Java
```java
import ai.guard8.shield.Shield;

Shield s = new Shield("password", "service.com");
byte[] encrypted = s.encrypt("secret data".getBytes());
byte[] decrypted = s.decrypt(encrypted);
```

### C#
```csharp
using Guard8.Shield;

var s = new Shield("password", "service.com");
byte[] encrypted = s.Encrypt(data);
byte[] decrypted = s.Decrypt(encrypted);
```

### Swift
```swift
import Shield

let s = try Shield.create(password: "password", service: "service.com")
let encrypted = try s.encrypt(data)
let decrypted = try s.decrypt(encrypted)
```

### Kotlin
```kotlin
import ai.guard8.shield.Shield

Shield.create("password", "service.com").use { s ->
    val encrypted = s.encrypt(data)
    val decrypted = s.decrypt(encrypted)
}
```

### WebAssembly (Browser)
```javascript
import init, { Shield } from './pkg/shield_wasm.js';

await init();
const s = new Shield("password", "service.com");
const encrypted = s.encrypt(new TextEncoder().encode("data"));
const decrypted = s.decrypt(encrypted);
```

## Pre-shared Key (No Password)

### Python
```python
from shield import quick_encrypt, quick_decrypt
import os

key = os.urandom(32)
encrypted = quick_encrypt(key, b"data")
decrypted = quick_decrypt(key, encrypted)
```

### JavaScript
```javascript
const { quickEncrypt, quickDecrypt } = require('@guard8/shield');
const crypto = require('crypto');

const key = crypto.randomBytes(32);
const encrypted = quickEncrypt(key, Buffer.from('data'));
const decrypted = quickDecrypt(key, encrypted);
```

### Rust
```rust
use shield_core::{quick_encrypt, quick_decrypt};

let key = [0u8; 32]; // Your key
let encrypted = quick_encrypt(&key, b"data")?;
let decrypted = quick_decrypt(&key, &encrypted)?;
```

## Streaming (Large Files)

### Python
```python
from shield import StreamCipher

cipher = StreamCipher.from_password("password", b"salt")
cipher.encrypt_file("large.bin", "large.enc")
cipher.decrypt_file("large.enc", "large.dec")
```

### JavaScript
```javascript
const { StreamCipher } = require('@guard8/shield');

const cipher = StreamCipher.fromPassword('password', Buffer.from('salt'));
cipher.encryptFile('large.bin', 'large.enc');
cipher.decryptFile('large.enc', 'large.dec');
```

### Rust
```rust
use shield_core::StreamCipher;

let cipher = StreamCipher::from_password("password", b"salt");
let encrypted = cipher.encrypt(&data)?;
let decrypted = cipher.decrypt(&encrypted)?;
```

## Forward Secrecy (Ratchet)

### Python
```python
from shield import RatchetSession
import os

root_key = os.urandom(32)
alice = RatchetSession(root_key, is_initiator=True)
bob = RatchetSession(root_key, is_initiator=False)

encrypted = alice.encrypt(b"Hello!")
decrypted = bob.decrypt(encrypted)
```

### JavaScript
```javascript
const { RatchetSession } = require('@guard8/shield');
const crypto = require('crypto');

const rootKey = crypto.randomBytes(32);
const alice = new RatchetSession(rootKey, true);
const bob = new RatchetSession(rootKey, false);

const encrypted = alice.encrypt(Buffer.from('Hello!'));
const decrypted = bob.decrypt(encrypted);
```

### Rust
```rust
use shield_core::RatchetSession;

let root_key = [0u8; 32];
let mut alice = RatchetSession::new(&root_key, true);
let mut bob = RatchetSession::new(&root_key, false);

let encrypted = alice.encrypt(b"Hello!")?;
let decrypted = bob.decrypt(&encrypted)?;
```

## TOTP (2FA)

### Python
```python
from shield import TOTP

secret = TOTP.generate_secret()
totp = TOTP(secret)
code = totp.generate()
is_valid = totp.verify(code)
uri = totp.provisioning_uri("user@example.com", "MyApp")
```

### JavaScript
```javascript
const { TOTP } = require('@guard8/shield');

const secret = TOTP.generateSecret();
const totp = new TOTP(secret);
const code = totp.generate();
const isValid = totp.verify(code);
const uri = totp.provisioningUri('user@example.com', 'MyApp');
```

## Recovery Codes

### Python
```python
from shield.totp import RecoveryCodes

rc = RecoveryCodes()
print(rc.codes)          # ['XXXX-XXXX', ...]
print(rc.remaining)      # 10
rc.verify("XXXX-XXXX")   # True (consumed)
```

### JavaScript
```javascript
const { RecoveryCodes } = require('@guard8/shield');

const rc = new RecoveryCodes();
console.log(rc.codes);      // ['XXXX-XXXX', ...]
console.log(rc.remaining);  // 10
rc.verify('XXXX-XXXX');     // true (consumed)
```

## Digital Signatures

### Python
```python
from shield.signatures import SymmetricSignature, LamportSignature

# HMAC-based (multi-use)
signer = SymmetricSignature.generate()
signature = signer.sign(b"message")
is_valid = signer.verify(b"message", signature, signer.verification_key)

# Lamport (one-time, post-quantum)
lamport = LamportSignature.generate()
signature = lamport.sign(b"message")  # Can only sign once!
is_valid = LamportSignature.verify(b"message", signature, lamport.public_key)
```

### JavaScript
```javascript
const { SymmetricSignature, LamportSignature } = require('@guard8/shield');

// HMAC-based
const signer = SymmetricSignature.generate();
const signature = signer.sign(Buffer.from('message'));
const isValid = signer.verify(Buffer.from('message'), signature, signer.verificationKey);

// Lamport (one-time)
const lamport = LamportSignature.generate();
const sig = lamport.sign(Buffer.from('message'));
const valid = LamportSignature.verify(Buffer.from('message'), sig, lamport.publicKey);
```

## Key Exchange (PAKE)

### Python
```python
from shield.exchange import PAKEExchange, KeySplitter

# Password-authenticated key exchange
salt = PAKEExchange.generate_salt()
client_key = PAKEExchange.derive("shared_password", salt, "client")
server_key = PAKEExchange.derive("shared_password", salt, "server")
session_key = PAKEExchange.combine(client_key, server_key)

# Key splitting (secret sharing)
key = os.urandom(32)
shares = KeySplitter.split(key, 3)  # Need all 3 to recover
recovered = KeySplitter.combine(shares)
```

### JavaScript
```javascript
const { PAKEExchange, KeySplitter } = require('@guard8/shield');

// PAKE
const salt = PAKEExchange.generateSalt();
const clientKey = PAKEExchange.derive('password', salt, 'client');
const serverKey = PAKEExchange.derive('password', salt, 'server');
const sessionKey = PAKEExchange.combine(clientKey, serverKey);

// Key splitting
const shares = KeySplitter.split(key, 3);
const recovered = KeySplitter.combine(shares);
```

## Key Rotation

### Python
```python
from shield.rotation import KeyRotationManager

manager = KeyRotationManager(initial_key)
encrypted_v1 = manager.encrypt(b"data")

manager.rotate(new_key)  # Now at version 2
encrypted_v2 = manager.encrypt(b"new data")

# Both versions decrypt correctly
manager.decrypt(encrypted_v1)  # Works with v1 key
manager.decrypt(encrypted_v2)  # Works with v2 key
```

### JavaScript
```javascript
const { KeyRotationManager } = require('@guard8/shield');

const manager = new KeyRotationManager(initialKey);
const encryptedV1 = manager.encrypt(Buffer.from('data'));

manager.rotate(newKey);
const encryptedV2 = manager.encrypt(Buffer.from('new data'));

manager.decrypt(encryptedV1);  // Works
manager.decrypt(encryptedV2);  // Works
```

## Secure Channel (Rust-only)

TLS-like encrypted transport using PAKE + RatchetSession.

### Rust (Sync)
```rust
use shield_core::{ShieldChannel, ChannelConfig};
use std::net::TcpStream;

// Both parties share a password
let config = ChannelConfig::new("shared-secret", "my-service");

// Server
let listener = std::net::TcpListener::bind("0.0.0.0:8080")?;
let (stream, _) = listener.accept()?;
let mut server = ShieldChannel::accept(stream, &config)?;

// Client
let stream = TcpStream::connect("127.0.0.1:8080")?;
let mut client = ShieldChannel::connect(stream, &config)?;

// Exchange messages with forward secrecy
client.send(b"Hello server!")?;
let msg = server.recv()?;  // "Hello server!"

server.send(b"Hello client!")?;
let response = client.recv()?;  // "Hello client!"
```

### Rust (Async with Tokio)
```rust
use shield_core::{AsyncShieldChannel, ChannelConfig};
use tokio::net::TcpStream;

let config = ChannelConfig::new("shared-secret", "my-service")
    .with_iterations(100_000)
    .with_timeout(5_000);

// Client
let stream = TcpStream::connect("127.0.0.1:8080").await?;
let mut channel = AsyncShieldChannel::connect(stream, &config).await?;

channel.send(b"Hello!").await?;
let response = channel.recv().await?;

// Diagnostics
println!("Messages sent: {}", channel.messages_sent());
println!("Service: {}", channel.service());
```

### Features
- PAKE handshake (no certificates needed)
- Forward secrecy via key ratcheting
- Message authentication (HMAC)
- Replay protection (counters)
- Wrong password = authentication failure

## Group Encryption

### Python
```python
from shield.group import GroupEncryption

group = GroupEncryption()
group.add_member("alice", alice_shared_key)
group.add_member("bob", bob_shared_key)

encrypted = group.encrypt(b"group message")

# Each member decrypts with their key
GroupEncryption.decrypt(encrypted, "alice", alice_shared_key)
GroupEncryption.decrypt(encrypted, "bob", bob_shared_key)
```

### JavaScript
```javascript
const { GroupEncryption } = require('@guard8/shield');

const group = new GroupEncryption();
group.addMember('alice', aliceKey);
group.addMember('bob', bobKey);

const encrypted = group.encrypt(Buffer.from('group message'));

GroupEncryption.decrypt(encrypted, 'alice', aliceKey);
GroupEncryption.decrypt(encrypted, 'bob', bobKey);
```

## Identity Provider (SSO)

### Python
```python
from shield.identity import IdentityProvider

provider = IdentityProvider(master_key, token_ttl=3600)
identity = provider.register("alice", "password123", "Alice Smith")

token = provider.authenticate("alice", "password123")
session = provider.validate_token(token)

# Service-specific tokens
service_token = provider.create_service_token(token, "api.example.com")
provider.validate_service_token(service_token, "api.example.com")
```

### JavaScript
```javascript
const { IdentityProvider } = require('@guard8/shield');

const provider = new IdentityProvider(masterKey, 3600);
const identity = provider.register('alice', 'password123', 'Alice Smith');

const token = provider.authenticate('alice', 'password123');
const session = provider.validateToken(token);

const serviceToken = provider.createServiceToken(token, 'api.example.com');
provider.validateServiceToken(serviceToken, 'api.example.com');
```

## Web Framework Integrations (Python)

### FastAPI Middleware

```python
from fastapi import FastAPI, Depends
from shield.integrations import ShieldMiddleware, ShieldTokenAuth

app = FastAPI()

# Encrypt all JSON responses
app.add_middleware(ShieldMiddleware, password="secret", service="api.example.com")

# Token authentication
auth = ShieldTokenAuth(password="secret", service="api.example.com")

@app.get("/protected")
async def protected(user: dict = Depends(auth)):
    return {"user_id": user["sub"]}
```

### Flask Extension

```python
from flask import Flask, g
from shield.integrations import ShieldFlask, shield_required

app = Flask(__name__)
shield = ShieldFlask(app, password="secret", service="api.example.com")

@app.route("/protected")
@shield_required(password="secret", service="api.example.com")
def protected():
    return {"user_id": g.shield_user["sub"]}
```

### Rate Limiting

```python
from shield.integrations import RateLimiter, TokenBucket, APIProtector

# Fixed window rate limiter
limiter = RateLimiter(password="secret", service="api", max_requests=100, window=60)
if limiter.is_allowed(user_id):
    process_request()

# Token bucket (allows bursts)
bucket = TokenBucket(password="secret", service="api", capacity=10, refill_rate=1.0)
if bucket.consume(user_id):
    process_request()

# Full API protection
protector = APIProtector(password="secret", service="api")
protector.add_rate_limit(max_requests=100, window=60)
protector.add_ip_blacklist(["1.2.3.0/24"])
result = protector.check_request(client_ip="10.0.0.1", user_id="user123")
```

### Encrypted Cookies

```python
from shield.integrations import EncryptedCookie

cookie = EncryptedCookie(password="secret", service="api.example.com")

# Encode session
value = cookie.encode({"user_id": "123", "role": "admin"})

# Make Set-Cookie header
header = cookie.make_header("session", {"user_id": "123"})

# Decode from request
data = cookie.decode(cookie_value)  # Returns None if tampered/expired
```

### Browser Key Exchange

```python
from shield.integrations import BrowserBridge

bridge = BrowserBridge(password="secret", service="api.example.com")

# Generate key for browser client
client_key = bridge.generate_client_key(session_id="session123", ttl=3600)
# Returns: {"key": "...", "session_id": "session123", "expires_at": ...}

# Encrypt data for specific client
encrypted = bridge.encrypt_for_client("session123", b"sensitive data")
```

## CLI (Rust)

```bash
# Install
cargo install shield-core

# Encrypt/decrypt files
shield encrypt secret.txt -o secret.enc
shield decrypt secret.enc -o secret.txt

# Check password strength
shield check "MyP@ssw0rd123"
# Output: STRONG - 72.3 bits entropy

# Encrypt text directly
shield text encrypt "secret message" -p password -s myservice
shield text decrypt "hex_ciphertext" -p password -s myservice

# Generate random key
shield keygen

# Show algorithm info
shield info
```

## Interoperability

All implementations produce **byte-identical output**:

```python
# Python encrypts
s = Shield("password", "service.com")
encrypted = s.encrypt(b"Hello!")
with open("encrypted.bin", "wb") as f:
    f.write(encrypted)
```

```javascript
// JavaScript decrypts
const s = new Shield('password', 'service.com');
const encrypted = fs.readFileSync('encrypted.bin');
const decrypted = s.decrypt(encrypted);
// Buffer: 'Hello!'
```

```rust
// Rust decrypts
let s = Shield::new("password", "service.com");
let encrypted = std::fs::read("encrypted.bin")?;
let decrypted = s.decrypt(&encrypted)?;
// b"Hello!"
```

## Password Strength

### Rust
```rust
use shield_core::password::{check_password, StrengthLevel};

let result = check_password("MyP@ssw0rd123");
println!("Entropy: {:.1} bits", result.entropy);
println!("Level: {:?}", result.level);
println!("Crack time: {}", result.crack_time_display());

// Warn on weak passwords
if matches!(result.level, StrengthLevel::Critical | StrengthLevel::Weak) {
    eprintln!("Warning: {}", result.suggestions.first().unwrap_or(&String::new()));
}
```

### Python
```python
from shield.password import check_password, StrengthLevel

result = check_password("MyP@ssw0rd123")
print(f"Entropy: {result.entropy:.1f} bits")
print(f"Level: {result.level.name}")
print(f"Crack time: {result.crack_time_display()}")

if result.level in (StrengthLevel.Critical, StrengthLevel.Weak):
    print(f"Warning: {result.suggestions[0]}")
```

## Security Parameters

| Parameter | Value |
|-----------|-------|
| Key derivation | PBKDF2-SHA256 |
| Iterations | 100,000 |
| Key size | 256 bits |
| Nonce size | 128 bits |
| MAC size | 128 bits |
| Stream cipher | SHA256-CTR |
| Authentication | HMAC-SHA256 |

## Why EXPTIME-Ready?

Shield uses only proven symmetric primitives with unconditional security bounds.

**Shield remains secure because:**
- 256-bit symmetric keys require 2^256 operations to break
- This is EXPTIME-hard (exponential in key size)
- Quantum computers only halve this to 2^128 (Grover's)
- No mathematical shortcut exists or can exist

**Shield uses only proven EXPTIME primitives:**
- SHA-256 (hash) - 2^256 preimage resistance
- HMAC-SHA256 (MAC) - 2^256 forgery resistance
- PBKDF2 (KDF) - 2^256 * iterations key space
- Lamport signatures - hash-based, quantum-safe

## Browser SDK

### Installation
```bash
npm install @guard8/shield-browser
```

### Auto-Decrypt Setup
```javascript
import { ShieldBrowser } from '@guard8/shield-browser';

// Initialize - fetches key and installs fetch hook
await ShieldBrowser.init('/api/shield-key');

// All fetch() calls now auto-decrypt!
const data = await fetch('/api/secret').then(r => r.json());
// data is already decrypted
```

### Server Setup (Python)
```python
from shield.integrations import BrowserBridge

bridge = BrowserBridge("password", "api.example.com")

# Key endpoint
@app.get("/api/shield-key")
async def get_key(session_id: str):
    return bridge.generate_client_key(session_id)

# Encrypted endpoint
@app.get("/api/secret")
async def get_secret(session_id: str):
    data = {"message": "Secret!"}
    encrypted = bridge.encrypt_for_client(session_id, json.dumps(data).encode())
    return {"encrypted": True, "data": base64.b64encode(encrypted).decode()}
```

### Manual Decryption
```javascript
const client = ShieldBrowser.getInstance();
const decrypted = client.decryptEnvelope(JSON.stringify(encryptedResponse));
const data = JSON.parse(decrypted);
```

## See Also

- [BENCHMARKS.md](BENCHMARKS.md) - Performance comparison vs AES-GCM, ChaCha20
- [MIGRATION.md](MIGRATION.md) - Migration from Fernet, NaCl, PyCryptodome
- [browser/README.md](browser/README.md) - Browser SDK documentation
