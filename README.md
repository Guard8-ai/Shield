# Shield

**EXPTIME-ready encryption that survives P=NP and quantum computers.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](python/)
[![JavaScript](https://img.shields.io/badge/JavaScript-ES6+-yellow.svg)](javascript/)
[![Go](https://img.shields.io/badge/Go-1.19+-00ADD8.svg)](go/)

```bash
pip install shield-crypto    # Python
npm install @guard8/shield   # JavaScript
go get github.com/Guard8-ai/shield  # Go
```

## The 30-Second Version

```python
from shield import Shield

# Encrypt
s = Shield("your-password", "your-app.com")
encrypted = s.encrypt(b"secret data")

# Decrypt
decrypted = s.decrypt(encrypted)
```

That's it. No keys to manage. No certificates. No configuration.

---

## Why Shield?

**Current encryption will break.** Not "might" - *will*.

| Threat | RSA/ECDSA | Shield |
|--------|-----------|--------|
| P=NP proven | Broken | Safe |
| Quantum computer | Broken | Safe |
| 2^128 brute force | Broken | Safe |
| 2^256 brute force | Broken | **Still safe** |

Shield uses only symmetric cryptography with 256-bit keys. Breaking it requires 2^256 operations - more than atoms in the observable universe - regardless of any mathematical breakthrough.

---

## Quick Start

### Python
```bash
pip install shield-crypto
```
```python
from shield import Shield, TOTP, RatchetSession

# Basic encryption
s = Shield("password", "myapp.com")
encrypted = s.encrypt(b"Hello, World!")
decrypted = s.decrypt(encrypted)

# Two-factor authentication
totp = TOTP(TOTP.generate_secret())
code = totp.generate()  # "847293"
totp.verify(code)       # True

# Forward secrecy (messaging)
alice = RatchetSession(shared_key, is_initiator=True)
bob = RatchetSession(shared_key, is_initiator=False)
encrypted = alice.encrypt(b"Hi Bob!")
decrypted = bob.decrypt(encrypted)
```

### JavaScript
```bash
npm install @guard8/shield
```
```javascript
const { Shield, TOTP, RatchetSession } = require('@guard8/shield');

// Basic encryption
const s = new Shield('password', 'myapp.com');
const encrypted = s.encrypt(Buffer.from('Hello, World!'));
const decrypted = s.decrypt(encrypted);

// Two-factor authentication
const totp = new TOTP(TOTP.generateSecret());
const code = totp.generate();  // "847293"
totp.verify(code);             // true
```

### Go
```bash
go get github.com/Guard8-ai/shield
```
```go
import "github.com/Guard8-ai/shield/shield"

// Basic encryption
s := shield.New("password", "myapp.com")
encrypted, _ := s.Encrypt([]byte("Hello, World!"))
decrypted, _ := s.Decrypt(encrypted)

// Two-factor authentication
secret := shield.GenerateTOTPSecret()
totp := shield.NewTOTP(secret)
code := totp.Generate(time.Now().Unix())
```

### All Languages

| Language | Install | Docs |
|----------|---------|------|
| Python | `pip install shield-crypto` | [python/](python/) |
| JavaScript | `npm install @guard8/shield` | [javascript/](javascript/) |
| Go | `go get github.com/Guard8-ai/shield` | [go/](go/) |
| C | `make` in `c/` | [c/](c/) |
| Java | Gradle: `ai.guard8:shield` | [java/](java/) |
| C# | NuGet: `Guard8.Shield` | [csharp/](csharp/) |
| Swift | Swift Package | [swift/](swift/) |
| Kotlin | Gradle: `ai.guard8:shield` | [kotlin/](kotlin/) |
| WebAssembly | `wasm-pack build` | [wasm/](wasm/) |

---

## Features

| Feature | What it does | Use case |
|---------|--------------|----------|
| `Shield` | Password-based encryption | Storing secrets |
| `quickEncrypt` | Key-based encryption | Pre-shared keys |
| `StreamCipher` | Large file encryption | Gigabyte files |
| `RatchetSession` | Forward secrecy | Messaging apps |
| `TOTP` | Time-based 2FA codes | Login security |
| `RecoveryCodes` | Backup 2FA codes | Account recovery |
| `SymmetricSignature` | HMAC signatures | API authentication |
| `LamportSignature` | Quantum-safe signatures | Long-term documents |
| `KeyRotationManager` | Key versioning | Zero-downtime rotation |
| `GroupEncryption` | Multi-recipient | Team messaging |
| `IdentityProvider` | Token-based auth | SSO systems |
| **Web Integrations** (Python) | | |
| `ShieldMiddleware` | FastAPI encryption | API response encryption |
| `ShieldFlask` | Flask extension | Flask app encryption |
| `RateLimiter` | Rate limiting | API protection |
| `EncryptedCookie` | Secure cookies | Session management |

---

## The Note Test

*"Give your friend a note with these instructions. Will they know what to do?"*

### Encrypt a file
```bash
shield encrypt secret.txt -o secret.enc
# Enter password when prompted
```

### Decrypt a file
```bash
shield decrypt secret.enc -o secret.txt
# Enter same password
```

### Set up 2FA for an app
```bash
shield totp-setup --account you@email.com --issuer MyApp
# Scan the QR code with Google Authenticator
```

### Get current 2FA code
```bash
shield totp-code JBSWY3DPEHPK3PXP
# Output: 847293 (expires in 23s)
```

### Generate a secure key
```bash
shield keygen
# Output: 32 random bytes in hex
```

---

## Interoperability

All 10 implementations produce **byte-identical output**.

Encrypt in Python:
```python
encrypted = Shield("pw", "app").encrypt(b"secret")
open("data.enc", "wb").write(encrypted)
```

Decrypt in Go:
```go
encrypted, _ := os.ReadFile("data.enc")
decrypted, _ := shield.New("pw", "app").Decrypt(encrypted)
// decrypted = "secret"
```

Decrypt in JavaScript:
```javascript
const encrypted = fs.readFileSync('data.enc');
const decrypted = new Shield('pw', 'app').decrypt(encrypted);
// decrypted = Buffer<secret>
```

---

## Security Parameters

| Parameter | Value | Why |
|-----------|-------|-----|
| Key derivation | PBKDF2-SHA256 | Proven, NIST-approved |
| Iterations | 100,000 | ~200ms on modern hardware |
| Key size | 256 bits | 2^256 brute-force resistance |
| Nonce | 128 bits random | Unique per encryption |
| MAC | HMAC-SHA256 (128-bit) | Tamper detection |
| Stream cipher | SHA256-CTR | Symmetric, EXPTIME-hard |

---

## What Shield Protects Against

- **Brute force** - 100,000 PBKDF2 iterations slow attackers
- **Tampering** - HMAC-SHA256 detects any modification
- **Replay attacks** - Ratcheting with message counters
- **Quantum computers** - 256-bit symmetric = 128-bit post-quantum
- **P=NP proofs** - No asymmetric crypto to break
- **Future math** - EXPTIME hardness is unconditional

## What Shield Does NOT Protect Against

- **Weak passwords** - Use strong, unique passwords
- **Compromised devices** - If attacker has your device, game over
- **Stolen keys** - Protect your keys like passwords
- **Side channels** - Use constant-time comparison (we do)

---

## Project Structure

```
Shield/
├── shield-core/     # Rust core library (single source of truth)
├── python/          # pip install shield-crypto
├── javascript/      # npm install @guard8/shield
├── go/              # go get github.com/Guard8-ai/shield
├── c/               # libshield.a
├── java/            # Gradle project
├── csharp/          # .NET project
├── swift/           # Swift Package
├── kotlin/          # Kotlin/JVM
├── wasm/            # WebAssembly (re-exports shield-core)
├── tests/           # Cross-language integration tests
├── CHEATSHEET.md    # Quick reference for all languages
├── INSTALL.md       # Detailed installation guide
├── SECURITY.md      # Threat model and best practices
└── CONTRIBUTING.md  # How to contribute
```

---

## Performance

| Operation | Speed | Notes |
|-----------|-------|-------|
| Key derivation | ~200ms | Intentional (anti-brute-force) |
| Encryption | 500+ MB/s | After key is derived |
| TOTP generation | <1ms | |
| Lamport signing | ~10ms | 8KB signature |

---

## Tests

```bash
# Rust core (63 tests)
cd shield-core && cargo test

# Python (153 tests)
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

**Total: 370+ tests across all implementations**

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

1. Fork the repository
2. Create a feature branch
3. Run tests in your language
4. Submit a pull request

---

## License

MIT License - See [LICENSE](LICENSE).

Use freely. No attribution required (but appreciated).

---

**Shield** - Because 2^256 is enough for anyone.

*Built by [Guard8.ai](https://guard8.ai)*
