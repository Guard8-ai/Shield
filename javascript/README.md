# @guard8/shield

[![npm version](https://badge.fury.io/js/@guard8%2Fshield.svg)](https://www.npmjs.com/package/@guard8/shield)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

EXPTIME-secure encryption library for Node.js - symmetric cryptography with proven exponential-time security.

## Why Shield?

Shield uses only symmetric primitives with EXPTIME-hard security guarantees. Breaking requires 2^256 operations - no shortcut exists:

- **PBKDF2-SHA256** for key derivation (100,000 iterations)
- **SHA256-based stream cipher** (AES-256-CTR equivalent)
- **HMAC-SHA256** for authentication

## Installation

```bash
npm install @guard8/shield
```

## Quick Start

### Basic Encryption

```javascript
const { Shield } = require('@guard8/shield');

// Password-based encryption
const s = new Shield('my_password', 'github.com');
const encrypted = s.encrypt(Buffer.from('secret data'));
const decrypted = s.decrypt(encrypted); // Buffer: 'secret data'
```

### Pre-shared Key

```javascript
const { quickEncrypt, quickDecrypt } = require('@guard8/shield');
const crypto = require('crypto');

const key = crypto.randomBytes(32);
const encrypted = quickEncrypt(key, Buffer.from('data'));
const decrypted = quickDecrypt(key, encrypted);
```

### Large File Encryption

```javascript
const { StreamCipher } = require('@guard8/shield');

const cipher = StreamCipher.fromPassword('password', Buffer.from('salt'));
cipher.encryptFile('large.bin', 'large.bin.enc');
cipher.decryptFile('large.bin.enc', 'large.bin.dec');
```

### Forward Secrecy (Ratchet)

```javascript
const { RatchetSession } = require('@guard8/shield');
const crypto = require('crypto');

const rootKey = crypto.randomBytes(32); // Exchanged via secure channel

const alice = new RatchetSession(rootKey, true);
const bob = new RatchetSession(rootKey, false);

// Each message uses a new key
const encrypted = alice.encrypt(Buffer.from('Hello!'));
const decrypted = bob.decrypt(encrypted); // Buffer: 'Hello!'
```

### TOTP (2FA)

```javascript
const { TOTP } = require('@guard8/shield');

// Setup
const secret = TOTP.generateSecret();
const totp = new TOTP(secret);

// Get QR code URI for authenticator apps
const uri = totp.provisioningUri('user@example.com', 'MyApp');

// Generate/verify codes
const code = totp.generate();
const isValid = totp.verify(code); // true
```

## API Reference

### Shield

Main encryption class with password-derived keys.

```javascript
new Shield(password, service, options?)
Shield.withKey(key)     // Create from raw 32-byte key
.encrypt(plaintext)     // Returns Buffer
.decrypt(ciphertext)    // Returns Buffer | null
```

### StreamCipher

Streaming encryption for large files.

```javascript
new StreamCipher(key, chunkSize?)
StreamCipher.fromPassword(password, salt, chunkSize?)
.encrypt(data)          // In-memory encryption
.decrypt(encrypted)     // In-memory decryption
.encryptFile(inPath, outPath)
.decryptFile(inPath, outPath)
```

### RatchetSession

Forward secrecy with key ratcheting.

```javascript
new RatchetSession(rootKey, isInitiator)
.encrypt(plaintext)
.decrypt(ciphertext)
.sendCounter            // Current send message count
.recvCounter            // Current receive message count
```

### TOTP

Time-based One-Time Passwords (RFC 6238).

```javascript
new TOTP(secret, options?)
TOTP.generateSecret(length?)
TOTP.secretToBase32(secret)
TOTP.secretFromBase32(b32)
.generate(timestamp?)
.verify(code, timestamp?, window?)
.provisioningUri(account, issuer?)
```

### RecoveryCodes

Backup codes for 2FA.

```javascript
new RecoveryCodes(codes?)
RecoveryCodes.generateCodes(count?, length?)
.verify(code)           // Returns boolean (consumes code if valid)
.remaining              // Number of unused codes
.codes                  // All codes array
```

## TypeScript Support

TypeScript declarations are included. Import types:

```typescript
import { Shield, TOTP, StreamCipher } from '@guard8/shield';
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

## License

CC0-1.0 (Public Domain) - Use freely, no attribution required.

## See Also

- [Shield Python Package](https://pypi.org/project/shield-crypto/)
- [Shield Rust Crate](https://crates.io/crates/shield-core)
- [GitHub Repository](https://github.com/Guard8-ai/Shield)
