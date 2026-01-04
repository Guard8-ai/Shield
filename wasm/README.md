# Shield WebAssembly Module

EXPTIME-secure encryption for browsers and any WebAssembly runtime.

## Building

```bash
# Install wasm-pack
cargo install wasm-pack

# Build for web
wasm-pack build --target web

# Build for Node.js
wasm-pack build --target nodejs

# Build for bundlers (webpack, etc.)
wasm-pack build --target bundler
```

## Usage (Browser)

```javascript
import init, { Shield, TOTP, RatchetSession, LamportSignature } from './pkg/shield_wasm.js';

await init();

// Basic encryption
const shield = new Shield("password", "my-service");
const plaintext = new TextEncoder().encode("Hello, Shield!");
const encrypted = shield.encrypt(plaintext);
const decrypted = shield.decrypt(encrypted);

// TOTP
const secret = TOTP.generateSecret();
const totp = new TOTP(secret);
const code = totp.generate(BigInt(Math.floor(Date.now() / 1000)));
console.log("TOTP code:", code);

// Forward secrecy with ratcheting
const rootKey = new Uint8Array(32);
const alice = new RatchetSession(rootKey, true);
const bob = new RatchetSession(rootKey, false);

const message = new TextEncoder().encode("Secret message");
const encryptedMsg = alice.encrypt(message);
const decryptedMsg = bob.decrypt(encryptedMsg);

// Post-quantum signatures
const lamport = new LamportSignature();
const sig = lamport.sign(new TextEncoder().encode("Sign this"));
const isValid = LamportSignature.verifySignature(
    new TextEncoder().encode("Sign this"),
    sig,
    lamport.publicKey
);
```

## API

### Shield
- `new Shield(password, service)` - Create from password
- `Shield.withKey(key)` - Create from 32-byte key
- `encrypt(plaintext)` - Encrypt data
- `decrypt(ciphertext)` - Decrypt data

### TOTP
- `new TOTP(secret)` - Create with secret
- `TOTP.generateSecret()` - Generate 20-byte secret
- `generate(timestamp)` - Generate code
- `verify(code, timestamp, window)` - Verify code
- `toBase32()` - Export secret
- `provisioningUri(account, issuer)` - Get otpauth:// URL

### RatchetSession
- `new RatchetSession(rootKey, isInitiator)` - Create session
- `encrypt(plaintext)` - Encrypt with ratcheting
- `decrypt(ciphertext)` - Decrypt with ratcheting
- `sendCounter` / `recvCounter` - Message counters

### LamportSignature
- `new LamportSignature()` - Generate key pair
- `sign(message)` - Sign (one-time use only)
- `LamportSignature.verifySignature(message, signature, publicKey)` - Verify
- `publicKey` - Get public key
- `isUsed` - Check if key was used

### Utilities
- `randomBytes(size)` - Generate random bytes
- `sha256(data)` - SHA-256 hash
- `hmacSha256(key, data)` - HMAC-SHA256
- `constantTimeEquals(a, b)` - Constant-time comparison
- `quickEncrypt(key, plaintext)` - One-shot encrypt
- `quickDecrypt(key, ciphertext)` - One-shot decrypt
