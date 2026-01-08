# Shield WebAssembly Module

EXPTIME-secure encryption for browsers and any WebAssembly runtime.

This crate re-exports WASM bindings from `shield-core`, providing a single source of truth for all Shield cryptographic implementations.

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
import init, {
    WasmShield, WasmTOTP, WasmRatchetSession, WasmLamportSignature,
    randomBytes, sha256, hmacSha256, constantTimeEquals, quickEncrypt, quickDecrypt
} from './pkg/shield_wasm.js';

await init();

// Basic encryption
const shield = new WasmShield("password", "my-service");
const plaintext = new TextEncoder().encode("Hello, Shield!");
const encrypted = shield.encrypt(plaintext);
const decrypted = shield.decrypt(encrypted);

// TOTP
const secret = WasmTOTP.generateSecret();
const totp = new WasmTOTP(secret);
const code = totp.generate(BigInt(Math.floor(Date.now() / 1000)));
console.log("TOTP code:", code);

// Forward secrecy with ratcheting
const rootKey = randomBytes(32);
const alice = new WasmRatchetSession(rootKey, true);
const bob = new WasmRatchetSession(rootKey, false);

const message = new TextEncoder().encode("Secret message");
const encryptedMsg = alice.encrypt(message);
const decryptedMsg = bob.decrypt(encryptedMsg);

// Post-quantum signatures
const lamport = new WasmLamportSignature();
const sig = lamport.sign(new TextEncoder().encode("Sign this"));
const isValid = WasmLamportSignature.verifySignature(
    new TextEncoder().encode("Sign this"),
    sig,
    lamport.publicKey
);
```

## API

### WasmShield
- `new WasmShield(password, service)` - Create from password
- `WasmShield.withKey(key)` - Create from 32-byte key
- `encrypt(plaintext)` - Encrypt data
- `decrypt(ciphertext)` - Decrypt data
- `key()` - Get derived key (for interop)

### WasmTOTP
- `new WasmTOTP(secret)` - Create with secret
- `WasmTOTP.withSettings(secret, digits, interval)` - Create with custom settings
- `WasmTOTP.generateSecret()` - Generate 20-byte secret
- `generate(timestamp)` - Generate code for timestamp
- `generateNow()` - Generate code for current time
- `verify(code, timestamp, window)` - Verify code
- `verifyNow(code, window)` - Verify code for current time
- `toBase32()` - Export secret as Base32
- `WasmTOTP.fromBase32(encoded)` - Decode Base32 secret
- `provisioningUri(account, issuer)` - Get otpauth:// URL

### WasmRatchetSession
- `new WasmRatchetSession(rootKey, isInitiator)` - Create session
- `encrypt(plaintext)` - Encrypt with ratcheting
- `decrypt(ciphertext)` - Decrypt with ratcheting
- `sendCounter` / `recvCounter` - Message counters

### WasmLamportSignature
- `new WasmLamportSignature()` - Generate key pair
- `sign(message)` - Sign (one-time use only)
- `WasmLamportSignature.verifySignature(message, signature, publicKey)` - Verify
- `publicKey` - Get public key
- `isUsed` - Check if key was used
- `fingerprint()` - Get key fingerprint

### Utilities
- `randomBytes(size)` - Generate random bytes
- `sha256(data)` - SHA-256 hash
- `hmacSha256(key, data)` - HMAC-SHA256
- `constantTimeEquals(a, b)` - Constant-time comparison
- `quickEncrypt(key, plaintext)` - One-shot encrypt
- `quickDecrypt(key, ciphertext)` - One-shot decrypt
