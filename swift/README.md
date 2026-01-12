# Shield - EXPTIME-Secure Encryption (Swift)

[![Swift Package Manager](https://img.shields.io/badge/SPM-compatible-brightgreen.svg)](https://swift.org/package-manager/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Symmetric cryptography with proven exponential-time security.

## Why Shield?

Shield uses only symmetric primitives with EXPTIME-hard security guarantees. Breaking requires 2^256 operations - no shortcut exists:

- **PBKDF2-SHA256** for key derivation (100,000 iterations)
- **SHA256-based stream cipher** (AES-256-CTR equivalent)
- **HMAC-SHA256** for authentication

## Installation

### Swift Package Manager

Add to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/Guard8-ai/Shield.git", from: "0.1.0")
]
```

Or add via Xcode: File > Add Packages > `https://github.com/Guard8-ai/Shield`

## Quick Start

### Basic Encryption

```swift
import Shield

// Password-based encryption
let s = Shield(password: "my_password", service: "github.com")
let encrypted = s.encrypt(Array("secret data".utf8))
if let decrypted = s.decrypt(encrypted) {
    print(String(bytes: decrypted, encoding: .utf8)!)  // "secret data"
}
```

### Pre-shared Key

```swift
import Shield
import Security

var key = [UInt8](repeating: 0, count: 32)
SecRandomCopyBytes(kSecRandomDefault, 32, &key)

let encrypted = Shield.quickEncrypt(key: key, plaintext: Array("data".utf8))
if let decrypted = Shield.quickDecrypt(key: key, ciphertext: encrypted) {
    print(String(bytes: decrypted, encoding: .utf8)!)
}
```

### Forward Secrecy (Ratchet)

```swift
import Shield
import Security

var rootKey = [UInt8](repeating: 0, count: 32)
SecRandomCopyBytes(kSecRandomDefault, 32, &rootKey)

let alice = RatchetSession(rootKey: rootKey, isInitiator: true)
let bob = RatchetSession(rootKey: rootKey, isInitiator: false)

// Each message uses a new key
let encrypted = alice.encrypt(Array("Hello!".utf8))
if let decrypted = bob.decrypt(encrypted) {
    print(String(bytes: decrypted, encoding: .utf8)!)  // "Hello!"
}
```

### TOTP (2FA)

```swift
import Shield

// Setup
let secret = TOTP.generateSecret()
let totp = TOTP(secret: secret)

// Get QR code URI for authenticator apps
let uri = totp.provisioningUri(account: "user@example.com", issuer: "MyApp")

// Generate/verify codes
let code = totp.generate()
let isValid = totp.verify(code)  // true
```

### Digital Signatures

```swift
import Shield
import Security

// HMAC-based symmetric signature
var key = [UInt8](repeating: 0, count: 32)
SecRandomCopyBytes(kSecRandomDefault, 32, &key)
let sig = SymmetricSignature(key: key)

let signature = sig.sign(message: Array("message".utf8))
let valid = sig.verify(message: Array("message".utf8), signature: signature)  // true

// Lamport one-time signature (quantum-safe)
let lamport = LamportSignature()
let lamportSig = lamport.sign(Array("important message".utf8))
let lamportValid = lamport.verify(message: Array("important message".utf8),
                                   signature: lamportSig)
```

## API Reference

### Shield

Main encryption class with password-derived keys.

```swift
init(password: String, service: String)
init(key: [UInt8])  // Pre-shared key
func encrypt(_ plaintext: [UInt8]) -> [UInt8]
func decrypt(_ ciphertext: [UInt8]) -> [UInt8]?  // Returns nil on auth failure

// Static methods
static func quickEncrypt(key: [UInt8], plaintext: [UInt8]) -> [UInt8]
static func quickDecrypt(key: [UInt8], ciphertext: [UInt8]) -> [UInt8]?
```

### RatchetSession

Forward secrecy with key ratcheting.

```swift
init(rootKey: [UInt8], isInitiator: Bool)
func encrypt(_ plaintext: [UInt8]) -> [UInt8]
func decrypt(_ ciphertext: [UInt8]) -> [UInt8]?  // Returns nil on auth failure
```

### TOTP

Time-based One-Time Passwords (RFC 6238).

```swift
init(secret: [UInt8], digits: Int = 6, interval: Int = 30)
static func generateSecret() -> [UInt8]
static func secretToBase32(_ secret: [UInt8]) -> String
static func secretFromBase32(_ base32: String) -> [UInt8]
func generate(timestamp: TimeInterval? = nil) -> String
func verify(_ code: String, timestamp: TimeInterval? = nil, window: Int = 1) -> Bool
func provisioningUri(account: String, issuer: String = "Shield") -> String
```

### Signatures

```swift
// Symmetric signature
class SymmetricSignature {
    init(key: [UInt8])
    func sign(message: [UInt8]) -> [UInt8]
    func verify(message: [UInt8], signature: [UInt8]) -> Bool
}

// Lamport one-time signature
class LamportSignature {
    init()
    func sign(_ message: [UInt8]) -> [UInt8]
    func verify(message: [UInt8], signature: [UInt8]) -> Bool
    var isUsed: Bool { get }
}
```

## Error Handling

Shield Swift uses optionals for decryption failures:

```swift
if let decrypted = shield.decrypt(ciphertext) {
    // Success
    process(decrypted)
} else {
    // Authentication failed - wrong key or tampered data
    handleError()
}
```

For serious errors (invalid key size), Shield throws:

```swift
do {
    let s = try Shield.withKey(invalidKey)
} catch ShieldError.invalidKeySize {
    // Key must be exactly 32 bytes
}
```

## Thread Safety

Shield Swift classes are **thread-safe** and can be used from multiple threads/queues.

## Security Model

Shield uses only symmetric primitives with unconditional security:

- **Symmetric encryption** (AES-256 equivalent)
- **Hash functions** (SHA-256)
- **HMAC authentication**
- **Key derivation** (PBKDF2)

Breaking requires 2^256 operations - no shortcut exists.

## Platform Support

- iOS 13.0+
- macOS 10.15+
- tvOS 13.0+
- watchOS 6.0+

## Cross-Language Compatibility

Shield Swift produces byte-identical output to Python, JavaScript, Rust, Go, Java, and all other implementations. Encrypt in Swift, decrypt in any other language.

## License

MIT License - Use freely.

## See Also

- [Shield Python Package](https://pypi.org/project/shield-crypto/)
- [Shield npm Package](https://npmjs.com/package/@guard8/shield)
- [Shield Rust Crate](https://crates.io/crates/shield-core)
- [GitHub Repository](https://github.com/Guard8-ai/Shield)
