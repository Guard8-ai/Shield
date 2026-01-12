# Shield - EXPTIME-Secure Encryption (iOS/macOS)

[![CocoaPods](https://img.shields.io/cocoapods/v/Shield.svg)](https://cocoapods.org/pods/Shield)
[![Swift Package Manager](https://img.shields.io/badge/SPM-compatible-brightgreen.svg)](https://swift.org/package-manager/)
[![Platform](https://img.shields.io/badge/platform-iOS%2013%2B%20%7C%20macOS%2010.15%2B-blue.svg)](https://developer.apple.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Symmetric cryptography with proven exponential-time security for Apple platforms.

## Why Shield?

Shield uses only symmetric primitives with EXPTIME-hard security guarantees. Breaking requires 2^256 operations - no shortcut exists:

- **PBKDF2-SHA256** for key derivation (100,000 iterations)
- **SHA256-based stream cipher** (AES-256-CTR equivalent)
- **HMAC-SHA256** for authentication
- **iOS Keychain** for secure key storage
- **Biometric protection** (Face ID / Touch ID)

## Installation

### Swift Package Manager (Recommended)

Add to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/Guard8-ai/Shield.git", from: "0.1.0")
]
```

Or in Xcode: File → Add Packages → `https://github.com/Guard8-ai/Shield`

### CocoaPods

```ruby
pod 'Shield', '~> 0.1.0'
```

### Carthage

```
github "Guard8-ai/Shield" ~> 0.1.0
```

## Quick Start

### Basic Encryption

```swift
import Shield

// Password-based encryption
let shield = Shield(password: "my_password", service: "github.com")
let encrypted = shield.encrypt(Array("secret data".utf8))
if let decrypted = shield.decrypt(encrypted) {
    print(String(bytes: decrypted, encoding: .utf8)!)  // "secret data"
}
```

### Pre-shared Key

```swift
import Shield

var key = [UInt8](repeating: 0, count: 32)
_ = SecRandomCopyBytes(kSecRandomDefault, 32, &key)

let encrypted = try Shield.quickEncrypt(key: key, plaintext: Array("data".utf8))
let decrypted = try Shield.quickDecrypt(key: key, ciphertext: encrypted)
```

### Secure Keychain Storage

```swift
import Shield

let keychain = SecureKeychain()

// Store a key securely
try keychain.store(key: secretKey, for: "my_app_key")

// Retrieve later
if let key = try keychain.retrieve(for: "my_app_key") {
    let shield = try Shield(key: key)
}

// Or create Shield with automatic key management
let shield = try keychain.getOrCreateShield(
    alias: "user_encryption_key",
    password: userPassword,
    service: "myapp.example.com"
)
```

### Biometric Protection (Face ID / Touch ID)

```swift
import Shield

let keychain = SecureKeychain()

// Store key with biometric protection
try keychain.storeWithBiometrics(
    alias: "biometric_key",
    password: password,
    service: "myapp.com"
)

// Retrieval will require Face ID / Touch ID
if let key = try keychain.retrieve(for: "biometric_key") {
    // User authenticated successfully
}
```

## API Reference

### Shield

```swift
// Create from password
init(password: String, service: String, iterations: UInt32 = 100_000)

// Create from pre-shared key
init(key: [UInt8]) throws

// Encrypt/decrypt
func encrypt(_ plaintext: [UInt8]) -> [UInt8]
func decrypt(_ encrypted: [UInt8]) -> [UInt8]?

// Static convenience methods
static func quickEncrypt(key: [UInt8], plaintext: [UInt8]) throws -> [UInt8]
static func quickDecrypt(key: [UInt8], ciphertext: [UInt8]) throws -> [UInt8]?
```

### SecureKeychain

```swift
// Store/retrieve keys
func store(key: [UInt8], for alias: String, biometricProtection: Bool = false) throws
func retrieve(for alias: String) throws -> [UInt8]?
func delete(for alias: String) throws
func exists(for alias: String) -> Bool

// Shield integration
func getOrCreateShield(alias: String, password: String, service: String) throws -> Shield
func storeWithBiometrics(alias: String, password: String, service: String) throws
```

## Security Features

### Keychain Protection Classes

Shield uses `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` by default, meaning:
- Keys are only accessible when device is unlocked
- Keys are not included in backups
- Keys are not synced to other devices

### Biometric Authentication

For sensitive keys, enable biometric protection:

```swift
try keychain.store(key: key, for: "sensitive", biometricProtection: true)
```

This requires Face ID or Touch ID before each access.

### Keychain Access Groups

Share keys between your apps:

```swift
let keychain = SecureKeychain(
    serviceName: "com.mycompany.shared",
    accessGroup: "TEAMID.com.mycompany.shared"
)
```

## SwiftUI Integration

```swift
import SwiftUI
import Shield

class EncryptionManager: ObservableObject {
    private let keychain = SecureKeychain()
    private var shield: Shield?

    func unlock(password: String) throws {
        shield = try keychain.getOrCreateShield(
            alias: "app_key",
            password: password,
            service: "myapp.com"
        )
    }

    func encrypt(_ text: String) -> Data? {
        guard let shield = shield else { return nil }
        let encrypted = shield.encrypt(Array(text.utf8))
        return Data(encrypted)
    }

    func decrypt(_ data: Data) -> String? {
        guard let shield = shield,
              let decrypted = shield.decrypt(Array(data)) else { return nil }
        return String(bytes: decrypted, encoding: .utf8)
    }
}
```

## Platform Support

| Platform | Minimum Version |
|----------|----------------|
| iOS      | 13.0           |
| macOS    | 10.15          |
| tvOS     | 13.0           |
| watchOS  | 6.0            |
| Catalyst | 13.0           |

## Thread Safety

Shield is **thread-safe**. A single instance can be used from multiple threads or concurrent tasks.

## Cross-Platform Compatibility

Shield iOS produces byte-identical output to all other Shield implementations:
- Android, Python, JavaScript, Rust, Go, C, Java, C#, Kotlin, WebAssembly

Encrypt on iOS, decrypt on any platform.

## Error Handling

```swift
do {
    let shield = try Shield(key: invalidKey)
} catch ShieldError.invalidKeySize(let expected, let actual) {
    print("Key must be \(expected) bytes, got \(actual)")
} catch ShieldError.keychainError(let status) {
    print("Keychain error: \(status)")
}
```

## License

MIT License - Use freely.

## See Also

- [Shield Android](../android) - Android implementation
- [Shield Python](https://pypi.org/project/shield-crypto/)
- [Shield npm](https://npmjs.com/package/@guard8/shield)
- [GitHub Repository](https://github.com/Guard8-ai/Shield)
