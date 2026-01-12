# Shield - EXPTIME-Secure Encryption (Go)

[![Go Reference](https://pkg.go.dev/badge/github.com/Guard8-ai/shield.svg)](https://pkg.go.dev/github.com/Guard8-ai/shield)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Symmetric cryptography with proven exponential-time security.

## Why Shield?

Shield uses only symmetric primitives with EXPTIME-hard security guarantees. Breaking requires 2^256 operations - no shortcut exists:

- **PBKDF2-SHA256** for key derivation (100,000 iterations)
- **SHA256-based stream cipher** (AES-256-CTR equivalent)
- **HMAC-SHA256** for authentication

## Installation

```bash
go get github.com/Guard8-ai/shield
```

## Quick Start

### Basic Encryption

```go
package main

import (
    "fmt"
    "github.com/Guard8-ai/shield/shield"
)

func main() {
    // Password-based encryption
    s := shield.New("my_password", "github.com")
    encrypted := s.Encrypt([]byte("secret data"))
    decrypted, err := s.Decrypt(encrypted)
    if err != nil {
        panic(err)
    }
    fmt.Printf("Decrypted: %s\n", decrypted)
}
```

### Pre-shared Key

```go
import (
    "crypto/rand"
    "github.com/Guard8-ai/shield/shield"
)

key := make([]byte, 32)
rand.Read(key)

encrypted := shield.QuickEncrypt(key, []byte("data"))
decrypted, err := shield.QuickDecrypt(key, encrypted)
```

### Large File Encryption

```go
import "github.com/Guard8-ai/shield/shield"

cipher := shield.NewStreamCipherFromPassword("password", []byte("salt"))
err := cipher.EncryptFile("large.bin", "large.bin.enc")
err = cipher.DecryptFile("large.bin.enc", "large.bin.dec")
```

### Forward Secrecy (Ratchet)

```go
import (
    "crypto/rand"
    "github.com/Guard8-ai/shield/shield"
)

rootKey := make([]byte, 32)
rand.Read(rootKey)

alice := shield.NewRatchetSession(rootKey, true)  // initiator
bob := shield.NewRatchetSession(rootKey, false)   // responder

// Each message uses a new key
encrypted := alice.Encrypt([]byte("Hello!"))
decrypted, _ := bob.Decrypt(encrypted)  // []byte("Hello!")
```

### TOTP (2FA)

```go
import "github.com/Guard8-ai/shield/shield"

// Setup
secret := shield.GenerateTOTPSecret()
totp := shield.NewTOTP(secret)

// Get QR code URI for authenticator apps
uri := totp.ProvisioningURI("user@example.com", "MyApp")

// Generate/verify codes
code := totp.Generate()
isValid := totp.Verify(code)  // true
```

### Digital Signatures

```go
import "github.com/Guard8-ai/shield/shield"

// HMAC-based symmetric signatures
key := make([]byte, 32)
rand.Read(key)
sig := shield.NewSymmetricSignature(key)

signature := sig.Sign([]byte("message"))
valid := sig.Verify([]byte("message"), signature)  // true

// Quantum-safe Lamport signatures
lamport := shield.NewLamportSignature()
oneSig := lamport.Sign([]byte("important message"))
valid = lamport.Verify([]byte("important message"), oneSig)
```

## API Reference

### Shield

Main encryption class with password-derived keys.

```go
shield.New(password, service string) *Shield
shield.WithKey(key []byte) *Shield
(*Shield) Encrypt(plaintext []byte) []byte
(*Shield) Decrypt(ciphertext []byte) ([]byte, error)
```

### StreamCipher

Streaming encryption for large files.

```go
shield.NewStreamCipher(key []byte) *StreamCipher
shield.NewStreamCipherFromPassword(password string, salt []byte) *StreamCipher
(*StreamCipher) EncryptFile(inPath, outPath string) error
(*StreamCipher) DecryptFile(inPath, outPath string) error
```

### RatchetSession

Forward secrecy with key ratcheting.

```go
shield.NewRatchetSession(rootKey []byte, isInitiator bool) *RatchetSession
(*RatchetSession) Encrypt(plaintext []byte) []byte
(*RatchetSession) Decrypt(ciphertext []byte) ([]byte, error)
```

### TOTP

Time-based One-Time Passwords (RFC 6238).

```go
shield.NewTOTP(secret []byte) *TOTP
shield.GenerateTOTPSecret() []byte
(*TOTP) Generate() string
(*TOTP) Verify(code string) bool
(*TOTP) ProvisioningURI(account, issuer string) string
```

## Error Handling

```go
import "github.com/Guard8-ai/shield/shield"

var (
    shield.ErrAuthenticationFailed  // MAC verification failed
    shield.ErrCiphertextTooShort    // Ciphertext smaller than minimum
    shield.ErrInvalidKeySize        // Key not 32 bytes
)
```

## Security Model

Shield uses only symmetric primitives with unconditional security:

- **Symmetric encryption** (AES-256 equivalent)
- **Hash functions** (SHA-256)
- **HMAC authentication**
- **Key derivation** (PBKDF2)

Breaking requires 2^256 operations - no shortcut exists.

## Cross-Language Compatibility

Shield Go produces byte-identical output to Python, JavaScript, Rust, and all other implementations. Encrypt in Go, decrypt in any other language.

## License

MIT License - Use freely.

## See Also

- [Shield Python Package](https://pypi.org/project/shield-crypto/)
- [Shield npm Package](https://npmjs.com/package/@guard8/shield)
- [Shield Rust Crate](https://crates.io/crates/shield-core)
- [GitHub Repository](https://github.com/Guard8-ai/Shield)
