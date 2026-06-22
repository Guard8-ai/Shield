# Shield - Authenticated Symmetric Encryption (Go)

[![Go Reference](https://pkg.go.dev/badge/github.com/Dikestra-ai/shield.svg)](https://pkg.go.dev/github.com/Dikestra-ai/shield)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Symmetric authenticated encryption with 256-bit keys (~128-bit post-quantum security).

## Why Shield?

Shield builds on well-established symmetric primitives (SHA-256, HMAC-SHA256, PBKDF2). A 256-bit key gives 256-bit classical and ~128-bit post-quantum brute-force resistance, assuming these primitives are secure:

- **PBKDF2-SHA256** for key derivation (600,000 iterations)
- **SHA256-based stream cipher** (AES-256-CTR equivalent)
- **HMAC-SHA256** for authentication

## Installation

```bash
go get github.com/Dikestra-ai/shield
```

## Quick Start

### Basic Encryption

```go
package main

import (
    "fmt"
    "github.com/Dikestra-ai/shield/shield"
)

func main() {
    // Password-based encryption
    s := shield.New("my_password", "github.com", nil)
    encrypted, err := s.Encrypt([]byte("secret data"))
    if err != nil {
        panic(err)
    }
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
    "github.com/Dikestra-ai/shield/shield"
)

key := make([]byte, 32)
rand.Read(key)

encrypted, _ := shield.QuickEncrypt(key, []byte("data"))
decrypted, err := shield.QuickDecrypt(key, encrypted)
```

### Large File Encryption

```go
import "github.com/Dikestra-ai/shield/shield"

cipher := shield.NewStreamCipherFromPassword("password", []byte("salt"))
err := cipher.EncryptFile("large.bin", "large.bin.enc")
err = cipher.DecryptFile("large.bin.enc", "large.bin.dec")
```

### Forward Secrecy (Ratchet)

```go
import (
    "crypto/rand"
    "github.com/Dikestra-ai/shield/shield"
)

rootKey := make([]byte, 32)
rand.Read(rootKey)

alice := shield.NewRatchetSession(rootKey, true)  // initiator
bob := shield.NewRatchetSession(rootKey, false)   // responder

// Each message uses a new key
encrypted, _ := alice.Encrypt([]byte("Hello!"))
decrypted, _ := bob.Decrypt(encrypted)  // []byte("Hello!")
```

### TOTP (2FA)

```go
import "github.com/Dikestra-ai/shield/shield"

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
import "github.com/Dikestra-ai/shield/shield"

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
shield.New(password, service string, maxAgeMs *int64) *Shield
shield.WithKey(key []byte) *Shield
(*Shield) Encrypt(plaintext []byte) ([]byte, error)
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
import "github.com/Dikestra-ai/shield/shield"

var (
    shield.ErrAuthenticationFailed  // MAC verification failed
    shield.ErrCiphertextTooShort    // Ciphertext smaller than minimum
    shield.ErrInvalidKeySize        // Key not 32 bytes
)
```

## Security Model

Shield builds on well-established symmetric primitives. Like all practical ciphers, their security is conjectural (it relies on standard assumptions), not unconditional:

- **Symmetric encryption** (AES-256 equivalent)
- **Hash functions** (SHA-256)
- **HMAC authentication**
- **Key derivation** (PBKDF2)

Brute-forcing a full 256-bit key requires 2^256 operations; this relies on the standard assumption that SHA-256/HMAC have no exploitable structure (an assumption, not a mathematical proof).

## Cross-Language Compatibility

Shield Go produces byte-identical output to Python, JavaScript, Rust, and all other implementations. Encrypt in Go, decrypt in any other language.

## License

MIT License - Use freely.

## See Also

- [Shield Python Package](https://pypi.org/project/shield-crypto/)
- [Shield npm Package](https://npmjs.com/package/@dikestra/shield)
- [Shield Rust Crate](https://crates.io/crates/shield-core)
- [GitHub Repository](https://github.com/Dikestra-ai/Shield)
