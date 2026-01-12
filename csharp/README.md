# Shield - EXPTIME-Secure Encryption (C#/.NET)

[![NuGet](https://img.shields.io/nuget/v/Guard8.Shield.svg)](https://www.nuget.org/packages/Guard8.Shield/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Symmetric cryptography with proven exponential-time security.

## Why Shield?

Shield uses only symmetric primitives with EXPTIME-hard security guarantees. Breaking requires 2^256 operations - no shortcut exists:

- **PBKDF2-SHA256** for key derivation (100,000 iterations)
- **SHA256-based stream cipher** (AES-256-CTR equivalent)
- **HMAC-SHA256** for authentication

## Installation

### NuGet Package Manager

```bash
Install-Package Guard8.Shield
```

### .NET CLI

```bash
dotnet add package Guard8.Shield
```

### PackageReference

```xml
<PackageReference Include="Guard8.Shield" Version="0.1.0" />
```

## Quick Start

### Basic Encryption

```csharp
using Guard8.Shield;

// Password-based encryption
var s = new Shield("my_password", "github.com");
byte[] encrypted = s.Encrypt(Encoding.UTF8.GetBytes("secret data"));
byte[] decrypted = s.Decrypt(encrypted);
Console.WriteLine(Encoding.UTF8.GetString(decrypted));  // "secret data"
```

### Pre-shared Key

```csharp
using Guard8.Shield;
using System.Security.Cryptography;

byte[] key = RandomNumberGenerator.GetBytes(32);

byte[] encrypted = Shield.QuickEncrypt(key, Encoding.UTF8.GetBytes("data"));
byte[] decrypted = Shield.QuickDecrypt(key, encrypted);
```

### Forward Secrecy (Ratchet)

```csharp
using Guard8.Shield;
using System.Security.Cryptography;

byte[] rootKey = RandomNumberGenerator.GetBytes(32);

var alice = new RatchetSession(rootKey, isInitiator: true);
var bob = new RatchetSession(rootKey, isInitiator: false);

// Each message uses a new key
byte[] encrypted = alice.Encrypt(Encoding.UTF8.GetBytes("Hello!"));
byte[] decrypted = bob.Decrypt(encrypted);  // "Hello!"
```

### TOTP (2FA)

```csharp
using Guard8.Shield;

// Setup
byte[] secret = TOTP.GenerateSecret();
var totp = new TOTP(secret);

// Get QR code URI for authenticator apps
string uri = totp.ProvisioningUri("user@example.com", "MyApp");

// Generate/verify codes
string code = totp.Generate();
bool isValid = totp.Verify(code);  // true
```

### Digital Signatures

```csharp
using Guard8.Shield;
using System.Security.Cryptography;

// HMAC-based symmetric signature
byte[] key = RandomNumberGenerator.GetBytes(32);
var sig = new SymmetricSignature(key);

byte[] signature = sig.Sign(Encoding.UTF8.GetBytes("message"));
bool valid = sig.Verify(Encoding.UTF8.GetBytes("message"), signature);  // true

// Lamport one-time signature (quantum-safe)
var lamport = new LamportSignature();
byte[] lamportSig = lamport.Sign(Encoding.UTF8.GetBytes("important message"));
bool lamportValid = lamport.Verify(Encoding.UTF8.GetBytes("important message"), lamportSig);
```

## API Reference

### Shield

Main encryption class with password-derived keys.

```csharp
new Shield(string password, string service)
new Shield(byte[] key)  // Pre-shared key
byte[] Encrypt(byte[] plaintext)
byte[] Decrypt(byte[] ciphertext)  // Returns null on auth failure

// Static methods
static byte[] QuickEncrypt(byte[] key, byte[] plaintext)
static byte[] QuickDecrypt(byte[] key, byte[] ciphertext)
```

### RatchetSession

Forward secrecy with key ratcheting.

```csharp
new RatchetSession(byte[] rootKey, bool isInitiator)
byte[] Encrypt(byte[] plaintext)
byte[] Decrypt(byte[] ciphertext)  // Returns null on auth failure
```

### TOTP

Time-based One-Time Passwords (RFC 6238).

```csharp
new TOTP(byte[] secret)
new TOTP(byte[] secret, int digits = 6, int interval = 30)
static byte[] GenerateSecret()
static string SecretToBase32(byte[] secret)
static byte[] SecretFromBase32(string base32)
string Generate()
string Generate(long timestamp)
bool Verify(string code, int window = 1)
bool Verify(string code, long timestamp, int window = 1)
string ProvisioningUri(string account, string issuer = "Shield")
```

### Signatures

```csharp
// Symmetric signature
new SymmetricSignature(byte[] key)
byte[] Sign(byte[] message)
bool Verify(byte[] message, byte[] signature)

// Lamport one-time signature
new LamportSignature()
byte[] Sign(byte[] message)
bool Verify(byte[] message, byte[] signature)
bool IsUsed { get; }
```

## Error Handling

```csharp
try
{
    byte[] decrypted = shield.Decrypt(ciphertext);
    if (decrypted == null)
    {
        // Authentication failed - wrong key or tampered data
    }
}
catch (ArgumentException ex)
{
    // Invalid input (key too short, ciphertext too short)
}
```

## Thread Safety

Shield .NET classes are **thread-safe**. A single `Shield` instance can be shared across threads.

## Security Model

Shield uses only symmetric primitives with unconditional security:

- **Symmetric encryption** (AES-256 equivalent)
- **Hash functions** (SHA-256)
- **HMAC authentication**
- **Key derivation** (PBKDF2)

Breaking requires 2^256 operations - no shortcut exists.

## Cross-Language Compatibility

Shield C# produces byte-identical output to Python, JavaScript, Rust, Go, Java, and all other implementations. Encrypt in C#, decrypt in any other language.

## Requirements

- .NET 6.0+
- No external dependencies (uses System.Security.Cryptography)

## License

MIT License - Use freely.

## See Also

- [Shield Python Package](https://pypi.org/project/shield-crypto/)
- [Shield npm Package](https://npmjs.com/package/@guard8/shield)
- [Shield Rust Crate](https://crates.io/crates/shield-core)
- [GitHub Repository](https://github.com/Guard8-ai/Shield)
