# Shield - EXPTIME-Secure Encryption (Java)

[![Maven Central](https://img.shields.io/maven-central/v/ai.guard8/shield.svg)](https://search.maven.org/artifact/ai.guard8/shield)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Symmetric cryptography with proven exponential-time security.

## Why Shield?

Shield uses only symmetric primitives with EXPTIME-hard security guarantees. Breaking requires 2^256 operations - no shortcut exists:

- **PBKDF2-SHA256** for key derivation (100,000 iterations)
- **SHA256-based stream cipher** (AES-256-CTR equivalent)
- **HMAC-SHA256** for authentication

## Installation

### Gradle

```groovy
implementation 'ai.guard8:shield:0.1.0'
```

### Maven

```xml
<dependency>
    <groupId>ai.guard8</groupId>
    <artifactId>shield</artifactId>
    <version>0.1.0</version>
</dependency>
```

## Quick Start

### Basic Encryption

```java
import ai.guard8.shield.Shield;

public class Example {
    public static void main(String[] args) {
        // Password-based encryption
        Shield s = new Shield("my_password", "github.com");
        byte[] encrypted = s.encrypt("secret data".getBytes());
        byte[] decrypted = s.decrypt(encrypted);
        System.out.println(new String(decrypted));  // "secret data"
    }
}
```

### Pre-shared Key

```java
import ai.guard8.shield.Shield;
import java.security.SecureRandom;

SecureRandom random = new SecureRandom();
byte[] key = new byte[32];
random.nextBytes(key);

byte[] encrypted = Shield.quickEncrypt(key, "data".getBytes());
byte[] decrypted = Shield.quickDecrypt(key, encrypted);
```

### Forward Secrecy (Ratchet)

```java
import ai.guard8.shield.RatchetSession;
import java.security.SecureRandom;

byte[] rootKey = new byte[32];
new SecureRandom().nextBytes(rootKey);

RatchetSession alice = new RatchetSession(rootKey, true);   // initiator
RatchetSession bob = new RatchetSession(rootKey, false);    // responder

// Each message uses a new key
byte[] encrypted = alice.encrypt("Hello!".getBytes());
byte[] decrypted = bob.decrypt(encrypted);  // "Hello!"
```

### TOTP (2FA)

```java
import ai.guard8.shield.TOTP;

// Setup
byte[] secret = TOTP.generateSecret();
TOTP totp = new TOTP(secret);

// Get QR code URI for authenticator apps
String uri = totp.provisioningUri("user@example.com", "MyApp");

// Generate/verify codes
String code = totp.generate();
boolean isValid = totp.verify(code);  // true
```

### Digital Signatures

```java
import ai.guard8.shield.Signatures;
import java.security.SecureRandom;

// HMAC-based symmetric signature
byte[] key = new byte[32];
new SecureRandom().nextBytes(key);
Signatures.SymmetricSignature sig = new Signatures.SymmetricSignature(key);

byte[] signature = sig.sign("message".getBytes());
boolean valid = sig.verify("message".getBytes(), signature);  // true

// Lamport one-time signature (quantum-safe)
Signatures.LamportSignature lamport = new Signatures.LamportSignature();
byte[] lamportSig = lamport.sign("important message".getBytes());
boolean lamportValid = lamport.verify("important message".getBytes(), lamportSig);
```

## API Reference

### Shield

Main encryption class with password-derived keys.

```java
new Shield(String password, String service)
new Shield(byte[] key)  // Pre-shared key
byte[] encrypt(byte[] plaintext)
byte[] decrypt(byte[] ciphertext)  // Returns null on auth failure

// Static methods
static byte[] quickEncrypt(byte[] key, byte[] plaintext)
static byte[] quickDecrypt(byte[] key, byte[] ciphertext)
```

### RatchetSession

Forward secrecy with key ratcheting.

```java
new RatchetSession(byte[] rootKey, boolean isInitiator)
byte[] encrypt(byte[] plaintext)
byte[] decrypt(byte[] ciphertext)  // Returns null on auth failure
```

### TOTP

Time-based One-Time Passwords (RFC 6238).

```java
new TOTP(byte[] secret)
new TOTP(byte[] secret, int digits, int interval)
static byte[] generateSecret()
static String secretToBase32(byte[] secret)
static byte[] secretFromBase32(String base32)
String generate()
String generate(long timestamp)
boolean verify(String code)
boolean verify(String code, long timestamp, int window)
String provisioningUri(String account, String issuer)
```

### Signatures

```java
// Symmetric signature
new Signatures.SymmetricSignature(byte[] key)
byte[] sign(byte[] message)
boolean verify(byte[] message, byte[] signature)

// Lamport one-time signature
new Signatures.LamportSignature()
byte[] sign(byte[] message)
boolean verify(byte[] message, byte[] signature)
boolean isUsed()
```

## Error Handling

```java
try {
    byte[] decrypted = shield.decrypt(ciphertext);
    if (decrypted == null) {
        // Authentication failed - wrong key or tampered data
    }
} catch (IllegalArgumentException e) {
    // Invalid input (key too short, ciphertext too short)
}
```

## Thread Safety

Shield Java classes are **thread-safe**. A single `Shield` instance can be shared across threads.

## Security Model

Shield uses only symmetric primitives with unconditional security:

- **Symmetric encryption** (AES-256 equivalent)
- **Hash functions** (SHA-256)
- **HMAC authentication**
- **Key derivation** (PBKDF2)

Breaking requires 2^256 operations - no shortcut exists.

## Cross-Language Compatibility

Shield Java produces byte-identical output to Python, JavaScript, Rust, Go, and all other implementations. Encrypt in Java, decrypt in any other language.

## Requirements

- Java 11+
- No external dependencies (uses javax.crypto)

## License

MIT License - Use freely.

## See Also

- [Shield Python Package](https://pypi.org/project/shield-crypto/)
- [Shield npm Package](https://npmjs.com/package/@guard8/shield)
- [Shield Rust Crate](https://crates.io/crates/shield-core)
- [GitHub Repository](https://github.com/Guard8-ai/Shield)
