# Shield - Authenticated Symmetric Encryption (Java)

[![Maven Central](https://img.shields.io/maven-central/v/ai.dikestra/shield.svg)](https://search.maven.org/artifact/ai.dikestra/shield)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Symmetric authenticated encryption with 256-bit keys (~128-bit post-quantum security).

## Why Shield?

Shield builds on well-established symmetric primitives (SHA-256, HMAC-SHA256, PBKDF2). A 256-bit key gives 256-bit classical and ~128-bit post-quantum brute-force resistance, assuming these primitives are secure:

- **PBKDF2-SHA256** for key derivation (600,000 iterations, OWASP 2023 floor)
- **Per-instance random 16-byte salt** stored in the ciphertext header (no shared keys across users)
- **SHA256-based stream cipher** (AES-256-CTR equivalent)
- **HMAC-SHA256** for authentication (the version byte and salt are authenticated)

### Wire format

The leading version byte and the salt are authenticated by the MAC.

```
Password mode:       version(0x02) || salt(16) || nonce(16) || ciphertext || mac(16)
Pre-shared-key mode: version(0x12) ||           nonce(16) || ciphertext || mac(16)
```

`ciphertext` = keystream-XOR of `counter(8) || timestamp(8) || pad_len(1) || padding(32-128) || plaintext`.
The MAC covers `version || [salt] || nonce || ciphertext`. Overhead is 66 + padding (password mode)
or 50 + padding (key mode) bytes over the plaintext.

## Installation

### Gradle

```groovy
implementation 'ai.dikestra:shield:2.2.0'
```

### Maven

```xml
<dependency>
    <groupId>ai.dikestra</groupId>
    <artifactId>shield</artifactId>
    <version>2.2.0</version>
</dependency>
```

## Quick Start

### Basic Encryption

```java
import ai.dikestra.shield.Shield;

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
import ai.dikestra.shield.Shield;
import java.security.SecureRandom;

SecureRandom random = new SecureRandom();
byte[] key = new byte[32];
random.nextBytes(key);

byte[] encrypted = Shield.quickEncrypt(key, "data".getBytes());
byte[] decrypted = Shield.quickDecrypt(key, encrypted);
```

### Forward Secrecy (Ratchet)

```java
import ai.dikestra.shield.RatchetSession;
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
import ai.dikestra.shield.TOTP;

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
import ai.dikestra.shield.Signatures;
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
byte[] decrypt(byte[] ciphertext)  // throws SecurityException on auth failure

// Static methods
static byte[] quickEncrypt(byte[] key, byte[] plaintext)
static byte[] quickDecrypt(byte[] key, byte[] ciphertext)
```

### RatchetSession

Forward secrecy with key ratcheting.

```java
new RatchetSession(byte[] rootKey, boolean isInitiator)
byte[] encrypt(byte[] plaintext)
byte[] decrypt(byte[] ciphertext)  // throws SecurityException on auth failure
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
    // Success - use decrypted data
} catch (SecurityException e) {
    // Authentication failed - wrong key or tampered data
} catch (IllegalArgumentException e) {
    // Invalid input (key too short, ciphertext too short)
}
```

## Thread Safety

Shield Java classes are **thread-safe**. A single `Shield` instance can be shared across threads.

## Security Model

Shield builds on well-established symmetric primitives. Like all practical ciphers, their security is conjectural (it relies on standard assumptions), not unconditional:

- **Symmetric encryption** (AES-256 equivalent)
- **Hash functions** (SHA-256)
- **HMAC authentication**
- **Key derivation** (PBKDF2)

Brute-forcing a full 256-bit key requires 2^256 operations; this relies on the standard assumption that SHA-256/HMAC have no exploitable structure (an assumption, not a mathematical proof).

## Cross-Language Compatibility

Shield Java produces byte-identical output to Python, JavaScript, Rust, Go, and all other implementations. Encrypt in Java, decrypt in any other language.

## Requirements

- Java 11+
- No external dependencies (uses javax.crypto)

## License

MIT License - Use freely.

## See Also

- [Shield Python Package](https://pypi.org/project/shield-crypto/)
- [Shield npm Package](https://npmjs.com/package/@dikestra/shield)
- [Shield Rust Crate](https://crates.io/crates/shield-core)
- [GitHub Repository](https://github.com/Dikestra-ai/Shield)
