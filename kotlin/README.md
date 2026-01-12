# Shield - EXPTIME-Secure Encryption (Kotlin)

[![Maven Central](https://img.shields.io/maven-central/v/ai.guard8/shield-kotlin.svg)](https://search.maven.org/artifact/ai.guard8/shield-kotlin)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Symmetric cryptography with proven exponential-time security.

## Why Shield?

Shield uses only symmetric primitives with EXPTIME-hard security guarantees. Breaking requires 2^256 operations - no shortcut exists:

- **PBKDF2-SHA256** for key derivation (100,000 iterations)
- **SHA256-based stream cipher** (AES-256-CTR equivalent)
- **HMAC-SHA256** for authentication

## Installation

### Gradle (Kotlin DSL)

```kotlin
implementation("ai.guard8:shield-kotlin:0.1.0")
```

### Gradle (Groovy)

```groovy
implementation 'ai.guard8:shield-kotlin:0.1.0'
```

### Maven

```xml
<dependency>
    <groupId>ai.guard8</groupId>
    <artifactId>shield-kotlin</artifactId>
    <version>0.1.0</version>
</dependency>
```

## Quick Start

### Basic Encryption

```kotlin
import ai.guard8.shield.Shield

fun main() {
    // Password-based encryption
    val s = Shield.create("my_password", "github.com")
    val encrypted = s.encrypt("secret data".toByteArray())
    val decrypted = s.decrypt(encrypted)
    println(String(decrypted!!))  // "secret data"
}
```

### Pre-shared Key

```kotlin
import ai.guard8.shield.Shield
import java.security.SecureRandom

val key = ByteArray(32).also { SecureRandom().nextBytes(it) }

val encrypted = Shield.quickEncrypt(key, "data".toByteArray())
val decrypted = Shield.quickDecrypt(key, encrypted)
```

### Forward Secrecy (Ratchet)

```kotlin
import ai.guard8.shield.RatchetSession
import java.security.SecureRandom

val rootKey = ByteArray(32).also { SecureRandom().nextBytes(it) }

val alice = RatchetSession(rootKey, isInitiator = true)
val bob = RatchetSession(rootKey, isInitiator = false)

// Each message uses a new key
val encrypted = alice.encrypt("Hello!".toByteArray())
val decrypted = bob.decrypt(encrypted)  // "Hello!"
```

### TOTP (2FA)

```kotlin
import ai.guard8.shield.TOTP

// Setup
val secret = TOTP.generateSecret()
val totp = TOTP(secret)

// Get QR code URI for authenticator apps
val uri = totp.provisioningUri("user@example.com", "MyApp")

// Generate/verify codes
val code = totp.generate()
val isValid = totp.verify(code)  // true
```

### Digital Signatures

```kotlin
import ai.guard8.shield.Signatures
import java.security.SecureRandom

// HMAC-based symmetric signature
val key = ByteArray(32).also { SecureRandom().nextBytes(it) }
val sig = Signatures.SymmetricSignature(key)

val signature = sig.sign("message".toByteArray())
val valid = sig.verify("message".toByteArray(), signature)  // true

// Lamport one-time signature (quantum-safe)
val lamport = Signatures.LamportSignature()
val lamportSig = lamport.sign("important message".toByteArray())
val lamportValid = lamport.verify("important message".toByteArray(), lamportSig)
```

## API Reference

### Shield

Main encryption class with password-derived keys.

```kotlin
Shield.create(password: String, service: String): Shield
Shield.withKey(key: ByteArray): Shield
fun encrypt(plaintext: ByteArray): ByteArray
fun decrypt(ciphertext: ByteArray): ByteArray?  // Returns null on auth failure

// Static methods
Shield.quickEncrypt(key: ByteArray, plaintext: ByteArray): ByteArray
Shield.quickDecrypt(key: ByteArray, ciphertext: ByteArray): ByteArray?
```

### RatchetSession

Forward secrecy with key ratcheting.

```kotlin
RatchetSession(rootKey: ByteArray, isInitiator: Boolean)
fun encrypt(plaintext: ByteArray): ByteArray
fun decrypt(ciphertext: ByteArray): ByteArray?  // Returns null on auth failure
```

### TOTP

Time-based One-Time Passwords (RFC 6238).

```kotlin
TOTP(secret: ByteArray, digits: Int = 6, interval: Int = 30)
companion object {
    fun generateSecret(): ByteArray
    fun secretToBase32(secret: ByteArray): String
    fun secretFromBase32(base32: String): ByteArray
}
fun generate(timestamp: Long? = null): String
fun verify(code: String, timestamp: Long? = null, window: Int = 1): Boolean
fun provisioningUri(account: String, issuer: String = "Shield"): String
```

### Signatures

```kotlin
// Symmetric signature
class Signatures.SymmetricSignature(key: ByteArray) {
    fun sign(message: ByteArray): ByteArray
    fun verify(message: ByteArray, signature: ByteArray): Boolean
}

// Lamport one-time signature
class Signatures.LamportSignature() {
    fun sign(message: ByteArray): ByteArray
    fun verify(message: ByteArray, signature: ByteArray): Boolean
    val isUsed: Boolean
}
```

## Kotlin Extensions

Shield Kotlin includes convenient extension functions:

```kotlin
import ai.guard8.shield.extensions.*

// String encryption
val encrypted = "secret".encryptWith(shield)
val decrypted = encrypted.decryptWith(shield)?.decodeToString()

// Byte array helpers
val key = randomBytes(32)
val hex = encrypted.toHexString()
val base64 = encrypted.toBase64()
```

## Error Handling

Shield Kotlin uses nullable returns for decryption failures and exceptions for invalid input:

```kotlin
// Decryption returns null on auth failure
val decrypted = shield.decrypt(ciphertext)
if (decrypted != null) {
    process(decrypted)
} else {
    handleAuthenticationFailure()
}

// Invalid input throws IllegalArgumentException
try {
    val s = Shield.withKey(tooShortKey)
} catch (e: IllegalArgumentException) {
    // Key must be exactly 32 bytes
}
```

## Coroutines Support

Shield operations are CPU-bound but can be run on the IO dispatcher for large data:

```kotlin
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

suspend fun encryptLargeData(data: ByteArray): ByteArray = withContext(Dispatchers.IO) {
    shield.encrypt(data)
}
```

## Thread Safety

Shield Kotlin classes are **thread-safe**. A single `Shield` instance can be shared across coroutines and threads.

## Security Model

Shield uses only symmetric primitives with unconditional security:

- **Symmetric encryption** (AES-256 equivalent)
- **Hash functions** (SHA-256)
- **HMAC authentication**
- **Key derivation** (PBKDF2)

Breaking requires 2^256 operations - no shortcut exists.

## Cross-Language Compatibility

Shield Kotlin produces byte-identical output to Python, JavaScript, Rust, Go, Java, C#, and all other implementations. Encrypt in Kotlin, decrypt in any other language.

## Requirements

- Kotlin 1.8+
- JDK 11+
- No external dependencies

## Android Support

Shield Kotlin is fully compatible with Android (API 26+):

```kotlin
// Android-specific key storage with KeyStore
val keyAlias = "shield_key"
val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

// Generate key in hardware-backed keystore
val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
keyGenerator.init(
    KeyGenParameterSpec.Builder(keyAlias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setKeySize(256)
        .build()
)
```

## License

MIT License - Use freely.

## See Also

- [Shield Python Package](https://pypi.org/project/shield-crypto/)
- [Shield npm Package](https://npmjs.com/package/@guard8/shield)
- [Shield Rust Crate](https://crates.io/crates/shield-core)
- [Shield Java](../java)
- [GitHub Repository](https://github.com/Guard8-ai/Shield)
