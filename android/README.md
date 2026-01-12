# Shield - EXPTIME-Secure Encryption (Android)

[![Maven Central](https://img.shields.io/maven-central/v/ai.guard8/shield-android.svg)](https://search.maven.org/artifact/ai.guard8/shield-android)
[![API](https://img.shields.io/badge/API-23%2B-brightgreen.svg)](https://android-arsenal.com/api?level=23)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Symmetric cryptography with proven exponential-time security for Android.

## Why Shield?

Shield uses only symmetric primitives with EXPTIME-hard security guarantees. Breaking requires 2^256 operations - no shortcut exists:

- **PBKDF2-SHA256** for key derivation (100,000 iterations)
- **SHA256-based stream cipher** (AES-256-CTR equivalent)
- **HMAC-SHA256** for authentication
- **Android Keystore** for hardware-backed key storage

## Installation

### Gradle (Kotlin DSL)

```kotlin
implementation("ai.guard8:shield-android:0.1.0")
```

### Gradle (Groovy)

```groovy
implementation 'ai.guard8:shield-android:0.1.0'
```

## Quick Start

### Basic Encryption

```kotlin
import ai.guard8.shield.Shield

// Password-based encryption
val shield = Shield.create("my_password", "github.com")
val encrypted = shield.encrypt("secret data".toByteArray())
val decrypted = shield.decrypt(encrypted)
println(String(decrypted!!))  // "secret data"
```

### Pre-shared Key

```kotlin
import ai.guard8.shield.Shield
import java.security.SecureRandom

val key = ByteArray(32).also { SecureRandom().nextBytes(it) }

val encrypted = Shield.quickEncrypt(key, "data".toByteArray())
val decrypted = Shield.quickDecrypt(key, encrypted)
```

### Secure Key Storage (Android Keystore)

```kotlin
import ai.guard8.shield.SecureKeyStore

val keyStore = SecureKeyStore(context)

// Store a key securely (encrypted with hardware-backed master key)
keyStore.storeKey("my_app_key", secretKey)

// Retrieve later
val key = keyStore.getKey("my_app_key")

// Or use hardware-backed key that never leaves secure hardware
val hwKey = keyStore.generateHardwareKey("hw_backed_key")
```

### Create Shield with Stored Key

```kotlin
import ai.guard8.shield.SecureKeyStore

val keyStore = SecureKeyStore(context)

// Gets existing key or creates new one from password
val shield = keyStore.getOrCreateShield(
    alias = "user_encryption_key",
    password = userPassword,
    service = "myapp.example.com"
)

val encrypted = shield.encrypt(sensitiveData)
```

## API Reference

### Shield

```kotlin
// Create from password
Shield.create(password: String, service: String): Shield

// Create from pre-shared key
Shield.withKey(key: ByteArray): Shield

// Encrypt/decrypt
fun encrypt(plaintext: ByteArray): ByteArray
fun decrypt(ciphertext: ByteArray): ByteArray?

// Static convenience methods
Shield.quickEncrypt(key: ByteArray, plaintext: ByteArray): ByteArray
Shield.quickDecrypt(key: ByteArray, ciphertext: ByteArray): ByteArray?
```

### SecureKeyStore

```kotlin
// Store/retrieve keys
fun storeKey(alias: String, key: ByteArray)
fun getKey(alias: String): ByteArray?
fun deleteKey(alias: String): Boolean
fun hasKey(alias: String): Boolean

// Hardware-backed keys (TEE/Secure Element)
fun generateHardwareKey(alias: String): SecretKey
fun getHardwareKey(alias: String): SecretKey?
fun isHardwareBackedAvailable(): Boolean

// Convenience method
fun getOrCreateShield(alias: String, password: String, service: String): Shield
```

## Security Features

### Hardware-Backed Storage

On supported devices (most Android 6.0+), keys are stored in:
- **TEE (Trusted Execution Environment)** - Isolated secure processor
- **StrongBox** (Android 9+) - Dedicated secure element

```kotlin
val keyStore = SecureKeyStore(context)

if (keyStore.isHardwareBackedAvailable()) {
    // Keys will be stored in secure hardware
    val hwKey = keyStore.generateHardwareKey("secure_key")
}
```

### Biometric Protection

```kotlin
val spec = KeyGenParameterSpec.Builder(alias, purposes)
    .setUserAuthenticationRequired(true)
    .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
    .build()
```

## Java Interop

Shield Android works seamlessly from Java:

```java
import ai.guard8.shield.Shield;

Shield shield = Shield.create("password", "service");
byte[] encrypted = shield.encrypt("secret".getBytes());
byte[] decrypted = shield.decrypt(encrypted);
```

## ProGuard / R8

Shield includes consumer ProGuard rules automatically. No additional configuration needed.

## Requirements

- Android API 23+ (Android 6.0 Marshmallow)
- Kotlin 1.8+ or Java 8+
- AndroidX Security library (included)

## Thread Safety

Shield Android classes are **thread-safe**. A single instance can be shared across coroutines and threads.

## Cross-Platform Compatibility

Shield Android produces byte-identical output to all other Shield implementations:
- Python, JavaScript, Rust, Go, C, Java, C#, Swift, Kotlin, WebAssembly

Encrypt on Android, decrypt on any platform.

## License

MIT License - Use freely.

## See Also

- [Shield iOS](../ios) - iOS/Swift implementation
- [Shield Python](https://pypi.org/project/shield-crypto/)
- [Shield npm](https://npmjs.com/package/@guard8/shield)
- [GitHub Repository](https://github.com/Guard8-ai/Shield)
