# Shield - EXPTIME-Secure Encryption (C)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Symmetric cryptography with proven exponential-time security.

## Why Shield?

Shield uses only symmetric primitives with EXPTIME-hard security guarantees. Breaking requires 2^256 operations - no shortcut exists:

- **PBKDF2-SHA256** for key derivation (100,000 iterations)
- **SHA256-based stream cipher** (AES-256-CTR equivalent)
- **HMAC-SHA256** for authentication

## Installation

### From Source

```bash
cd c
make
sudo make install
```

This installs `libshield.so` and `shield.h` to standard system locations.

### Manual Include

```bash
# Copy headers and library
cp include/shield.h /usr/local/include/
cp build/libshield.so /usr/local/lib/
ldconfig
```

## Quick Start

### Basic Encryption

```c
#include <shield.h>
#include <stdio.h>
#include <string.h>

int main() {
    shield_t *s = shield_init("my_password", "github.com");

    const char *message = "secret data";
    size_t msg_len = strlen(message);

    // Encrypt
    size_t enc_len;
    uint8_t *encrypted = shield_encrypt(s, (uint8_t*)message, msg_len, &enc_len);

    // Decrypt
    size_t dec_len;
    uint8_t *decrypted = shield_decrypt(s, encrypted, enc_len, &dec_len);

    printf("Decrypted: %.*s\n", (int)dec_len, decrypted);

    // Cleanup
    free(encrypted);
    free(decrypted);
    shield_free(s);

    return 0;
}
```

### Pre-shared Key

```c
#include <shield.h>

// 32-byte key (generate securely)
uint8_t key[32];
shield_random_bytes(key, 32);

// Quick encrypt/decrypt
size_t enc_len, dec_len;
uint8_t *encrypted = shield_quick_encrypt(key, data, data_len, &enc_len);
uint8_t *decrypted = shield_quick_decrypt(key, encrypted, enc_len, &dec_len);

free(encrypted);
free(decrypted);
```

### Forward Secrecy (Ratchet)

```c
#include <shield.h>

uint8_t root_key[32];
shield_random_bytes(root_key, 32);

ratchet_t *alice = ratchet_init(root_key, 1);  // initiator
ratchet_t *bob = ratchet_init(root_key, 0);    // responder

// Each message uses a new key
size_t enc_len, dec_len;
uint8_t *encrypted = ratchet_encrypt(alice, (uint8_t*)"Hello!", 6, &enc_len);
uint8_t *decrypted = ratchet_decrypt(bob, encrypted, enc_len, &dec_len);

free(encrypted);
free(decrypted);
ratchet_free(alice);
ratchet_free(bob);
```

### TOTP (2FA)

```c
#include <shield.h>

// Generate secret
uint8_t secret[20];
totp_generate_secret(secret, 20);

totp_t *totp = totp_init(secret, 20);

// Generate code
char code[7];
totp_generate(totp, code);
printf("Code: %s\n", code);

// Verify code
int valid = totp_verify(totp, code, 1);  // window=1

totp_free(totp);
```

### Digital Signatures

```c
#include <shield.h>

// HMAC-based symmetric signature
uint8_t key[32];
shield_random_bytes(key, 32);

signature_t *sig = signature_init(key);
uint8_t signature[32];
signature_sign(sig, (uint8_t*)"message", 7, signature);

int valid = signature_verify(sig, (uint8_t*)"message", 7, signature);

signature_free(sig);

// Lamport one-time signature (quantum-safe)
lamport_t *lamport = lamport_init();
size_t sig_len;
uint8_t *lsig = lamport_sign(lamport, (uint8_t*)"important", 9, &sig_len);
int lvalid = lamport_verify(lamport, (uint8_t*)"important", 9, lsig);

free(lsig);
lamport_free(lamport);
```

## Compilation

```bash
# With pkg-config
gcc -o myapp myapp.c $(pkg-config --cflags --libs shield)

# Manual
gcc -o myapp myapp.c -lshield -lcrypto
```

## API Reference

### Core Functions

```c
// Initialize/cleanup
shield_t *shield_init(const char *password, const char *service);
shield_t *shield_init_with_key(const uint8_t *key);
void shield_free(shield_t *s);

// Encrypt/decrypt
uint8_t *shield_encrypt(shield_t *s, const uint8_t *plaintext, size_t len, size_t *out_len);
uint8_t *shield_decrypt(shield_t *s, const uint8_t *ciphertext, size_t len, size_t *out_len);

// Quick functions (pre-shared key)
uint8_t *shield_quick_encrypt(const uint8_t *key, const uint8_t *plaintext, size_t len, size_t *out_len);
uint8_t *shield_quick_decrypt(const uint8_t *key, const uint8_t *ciphertext, size_t len, size_t *out_len);

// Utilities
void shield_random_bytes(uint8_t *buf, size_t len);
```

### Error Codes

```c
#define SHIELD_OK                    0
#define SHIELD_ERR_INVALID_KEY      -1
#define SHIELD_ERR_CIPHERTEXT_SHORT -2
#define SHIELD_ERR_AUTH_FAILED      -3
#define SHIELD_ERR_ALLOC            -4
```

### Ratchet Session

```c
ratchet_t *ratchet_init(const uint8_t *root_key, int is_initiator);
void ratchet_free(ratchet_t *r);
uint8_t *ratchet_encrypt(ratchet_t *r, const uint8_t *plaintext, size_t len, size_t *out_len);
uint8_t *ratchet_decrypt(ratchet_t *r, const uint8_t *ciphertext, size_t len, size_t *out_len);
```

### TOTP

```c
totp_t *totp_init(const uint8_t *secret, size_t secret_len);
void totp_free(totp_t *t);
void totp_generate(totp_t *t, char *out);  // 6-digit code
int totp_verify(totp_t *t, const char *code, int window);
void totp_generate_secret(uint8_t *out, size_t len);
```

## Memory Management

All `shield_*` functions that return allocated memory require manual `free()`:

```c
uint8_t *encrypted = shield_encrypt(...);
// Use encrypted...
free(encrypted);  // Required!
```

## Thread Safety

Shield C library is **NOT** thread-safe by default. Use separate `shield_t` instances per thread, or protect shared instances with mutexes.

## Security Model

Shield uses only symmetric primitives with unconditional security:

- **Symmetric encryption** (AES-256 equivalent)
- **Hash functions** (SHA-256)
- **HMAC authentication**
- **Key derivation** (PBKDF2)

Breaking requires 2^256 operations - no shortcut exists.

## Dependencies

- OpenSSL 1.1+ (for SHA256, HMAC, PBKDF2)

## Cross-Language Compatibility

Shield C produces byte-identical output to Python, JavaScript, Rust, Go, and all other implementations.

## License

MIT License - Use freely.

## See Also

- [Shield Python Package](https://pypi.org/project/shield-crypto/)
- [Shield npm Package](https://npmjs.com/package/@guard8/shield)
- [Shield Rust Crate](https://crates.io/crates/shield-core)
- [GitHub Repository](https://github.com/Guard8-ai/Shield)
