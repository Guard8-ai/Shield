# Migration Guide

How to migrate from common encryption libraries to Shield.

## From Fernet (cryptography.fernet)

Fernet is Python's `cryptography` library's high-level symmetric encryption.

### Before (Fernet)

```python
from cryptography.fernet import Fernet

# Generate and store key
key = Fernet.generate_key()
f = Fernet(key)

# Encrypt
token = f.encrypt(b"secret data")

# Decrypt
plaintext = f.decrypt(token)
```

### After (Shield)

```python
from shield import Shield

# Password-based (no key file needed)
s = Shield("your_password", "your_service")

# Encrypt
encrypted = s.encrypt(b"secret data")

# Decrypt
plaintext = s.decrypt(encrypted)
```

### Key Differences

| Feature | Fernet | Shield |
|---------|--------|--------|
| Key derivation | Manual (generate + store) | Built-in PBKDF2 |
| Key storage | You manage key file | Password-based |
| Algorithm | AES-128-CBC + HMAC-SHA256 | SHA256-CTR + HMAC-SHA256 |
| Key size | 128-bit | 256-bit |
| Format | Base64 token | Binary (nonce + ciphertext + MAC) |

### Migration Steps

1. **Decrypt existing data** with Fernet
2. **Re-encrypt** with Shield
3. **Store password** securely (not in code)

```python
from cryptography.fernet import Fernet
from shield import Shield

# Old Fernet key
old_key = b"your-fernet-key-here"
f = Fernet(old_key)

# New Shield instance
s = Shield("your_new_password", "your_service")

# Migrate data
for old_token in old_encrypted_data:
    plaintext = f.decrypt(old_token)
    new_encrypted = s.encrypt(plaintext)
    store(new_encrypted)
```

---

## From cryptography (low-level)

Using `cryptography` library's hazmat layer directly.

### Before (AES-GCM)

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

key = AESGCM.generate_key(bit_length=256)
aesgcm = AESGCM(key)

nonce = os.urandom(12)
ciphertext = aesgcm.encrypt(nonce, b"secret data", associated_data=None)

# Must store nonce separately or prepend
stored = nonce + ciphertext

# Decrypt
nonce = stored[:12]
ciphertext = stored[12:]
plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
```

### After (Shield)

```python
from shield import Shield

s = Shield("your_password", "your_service")

# Encrypt (nonce handled automatically)
encrypted = s.encrypt(b"secret data")

# Decrypt
plaintext = s.decrypt(encrypted)
```

### Key Differences

| Feature | cryptography (AES-GCM) | Shield |
|---------|------------------------|--------|
| Nonce handling | Manual | Automatic |
| Key management | Manual | PBKDF2 from password |
| Associated data | Supported | Not supported |
| Format | Custom | Standard (nonce + ct + mac) |

### Migration with Pre-shared Keys

If you have existing AES keys, use `Shield.with_key()`:

```python
from shield import Shield

existing_key = bytes.fromhex("your_32_byte_hex_key_here")
s = Shield.with_key(existing_key)

encrypted = s.encrypt(b"data")
```

---

## From NaCl / libsodium (PyNaCl)

NaCl's secretbox provides authenticated encryption.

### Before (NaCl secretbox)

```python
from nacl.secret import SecretBox
from nacl.utils import random

key = random(SecretBox.KEY_SIZE)  # 32 bytes
box = SecretBox(key)

encrypted = box.encrypt(b"secret data")
plaintext = box.decrypt(encrypted)
```

### After (Shield)

```python
from shield import Shield

s = Shield("your_password", "your_service")

encrypted = s.encrypt(b"secret data")
plaintext = s.decrypt(encrypted)
```

### Key Differences

| Feature | NaCl secretbox | Shield |
|---------|----------------|--------|
| Algorithm | XSalsa20 + Poly1305 | SHA256-CTR + HMAC-SHA256 |
| Nonce size | 24 bytes | 16 bytes |
| Key derivation | Manual | Built-in PBKDF2 |
| MAC | Poly1305 (faster) | HMAC-SHA256 (more standard) |

### Migration with Existing Keys

```python
from nacl.secret import SecretBox
from shield import Shield

# Old NaCl key
nacl_key = b"your_32_byte_key_here"

# Migrate to Shield with same key
s = Shield.with_key(nacl_key)

# Or derive new key from password
s = Shield("password", "service")
```

---

## From PyCryptodome

### Before (AES-CTR + HMAC)

```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hmac
import hashlib

key = get_random_bytes(32)
nonce = get_random_bytes(16)

cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
ciphertext = cipher.encrypt(b"secret data")

# Manual MAC
mac = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()[:16]
stored = nonce + ciphertext + mac
```

### After (Shield)

```python
from shield import Shield

s = Shield("your_password", "your_service")
encrypted = s.encrypt(b"secret data")  # Nonce + ciphertext + MAC handled
```

---

## From hashlib (DIY encryption)

If you built your own encryption (please don't!):

### Before (Insecure DIY)

```python
import hashlib
from Crypto.Cipher import AES

# DON'T DO THIS - example of what to migrate from
password = "mypassword"
key = hashlib.sha256(password.encode()).digest()
# Missing: proper KDF, nonce handling, authentication
```

### After (Shield)

```python
from shield import Shield

# Shield handles everything correctly
s = Shield("mypassword", "myservice")
encrypted = s.encrypt(b"data")
```

---

## Cross-Language Migration

Shield provides identical implementations across 10 languages. Data encrypted in one language decrypts in any other.

### Encrypt in Python, Decrypt in JavaScript

```python
# Python
from shield import Shield
s = Shield("shared_password", "shared_service")
encrypted = s.encrypt(b"secret")
print(encrypted.hex())  # Send to JS
```

```javascript
// JavaScript
const { Shield } = require('@guard8/shield');
const s = new Shield('shared_password', 'shared_service');
const encrypted = Buffer.from('...hex_from_python...', 'hex');
const decrypted = s.decrypt(encrypted);
```

---

## Best Practices for Migration

### 1. Test Thoroughly

```python
# Verify decryption works before deleting old data
old_plaintext = old_decrypt(old_ciphertext)
new_encrypted = shield.encrypt(old_plaintext)
new_plaintext = shield.decrypt(new_encrypted)
assert old_plaintext == new_plaintext
```

### 2. Migrate Incrementally

```python
def decrypt(data):
    """Try Shield first, fall back to old system."""
    try:
        return shield.decrypt(data)
    except:
        return old_decrypt(data)

def encrypt(data):
    """Always use Shield for new encryptions."""
    return shield.encrypt(data)
```

### 3. Rotate Keys After Migration

```python
from shield.rotation import KeyRotationManager

manager = KeyRotationManager(old_key, version=1)
manager.rotate(new_key)  # Add version 2

# Old ciphertext still decrypts
# New encryptions use version 2
```

### 4. Use Password Strength Checker

```python
from shield.password import check_password, StrengthLevel

result = check_password("your_password")
if result.level in (StrengthLevel.Critical, StrengthLevel.Weak):
    print(f"Warning: {result.suggestions}")
```

---

## FAQ

### Q: Can Shield decrypt Fernet/NaCl data directly?

No. Decrypt with the original library, then re-encrypt with Shield.

### Q: Is Shield faster than AES-GCM?

No. Shield is ~10-20x slower than hardware-accelerated AES-GCM. See [BENCHMARKS.md](BENCHMARKS.md) for details. This is acceptable for most use cases.

### Q: Why migrate to Shield?

1. **Password-based**: No key files to manage
2. **Cross-language**: 10 identical implementations
3. **EXPTIME security**: Proven 2^256 brute-force resistance
4. **Simpler API**: `encrypt()`/`decrypt()` handle everything
