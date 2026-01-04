# Quick Start

**Goal:** Encrypt something in 2 minutes.

---

## Step 1: Install

Pick your language:

```bash
pip install shield-crypto          # Python
npm install @guard8/shield         # JavaScript
go get github.com/Guard8-ai/shield # Go
```

---

## Step 2: Encrypt

### Python
```python
from shield import Shield

# Create encryptor with your password
s = Shield("my-secret-password", "my-app")

# Encrypt
encrypted = s.encrypt(b"Hello, World!")

# Save to file
with open("secret.enc", "wb") as f:
    f.write(encrypted)

print("Done! Encrypted data saved to secret.enc")
```

### JavaScript
```javascript
const { Shield } = require('@guard8/shield');
const fs = require('fs');

// Create encryptor with your password
const s = new Shield('my-secret-password', 'my-app');

// Encrypt
const encrypted = s.encrypt(Buffer.from('Hello, World!'));

// Save to file
fs.writeFileSync('secret.enc', encrypted);

console.log('Done! Encrypted data saved to secret.enc');
```

### Go
```go
package main

import (
    "os"
    "github.com/Guard8-ai/shield/shield"
)

func main() {
    // Create encryptor with your password
    s := shield.New("my-secret-password", "my-app")

    // Encrypt
    encrypted, _ := s.Encrypt([]byte("Hello, World!"))

    // Save to file
    os.WriteFile("secret.enc", encrypted, 0644)

    println("Done! Encrypted data saved to secret.enc")
}
```

---

## Step 3: Decrypt

### Python
```python
from shield import Shield

# Same password and app name
s = Shield("my-secret-password", "my-app")

# Read encrypted file
with open("secret.enc", "rb") as f:
    encrypted = f.read()

# Decrypt
decrypted = s.decrypt(encrypted)

print("Decrypted:", decrypted.decode())
# Output: Decrypted: Hello, World!
```

### JavaScript
```javascript
const { Shield } = require('@guard8/shield');
const fs = require('fs');

// Same password and app name
const s = new Shield('my-secret-password', 'my-app');

// Read encrypted file
const encrypted = fs.readFileSync('secret.enc');

// Decrypt
const decrypted = s.decrypt(encrypted);

console.log('Decrypted:', decrypted.toString());
// Output: Decrypted: Hello, World!
```

### Go
```go
package main

import (
    "os"
    "github.com/Guard8-ai/shield/shield"
)

func main() {
    // Same password and app name
    s := shield.New("my-secret-password", "my-app")

    // Read encrypted file
    encrypted, _ := os.ReadFile("secret.enc")

    // Decrypt
    decrypted, _ := s.Decrypt(encrypted)

    println("Decrypted:", string(decrypted))
    // Output: Decrypted: Hello, World!
}
```

---

## That's It!

You just encrypted and decrypted data.

### What's Next?

| Want to... | See... |
|------------|--------|
| Encrypt large files | [CHEATSHEET.md#streaming](CHEATSHEET.md#streaming-large-files) |
| Add 2FA to your app | [CHEATSHEET.md#totp](CHEATSHEET.md#totp-2fa) |
| Build a messaging app | [CHEATSHEET.md#forward-secrecy](CHEATSHEET.md#forward-secrecy-ratchet) |
| Understand the security | [SECURITY.md](SECURITY.md) |

---

## Common Questions

### "What if I forget my password?"

Your data is gone forever. There is no backdoor. That's the point.

**Solution:** Use a password manager.

### "Can I use the same password for different apps?"

Yes, but use different `service` names:
```python
s1 = Shield("same-password", "app1.com")
s2 = Shield("same-password", "app2.com")
# These create different encryption keys
```

### "How do I share encrypted data?"

Share the password securely (in person, encrypted chat, etc.), then share the encrypted file however you want.

### "Is this secure?"

Yes. Shield uses:
- 256-bit keys (unbreakable by any known method)
- HMAC authentication (detects any tampering)
- No asymmetric crypto (survives P=NP and quantum computers)

See [SECURITY.md](SECURITY.md) for the full threat model.

---

## Command Line (Python only)

```bash
# Encrypt a file
shield encrypt secret.txt -o secret.enc

# Decrypt a file
shield decrypt secret.enc -o secret.txt

# Generate a secure key
shield keygen
```

---

**Questions?** Open an issue: https://github.com/Guard8-ai/Shield/issues
