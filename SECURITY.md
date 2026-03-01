# Security Model

Shield's threat model, guarantees, and limitations.

---

## The EXPTIME Guarantee

Shield provides **EXPTIME security**: breaking the encryption requires exponential time in the key size, regardless of any mathematical breakthroughs.

### What This Means

| Attack | Required Operations | Feasibility |
|--------|---------------------|-------------|
| Brute force 256-bit key | 2^256 | Impossible (more than atoms in universe) |
| Quantum computer (Grover) | 2^128 | Still impossible for foreseeable future |
| P=NP proven | Still 2^256 | No polynomial shortcut exists |
| New math discovered | Still 2^256 | Symmetric crypto has unconditional bounds |

### Why Shield Uses Symmetric Cryptography

RSA, ECDSA, and similar schemes rely on computational assumptions that may be broken by future discoveries.

Shield uses **no computational assumptions**. The 2^256 bound is a mathematical fact, not a belief.

---

## Threat Model

### What Shield Protects

| Threat | Protection | How |
|--------|------------|-----|
| Passive eavesdropper | Encryption | Cannot read ciphertext without key |
| Active attacker | Authentication | HMAC detects any tampering |
| Replay attacks | Ratcheting | Counter prevents message reuse |
| Password guessing | PBKDF2 | 100,000 iterations = ~200ms per guess |
| Quantum computer | 256-bit keys | Grover only halves effective key size |
| P=NP proof | Symmetric only | No asymmetric assumptions to break |
| Key compromise (past) | Ratcheting | Forward secrecy protects old messages |

### What Shield Does NOT Protect

| Threat | Why Not | Mitigation |
|--------|---------|------------|
| Weak password | User choice | Use 16+ character passwords |
| Compromised endpoint | Out of scope | Secure your devices |
| Stolen key file | Out of scope | Protect key storage |
| Side-channel attacks | Hardware dependent | Use constant-time code (we do) |
| Rubber hose attack | Physical security | Out of scope |

---

## Cryptographic Primitives

All primitives are NIST-approved and battle-tested:

| Primitive | Standard | Security Level |
|-----------|----------|----------------|
| SHA-256 | FIPS 180-4 | 256-bit preimage |
| HMAC-SHA256 | RFC 2104 | 256-bit MAC |
| PBKDF2-SHA256 | RFC 8018 | Key stretching |
| SHA256-CTR | Custom | 256-bit stream cipher |

### Why SHA256-CTR Instead of AES?

Shield uses a SHA256-based counter mode instead of AES for philosophical consistency:

1. **Same security**: Both are 256-bit symmetric ciphers
2. **Simpler**: One primitive (SHA256) instead of two
3. **Portable**: SHA256 is easier to implement correctly
4. **Future-proof**: Hash functions are more quantum-resistant

---

## Password Security

### How Passwords Become Keys

```
master_key = PBKDF2(password, SHA256(service), 100,000) → 256-bit key

# v2.1: Key separation via HMAC domain labels
enc_key = HMAC-SHA256(master_key, "shield-encrypt")
mac_key = HMAC-SHA256(master_key, "shield-authenticate")
```

Key separation prevents cross-protocol key reuse (CWE-323). The `enc_key` is used for keystream generation and the `mac_key` for HMAC authentication.

### Password Recommendations

| Password Type | Entropy | Time to Crack |
|---------------|---------|---------------|
| 8 random chars | ~50 bits | Days |
| 12 random chars | ~72 bits | Years |
| 16 random chars | ~95 bits | Centuries |
| 4 random words | ~50-60 bits | Months |
| 6 random words | ~75-90 bits | Millennia |

**Minimum recommendation:** 12 random characters OR 5 random words.

### Service Identifier

The `service` parameter prevents key reuse across applications:
- Same password + different service = different key
- Compromise of one service doesn't affect others

---

## Message Format

```
+----------+------------+--------+
|  Nonce   | Ciphertext |  MAC   |
| 16 bytes |  N bytes   | 16 bytes|
+----------+------------+--------+
```

- **Nonce**: Random, unique per message
- **Ciphertext**: XOR of plaintext with SHA256-CTR keystream
- **MAC**: HMAC-SHA256(key, nonce || ciphertext), truncated to 128 bits

### Security Properties

1. **Confidentiality**: Ciphertext reveals nothing about plaintext
2. **Integrity**: Any modification detected by MAC
3. **Authentication**: Only key holder can create valid MAC
4. **Non-malleability**: Cannot modify ciphertext meaningfully

---

## Forward Secrecy (Ratcheting)

RatchetSession provides forward secrecy:

```
root_key → chain_key_1 → chain_key_2 → chain_key_3 → ...
              ↓              ↓              ↓
           msg_key_1      msg_key_2      msg_key_3
```

- Each message uses a unique key
- Keys are deleted after use
- Compromise of current key doesn't reveal past messages

---

## Lamport Signatures

For quantum-safe document signing:

| Property | Value |
|----------|-------|
| Security | 256-bit (128-bit post-quantum) |
| Signature size | 8,192 bytes |
| Public key size | 16,384 bytes |
| Uses | One signature per key pair |

### When to Use Lamport

- Long-term document signatures
- High-value transactions
- When quantum resistance is required

### When NOT to Use Lamport

- High-volume signing (use SymmetricSignature)
- Interactive protocols (too slow)
- Bandwidth-constrained environments

---

## Implementation Security

### Constant-Time Operations

All MAC verifications use constant-time comparison to prevent timing attacks (CWE-208):

- **Rust**: `subtle::ConstantTimeEq` for all MAC and secret comparisons
- **Python**: `hmac.compare_digest()`
- **JavaScript**: `crypto.timingSafeEqual()`
- **Go**: `subtle.ConstantTimeCompare()`

Additionally, `IdentityProvider::authenticate()` runs PBKDF2 even for non-existent users to prevent user enumeration timing attacks (CWE-203).

### Memory Handling (v2.1)

**Rust core** uses the `zeroize` crate for secure key material cleanup:

- `Shield` — encryption keys zeroized on drop (`#[derive(Zeroize, ZeroizeOnDrop)]`)
- `RatchetSession` — chain keys zeroized on drop
- `TOTP` — secret zeroized on drop
- `SymmetricSignature` — signing/verification keys zeroized on drop
- `LamportSignature` — private key material zeroized on drop
- `IdentityProvider` — master keys, password hashes, and salts zeroized via explicit `Drop` impl
- `SecureSession` — session keys zeroized via explicit `Drop` impl

Other language implementations rely on garbage collection with best-effort cleanup.

---

## Reporting Vulnerabilities

If you discover a security vulnerability:

1. **Do NOT** open a public issue
2. Email: security@guard8.ai
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
4. We will respond within 48 hours
5. We will credit you in the fix (unless you prefer anonymity)

---

## Audit Status

| Component | Status |
|-----------|--------|
| Rust core (shield-core) | v2.1 security hardening complete (189-finding assessment) |
| Core algorithms | Internal review + hardened |
| Python implementation | Internal review |
| JavaScript implementation | Internal review |
| Go implementation | Internal review |
| Formal verification | Planned |
| External audit | Planned |

### v2.1 Security Hardening (2026-03-01)

Based on a comprehensive 189-finding security assessment, all Rust-applicable findings were resolved:

- **Key separation**: Derived separate `enc_key` and `mac_key` via HMAC-SHA256 domain labels
- **HMAC-SHA256 upgrade**: Replaced 13 internal `SHA256(key||data)` patterns with HMAC-SHA256
- **Constant-time comparisons**: All MAC verifications use `subtle::ConstantTimeEq`
- **Zeroize on Drop**: All key-holding structs securely clear memory
- **Counter overflow guards**: All 8 keystream generators prevent silent `u32` wraparound
- **Sync channel timeout**: TCP handshake enforces configurable timeout
- **TOTP hardening**: Digits clamping, window=0 exact-match, 64-bit recovery codes
- **CLI security**: Password input via stdin, `--force` for overwrites
- **Modulo bias elimination**: Padding uses rejection sampling
- **Padding validation**: Decryption rejects out-of-bounds `pad_len`

Test count: 119 tests (104 unit + 7 interop + 8 doc-tests), clippy clean with `-D warnings`.

---

## Comparison with Alternatives

| Feature | Shield | libsodium | OpenSSL | GPG |
|---------|--------|-----------|---------|-----|
| Post-quantum ready | Yes | Partial | No | No |
| P=NP safe | Yes | Partial | No | No |
| Zero dependencies | Yes | No | No | No |
| Cross-language | 10 langs | Many | C only | CLI |
| Forward secrecy | Built-in | External | External | No |

---

## References

- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [PBKDF2 RFC 8018](https://tools.ietf.org/html/rfc8018)
- [HMAC RFC 2104](https://tools.ietf.org/html/rfc2104)
- [SHA-256 FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)
- [TOTP RFC 6238](https://tools.ietf.org/html/rfc6238)
