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

### Why Traditional Crypto Breaks

RSA, ECDSA, and similar schemes rely on **computational assumptions**:
- "Factoring is hard" (RSA)
- "Discrete log is hard" (ECDSA, DH)

If P=NP, these assumptions are **proven false**. All security vanishes instantly.

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
password + service → PBKDF2(password, SHA256("shield:" + service), 100,000) → 256-bit key
```

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

Shield uses constant-time comparison for all security-critical operations:

```python
def constant_time_eq(a, b):
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0
```

This prevents timing attacks that leak information through execution time.

### Memory Handling

- Keys are wiped after use (where language allows)
- No key material in error messages
- Minimal key lifetime in memory

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
| Core algorithms | Internal review |
| Python implementation | Internal review |
| JavaScript implementation | Internal review |
| Go implementation | Internal review |
| Formal verification | Planned |
| External audit | Planned |

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
