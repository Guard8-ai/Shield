# Shield Test Suite

## Overview

This directory contains cross-language interoperability tests and conformance
vectors for the Shield encryption library.

---

## Ratchet Families

Shield's ratchet module shipped with three incompatible wire-format families
across its language bindings. This is a known architectural divergence documented
in the ARC security review r1b (2026-07-14) and formally tracked for full
realignment in **backend-064**.

### Family Table

| Family | Bindings | Chain KDF | Keystream PRF | Counter Placement |
|--------|----------|-----------|---------------|-------------------|
| **A** | Rust, WASM | HMAC-SHA256(root, label) | HMAC(enc\_key, nonce\|\|block\_ctr) | Encrypted (inside XOR payload) |
| **B** | Python, JavaScript, Kotlin, Android, iOS | SHA256(root \|\| label) | SHA256(msg\_key \|\| nonce \|\| block\_ctr) | Encrypted (inside XOR payload) |
| **C** | Go, Java, Swift, C#, C | SHA256(root \|\| label) | SHA256(msg\_key \|\| nonce \|\| block\_ctr) | Cleartext prefix (first 8 bytes of frame) |

### Wire Format Details

**Family A** frame layout:
```
nonce(16) || HMAC_keystream_XOR(ctr_le64 || plaintext) || HMAC_mac_truncated(16)
```
- Chain init: `HMAC-SHA256(root, "send")` / `HMAC-SHA256(root, "recv")`
- Chain step: `new_chain = HMAC(chain, "chain")`, `msg_key = HMAC(chain, "message")`
- Subkeys: `enc_key = HMAC(msg_key, "shield-ratchet-encrypt")`,
           `mac_key = HMAC(msg_key, "shield-ratchet-authenticate")`
- MAC input: `nonce || ciphertext`

**Family B** frame layout:
```
nonce(16) || SHA256_keystream_XOR(ctr_le64 || plaintext) || HMAC_mac_truncated(16)
```
- Chain init: `SHA256(root || "send")` / `SHA256(root || "recv")`
- Chain step: `new_chain = SHA256(chain || "chain")`, `msg_key = SHA256(chain || "message")`
- MAC input: `nonce || ciphertext`

**Family C** frame layout:
```
counter_le64(8) || nonce(16) || SHA256_keystream_XOR(plaintext) || HMAC_mac_truncated(16)
```
- Chain init: `SHA256(root || "init_send")` / `SHA256(root || "init_recv")`
- Chain step: `msg_key = SHA256(chain || "message")`, `new_chain = SHA256(chain || "ratchet")`
- MAC input: `ctr_le64 || nonce || ciphertext`

### Key Differences Between Families

- **A vs B**: Family A uses HMAC-SHA256 for the chain KDF (keyed PRF), while
  Family B uses plain SHA256 (unkeyed). Family A also derives separate encryption
  and MAC subkeys per message.
- **B vs C**: Same chain algorithm and keystream, but different init labels
  (`"send"`/`"recv"` vs `"init_send"`/`"init_recv"`), different chain step label
  for ratcheting (`"chain"` vs `"ratchet"`), and a different counter placement:
  Family B encrypts the counter inside the payload, Family C puts it as a
  cleartext 8-byte prefix.
- **A vs C**: Both differences above combined.

---

## Test Vector Files

| File | Description |
|------|-------------|
| `ratchet_vectors.json` | All three families in one file |
| `ratchet_vectors_family_a.json` | Family A (Rust, WASM) vectors only |
| `ratchet_vectors_family_b.json` | Family B (Python, JS, Kotlin, Android, iOS) vectors only |
| `ratchet_vectors_family_c.json` | Family C (Go, Java, Swift, C#, C) vectors only |
| `v2_test_vectors.json` | Base v4 AEAD format vectors (all bindings) |

Vectors use a fixed nonce for reproducibility. The `gen_vectors.py` script
generates and self-verifies all vectors using pure-Python implementations of
each family's algorithm.

---

## Interoperability Scope

### What IS tested / supported

- **Within-family** interop only:
  - Family B: Python encrypts, JS decrypts (and vice versa)
  - Family C: Go encrypts, and should be decryptable by Java, Swift, C#, C
- **Base v4 AEAD** (quickEncrypt / Shield password-based): all bindings share
  a single wire format and are fully cross-language compatible.

### What is NOT tested / NOT supported

- **Cross-family ratchet**: A ratchet session started in Python (Family B) cannot
  be decrypted by Go (Family C), and neither can be decrypted by Rust (Family A).
  These combinations are expected to fail and are intentionally not tested.

### Future work

Full realignment of all bindings to Family A (the Rust/WASM HMAC-based format)
is tracked in **backend-064**. Once complete, a single shared ratchet vector set
will cover all bindings.

---

## Running Tests

```bash
# Cross-language AEAD interop (Python, JS, Go)
pytest tests/test_cross_language.py -v

# Cross-language AEAD interop v2
pytest tests/test_cross_language_v2.py -v

# All tests
pytest tests/ -v
```
