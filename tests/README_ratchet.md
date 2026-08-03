# Ratchet Family Compatibility

Shield's ratchet implementation exists in three incompatible families.
Cross-family decryption WILL fail — this is by design (different KDF choices).

| Family | Implementations | Chain KDF | Counter Placement |
|--------|-----------------|-----------|-------------------|
| A | Rust, WASM | HMAC-SHA256 (`HMAC(chain, "chain")` / `HMAC(chain, "message")`) | Encrypted (inside ciphertext) |
| B | Python, JavaScript, Kotlin, Android, iOS | SHA-256 (`SHA256(chain \|\| "chain")` / `SHA256(chain \|\| "message")`) | Encrypted (inside ciphertext) |
| C | Go, Java, Swift, C#, C | SHA-256 (`SHA256(chain \|\| "message")` / `SHA256(chain \|\| "ratchet")`) | Cleartext prefix (8-byte LE uint64) |

## Key Differences

### Family A (Rust, WASM)
- Initial chain: `HMAC-SHA256(root_key, "send"/"recv")`
- Chain step: `new_chain = HMAC(chain_key, "chain")`, `msg_key = HMAC(chain_key, "message")`
- Subkeys: `enc_key = HMAC(msg_key, "shield-ratchet-encrypt")`, `mac_key = HMAC(msg_key, "shield-ratchet-authenticate")`
- Keystream: `HMAC(enc_key, nonce || block_u32_le)` — uses HMAC not SHA256
- MAC input: `HMAC(mac_key, nonce || ciphertext)[:16]`
- Frame: `nonce(16) || ciphertext(8 + plaintext_len) || mac(16)`

### Family B (Python, JavaScript, Kotlin, Android, iOS)
- Initial chain: `SHA256(root_key || "send"/"recv")`
- Chain step: `new_chain = SHA256(chain_key || "chain")`, `msg_key = SHA256(chain_key || "message")`
- Keystream: `SHA256(msg_key || nonce || block_u32_le)`
- MAC input: `HMAC-SHA256(msg_key, nonce || ciphertext)[:16]`
- Frame: `nonce(16) || ciphertext(8 + plaintext_len) || mac(16)`

### Family C (Go, Java, Swift, C#, C)
- Initial chain: `SHA256(root_key || "init_send"/"init_recv")` — different init labels
- Chain step: `msg_key = SHA256(chain_key || "message")`, `new_chain = SHA256(chain_key || "ratchet")` — different label order
- Keystream: `SHA256(msg_key || nonce || block_u32_le)`
- MAC input: `HMAC-SHA256(msg_key, counter_le64 || nonce || ciphertext)[:16]` — counter in MAC
- Frame: `counter_le64(8) || nonce(16) || ciphertext(plaintext_len) || mac(16)` — counter cleartext

## Test Vectors

- `ratchet_vectors_family_a.json` — Family A (Rust/WASM) vectors
- `ratchet_vectors_family_b.json` — Family B (Python/JS/Kotlin/Android/iOS) vectors
- `ratchet_vectors_family_c.json` — Family C (Go/Java/Swift/C#/C) vectors
- `ratchet_vectors.json` — All three families in a single combined file

Generated deterministically by `tests/gen_vectors.py` using:
- `root_key = 0x4242...42` (32 bytes)
- `fixed_nonce = 0x000102...0f` (16 bytes, production uses random nonces)
- `plaintext = "Hello, Shield!"` (14 bytes)

## What These Vectors Test

**Within-family compatibility**: all implementations in the same family MUST
produce identical `chain_key` and `message_key` sequences given the same
initial chain key. Use these vectors to confirm a new binding produces
byte-identical output before declaring it part of a family.

**Cross-family is NOT tested here** — cross-family compatibility is undefined
and intentionally not supported. See `PROTOCOL.md` for architectural context.

The ratchet family split is a known issue tracked in `backend-064` (full
realignment of all bindings to Family A, the Rust HMAC reference).

## Running the Tests

```bash
# Validate Family B vectors against the Python implementation
python -m pytest tests/test_ratchet_vectors.py -v

# Regenerate all vector files (also verifies them with round-trip asserts)
python tests/gen_vectors.py
```
