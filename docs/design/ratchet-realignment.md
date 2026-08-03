# Ratchet Realignment Design

**Status:** Proposed (Python reference implementation in `python/shield/ratchet_v2.py`)
**Date:** 2026-08-03
**Author:** Claude (Eliran Sabag)
**Tracks:** ARC r1b security audit — ratchet interoperability finding

---

## Problem

Shield v4 has three mutually incompatible ratchet families. Handshakes succeed
cross-language (session-key exchange was unified in 2026-06-30), but the first
ratchet data frame fails between families. No two families can decrypt each
other's ratchet messages.

### Family A — Rust, WASM (reference implementation)

**Chain initialization:**
```
send_chain = HMAC-SHA256(root_key, "send")
recv_chain = HMAC-SHA256(root_key, "recv")
```

**Per-step ratchet:**
```
new_chain = HMAC-SHA256(chain_key, "chain")
msg_key   = HMAC-SHA256(chain_key, "message")
```

**Message key expansion** (unique to Family A):
```
enc_key = HMAC-SHA256(msg_key, "shield-ratchet-encrypt")
mac_key = HMAC-SHA256(msg_key, "shield-ratchet-authenticate")
```

**Keystream:** `HMAC-SHA256(enc_key, nonce || block_counter_u32_le)` per 32-byte block

**Wire format:** `nonce(16) || ciphertext(with counter inside) || mac(16)`
Counter is XOR-encrypted inside the ciphertext, not sent in cleartext.

**MAC covers:** `nonce || ciphertext`

---

### Family B — Python, JavaScript, Kotlin, Android, iOS

**Chain initialization:**
```
send_chain = SHA256(root_key || "send")
recv_chain = SHA256(root_key || "recv")
```
Note: same labels as Family A but uses raw SHA-256 concatenation instead of HMAC.

**Per-step ratchet:**
```
new_chain = SHA256(chain_key || "chain")
msg_key   = SHA256(chain_key || "message")
```
Note: same labels as Family A but SHA-256 concat, not HMAC.

**No subkey expansion.** The single `msg_key` is used directly for both
keystream generation and MAC.

**Keystream:** `SHA256(key || nonce || block_counter_u32_le)` per 32-byte block

**Wire format:** `nonce(16) || ciphertext(with counter inside) || mac(16)`
Counter is XOR-encrypted inside ciphertext (same position as Family A).

**MAC covers:** `nonce || ciphertext` using `HMAC-SHA256(msg_key, nonce || ciphertext)`

Key divergence from A: no subkey expansion; raw SHA-256 concat for chain KDF.

---

### Family C — Go, Java, Swift, C#, C

**Chain initialization** (different labels from both A and B):
```
send_chain = SHA256(root_key || "init_send")
recv_chain = SHA256(root_key || "init_recv")
```

**Per-step ratchet:**
```
msg_key   = SHA256(chain_key || "message")
new_chain = SHA256(chain_key || "ratchet")   ← different label than A/B
```
Note: Family A/B use `"chain"` for next chain; Family C uses `"ratchet"`.

**No subkey expansion.** Single `msg_key` used for both keystream and MAC.

**Keystream:** `SHA256(key || nonce || block_counter_u32_le)` per 32-byte block
(same formula as B but using the msg_key directly)

**Wire format:** `counter(8, cleartext) || nonce(16) || ciphertext || mac(16)`
**Counter is in CLEARTEXT as an 8-byte prefix.** This is the most visible wire
incompatibility with A and B.

**MAC covers:** `counter_bytes || nonce || ciphertext` (different MAC scope than A/B)

---

## Incompatibility Summary

| Property                  | Family A (Rust) | Family B (Py/JS) | Family C (Go/Java) |
|---------------------------|-----------------|------------------|--------------------|
| Chain KDF primitive       | HMAC-SHA256     | SHA256 concat    | SHA256 concat      |
| Init labels               | "send"/"recv"   | "send"/"recv"    | "init_send"/"init_recv" |
| Next-chain label          | "chain"         | "chain"          | "ratchet"          |
| Msg key subkey expansion  | Yes (2 subkeys) | No               | No                 |
| Counter in wire format    | Inside CT (encrypted) | Inside CT (encrypted) | Cleartext prefix |
| MAC scope                 | nonce‖CT        | nonce‖CT         | counter‖nonce‖CT   |

No two families produce compatible ciphertext for any of these properties.

---

## Proposed v5 Unified Ratchet

Adopt HKDF-SHA256 for both chain and message key derivation, inspired by the
Signal Double Ratchet specification and aligned with Family A's HMAC direction
(but using HKDF, which is the standard primitive for key derivation).

**Chain initialization (from root key + DH output):**
```
chain_key = HKDF(salt=root_key, ikm=dh_output, info="shield-ratchet-root", len=32)
```

**Per-step symmetric ratchet:**
```
chain_key_next = HKDFExpand(prk=chain_key, info="shield-ratchet-chain", len=32)
message_key    = HKDFExpand(prk=chain_key, info="shield-ratchet-msg",   len=32)
```

**Message encryption:** The message_key feeds into the existing Shield v4 AEAD
(encrypt/decrypt operations). No custom keystream construction — the v5 ratchet
only governs key derivation, not the encryption primitive.

**Wire format:** No change to the v4 ciphertext envelope. The ratchet step
produces a 32-byte `message_key`; that key is handed to Shield's existing
encrypt/decrypt operations. Ratchet sessions are identified by a version byte
in the session state (not the wire frame).

**This is the Family A direction** (HMAC-based chain KDF) but uses HKDF, which
provides domain separation via `info` strings without requiring a two-pass
HMAC-with-label construction.

---

## Why HKDF Over Bare HMAC Labels

Family A's `HMAC(chain_key, "message")` is equivalent to HKDF-Expand with a
fixed PRK. HKDF makes this explicit: `HKDFExpand(prk=chain_key, info=label)`.
Benefits:

1. Standard primitive (RFC 5869) — implementable from standard library in all
   target languages without custom code.
2. Domain separation via `info` strings is the documented, intended usage.
3. `HKDF-Extract + Expand` covers the root ratchet (DH → chain_key) with a
   single standard primitive rather than a custom HMAC construction.
4. All 10+ target languages have RFC 5869-compliant HKDF in their standard or
   widely-used crypto library.

---

## Migration Path

1. **Version byte** added to ratchet session state (not wire):
   - `0x01` = v4 (current Family A/B/C — per-binding behavior, not interoperable)
   - `0x02` = v5 (unified HKDF ratchet)
2. Each binding implements `ratchet_v2` alongside the existing `ratchet`.
3. **Session negotiation:** both parties announce supported versions during key
   exchange. They select the highest mutually supported version.
4. **v4 sessions remain functional** for existing deployments. No forced
   migration. New sessions default to v5 when both sides support it.
5. **Cross-language test vectors** are generated from the Python reference
   implementation and consumed by each binding's test suite.

---

## Wire Format Change

No change to the Shield AEAD ciphertext format. The ratchet provides a
32-byte `message_key`; that key enters the existing encrypt/decrypt path.

The only wire-visible change is the session version byte in the session
establishment message (key exchange / Channel handshake). Existing v4 sessions
decode normally because the receiver checks the version byte first.

---

## Implementation Checklist (v5 rollout)

- [ ] Python: `ratchet_v2.py` (reference — **done**, see `python/shield/ratchet_v2.py`)
- [ ] Generate test vectors from Python reference
- [ ] JavaScript: `ratchet_v2.js`
- [ ] Kotlin/Android: `RatchetSessionV2.kt`
- [ ] iOS/Swift: `RatchetSessionV2.swift`
- [ ] Go: `ratchet_v2.go`
- [ ] Java: `RatchetSessionV2.java`
- [ ] C#: `RatchetSessionV2.cs`
- [ ] C: `shield_ratchet_v2.c`
- [ ] Rust: align to v5 (already closest; replace `HMAC(chain, "chain")` with
      `HKDFExpand(chain, "shield-ratchet-chain")`)
- [ ] WASM: rebuild from Rust
- [ ] All bindings: cross-language test using shared vectors

---

## Python Reference

See `python/shield/ratchet_v2.py` for the canonical implementation.

The reference is intentionally standalone (no dependency on `shield.core`) so
it can be studied and ported without understanding the full Shield codebase.
