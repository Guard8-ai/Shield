# ADR-001: Argon2id Migration for Password-Mode Key Derivation

**Status:** Accepted (deferred pending multi-language implementation)
**Date:** 2026-08-03
**Authors:** Guard8.ai Security Team

## Context

Shield v4 uses PBKDF2-HMAC-SHA256 at 100,000 iterations for password-mode
key derivation. This is below the OWASP 2023 minimum recommendation of 600,000
and is vulnerable to GPU/ASIC parallelism at ~10,000–100,000 hashes/s per GPU.

Argon2id (winner of the 2015 Password Hashing Competition, OWASP recommended
since 2023) is memory-hard: its memory cost parameter forces sequential
computation that cannot be parallelized cheaply on commodity GPUs/ASICs.
Typical throughput for Argon2id with m=64MB, t=3, p=4 is ~1–10 hashes/s
per GPU, a ~1,000–10,000x improvement in attacker cost vs PBKDF2-100k.

## Decision

**Adopt Argon2id as the password-mode KDF for Shield v5.** Implementation
is deferred until all 12 language bindings have been audited for platform
support.

**Interim measure:** Raise PBKDF2 iterations from 100,000 to 800,000 in
the Rust core. This provides an 8x increase in attacker cost with acceptable
performance impact on modern hardware (~50–80ms derive time on a single core).
Python and Go bindings currently also use 100,000 and should be updated in
a follow-on task coordinating all language bindings.

## Wire Format Change

Argon2id requires a new version byte. Proposed: `0x14` (20) for Argon2id
ciphertexts; `0x13` (19) remains valid for decryption. Migration path:
- New encryptions use `0x14` + Argon2id params (m, t, p) in the authenticated header
- Old `0x13` ciphertexts remain decryptable indefinitely (legacy KDF path)
- No server-side migration needed (per-ciphertext KDF detection)

## Platform Support Matrix

| Platform       | Argon2id library         | Status          |
|----------------|--------------------------|-----------------|
| Rust           | `argon2` crate (0.5+)   | Available       |
| Python         | `argon2-cffi` (21+)     | Available       |
| Go             | `golang.org/x/crypto`   | Available       |
| JavaScript     | `argon2` (npm)          | Available (Node)|
| Browser/WASM   | WASM port available      | Needs evaluation|
| Java/Kotlin    | Bouncy Castle / libsodium| Available       |
| Android        | Bouncy Castle            | Available       |
| iOS/Swift      | CryptoKit lacks Argon2id; requires libsodium binding | Needs investigation |
| C              | libsodium `crypto_pwhash` | Available      |
| C#/.NET        | `Konscious.Security.Cryptography.Argon2` | Available |

## Performance Estimate (Argon2id m=64MB, t=3, p=4)

Benchmark targets (single-core, i7-13th gen equivalent):
- Derive time: ~150–300ms
- Memory: 64MB per derive (not parallelizable on GPU)
- Attacker cost per hash: ~$0.001–0.01 (vs ~$0.0000001 for PBKDF2-100k)

For server-side password-mode decrypt throughput at 10 req/s:
- PBKDF2-800k: ~80ms total derive overhead per request (acceptable)
- Argon2id (m=64MB, t=3, p=4): ~250ms per request — would require async/concurrent derive pool

## Recommendation

1. **Adopt Argon2id** with params: `m=65536` (64MB), `t=3`, `p=4`
2. **Begin Rust implementation** (argon2 crate, version byte 0x14, header change)
3. **Defer iOS/Swift** pending libsodium binding evaluation
4. **Raise interim PBKDF2** to 800,000 iterations in Rust core (this release);
   coordinate remaining bindings (Python, Go, JS, etc.) in a follow-on task

## Consequences

- Ciphertexts encrypted with Argon2id (0x14) cannot be decrypted by v4 clients until they upgrade
- iOS/Swift may require libsodium FFI (external dependency, not in CryptoKit)
- Server deployments with high password-mode decrypt throughput need async derive pool
- The interim PBKDF2 bump from 100k to 800k breaks cross-binding interoperability
  until all bindings are updated to the same iteration count
