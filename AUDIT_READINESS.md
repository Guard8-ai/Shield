# Shield — Audit-Readiness Package

*The brief to hand an independent cryptographic auditor (e.g. Trail of Bits, NCC Group, Cure53). Its purpose is to let a firm scope, price, and execute an engagement with minimal back-and-forth — and to make clear, up front, exactly what we already know and what we are asking them to verify.*

**Status:** pre-audit. An independent third-party audit is the single gating item before Shield can be represented as enterprise-/government-deployable. This document does not claim that status; it prepares for the engagement that confers it.

**Version under review:** `2.2.0` across all bindings.
**Source of truth:** `shield-core` (Rust). All other bindings are required to match it byte-for-byte.
**License:** MIT.

---

## 1. Engagement objective

Independently verify that Shield's cryptographic construction is sound, that its 12 language implementations correctly and equivalently implement that construction, and that the security claims in `THREAT_MODEL.md` hold (and that nothing is overclaimed). Produce a public report we can show enterprise and government reviewers.

We are explicitly **not** asking the auditor to bless a novel primitive — there is none. The data path is standard AEAD from each platform's vetted library. The audit's value is in the *integration*: key schedule, wire format, cross-language equivalence, misuse-resistance, and the higher-level protocols (ratchet, group, PQ-hybrid KEX, confidential-computing key custody).

---

## 2. System overview

Shield is a misuse-resistant authenticated-encryption library exposed identically across **12 bindings**: Rust (`shield-core`, source of truth), Python (`shield-crypto`), JavaScript/Node (`@dikestra/shield`), Go, C, C#, Java, Kotlin, Swift, iOS, WebAssembly, Android.

Layers, lowest to highest:

1. **Base AEAD encryption** (`encrypt`/`decrypt`, `with_key`) — standard AEAD, wire format v4 (§3).
2. **Session helper** (`SecureSession`) — auto-rotating per-version key; as of 2026-06-28 seals through the same base AEAD (no bespoke cipher).
3. **Forward-secret protocols** — `RatchetSession` (per-message key ratchet), `GroupEncryption`, streaming. These use an HMAC-SHA256 keyed-stream construction by design (documented; see §6).
4. **Key exchange** — hybrid **X25519 + ML-KEM-768** post-quantum KEX (§4).
5. **Confidential-computing key custody** — enclave attestation (Intel SGX, AMD SEV, AWS Nitro) in `shield-core/src/confidential/`.
6. **Auxiliary** — identity/SSO tokens (HMAC-authenticated), TOTP, Lamport hash-based signatures, recovery.

---

## 3. Base cipher — wire format v4 (primary audit target)

Standard AEAD; no hand-rolled symmetric cipher. Two framings:

```
Password mode:  0x03 || suite(1) || salt(16) || nonce(12) || AEAD_seal
Key mode:       0x13 || suite(1) ||            nonce(12) || AEAD_seal
```

- **suite:** `0x01` = AES-256-GCM (default), `0x02` = ChaCha20-Poly1305.
- **AAD** (authenticated, not encrypted) = every byte before the nonce: `version || suite || [salt]`.
- **Inner AEAD plaintext** (encrypted + authenticated) = `timestamp_ms(8 LE) || pad_len(1) || random_padding(32–128) || message`. No message counter.
- **Key schedule:**
  - password → `PBKDF2-HMAC-SHA256(password, salt || service, 600_000, 32)`
  - key mode → caller-supplied 32 bytes
  - then `aead_key = HKDF-SHA256-Expand(master, info="shield/aead/v4", L=32)`
- nonce = 12 random bytes per message; tag = 16 bytes; padding length rejection-sampled in [32,128]; default freshness window 60 s (disableable).

AEAD providers per binding (independent stacks — a deliberate diversity argument and an audit cross-check): Rust `ring`; Python `cryptography` (OpenSSL); Go stdlib; Node `crypto`; .NET BCL; JCE (Java/Kotlin/Android); CryptoKit (Swift/iOS); Windows CNG/BCrypt (C, AES-GCM only).

**Conformance oracle:** `tests/v4_test_vectors.json` — 8 deterministic vectors (6 AES, 2 ChaCha), each with `master_key_hex`, `aead_key_hex`, `expected_output_hex`. Every binding reproduces all of them byte-for-byte. This is the mechanism that makes "12 implementations agree" a checkable fact rather than an assertion.

---

## 4. Post-quantum hybrid KEX

Hybrid **X25519 + ML-KEM-768** (FIPS 203 / RFC 7748), HPKE/PGP-style (bound to a recipient's static key):

- KDF: `HKDF-SHA256(salt="shield/pq-hybrid/v1", ikm = x25519_ss || mlkem_ss, info = bob_bundle || eph_xpub || kem_ct)`
- public bundle 1216 B (`mlkem_pub(1184) || x_pub(32)`); handshake 1120 B (`eph_xpub(32) || kem_ct(1088)`); private 96 B (`mlkem_seed(64, d‖z) || x_scalar(32)`).
- Output: 32-byte key feeding `with_key()`.
- No hand-rolled lattice math: Rust `ml-kem` + `x25519-dalek`; JS `@noble/post-quantum`; C#/Java/Kotlin/Android Bouncy Castle; Python `cryptography`; Go stdlib.
- Conformance oracle: `tests/pq_kex_vectors.json`.

Coverage today: **9 of 12 execution-verified** (Python, Go, Rust, JS, C#, Java, Kotlin, Android, **C** — ML-KEM-768 via liboqs + X25519/HKDF via OpenSSL, vectors byte-identical); Swift/iOS written + parse-clean (Mac to execute).

---

## 5. What we ask the auditor to cover

1. **Construction review** of the v4 AEAD framing and key schedule (§3): AAD coverage, nonce strategy, HKDF labeling/domain separation, PBKDF2 parameters, padding/length-obfuscation, freshness semantics.
2. **Implementation review** of `shield-core` (Rust) as the normative implementation, then a differential review of the other 11 against it (the conformance vectors are the anchor).
3. **Higher protocols:** ratchet (forward secrecy / post-compromise), group, and the PQ-hybrid KEX (transcript binding / UKS resistance, low-order point handling, downgrade).
4. **Misuse-resistance:** API surface for foot-guns; nonce-reuse exposure at scale; key-commitment considerations.
5. **Confidential-computing custody:** attestation flows in `src/confidential/`.
6. **Auxiliary modules:** identity tokens, Lamport signatures, TOTP, recovery.
7. **Dependency & supply-chain:** the vetted-crypto deps above; `cargo audit` / `npm audit` posture.
8. **Claims audit:** confirm `THREAT_MODEL.md`, `README.md`, `SECURITY.md` do not overstate.

---

## 6. Known limitations we are disclosing up front (please verify, don't rediscover)

From `THREAT_MODEL.md`:

- **Nonce-reuse at extreme scale.** 12-byte random nonces; a single key should encrypt well under ~2³² messages. A GCM nonce collision is catastrophic. Mitigation: rotate keys / use `RatchetSession`.
- **Freshness ≠ replay protection.** The base API checks a timestamp window only; it does not track seen nonces. Use `RatchetSession` (monotonic counters) for true anti-replay.
- **No forward secrecy in the base API** (static keys). Use `RatchetSession`. The PQ-hybrid KEX is recipient-static and likewise provides no FS by itself.
- **AEAD is not key-committing.** Relevant if a use case depends on key-commitment.
- **Ratchet/stream/group keystream** uses HMAC-SHA256 as a keyed PRF stream (encrypt-then-MAC), not an AEAD. Standard construction, but non-AEAD — flagged for explicit review.
- **C base cipher is AES-256-GCM only** (Windows CNG lacks ChaCha20); C post-quantum is now implemented (liboqs + OpenSSL, POSIX).
- **`SecureSession`** disables the freshness window (at-rest payloads) — intended; tag still provides integrity.
- **`cargo audit` ignores RUSTSEC-2023-0071 (`rsa` Marvin timing attack) with justification.** `rsa` is a transitive dependency of `dcap-qvl` (SGX DCAP quote verification) and is used **only to verify Intel PCK certificate-chain signatures (public-key verification)**. The advisory is a side-channel in RSA *private-key* operations, which Shield never performs, so it does not apply. No fixed `rsa` release exists yet; the ignore is documented in `.github/workflows/ci.yml` and will be revisited on upstream fix.
- **CodeQL `js/insufficient-password-hash` on `javascript/src/exchange.js` (`PAKEExchange.combine`) is dismissed as a false positive.** The query treats the HMAC key in `combine` as a lightly-hashed password. It is not a password: each input is a `PAKEExchange.derive()` output = `HMAC-SHA256(PBKDF2-HMAC-SHA256(secret, salt, 600k), role)`, i.e. an already-stretched 256-bit key. `combine` performs key-combination (`HMAC-SHA256(sorted[0], sorted[1])`), not password hashing — brute force is 2²⁵⁶ and the password stretching already happened once, inside `derive()`, via PBKDF2-600k. The construction is byte-for-byte locked by `tests/channel_session_vectors.json` and the Rust source of truth, so it cannot be changed to placate the heuristic without re-breaking cross-language interop. Same false-positive class as the earlier name-heuristic hit cleared in `dda84ea`. The dismissal reason is recorded on the GitHub alert; an inline code comment at the sink explains it for readers.
- **`shield-proxy` HA heartbeats are unauthenticated unless `redundancy.psk` is set.** Heartbeats are now HMAC-SHA256-authenticated (RT2-6) with replay/freshness checks, but only when a pre-shared key is configured; without it the proxy logs a warning and falls back to the legacy unauthenticated path. Set a high-entropy `redundancy.psk` on both nodes in production. (DNS reply source/transaction-ID validation (RT2-5) and loopback-by-default metrics bind (RT2-9) are now enforced unconditionally.)
- **Python `integrations/confidential/*.py` attestation providers do NOT verify signatures, now fail-closed.** The Python SGX/SEV/MAA/Nitro `verify()` parse evidence and compare measurement fields but never check the quote/token signature or certificate chain (the Python twin of the prior Rust CORE-CRIT-1, a separate code path). They now return `verified=False` by default — so forged evidence cannot release keys via `TEEKeyManager` — and only accept unverified evidence when explicitly constructed with `allow_insecure_demo=True` (which warns). The production signature/cert-chain-verifying implementation is the hardened **Rust `shield-core` confidential** module; a real Python verifier (or FFI to the Rust one) is a tracked follow-up.
- **Python `integrations/fido2_api.py` and `integrations/pgvector_api.py` are insecure demo scaffolding, now fail-closed.** They perform no real WebAuthn / token / vector verification (unsigned forgeable tokens, unauthenticated credential routes, any-bearer-token acceptance, non-AEAD demo "encryption" with a plaintext shadow copy). They now **refuse to instantiate unless `allow_insecure_demo=True`** and warn at construction, so a developer cannot deploy them as a silent auth bypass. Real implementations (Rust `fido2`/`pgvector` modules, real token verifier) are the production path and a tracked follow-up. Not exported from `shield.integrations` (import-by-path only).
- **`PAKEExchange` / `ShieldChannel` is a pre-shared-key handshake, NOT a true PAKE.** The handshake contribution `HMAC(PBKDF2(secret, salt), role)` is sent on the wire with the salt, so a recorded handshake permits an **offline dictionary attack** against a low-entropy secret (PBKDF2 600k only slows each guess). It is safe **only with a high-entropy shared secret**. A real DH-based PAKE (SPAKE2/CPace) is a tracked follow-up; for password/forward-secret use, the X25519+ML-KEM-768 hybrid KEX is the recommended path. The `PAKEExchange` type name is retained for API compatibility but the docs (exchange.rs, channel.rs, PROTOCOL.md §3.2, README, CHEATSHEET) disclose this explicitly.

---

## 7. Out of scope for this engagement

Swift/iOS *execution* (pending Apple hardware — code is parse-clean and byte-identical by construction); packaging/distribution; business/GTM claims.

---

## 8. Reproduction — how to run everything

| Binding | Command | Expected |
|---|---|---|
| Rust | `cd shield-core && cargo test --lib && cargo clippy --lib --all-targets` | 99 tests pass, clippy clean |
| Rust PQ | `cargo test --features pq` | PQ vectors pass |
| Python | `cd python && python -X utf8 -m pytest -q` | 209 passed |
| JavaScript | `cd javascript && node --test test/` | 119 pass |
| Go | `cd go/shield && go test ./... && go vet ./...` | ok, vet clean |
| C# | `cd csharp && dotnet test` | green |
| Java/Kotlin/Android | `gradle test` / `gradle :shield:testDebugUnitTest` | green |
| C | `clang -O2 -I./c/include c/src/shield.c c/tests/test_shield.c -lbcrypt -ladvapi32` | 34/34 |
| C post-quantum | `c/scripts/build_and_test_pq.sh` (Linux/macOS; builds liboqs + OpenSSL) | 3/3 vectors byte-identical |
| Cross-language | `python -X utf8 tests/test_cross_language_v2.py` | 8/8 byte-for-byte |
| WASM | `wasm-pack build` | builds clean |

(Swift/iOS: `swift test` / `xcodebuild test` on macOS.)

---

## 9. Artifact inventory

- **Normative spec:** `PROTOCOL.md`, `THREAT_MODEL.md`.
- **Source of truth:** `shield-core/src/` (esp. `shield.rs`, `identity.rs`, `pqhybrid.rs`, `confidential/`).
- **Conformance vectors:** `tests/v4_test_vectors.json`, `tests/pq_kex_vectors.json`.
- **Change history (honest record):** `CHANGES-FROM-ORIGINAL.md` (Parts 10 = v4 AEAD, 11 = PQ rollout, 12 = SecureSession→AEAD, 13 = C post-quantum).
- **Benchmarks:** `BENCHMARKS.md`.

*(Note: earlier LLM self-review documents that predated the rebuild and carried the discredited "EXPTIME" framing have been removed to avoid confusion — this is the intended scoping document for an independent review.)*

---

## 10. Engagement logistics (to fill in with the firm)

- **Candidate firms:** Trail of Bits, NCC Group, Cure53 (all have published AEAD/PQ/library audits).
- **Suggested model:** fixed-scope review of §5 items 1–4 first (the core), with 5–8 as a second phase.
- **Deliverable:** public report + remediation cycle; we will fix and re-verify against the conformance vectors.
- **Open questions for the auditor:**
  1. Is the length-obfuscation padding worth its complexity, or a liability?
  2. Should we add a key-committing AEAD mode (e.g. via a commitment tag) as a suite?
  3. Recommended nonce strategy (random vs. counter/XChaCha) for very high-volume keys?
  4. Argon2id as an additional KDF suite — priority?

---

*We would rather be vetted hard than oversell. Every result in §8 is reproducible from this repository today.*
