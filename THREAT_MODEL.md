# Shield — Threat Model

*Wire format v4 (standard AEAD). This document is deliberately honest: it states what Shield protects, what it does not, and the assumptions each guarantee rests on. It is written for a reviewing cryptographer or a security team performing due diligence.*

**Last updated:** 2026-06-22

---

## 1. What Shield is

Shield is an authenticated symmetric-encryption library with a misuse-resistant, one-line API, available byte-for-byte across 12 language bindings. As of v4 the data-encryption step is a **standard AEAD** — AES-256-GCM (default) or ChaCha20-Poly1305 — drawn from each platform's vetted cryptographic library (no hand-rolled cipher). Higher layers (`RatchetSession`, `GroupEncryption`, key exchange, post-quantum hybrid KEX) build on top.

### Cryptographic construction (v4)

```
Password mode:  0x03 || suite(1) || salt(16) || nonce(12) || AEAD_seal
Key mode:       0x13 || suite(1) || nonce(12) || AEAD_seal
AAD            = version || suite || [salt]      (authenticated, not encrypted)
inner plaintext = timestamp_ms(8 LE) || pad_len(1) || padding(32–128) || message
```

- **Key derivation (password mode):** `master = PBKDF2-HMAC-SHA256(password, salt ‖ service, 600 000, 32)`, then `aead_key = HKDF-SHA256-Expand(master, "shield/aead/v4", 32)`.
- **Key derivation (key mode):** `master = the 32-byte pre-shared key`, then the same HKDF-Expand.
- **Confidentiality + integrity:** provided by the AEAD (GCM / Poly1305) over the inner plaintext, with the version+suite(+salt) bound as additional authenticated data.
- **Length hiding:** 32–128 bytes of random padding inside the AEAD plaintext, so ciphertext length does not reveal exact message length.
- **Freshness:** an 8-byte timestamp inside the AEAD plaintext, checked against a configurable window (default 60 s).

---

## 2. Assets

| Asset | Protection goal |
|---|---|
| Message plaintext | Confidentiality + integrity |
| Password / pre-shared key | Never transmitted; password stretched with PBKDF2 |
| Message length (approx.) | Partially hidden via random padding |
| Version / suite / salt header | Integrity (authenticated as AEAD AAD) |

---

## 3. Adversary model

We consider an active network adversary who can observe, modify, drop, reorder, and replay ciphertexts, and who may adaptively submit chosen ciphertexts to a decryptor (chosen-ciphertext attack). We assume the endpoints and their RNG are not compromised and that the AEAD key is secret.

---

## 4. Guarantees (and the assumptions they rest on)

| # | Guarantee | Rests on |
|---|---|---|
| G1 | **Confidentiality** of message contents against the adversary above. | IND-CPA/CCA security of AES-256-GCM / ChaCha20-Poly1305; secret 256-bit key; **unique (key, nonce) pairs** (see L1). |
| G2 | **Integrity / authenticity** — any modification to ciphertext, nonce, salt, suite or version byte is detected. | 128-bit AEAD tag (forgery prob. ≈ 2⁻¹²⁸); the version/suite/salt are bound as AAD. |
| G3 | **No padding oracle / no format-confusion oracle.** | AEAD verifies the tag before any plaintext is released; the inner layout is parsed only after authentication. |
| G4 | **Per-user key isolation.** Two users with the same password+service derive different keys. | Per-instance random 16-byte salt carried in the header (fixes the original deterministic-salt bug). |
| G5 | **Password-cracking cost.** Offline guessing is throttled. | PBKDF2-HMAC-SHA256 at the OWASP-2023 floor of 600 000 iterations. Argon2id would be stronger (see §6). |
| G6 | **Cross-language equivalence.** Every binding produces byte-identical ciphertext and interoperates. | A shared conformance-vector suite (`tests/v4_test_vectors.json`) reproduced byte-for-byte by 9 executed bindings. |

---

## 5. Limits — what Shield does NOT provide (by design)

| # | Non-guarantee | Why / mitigation |
|---|---|---|
| L1 | **Nonce-reuse safety at extreme scale.** Nonces are 12 random bytes per message. By the birthday bound, a single key should encrypt well under ~2³² messages before nonce-collision risk becomes non-negligible; a GCM nonce collision is catastrophic (loses confidentiality + authenticity for the colliding pair). | **Rotate keys** (or use `RatchetSession`, which derives a fresh key per message) for very high-volume streams. Document key-rotation guidance for callers at scale. |
| L2 | **Full replay protection.** The base API only checks a timestamp *freshness window*; it does **not** track seen nonces, so an identical ciphertext can be replayed within the window. | Use `RatchetSession` (monotonic per-message counters) for true anti-replay. This is stated in the code and docs. |
| L3 | **Forward secrecy / post-compromise security** for the base API. The base cipher uses long-term static keys; compromise of the key exposes past and future messages encrypted under it. | Use `RatchetSession` for forward secrecy. The PQ hybrid KEX is bound to a recipient's static key (HPKE/PGP-style) and likewise provides no FS by itself. |
| L4 | **Anonymity / metadata protection.** Length is only coarsely hidden (±padding); timing, frequency, and routing metadata are out of scope. | Application-level mitigations (cover traffic, fixed-size records) if needed. |
| L5 | **Protection against a compromised endpoint or RNG.** If the platform CSPRNG is broken or the host is malware-infected, all bets are off. | Standard platform assumption. Shield uses each platform's CSPRNG (`getrandom`/`SecRandomCopyBytes`/`BCryptGenRandom`/`crypto.randomBytes`/etc.). |
| L6 | **Quantum resistance of the *asymmetric* layer is only via the hybrid KEX.** The symmetric AEAD already gives ~128-bit post-quantum security (Grover). Asymmetric key agreement is post-quantum only where the X25519+ML-KEM-768 hybrid KEX is used. | Finish rolling the PQ hybrid KEX to all bindings (in progress); never claim "post-quantum" where only the symmetric argument applies. |
| L7 | **C binding cipher coverage.** The C binding's AEAD backend is Windows CNG (AES-256-GCM only); it does not offer ChaCha20-Poly1305 (CNG lacks it) and a POSIX/OpenSSL backend is not yet wired. | Documented; AES-256-GCM is the default suite everywhere. |

---

## 6. Residual risks & recommended hardening

- **Independent third-party audit (highest priority, not yet done).** No regulated buyer should deploy on the vendor's say-so. This threat model is written *before* an external audit, to scope one.
- **Argon2id for password mode.** PBKDF2-600k meets current floors but Argon2id is memory-hard and materially better against GPU/ASIC cracking. A suite-style upgrade is the natural next step.
- **Nonce strategy at scale.** Consider a deterministic/counter nonce scheme (or XAES-256-GCM / AES-GCM-SIV) for callers encrypting enormous volumes under one key, to remove the birthday bound of random nonces (L1).
- **Key commitment.** AES-GCM and ChaCha20-Poly1305 are not key-committing. If multi-recipient/partitioning-oracle scenarios are in scope, add a key-commitment construction.

---

## 7. Out of scope

Side-channel resistance of the underlying platform AEAD implementations (Shield relies on the platform/library being constant-time where it claims to be); supply-chain integrity of the platform crypto libraries; physical attacks; social engineering.

---

*Everything stated here is reproducible from the repository. The honest enumeration of limits (§5) is the point: Shield's guarantees are exactly those of a correctly-used standard AEAD plus a misuse-resistant API and cross-language conformance — no more, and stated as such.*
