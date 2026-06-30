# Shield Wire Protocol Specification

**Version**: 4.0
**Status**: Draft
**Last Updated**: 2026-06-23

## Overview

This document specifies the wire format and protocol for Shield encrypted messages and the ShieldChannel secure transport.

Wire format **v4** encrypts with a **standard AEAD** — AES-256-GCM (default) or
ChaCha20-Poly1305 — replacing the custom SHA-256 keystream + HMAC construction
used by formats ≤ v3. No cryptography is hand-rolled in the base format: every
binding uses its platform's audited AEAD and KDF.

The canonical reference for the wire format is the Rust implementation at
`shield-core/src/shield.rs`; all other language bindings are byte-for-byte
compatible with it, gated by `tests/v4_test_vectors.json`.

> **Scope note.** The base `Shield` encrypt/decrypt API (§1) uses a standard
> AEAD. The internal `StreamCipher` (§4) and `RatchetSession` (§3) layers retain
> a SHA-256 / HMAC-SHA256 keystream construction (§2); those are separate modules
> and are *not* the base format.

## 1. Basic Encryption Format

Every message carries two explicit, authenticated leading bytes — a **version**
and a **cipher suite** — followed by the AEAD nonce and the AEAD output
(ciphertext with appended tag). Two modes are defined:

- **Password mode** (`0x03`) — keys derived from a password via PBKDF2; carries a per-instance random salt in the header.
- **Pre-shared-key mode** (`0x13`) — keys supplied directly (`with_key` / `quick_encrypt`); no password, no salt.

The version and suite bytes (and, in password mode, the salt) are authenticated
as the AEAD's associated data (AAD), so there is no format guessing: decryption
dispatches on the version byte and hard-rejects any unknown value.

### 1.1 Message Structure

**Password mode** (version `0x03`):

```
+---------+-------+----------+----------+--------------------------+
| Version | Suite |   Salt   |  Nonce   |  Ciphertext || AEAD tag  |
| 1 byte  | 1 byte| 16 bytes | 12 bytes |   N + 16 bytes           |
+---------+-------+----------+----------+--------------------------+
```

**Pre-shared-key mode** (version `0x13`):

```
+---------+-------+----------+--------------------------+
| Version | Suite |  Nonce   |  Ciphertext || AEAD tag  |
| 1 byte  | 1 byte| 12 bytes |   N + 16 bytes           |
+---------+-------+----------+--------------------------+
```

| Field | Size | Description |
|-------|------|-------------|
| Version | 1 byte | `0x03` = password mode, `0x13` = pre-shared-key mode. Authenticated (AAD). |
| Suite | 1 byte | `0x01` = AES-256-GCM, `0x02` = ChaCha20-Poly1305. Authenticated (AAD). |
| Salt | 16 bytes | Per-instance random PBKDF2 salt. **Password mode only.** Authenticated (AAD). |
| Nonce | 12 bytes | Random value, unique per message (standard 96-bit AEAD nonce) |
| Ciphertext \|\| tag | N + 16 bytes | `AEAD_Seal(aead_key, nonce, inner, aad)`; the 128-bit tag is appended |

**Header overhead** (excluding the inner plaintext metadata in §1.6):
- Password mode: 1 + 1 + 16 + 12 + 16 (tag) = **46 bytes**
- Pre-shared-key mode: 1 + 1 + 12 + 16 (tag) = **30 bytes**

### 1.2 Key Derivation

Key derivation applies only to **password mode**. Pre-shared-key mode uses the supplied 32-byte key directly as the master key.

```
# Password mode. The 16-byte salt is generated at random per Shield
# instance and stored in the message header (§1.1) so a recipient with the
# same password+service can re-derive the key.
master_key = PBKDF2-HMAC-SHA256(
    password    = password,
    salt        = salt(16 random bytes) || service,
    iterations  = 600000,
    key_length  = 32
)
```

`service` is folded into the PBKDF2 salt input as a domain separator (concatenated *after* the random salt: `salt || service`). Different services therefore yield different keys, and the per-instance random salt removes precomputation / shared-key weaknesses.

The AEAD key is then derived from the master key in **both** modes via
HKDF-Expand (the master key is the PRK; this is Expand only, not Extract):

```
aead_key = HKDF-SHA256-Expand(master_key, info = "shield/aead/v4", L = 32)
```

This gives domain separation and avoids using the master key directly as a
cipher key. There is no separate MAC key — the AEAD provides integrity.

> **Decrypt-side key cache.** Password-mode decryption derives the key from the
> *sender's* header salt; since peers sharing a password pick independent random
> salts, every binding keeps a salt-keyed cache of derived master keys so repeat
> messages from a sender avoid re-running PBKDF2. This is an implementation
> optimization and does not affect the wire format.

### 1.3 Encryption Process

```
1. Build inner = timestamp || pad_len || padding || plaintext  (see §1.6)
2. Generate random nonce (12 bytes)
3. Build aad:
     password mode:        aad = version(0x03) || suite || salt(16)
     pre-shared-key mode:  aad = version(0x13) || suite
4. ct_and_tag = AEAD_Seal(aead_key, nonce, inner, aad)
5. output = aad || nonce || ct_and_tag
```

The AEAD authenticates both the `aad` (version, suite, and in password mode the
salt) and the encrypted `inner`. Any modification to the header or ciphertext
fails tag verification.

### 1.4 Decryption Process

```
1. IF len(input) < 1: reject
2. version = input[0]

3. IF version == 0x03 (password mode):
     suite   = input[1]
     salt    = input[2:18]
     aad     = input[0:18]
     nonce   = input[18:30]
     ct_tag  = input[30:]
     master_key = PBKDF2-HMAC-SHA256(password, salt || service, 600000, 32)   # cached by salt
     aead_key   = HKDF-SHA256-Expand(master_key, "shield/aead/v4", 32)
   ELIF version == 0x13 (pre-shared-key mode):
     suite   = input[1]
     aad     = input[0:2]
     nonce   = input[2:14]
     ct_tag  = input[14:]
     aead_key = HKDF-SHA256-Expand(this instance's master key, "shield/aead/v4", 32)
   ELSE:
     reject   # unknown / legacy version — no fallback decrypt path

4. inner = AEAD_Open(aead_key, nonce, ct_tag, aad)   # reject on tag failure
5. Parse and validate inner (see §1.6), apply freshness check (see §1.7)
6. return plaintext
```

> **No legacy decrypt path.** This is a clean break. `decrypt()` dispatches solely
> on the authenticated version byte and rejects anything that is not `0x03` or
> `0x13`. Ciphertexts written by ≤ v3 Shield (`0x02` / `0x12`) cannot be read by
> the current code and must be re-encrypted.

### 1.5 Mode Selection

| Constructor | Mode | Version byte | Salt in header |
|-------------|------|--------------|----------------|
| `Shield::new(password, service)` | Password | `0x03` | Yes (16 random bytes) |
| `Shield::with_key(key)` | Pre-shared-key | `0x13` | No |
| `quick_encrypt(key, data)` | Pre-shared-key | `0x13` | No |

The cipher suite defaults to `0x01` (AES-256-GCM); `with_suite(0x02)` selects
ChaCha20-Poly1305.

### 1.6 Inner Plaintext Structure

Before sealing, the plaintext is wrapped with metadata. This inner buffer is the
AEAD plaintext and is identical in both modes. Note there is **no counter** field
(v4 dropped it):

```
+------------+----------+---------+-------------+
| Timestamp  | Pad Len  | Padding |  Plaintext  |
|  8 bytes   | 1 byte   | 32-128B |  variable   |
+------------+----------+---------+-------------+
```

| Field | Size | Description |
|-------|------|-------------|
| Timestamp | 8 bytes | Unix timestamp in milliseconds (little-endian uint64) |
| Pad Len | 1 byte | Length of random padding (32-128) |
| Padding | 32-128 bytes | Random padding for length obfuscation |
| Plaintext | Variable | Actual message data |

The padding length is drawn uniformly from [32, 128] using rejection sampling to avoid modulo bias.

#### 1.6.1 Constants

```
INNER_HEADER_SIZE = 9     # timestamp(8) + pad_len(1)
MIN_PADDING       = 32    # Minimum padding bytes
MAX_PADDING       = 128   # Maximum padding bytes
PBKDF2_ITERATIONS = 600000
NONCE_SIZE        = 12
SALT_SIZE         = 16
TAG_SIZE          = 16
HKDF_AEAD_INFO    = "shield/aead/v4"
SUITE_AES_256_GCM         = 0x01
SUITE_CHACHA20_POLY1305   = 0x02
DEFAULT_MAX_AGE_MS = 60000  # Default freshness window (see §1.7)
```

### 1.7 Freshness Window (timestamp-based)

After the AEAD tag is verified and the inner layout parsed, an optional timestamp check is applied. It is a freshness window, **not** full replay protection: the base API does not track seen nonces, so an identical ciphertext can be replayed within the window. Use RatchetSession for per-message counters.

```
IF max_age_ms is not None:
    now_ms = current_time_milliseconds()
    age    = now_ms - timestamp_ms
    # Reject if too far in the future (>5s clock skew) or older than the window
    IF timestamp_ms > now_ms + 5000 OR age > max_age_ms:
        reject
```

Properties:
- Default window: 60 seconds (`max_age_ms = 60000`), configurable per instance.
- 5-second tolerance for future-dated timestamps (clock skew).
- Set `max_age_ms = None` to disable the check.
- `pad_len` is validated to be within [32, 128]; out-of-range values reject the message.

## 2. Internal Keystream (StreamCipher and Ratchet only)

> **This section does NOT describe the base `Shield` format**, which uses a
> standard AEAD (§1). It describes the keystream still used by the internal
> `StreamCipher` (§4) and `RatchetSession` (§3) modules.

### 2.1 Keystream Generation

```
counter = 0
position = 0

while need_more_bytes:
    block_input = nonce || counter.to_bytes(4, little_endian)
    block = SHA256(encryption_key || block_input)     # StreamCipher
    # or HMAC-SHA256(message_key, nonce || counter)   # Ratchet (§3.8)
    output block bytes
    counter += 1
```

**Counter overflow guard:** keystream generators assert that `counter` fits in
`u32` (max 2^32 blocks = 137 GB); exceeding this is a hard failure, not silent
wraparound.

### 2.2 Block Structure

```
+----------------+----------------+
|     Nonce      |    Counter     |
|   (16 bytes)   |   (4 bytes)    |
+----------------+----------------+
         |
         v
    SHA256(key || input)   (StreamCipher)  /  HMAC-SHA256(key, input)  (Ratchet)
         |
         v
    32-byte keystream block
```

> **Note (cross-language wire format):** The `StreamCipher` keystream uses raw
> SHA256 for cross-language interoperability. Internal modules (ratchet,
> rotation, group, identity, exchange, signatures) use HMAC-SHA256 as a keyed PRF
> — see §3.8.

## 3. ShieldChannel Protocol

### 3.1 Handshake Overview

```
Client                              Server
   |                                   |
   |-------- ClientHello ------------>|
   |                                   |
   |<------- ServerHello -------------|
   |                                   |
   |-------- ClientFinish ----------->|
   |                                   |
   |<------- ServerFinish ------------|
   |                                   |
   |======= Encrypted Data ==========|
```

### 3.2 Pre-Shared-Key Handshake

> **Security note — this is NOT a true PAKE.** Despite the `PAKEExchange` type
> name, this handshake does *not* provide the guarantee of a real
> Password-Authenticated Key Exchange (SPAKE2/CPace/OPAQUE). Each party's
> contribution is a deterministic function of the shared secret and a salt, and
> both the salt and the contribution are sent in the clear. An attacker who
> records one handshake can mount an **offline dictionary attack** against a
> low-entropy secret (PBKDF2's 600 000 iterations only slow each guess). This
> cannot be fixed in a symmetric-only design.
>
> **Use this handshake only with a high-entropy shared secret** (≥128 bits — a
> random key or long diceware passphrase). For password-based or forward-secret
> establishment, use the X25519 + ML-KEM-768 hybrid KEX (§5 / `pqhybrid`)
> instead and feed its 32-byte output into the pre-shared-key path.

Both parties derive a shared key from the shared secret (a deterministic
pre-shared-key derivation, written `pake_key` below for historical reasons):

```
pake_key = HMAC-SHA256(password, service || "pake")
```

### 3.3 ClientHello Message

```
+--------+------------------+-----------------+
|  Type  |  Client Random   |  Client Contrib |
| 1 byte |    32 bytes      |    32 bytes     |
+--------+------------------+-----------------+

Type = 0x01 (ClientHello)
Client Random = random 32 bytes
Client Contrib = HMAC-SHA256(pake_key, client_random || "client")
```

### 3.4 ServerHello Message

```
+--------+------------------+-----------------+
|  Type  |  Server Random   |  Server Contrib |
| 1 byte |    32 bytes      |    32 bytes     |
+--------+------------------+-----------------+

Type = 0x02 (ServerHello)
Server Random = random 32 bytes
Server Contrib = HMAC-SHA256(pake_key, server_random || "server")
```

### 3.5 Session Key Derivation

```
shared_secret = HMAC-SHA256(
    pake_key,
    client_contrib || server_contrib || client_random || server_random
)

session_key = HMAC-SHA256(shared_secret, "session_key")
```

The session key is additionally bound to the **service identifier** for domain
separation: the same shared secret used for two different services derives two
different session keys, so a credential provisioned for one service cannot
establish a channel for another. (Concretely, the implementation folds the
service bytes into the final key-derivation HMAC input.)

> **Note (cross-language status):** the prose above is a simplified model. The
> actual key-derivation primitives are *not yet byte-identical across bindings* —
> Rust uses HMAC-SHA256 throughout while Go/Python/JS use SHA256 for the
> contribution/combine/session steps — so a Rust channel peer does **not**
> currently interoperate with a Go/Python/JS peer. Unifying these (alongside a
> real DH-based PAKE) is a tracked follow-up. The service-binding domain
> separation described here is implemented in **all** bindings.

### 3.6 Finish Messages

```
ClientFinish:
+--------+-------------------+
|  Type  |    Verify Data    |
| 1 byte |     32 bytes      |
+--------+-------------------+

Type = 0x03 (ClientFinish)
Verify Data = HMAC-SHA256(session_key, "client_finished" || transcript)

ServerFinish:
Type = 0x04 (ServerFinish)
Verify Data = HMAC-SHA256(session_key, "server_finished" || transcript)
```

### 3.7 Data Messages

After handshake, all messages use RatchetSession:

```
+--------+----------+-----------+------------------+--------+
|  Type  |  Length  |  Counter  |    Ciphertext    |  MAC   |
| 1 byte | 4 bytes  |  8 bytes  |    variable      | 16 bytes|
+--------+----------+-----------+------------------+--------+

Type = 0x05 (Data)
Length = total message length (big-endian)
Counter = message sequence number (big-endian)
```

### 3.8 Key Ratcheting

After each message (using HMAC-SHA256 as keyed PRF):

```
new_chain_key = HMAC-SHA256(chain_key, "chain")
message_key   = HMAC-SHA256(chain_key, "message")
```

Keystream generation in ratchet messages also uses HMAC-SHA256:

```
keystream_block[i] = HMAC-SHA256(message_key, nonce || counter_i)
```

> All internal modules (ratchet, rotation, group, identity, exchange,
> signatures) use `HMAC-SHA256(key, data)` rather than raw `SHA256(key||data)`
> for formal PRF security (Bellare 2006), length-extension resistance, and NIST
> SP 800-108 alignment.

### 3.9 Sync Channel Timeout

`ShieldChannel<TcpStream>` provides `connect_tcp()` and `accept_tcp()` methods that enforce `handshake_timeout_ms` via socket read/write timeouts during the handshake phase. Timeouts are cleared after successful handshake to avoid interfering with application-level I/O.

## 4. StreamCipher Format

Uses the SHA-256 keystream + HMAC-SHA256 construction described in §2 (not the
base AEAD), chunked for large-file processing.

### 4.1 Chunk Structure

```
+-------------+------------------+--------+
| Chunk Nonce |   Chunk Data     |  MAC   |
|  16 bytes   |   64KB max       | 16 bytes|
+-------------+------------------+--------+
```

### 4.2 Stream Header

```
+----------+--------------+------------+
|  Magic   |   Version    | Chunk Size |
| 4 bytes  |   2 bytes    |  4 bytes   |
+----------+--------------+------------+

Magic = "SHLD" (0x53484C44)
Version = 0x0001
Chunk Size = 65536 (default)
```

### 4.3 Chunk Framing and Authenticated End-of-Stream

On the wire each chunk is length-prefixed and the stream ends with an
**authenticated** end-of-stream tag (a length commitment):

```
header   = chunk_size(u32 LE, 4) || stream_salt(16)
chunk[i] = chunk_len(u32 LE, 4) || (nonce(16) || ciphertext || mac(16))
trailer  = u32_LE(0) || eof_tag(32)

eof_key  = HMAC-SHA256(master_key, "shield-stream-eof")
eof_tag  = HMAC-SHA256(eof_key, stream_salt || chunk_count_u64_LE)
```

`chunk_count` is the total number of data chunks. The decryptor **requires** the
zero-length marker followed by a valid `eof_tag`, verified in constant time
against the number of chunks actually read.

> **Why (truncation resistance):** without an authenticated terminator, an
> attacker could drop trailing chunks (each remaining chunk's per-chunk MAC
> still verifies) and the decryptor would silently return truncated plaintext —
> even re-appending a bare zero marker would be accepted. Binding the chunk
> count into a keyed tag means a truncated stream cannot produce a matching
> `eof_tag` without the master key, and a stream that simply ends early (no
> marker) is rejected. This tag is part of the cross-language wire format: every
> binding derives the identical `eof_tag` (golden vector
> `52d4dfbeccc364bd69a2f232aa460bd1eb79b0c93903f344dd7b937703918431` for
> master_key=32×0x42, stream_salt=16×0x01, chunk_count=3).

## 5. TOTP Format

### 5.1 Secret Encoding

```
Base32-encoded secret (RFC 4648)
Default length: 20 bytes (160 bits)
```

### 5.2 Code Generation (RFC 6238)

```
time_step = floor(unix_timestamp / 30)
hmac = HMAC-SHA1(secret, time_step.to_bytes(8, big_endian))
offset = hmac[-1] & 0x0F
code = (hmac[offset:offset+4] & 0x7FFFFFFF) % 1000000
```

## 6. Version Compatibility

| Version | Release Date | Format Changes | Breaking Changes |
|---------|--------------|----------------|------------------|
| 1.0 | 2026-01-11 | Initial specification (historical) | N/A |
| 2.0 | 2026-02-20 | Inner timestamp + length-obfuscation padding (historical) | Could not be read by 1.0 |
| 2.1 | 2026-03-01 | Key separation (enc_key/mac_key via HMAC domain labels), HMAC-SHA256 in all internal modules, counter overflow guards (historical) | Wire format unchanged from 2.0 |
| 3.0 | 2026-06-12 | Explicit authenticated version byte (`0x02`/`0x12`); per-instance random PBKDF2 salt in header; iterations 100k → 600k (historical) | Clean break from ≤ 2.1 |
| 4.0 | 2026-06-22 | **Standard AEAD core** (AES-256-GCM default / ChaCha20-Poly1305) replaces the SHA-256 keystream + HMAC; added suite byte; version bytes `0x03`/`0x13`; nonce 16 → 12 bytes; AEAD tag replaces the separate HMAC; inner counter removed; `aead_key = HKDF-Expand(master_key)` | **Clean break.** ≤ 3.0 ciphertexts (`0x02`/`0x12`) are not readable by 4.0; no legacy decrypt path. |

> **Note on historical versions.** The 1.0–3.0 formats are documented for history
> only. They are **not** accepted by the current code; decryption dispatches on
> the explicit, AEAD-authenticated version byte (§1.1).

### 6.1 Version Detection

Each message begins with an explicit version byte (§1.1) authenticated as AEAD AAD:

- `0x03` — password mode (`version || suite || salt(16) || nonce(12) || ct||tag`)
- `0x13` — pre-shared-key mode (`version || suite || nonce(12) || ct||tag`)

Decryption dispatches on this byte before any cryptographic work and hard-rejects any other value. There is no plaintext-heuristic detection and no fallback to older formats.

### 6.2 Compatibility Matrix

| Producer | Consumer | Result |
|----------|----------|--------|
| ≤ 3.0 (`0x02`/`0x12`) | 4.0 | ❌ Rejected (unknown version byte) |
| 4.0 | ≤ 3.0 | ❌ Fails (older code cannot parse the suite byte / AEAD) |
| 4.0 password (`0x03`) | 4.0 password | ✅ Works |
| 4.0 PSK (`0x13`) | 4.0 PSK | ✅ Works |

### 6.3 Migration Guidance

4.0 is a deliberate clean break. There is no in-place upgrade path and no dual-read window:

1. Data encrypted with ≤ 3.0 Shield must be **re-encrypted** with 4.0 to remain readable.
2. All producers and consumers should be upgraded to 4.0 together.
3. Mixed-version deployments will see cross-version messages rejected (see the matrix above), not silently mis-decrypted.

## 7. Security Considerations

### 7.1 Nonce Uniqueness

- The 96-bit nonce MUST be random and unique per message under a given key.
- For AES-GCM, the safe limit is ~2^32 messages per key with random nonces
  (birthday bound on the 96-bit nonce); rotate keys for very high message volumes.
- Use a cryptographically secure RNG.

### 7.2 Timing Attacks

- AEAD tag verification is constant-time within the underlying provider.
- Any application-level comparisons MUST also be constant-time (`subtle` in Rust).

### 7.3 Key Material

- Keys MUST be zeroized after use (the Rust `Shield`, including its derived-key
  cache, zeroizes on drop).
- Never log or serialize keys.
- Use secure memory where available.

### 7.4 Key Commitment

- AES-GCM and ChaCha20-Poly1305 are not key-committing: a ciphertext can, in
  principle, be made to decrypt under two different keys. Shield's threat model
  does not currently rely on key commitment; see `THREAT_MODEL.md`.

## 8. Test Vectors

Deterministic, byte-exact vectors live in `tests/v4_test_vectors.json` (6
AES-256-GCM + 2 ChaCha20-Poly1305 vectors), each carrying `master_key_hex`,
`aead_key_hex`, and `expected_output_hex`. Every binding reproduces them
byte-for-byte. The structure below documents the layout; consult the JSON for
exact bytes.

### 8.1 Password Mode (version `0x03`)

```
Password:  "test-password"
Service:   "test.example.com"
Plaintext: "Hello, World!" (hex: 48656c6c6f2c20576f726c6421)
Suite:     0x01 (AES-256-GCM)
Salt:      16 bytes (fixed per vector)
Nonce:     12 bytes (fixed per vector)
Timestamp / padding: fixed per vector

Key derivation:
  master_key = PBKDF2-HMAC-SHA256("test-password", salt || "test.example.com", 600000, 32)
  aead_key   = HKDF-SHA256-Expand(master_key, "shield/aead/v4", 32)

Inner (AEAD plaintext): timestamp(8) || pad_len(1) || padding(32-128) || "Hello, World!"
AAD:    version(0x03) || suite(0x01) || salt(16)
Output: version(1) || suite(1) || salt(16) || nonce(12) || ciphertext || tag(16)
```

### 8.2 Pre-Shared-Key Mode (version `0x13`)

```
Key:       32 bytes (caller-supplied; no PBKDF2)
aead_key = HKDF-SHA256-Expand(key, "shield/aead/v4", 32)

Inner:  identical layout to §8.1
AAD:    version(0x13) || suite
Output: version(1) || suite(1) || nonce(12) || ciphertext || tag(16)
```

### 8.3 Freshness / Rejection Test Cases

```
Test Case 1: Valid message (within window) -> decrypts
Test Case 2: Expired (timestamp = now - 120000, window 60000) -> rejected
Test Case 3: Future-dated (timestamp = now + 10000, skew 5000) -> rejected
Test Case 4: Unknown version byte (not 0x03/0x13, e.g. a ≤3.0 ciphertext) -> rejected before any crypto
Test Case 5: Tampered version/suite/salt/ciphertext -> AEAD tag fails -> rejected
```

### 8.4 Cross-Language Verification

All implementations MUST produce byte-identical output for the same inputs
(password+service or key; salt, nonce, timestamp, padding in test mode). Every
binding (Python, JavaScript, Go, Java, Kotlin, Android, C#, C, Swift/iOS, WASM):

1. Emits the correct version + suite bytes and, in password mode, the 16-byte salt.
2. Derives `master_key` via PBKDF2-HMAC-SHA256 over `salt || service`, 600000 iterations.
3. Derives `aead_key` via HKDF-SHA256-Expand with `info = "shield/aead/v4"`.
4. Seals with the selected AEAD over `aad = version || suite || [salt]`.
5. Rejects unknown version bytes and expired messages consistently.
6. Produces identical length variation (32-128 byte random padding).

> **C binding:** AES-256-GCM only (Windows CNG provides no ChaCha20-Poly1305);
> suite `0x02` is unavailable there. All other bindings support both suites.

## References

- NIST SP 800-38D: AES-GCM
- RFC 8439: ChaCha20-Poly1305
- RFC 5869: HKDF
- RFC 8018 / NIST SP 800-132: PBKDF2
- RFC 2104: HMAC
- RFC 6238: TOTP
- RFC 4648: Base Encodings
