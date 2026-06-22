# Shield Wire Protocol Specification

**Version**: 3.0
**Status**: Draft
**Last Updated**: 2026-06-12

## Overview

This document specifies the wire format and protocol for Shield encrypted messages and the ShieldChannel secure transport.

The canonical reference for the wire format is the Python implementation at `python/shield/core.py`; all other language bindings are byte-for-byte compatible with it.

## 1. Basic Encryption Format

The current format carries an explicit, authenticated version byte at the front of every message. Two modes are defined:

- **Password mode** (`0x02`) — keys derived from a password via PBKDF2; carries a per-instance random salt in the header.
- **Pre-shared-key mode** (`0x12`) — keys supplied directly (`with_key` / `quick_encrypt`); no password, no salt.

The leading version byte is authenticated by the MAC, so there is no format guessing on decryption: decryption dispatches on the version byte and hard-rejects any unknown value.

### 1.1 Message Structure

**Password mode** (version `0x02`):

```
+---------+----------+----------+------------------+----------+
| Version |   Salt   |  Nonce   |    Ciphertext    |   MAC    |
| 1 byte  | 16 bytes | 16 bytes |    (variable)    | 16 bytes |
+---------+----------+----------+------------------+----------+
```

**Pre-shared-key mode** (version `0x12`):

```
+---------+----------+------------------+----------+
| Version |  Nonce   |    Ciphertext    |   MAC    |
| 1 byte  | 16 bytes |    (variable)    | 16 bytes |
+---------+----------+------------------+----------+
```

| Field | Size | Description |
|-------|------|-------------|
| Version | 1 byte | `0x02` = password mode, `0x12` = pre-shared-key mode. Authenticated by the MAC. |
| Salt | 16 bytes | Per-instance random PBKDF2 salt. **Password mode only.** Authenticated by the MAC. |
| Nonce | 16 bytes | Random value, unique per message |
| Ciphertext | Variable | Encrypted inner plaintext (see §1.6) |
| MAC | 16 bytes | HMAC-SHA256 truncated to 128 bits |

**Header overhead** (excluding the inner plaintext metadata in §1.6):
- Password mode: 1 + 16 + 16 + 16 = **49 bytes**
- Pre-shared-key mode: 1 + 16 + 16 = **33 bytes**

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

`service` is folded into the PBKDF2 salt input as a domain separator (concatenated *after* the random salt: `salt || service`). Different services therefore still yield different keys, while the per-instance random salt removes the old precomputation / shared-key weakness.

Subkey separation is identical in both modes and applied to the 32-byte master key:

```
enc_key = HMAC-SHA256(master_key, "shield-encrypt")        # 32 bytes
mac_key = HMAC-SHA256(master_key, "shield-authenticate")   # 32 bytes
```

### 1.3 Encryption Process

```
1. Build inner = counter || timestamp || pad_len || padding || plaintext  (see §1.6)
2. Generate random nonce (16 bytes)
3. keystream = SHA256-CTR(enc_key, nonce, len(inner))
4. ciphertext = inner XOR keystream
5. Build header:
     password mode:        header = version(0x02) || salt(16)
     pre-shared-key mode:  header = version(0x12)
6. mac = HMAC-SHA256(mac_key, header || nonce || ciphertext)[0:16]
7. output = header || nonce || ciphertext || mac
```

The MAC authenticates `version || [salt] || nonce || ciphertext` — i.e. the version byte and (in password mode) the salt are covered.

### 1.4 Decryption Process

```
1. IF len(input) < 1: reject
2. version = input[0]

3. IF version == 0x02 (password mode):
     salt    = input[1:17]
     header  = input[0:17]
     body    = input[17:]
     # Re-derive key from the header salt (sender's salt may differ from ours)
     master_key      = PBKDF2-HMAC-SHA256(password, salt || service, 600000, 32)
     enc_key, mac_key = subkeys(master_key)
   ELIF version == 0x12 (pre-shared-key mode):
     header  = input[0:1]
     body    = input[1:]
     enc_key, mac_key = this instance's subkeys
   ELSE:
     reject   # unknown / legacy version — no fallback decrypt path

4. nonce      = body[0:16]
5. ciphertext = body[16:-16]
6. mac        = body[-16:]

7. expected_mac = HMAC-SHA256(mac_key, header || nonce || ciphertext)[0:16]
8. Verify: constant_time_compare(mac, expected_mac) -> reject on mismatch

9. keystream = SHA256-CTR(enc_key, nonce, len(ciphertext))
10. inner    = ciphertext XOR keystream
11. Parse and validate inner (see §1.6), apply freshness check (see §1.7)
12. return plaintext
```

> **No legacy decrypt path.** This is a clean break from the older formats. The main `decrypt()` routine dispatches solely on the authenticated version byte and rejects anything that is not `0x02` or `0x12`. Older heuristic (timestamp-range) formats are not accepted. Ciphertexts written by pre-`3.0` Shield must be re-encrypted; they cannot be read by the current code.

### 1.5 Mode Selection

| Constructor | Mode | Version byte | Salt in header |
|-------------|------|--------------|----------------|
| `Shield(password, service)` | Password | `0x02` | Yes (16 random bytes) |
| `Shield.with_key(key)` | Pre-shared-key | `0x12` | No |
| `quick_encrypt(key, data)` | Pre-shared-key | `0x12` | No |

### 1.6 Inner Plaintext Structure

Before encryption, the plaintext is wrapped with metadata. This inner layout is XOR-encrypted under the keystream and is identical in both modes:

```
+----------+------------+----------+---------+-------------+
| Counter  | Timestamp  | Pad Len  | Padding |  Plaintext  |
| 8 bytes  |  8 bytes   | 1 byte   | 32-128B |  variable   |
+----------+------------+----------+---------+-------------+
```

| Field | Size | Description |
|-------|------|-------------|
| Counter | 8 bytes | Message counter (little-endian uint64), increments per encrypt within a Shield instance |
| Timestamp | 8 bytes | Unix timestamp in milliseconds (little-endian uint64) |
| Pad Len | 1 byte | Length of random padding (32-128) |
| Padding | 32-128 bytes | Random padding for length obfuscation |
| Plaintext | Variable | Actual message data |

The padding length is drawn uniformly from [32, 128] using rejection sampling to avoid modulo bias.

#### 1.6.1 Constants

```
INNER_HEADER_SIZE = 17    # counter(8) + timestamp(8) + pad_len(1)
MIN_PADDING       = 32    # Minimum padding bytes
MAX_PADDING       = 128   # Maximum padding bytes
PBKDF2_ITERATIONS = 600000
NONCE_SIZE        = 16
SALT_SIZE         = 16
MAC_SIZE          = 16
DEFAULT_MAX_AGE_MS = 60000  # Default freshness window (see §1.7)
```

### 1.7 Freshness Window (timestamp-based)

After the MAC is verified and the inner layout parsed, an optional timestamp check is applied. It is a freshness window, **not** full replay protection: the base API does not track seen nonces, so an identical ciphertext can be replayed within the window. Use RatchetSession for per-message counters.

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

## 2. SHA256-CTR Stream Cipher

### 2.1 Keystream Generation

```
counter = 0
position = 0

while need_more_bytes:
    block_input = nonce || counter.to_bytes(4, little_endian)
    block = SHA256(encryption_key || block_input)
    output block bytes
    counter += 1
```

**Counter overflow guard (v2.1):** Keystream generators assert that `counter` fits in `u32` (max 2^32 blocks = 137GB). Exceeding this limit causes a hard failure rather than silent wraparound.

### 2.2 Block Structure

```
+----------------+----------------+
|     Nonce      |    Counter     |
|   (16 bytes)   |   (4 bytes)    |
+----------------+----------------+
         |
         v
    SHA256(key || input)
         |
         v
    32-byte keystream block
```

> **Note (cross-language wire format):** The core `Shield` and `StreamCipher` keystream use raw SHA256 for cross-language interoperability. Internal-only modules (ratchet, rotation, group, identity, exchange, signatures) use HMAC-SHA256 as keyed PRF — see Section 3.8.

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

### 3.2 PAKE Key Exchange

Both parties derive a shared key from the password:

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

> **v2.1 upgrade (Rust):** All internal modules (ratchet, rotation, group, identity, exchange, signatures) replaced raw `SHA256(key||data)` patterns with `HMAC-SHA256(key, data)` for formal PRF security (Bellare 2006), length-extension resistance, and NIST SP 800-108 compliance.

### 3.9 Sync Channel Timeout (v2.1)

`ShieldChannel<TcpStream>` provides `connect_tcp()` and `accept_tcp()` methods that enforce `handshake_timeout_ms` via socket read/write timeouts during the handshake phase. Timeouts are cleared after successful handshake to avoid interfering with application-level I/O.

## 4. StreamCipher Format

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
| 2.1 | 2026-03-01 | Key separation (enc_key/mac_key via HMAC domain labels), HMAC-SHA256 in all internal modules, counter overflow guards, sync channel timeout (historical) | Wire format unchanged from 2.0 |
| 3.0 | 2026-06-12 | Explicit authenticated version byte; per-instance random PBKDF2 salt carried in header (password mode); PBKDF2 iterations 100k → 600k; `service` folded into salt as a domain separator; salt + version authenticated by the MAC | **Clean break.** Pre-3.0 ciphertexts are not readable by 3.0; no legacy decrypt path. |

> **Note on historical versions.** The 1.0 / 2.0 / 2.1 formats listed above are documented here only for history. They are **not** accepted by the current code. The fragile timestamp-range "auto-detection" that older versions relied on to tell v1 from v2 has been removed entirely and replaced by the explicit, MAC-authenticated version byte in §1.1.

### 6.1 Version Detection

Each message begins with an explicit version byte (§1.1) that is authenticated by the MAC:

- `0x02` — password mode (`version || salt(16) || nonce || ciphertext || mac`)
- `0x12` — pre-shared-key mode (`version || nonce || ciphertext || mac`)

Decryption dispatches on this byte before any cryptographic work and hard-rejects any other value. There is no plaintext-heuristic detection and no fallback to older formats.

### 6.2 Compatibility Matrix

| Producer | Consumer | Result |
|----------|----------|--------|
| Pre-3.0 | 3.0 | ❌ Rejected (unknown/absent version byte) |
| 3.0 | Pre-3.0 | ❌ Fails (older code cannot parse the version byte / salt) |
| 3.0 password (`0x02`) | 3.0 password | ✅ Works |
| 3.0 PSK (`0x12`) | 3.0 PSK | ✅ Works |

### 6.3 Migration Guidance

3.0 is a deliberate clean break. There is no in-place upgrade path and no dual-read window:

1. Data encrypted with pre-3.0 Shield must be **re-encrypted** with 3.0 to remain readable.
2. All producers and consumers should be upgraded to 3.0 together.
3. Mixed-version deployments will see cross-version messages rejected (see the matrix above), not silently mis-decrypted.

## 7. Security Considerations

### 7.1 Nonce Uniqueness

- Nonces MUST be random and unique per message
- Nonce reuse breaks confidentiality
- Use cryptographically secure RNG

### 7.2 Timing Attacks

- All comparisons MUST be constant-time
- Use `subtle` crate (Rust) or equivalent

### 7.3 Key Material

- Keys MUST be zeroized after use
- Never log or serialize keys
- Use secure memory where available

## 8. Test Vectors

### 8.1 Password Mode (version `0x02`, deterministic test values)

```
Password:  "test-password"
Service:   "test.example.com"
Plaintext: "Hello, World!" (hex: 48656c6c6f2c20576f726c6421)
Salt:      00000000000000000000000000000000 (for testing only; normally random)
Nonce:     00000000000000000000000000000000 (for testing only)
Timestamp: 1672531200000 (2023-01-01 00:00:00 UTC)
Padding:   32 bytes of 0x00 (for testing only)

Key derivation:
  master_key = PBKDF2-HMAC-SHA256("test-password",
                                  salt || "test.example.com",
                                  600000, 32)
  enc_key = HMAC-SHA256(master_key, "shield-encrypt")
  mac_key = HMAC-SHA256(master_key, "shield-authenticate")

Inner data (XOR-encrypted under the keystream):
- Counter:   0000000000000000 (8 bytes)
- Timestamp: 00e057ac85010000 (8 bytes, little-endian: 1672531200000)
- Pad Len:   20               (1 byte, hex: 0x20 = 32)
- Padding:   32 bytes of 0x00
- Plaintext: "Hello, World!"   (13 bytes)
Inner length: 8 + 8 + 1 + 32 + 13 = 62 bytes

Output format: version(1) || salt(16) || nonce(16) || ciphertext(62) || mac(16)
Output length: 1 + 16 + 16 + 62 + 16 = 111 bytes
MAC input:     version(0x02) || salt(16) || nonce(16) || ciphertext(62)
```

### 8.2 Pre-Shared-Key Mode (version `0x12`, deterministic test values)

```
Key:       32 bytes (caller-supplied; no PBKDF2)
Plaintext: "Hello, World!" (hex: 48656c6c6f2c20576f726c6421)
Nonce:     00000000000000000000000000000000 (for testing only)
Timestamp: 1672531200000
Padding:   32 bytes of 0x00 (for testing only)

Inner data: identical layout to §8.1 (62 bytes for this example)

Output format: version(1) || nonce(16) || ciphertext(62) || mac(16)
Output length: 1 + 16 + 62 + 16 = 95 bytes
MAC input:     version(0x12) || nonce(16) || ciphertext(62)
```

### 8.3 Freshness / Rejection Test Cases

```
Test Case 1: Valid message (within window)
- Timestamp within [now - max_age_ms, now + 5000]
- Result: Decrypts successfully

Test Case 2: Expired message (max_age_ms = 60000)
- Timestamp: now - 120000 (2 minutes ago)
- Result: Rejected (age > max_age_ms)

Test Case 3: Future message (>5s clock skew)
- Timestamp: now + 10000 (10 seconds in the future)
- Result: Rejected (timestamp > now + 5000)

Test Case 4: Unknown version byte
- First byte is not 0x02 or 0x12 (e.g. a pre-3.0 ciphertext)
- Result: Rejected before any key derivation or MAC check

Test Case 5: Tampered version or salt
- Any change to the version byte or (password mode) the salt
- Result: MAC verification fails -> rejected
```

### 8.4 Cross-Language Verification

All implementations MUST produce byte-identical output for:
- Same password and service (password mode) or same key (PSK mode)
- Same salt (password mode, test mode only)
- Same nonce (test mode only)
- Same timestamp and padding (test mode only)

Byte-for-byte compatibility requires that every language binding (Python, JavaScript, Go, Java, C, etc.):
1. Emits the correct version byte (`0x02` / `0x12`) and, in password mode, the 16-byte salt.
2. Derives keys with PBKDF2-HMAC-SHA256 over `salt || service`, 600000 iterations.
3. Computes the MAC over `version || [salt] || nonce || ciphertext`.
4. Rejects unknown version bytes and expired messages consistently.
5. Produces identical length variation (32-128 byte random padding).

## References

- RFC 2104: HMAC
- RFC 6238: TOTP
- RFC 4648: Base Encodings
- NIST SP 800-132: PBKDF2
