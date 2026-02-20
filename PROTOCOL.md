# Shield Wire Protocol Specification

**Version**: 2.0
**Status**: Draft
**Last Updated**: 2026-02-20

## Overview

This document specifies the wire format and protocol for Shield encrypted messages and the ShieldChannel secure transport.

## 1. Basic Encryption Format

### 1.1 Message Structure

```
+----------------+------------------+----------------+
|     Nonce      |    Ciphertext    |      MAC       |
|   (16 bytes)   |   (variable)     |   (16 bytes)   |
+----------------+------------------+----------------+
```

| Field | Size | Description |
|-------|------|-------------|
| Nonce | 16 bytes | Random value, unique per message |
| Ciphertext | Variable | Encrypted plaintext |
| MAC | 16 bytes | HMAC-SHA256 truncated to 128 bits |

### 1.2 Key Derivation

```
master_key = PBKDF2-SHA256(
    password = password,
    salt = SHA256(service),
    iterations = 100000,
    key_length = 32
)

encryption_key = master_key[0:32]
mac_key = SHA256(master_key || "mac")
```

### 1.3 Encryption Process

```
1. Generate random nonce (16 bytes)
2. keystream = SHA256-CTR(encryption_key, nonce)
3. ciphertext = plaintext XOR keystream
4. mac = HMAC-SHA256(mac_key, nonce || ciphertext)[0:16]
5. output = nonce || ciphertext || mac
```

### 1.4 Decryption Process

```
1. Parse: nonce = input[0:16], ciphertext = input[16:-16], mac = input[-16:]
2. expected_mac = HMAC-SHA256(mac_key, nonce || ciphertext)[0:16]
3. Verify: constant_time_compare(mac, expected_mac)
4. keystream = SHA256-CTR(encryption_key, nonce)
5. plaintext = ciphertext XOR keystream
```

### 1.5 Version 2 Format (Replay Protection & Length Obfuscation)

**Added**: 2026-02-20
**Status**: Current (default in all new implementations)

Version 2 adds two security enhancements while maintaining backward compatibility with v1:

1. **Replay Protection**: Timestamp validation prevents replay attacks
2. **Length Obfuscation**: Random padding hides message length patterns

#### 1.5.1 V2 Inner Plaintext Structure

Before encryption, plaintext is wrapped with additional metadata:

```
+----------+------------+----------+---------+-------------+
| Counter  | Timestamp  | Pad Len  | Padding |  Plaintext  |
| 8 bytes  |  8 bytes   | 1 byte   | 32-128B |  variable   |
+----------+------------+----------+---------+-------------+
```

| Field | Size | Description |
|-------|------|-------------|
| Counter | 8 bytes | Message counter (little-endian uint64), currently always 0 |
| Timestamp | 8 bytes | Unix timestamp in milliseconds (little-endian int64) |
| Pad Len | 1 byte | Length of random padding (32-128 bytes) |
| Padding | 32-128 bytes | Random padding for length obfuscation |
| Plaintext | Variable | Actual message data |

#### 1.5.2 V2 Encryption Process

```
1. Generate random nonce (16 bytes)
2. Get current timestamp in milliseconds (int64)
3. Generate random padding length: pad_len = random(32, 128)
4. Generate random padding: padding = random_bytes(pad_len)
5. Build inner_data = counter || timestamp || pad_len || padding || plaintext
6. keystream = SHA256-CTR(encryption_key, nonce, len(inner_data))
7. ciphertext = inner_data XOR keystream
8. mac = HMAC-SHA256(mac_key, nonce || ciphertext)[0:16]
9. output = nonce || ciphertext || mac
```

#### 1.5.3 V2 Decryption Process with Auto-Detection

```
1. Parse: nonce = input[0:16], ciphertext = input[16:-16], mac = input[-16:]
2. expected_mac = HMAC-SHA256(mac_key, nonce || ciphertext)[0:16]
3. Verify: constant_time_compare(mac, expected_mac) -> fail if mismatch
4. keystream = SHA256-CTR(encryption_key, nonce)
5. decrypted = ciphertext XOR keystream

6. Auto-detect v2 format:
   IF len(decrypted) >= 17:  # V2_HEADER_SIZE
       timestamp_ms = decrypted[8:16] as little-endian int64

       IF 1577836800000 <= timestamp_ms <= 4102444800000:  # 2020-2100 range
           # V2 format detected
           pad_len = decrypted[16] as uint8
           data_start = 17 + pad_len

           # Replay protection
           IF max_age_ms is not None:
               now_ms = current_time_milliseconds()
               age = now_ms - timestamp_ms

               # Reject if too far in future (>5s clock skew) or too old
               IF timestamp_ms > now_ms + 5000 OR age > max_age_ms:
                   FAIL with "replay detected" or "authentication failed"

           plaintext = decrypted[data_start:]
       ELSE:
           # V1 format (no timestamp or timestamp out of range)
           plaintext = decrypted[8:]  # Skip counter only
   ELSE:
       # V1 format (too short for v2 header)
       plaintext = decrypted[8:]

7. return plaintext
```

#### 1.5.4 V2 Constants

```
V2_HEADER_SIZE = 17       # counter(8) + timestamp(8) + pad_len(1)
MIN_PADDING = 32          # Minimum padding bytes
MAX_PADDING = 128         # Maximum padding bytes
MIN_TIMESTAMP_MS = 1577836800000  # 2020-01-01 00:00:00 UTC
MAX_TIMESTAMP_MS = 4102444800000  # 2100-01-01 00:00:00 UTC
DEFAULT_MAX_AGE_MS = 60000        # Default 60 second replay window
```

#### 1.5.5 V2 Security Properties

1. **Replay Protection**:
   - Default 60-second validity window (configurable)
   - 5-second clock skew tolerance for future timestamps
   - Can be disabled by setting `max_age_ms = None/null/-1`
   - **CRITICAL**: Expired v2 messages are rejected, NOT decrypted as v1

2. **Length Obfuscation**:
   - Random padding between 32-128 bytes (average ~86 bytes overhead)
   - Hides actual message length patterns
   - Different encryptions of same plaintext produce different lengths

3. **Backward Compatibility**:
   - V2 implementations automatically detect and decrypt v1 ciphertext
   - Auto-detection uses timestamp range (2020-2100) as discriminator
   - V1 implementations cannot decrypt v2 ciphertext (will produce garbage)

#### 1.5.6 Migration from V1 to V2

**Phase 1 - Deploy V2 Decoders** (backward compatible):
```
1. Update all consumers to v2-aware implementations
2. They can now decrypt both v1 and v2 messages
3. Continue encrypting with v1 for now
```

**Phase 2 - Switch to V2 Encryption**:
```
1. Update all producers to encrypt with v2 format
2. V2-aware consumers handle it automatically
3. Old v1-only consumers will fail (expected)
```

**Phase 3 - V1 Cleanup** (optional):
```
1. Remove explicit v1 decryption methods if no longer needed
2. Keep auto-detection for historical data
```

## 2. SHA256-CTR Stream Cipher

### 2.1 Keystream Generation

```
counter = 0
position = 0

while need_more_bytes:
    block_input = nonce || counter.to_bytes(8, big_endian)
    block = SHA256(encryption_key || block_input)
    output block bytes
    counter += 1
```

### 2.2 Block Structure

```
+----------------+----------------+
|     Nonce      |    Counter     |
|   (16 bytes)   |   (8 bytes)    |
+----------------+----------------+
         |
         v
    SHA256(key || input)
         |
         v
    32-byte keystream block
```

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
pake_key = SHA256(password || service || "pake")
```

### 3.3 ClientHello Message

```
+--------+------------------+-----------------+
|  Type  |  Client Random   |  Client Contrib |
| 1 byte |    32 bytes      |    32 bytes     |
+--------+------------------+-----------------+

Type = 0x01 (ClientHello)
Client Random = random 32 bytes
Client Contrib = SHA256(pake_key || client_random || "client")
```

### 3.4 ServerHello Message

```
+--------+------------------+-----------------+
|  Type  |  Server Random   |  Server Contrib |
| 1 byte |    32 bytes      |    32 bytes     |
+--------+------------------+-----------------+

Type = 0x02 (ServerHello)
Server Random = random 32 bytes
Server Contrib = SHA256(pake_key || server_random || "server")
```

### 3.5 Session Key Derivation

```
shared_secret = SHA256(
    client_contrib ||
    server_contrib ||
    client_random ||
    server_random ||
    pake_key
)

session_key = SHA256(shared_secret || "session_key")
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

After each message:

```
new_chain_key = SHA256(chain_key || "ratchet")
message_key = SHA256(chain_key || "message" || counter)
```

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
| 1.0 | 2025-01-11 | Initial specification | N/A |
| 2.0 | 2026-02-20 | Replay protection (timestamp) + length obfuscation (random padding) | V1 implementations cannot decrypt v2 messages (by design) |

### 6.1 Version Detection

Messages do not include explicit version markers. V2 implementations use **timestamp range detection**:

- **Auto-Detection Logic**:
  1. Decrypt the ciphertext (XOR with keystream)
  2. Extract bytes 8-16 as little-endian int64 (potential timestamp)
  3. If `1577836800000 <= timestamp <= 4102444800000` (2020-2100), treat as v2
  4. Otherwise, treat as v1 (skip 8-byte counter)

- **Why 2020-2100 Range?**:
  - Wide enough for production use (80 years)
  - Unlikely to collide with random v1 data
  - V1 format with random counter+plaintext rarely falls in this range
  - Deterministic and safe for auto-detection

### 6.2 Compatibility Matrix

| Producer | Consumer | Result |
|----------|----------|--------|
| V1 | V1 | ✅ Works (v1 format) |
| V1 | V2 | ✅ Works (auto-detected as v1) |
| V2 | V1 | ❌ **Fails** (v1 cannot parse v2) |
| V2 | V2 | ✅ Works (v2 format with replay protection) |

### 6.3 Migration Guidance

To upgrade from v1 to v2 without downtime:

1. **Deploy v2 consumers first** (can read both v1 and v2)
2. **Wait for full rollout** (all consumers upgraded)
3. **Switch producers to v2** (start encrypting with v2 format)
4. **Verify monitoring** (check for v1 stragglers)

Compatibility is maintained through:
- Fixed field sizes
- Extensible handshake messages
- Forward-compatible parsing
- **Automatic v1/v2 detection** (no version field needed)

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

### 8.1 V1 Basic Encryption

```
Password: "test-password"
Service: "test.example.com"
Plaintext: "Hello, World!" (hex: 48656c6c6f2c20576f726c6421)
Nonce: 00000000000000000000000000000000 (for testing only)

Expected Master Key: [implementation-specific due to PBKDF2]
Expected Output: [nonce][ciphertext][mac]
```

### 8.2 V2 Encryption (with Deterministic Test Values)

```
Password: "test-password"
Service: "test.example.com"
Plaintext: "Hello, World!" (hex: 48656c6c6f2c20576f726c6421)
Nonce: 00000000000000000000000000000000 (for testing only)
Timestamp: 1672531200000 (2023-01-01 00:00:00 UTC)
Padding: 32 bytes of 0x00 (for testing only)

Inner Data Structure:
- Counter: 0000000000000000 (8 bytes)
- Timestamp: 00e057ac85010000 (8 bytes, little-endian: 1672531200000)
- Pad Len: 20 (1 byte, hex: 20)
- Padding: 32 bytes of 0x00
- Plaintext: "Hello, World!"

Expected Output Format: [nonce(16)][ciphertext(variable)][mac(16)]
Ciphertext Length: 8 + 8 + 1 + 32 + 13 = 62 bytes (before MAC)
```

### 8.3 V2 Auto-Detection Test Cases

```
Test Case 1: Valid V2 Message
- Decrypted inner data starts with timestamp 1672531200000 (0x00e057ac85010000 LE)
- Timestamp in range [1577836800000, 4102444800000]
- Result: Detected as V2, extract plaintext after header+padding

Test Case 2: V1 Message
- Decrypted inner data: counter(0) + random plaintext
- Bytes 8-16 interpreted as timestamp: likely out of range
- Result: Detected as V1, skip 8 bytes (counter only)

Test Case 3: V2 Expired Message (max_age_ms=60000)
- Timestamp: current_time - 120000 (2 minutes ago)
- Result: Rejected with authentication/replay error

Test Case 4: V2 Future Message (>5s clock skew)
- Timestamp: current_time + 10000 (10 seconds in future)
- Result: Rejected with authentication error
```

### 8.4 Cross-Language Verification

All implementations MUST produce identical output for:
- Same password
- Same service
- Same plaintext
- Same nonce (test mode only)
- **V2 Specific**: Same timestamp and padding (test mode only)

**V2 Byte-for-Byte Compatibility**:
All language implementations (Python, JavaScript, Go, Java, C, etc.) must:
1. Encrypt to byte-identical v2 format (given same timestamp/padding)
2. Auto-detect v1 vs v2 using identical timestamp range
3. Reject expired messages consistently
4. Produce identical length variation (32-128 byte random padding)

## References

- RFC 2104: HMAC
- RFC 6238: TOTP
- RFC 4648: Base Encodings
- NIST SP 800-132: PBKDF2
