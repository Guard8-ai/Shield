# Shield Wire Protocol Specification

**Version**: 1.0
**Status**: Draft
**Last Updated**: 2026-01-11

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

| Version | Format Changes |
|---------|----------------|
| 1.0 | Initial specification |

### 6.1 Version Detection

Messages do not include explicit version markers. Compatibility is maintained through:
- Fixed field sizes
- Extensible handshake messages
- Forward-compatible parsing

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

### 8.1 Basic Encryption

```
Password: "test-password"
Service: "test.example.com"
Plaintext: "Hello, World!" (hex: 48656c6c6f2c20576f726c6421)
Nonce: 00000000000000000000000000000000 (for testing only)

Expected Master Key: [implementation-specific due to PBKDF2]
Expected Output: [nonce][ciphertext][mac]
```

### 8.2 Cross-Language Verification

All implementations MUST produce identical output for:
- Same password
- Same service
- Same plaintext
- Same nonce (test mode only)

## References

- RFC 2104: HMAC
- RFC 6238: TOTP
- RFC 4648: Base Encodings
- NIST SP 800-132: PBKDF2
