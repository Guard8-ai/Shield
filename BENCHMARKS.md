# Shield Performance Benchmarks

Shield's wire format **v4** uses a standard AEAD — **AES-256-GCM** (default) or
**ChaCha20-Poly1305** — taken from each platform's audited crypto provider. There
is no custom cipher: "Shield throughput" is therefore essentially the underlying
AEAD's throughput plus a small, constant per-message overhead (one HKDF-Expand to
derive the AEAD key, a 32–128-byte random padding layer for length hiding, an
8-byte timestamp, and buffer allocation).

These numbers are **measured**, not estimated. They are a single-machine,
single-threaded snapshot for orientation, not a vendor benchmark.

**Test environment**: 11th Gen Intel Core i9-11900H @ 2.50 GHz (16 logical
cores), Windows 11. Rust 1.96 (`ring` AEAD), Go 1.24 (stdlib), Node 20, CPython
3.13. Rust via `criterion`; Go via `testing.B`; Python/JS via a fixed-time
micro-benchmark loop.

> **Reading these tables.** Compare *encrypt vs decrypt* and *Shield vs raw AEAD*
> **within the same language** — those are apples-to-apples. Do **not** compare
> raw MB/s *across* languages: each runtime has a different allocator, GC, and
> measurement harness, so small-payload numbers in particular reflect per-call
> interpreter/runtime overhead more than crypto speed.

## Rust (source of truth): Shield v4 vs. raw AEAD

Median latency per operation. `Shield` is the full v4 construction (HKDF-Expand +
padding + timestamp + AES-256-GCM); `AES-256-GCM` / `ChaCha20-Poly1305` are the
bare `ring` AEAD with no framing — i.e. Shield's per-message overhead is the gap.

| Size  | Shield enc | Shield dec | AES-GCM enc | AES-GCM dec | ChaCha enc | ChaCha dec |
|-------|-----------:|-----------:|------------:|------------:|-----------:|-----------:|
| 64 B  |    893 ns  |    680 ns  |     178 ns  |     117 ns  |    288 ns  |    202 ns  |
| 256 B |    987 ns  |    728 ns  |     204 ns  |     132 ns  |    389 ns  |    291 ns  |
| 1 KB  |   1.08 µs  |    861 ns  |     318 ns  |     253 ns  |    774 ns  |    692 ns  |
| 16 KB |   4.44 µs  |   3.23 µs  |    3.12 µs  |    2.29 µs  |   8.58 µs  |   8.05 µs  |
| 64 KB |   14.6 µs  |   13.0 µs  |    13.3 µs  |    10.5 µs  |   36.2 µs  |   32.6 µs  |
| 1 MB  |    902 µs  |    647 µs  |     720 µs  |     389 µs  |   1.06 ms  |    755 µs  |

Steady-state throughput (1 MB payload, derived from the medians above):

| Operation              | Throughput |
|------------------------|-----------:|
| Shield (AES-256-GCM) encrypt | ~1.16 GB/s |
| Shield (AES-256-GCM) decrypt | ~1.62 GB/s |
| raw AES-256-GCM encrypt      | ~1.46 GB/s |
| raw AES-256-GCM decrypt      | ~2.70 GB/s |
| Shield (ChaCha20) encrypt    | ~0.99 GB/s |
| Shield (ChaCha20) decrypt    | ~1.39 GB/s |

**Takeaways**

- AES-256-GCM is the fast path on this CPU (AES-NI). Use the ChaCha20-Poly1305
  suite only where there is no hardware AES.
- Shield's overhead over the raw AEAD is small and roughly constant per message
  (HKDF-Expand + building the padded inner buffer). At 64 KB it is ~10%; it grows
  at 1 MB because Shield allocates a separate padded plaintext buffer before
  sealing. For bulk data, prefer `StreamCipher` (chunked) over a single
  `encrypt()` call.
- At tiny payloads the per-call fixed cost dominates, so MB/s looks low even
  though absolute latency is sub-microsecond.

## Cross-language throughput (indicative)

Encrypt / decrypt throughput (MB/s) for the password-mode API. See the reading
note above — these are **not** directly comparable across rows.

| Size  | Rust enc/dec | Go enc/dec | Python enc/dec | Node enc/dec |
|-------|-------------:|-----------:|---------------:|-------------:|
| 64 B  |   72 / 94    |   54 / 40  |    12 / 7      |    4 / 6     |
| 256 B |  259 / 352   |  116 / 145 |    44 / 28     |   16 / 23    |
| 1 KB  |  950 / 1190  |  396 / 459 |   167 / 78     |   62 / 78    |
| 16 KB | 3690 / 5070  | 1232 / 2171|  1490 / 1200   |  242 / 520   |
| 64 KB | 4490 / 5030  | 1289 / 2365|  4130 / 2810   |  410 / 873   |
| 1 MB  | 1162 / 1620  | 1503 / 3189|  1040 / 952    |  644 / 1150  |

All bindings reach hundreds of MB/s to multiple GB/s once payloads are large
enough to amortize per-call overhead — i.e. all are bound by the same hardware
AES-GCM underneath. The native bindings (Rust/Go) lead at small payloads where
runtime overhead matters most.

## Key derivation cost

Password mode runs **PBKDF2-HMAC-SHA256 with 600,000 iterations** (OWASP 2023
floor). This is a deliberate, one-time cost per Shield instance — reuse the
instance for many operations.

| Language | PBKDF2 (600k) |
|----------|--------------:|
| Rust     |    ~107 ms    |
| Go       |    ~127 ms    |
| Python   |    ~148 ms    |
| Node     |    ~288 ms    |

```rust
// Slow: re-derives the key every time (~107 ms each)
for msg in &messages {
    Shield::new("password", "service").encrypt(msg)?;
}

// Fast: derive once, reuse
let shield = Shield::new("password", "service"); // ~107 ms once
for msg in &messages {
    shield.encrypt(msg)?;                          // sub-µs each
}
```

### Decrypt-side key caching

Password-mode *decryption* derives the key from the **sender's** salt carried in
the message header. Because two parties sharing a password each pick their own
random salt, a peer's salt differs from yours, so a naive implementation would
re-run the full 600k-iteration PBKDF2 on **every inbound message**.

All bindings (Rust, Go, Python, JS, and the others) therefore keep a salt-keyed
cache of derived master keys: the first message from a given sender pays the
PBKDF2 cost once, and subsequent messages from that sender decrypt in
microseconds. The cache holds only derived keys (not passwords), is self-rate-
limited (each new entry costs a full PBKDF2 to populate), and in the Rust
implementation is zeroized when the `Shield` is dropped. This does not affect the
wire format or cross-language interop — output is identical with or without it.

## Running the benchmarks

```bash
# Rust (source of truth). --no-default-features --features std skips the CLI bin,
# which avoids a Windows-only cdylib+bin link quirk (cargo #6313) during `bench`.
cd shield-core
cargo bench --bench encrypt_bench --no-default-features --features std

# Go
cd go && go test -bench=. -run='^$' -benchtime=1s ./shield/

# Python
python -X utf8 tests/bench/bench.py

# Node
node tests/bench/bench.js
```

## Optimization tips

- **Reuse instances.** Pay PBKDF2 once; encrypt/decrypt many times.
- **Pre-shared-key mode** (`with_key` / `quick_encrypt`) skips PBKDF2 entirely
  for machine-to-machine keys from a KMS/enclave.
- **Bulk data** (video, backups, large files): use `StreamCipher` for chunked
  processing instead of a single `encrypt()` of the whole payload.
- **Pick the suite to match the hardware.** AES-256-GCM where AES-NI exists
  (almost all server/desktop x86 and modern ARM); ChaCha20-Poly1305 otherwise.
