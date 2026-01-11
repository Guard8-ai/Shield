# Shield Performance Benchmarks

Comparative benchmarks measuring Shield's SHA256-CTR cipher against industry-standard AES-256-GCM and ChaCha20-Poly1305.

**Test Environment**: Linux 6.18.3, AMD/Intel x64, Rust 1.76+

## Summary

| Algorithm | 1KB Throughput | 1MB Throughput | Key Derivation |
|-----------|----------------|----------------|----------------|
| **AES-256-GCM** | ~2.1 GB/s | ~3.4 GB/s | N/A (pre-shared key) |
| **ChaCha20-Poly1305** | ~775 MB/s | ~1.1 GB/s | N/A (pre-shared key) |
| **Shield (SHA256-CTR)** | ~190 MB/s | ~161 MB/s | ~29ms (100k PBKDF2) |

## Analysis

### Why Shield is Slower

Shield uses SHA-256 for keystream generation instead of:
- **AES-NI**: Hardware-accelerated AES instructions (available on most x86/ARM CPUs)
- **ChaCha20**: Optimized SIMD implementations

This is a deliberate trade-off:
1. **Simplicity**: One primitive (SHA-256) instead of two (AES + GHASH)
2. **Portability**: SHA-256 is easier to implement correctly
3. **Philosophy**: Hash-based construction for consistency with EXPTIME model

### When Shield Speed is Sufficient

| Use Case | Data Size | Shield Time | Verdict |
|----------|-----------|-------------|---------|
| API tokens | 64 B | ~1 µs | ✅ Fast enough |
| JSON payloads | 256 B | ~1.7 µs | ✅ Fast enough |
| Config files | 1 KB | ~5 µs | ✅ Fast enough |
| Small documents | 16 KB | ~87 µs | ✅ Fast enough |
| Images | 64 KB | ~276 µs | ✅ Fast enough |
| Large files | 1 MB | ~6 ms | ⚠️ Consider streaming |
| Video/large data | 100+ MB | ~600+ ms | ❌ Use StreamCipher |

### Key Derivation Cost

Shield's PBKDF2 with 100,000 iterations takes ~29ms. This is intentional:
- Prevents brute-force password attacks
- One-time cost per session
- Reuse Shield instance for multiple operations

```rust
// Slow: New derivation each time
for msg in messages {
    let s = Shield::new("password", "service");  // 29ms each!
    s.encrypt(msg);
}

// Fast: Reuse instance
let s = Shield::new("password", "service");  // 29ms once
for msg in messages {
    s.encrypt(msg);  // ~µs each
}
```

## Detailed Results

### Encryption Throughput

| Size | Shield | AES-256-GCM | ChaCha20-Poly1305 |
|------|--------|-------------|-------------------|
| 64 B | 53 MB/s | 797 MB/s | 208 MB/s |
| 256 B | 144 MB/s | 945 MB/s | 381 MB/s |
| 1 KB | 190 MB/s | 2.1 GB/s | 775 MB/s |
| 16 KB | 179 MB/s | 5.8 GB/s | 1.0 GB/s |
| 64 KB | 227 MB/s | 3.5 GB/s | 1.0 GB/s |
| 1 MB | 161 MB/s | 3.4 GB/s | 1.1 GB/s |

### Decryption Throughput

| Size | Shield | AES-256-GCM | ChaCha20-Poly1305 |
|------|--------|-------------|-------------------|
| 64 B | ~50 MB/s | 792 MB/s | 186 MB/s |
| 256 B | ~140 MB/s | 2.1 GB/s | 481 MB/s |
| 1 KB | ~180 MB/s | 3.5 GB/s | 1.4 GB/s |
| 16 KB | ~175 MB/s | 5.0 GB/s | 1.0 GB/s |
| 64 KB | ~220 MB/s | 4.0 GB/s | 1.1 GB/s |
| 1 MB | ~160 MB/s | 3.5 GB/s | 1.0 GB/s |

## Running Benchmarks

```bash
# Full benchmark suite
cd shield-core && cargo bench

# Quick benchmark (fewer iterations)
cargo bench -- --quick

# Specific benchmark
cargo bench -- shield_encrypt
cargo bench -- aes_gcm
cargo bench -- chacha20
```

## Optimization Tips

### For High Throughput

```rust
// Use StreamCipher for large files (per-chunk parallelization)
use shield_core::StreamCipher;

let cipher = StreamCipher::new(key);
cipher.encrypt_file("large.bin", "large.enc")?;
```

### For Latency-Sensitive Applications

```rust
// Pre-derive keys at startup
lazy_static! {
    static ref SHIELD: Shield = Shield::new("password", "service");
}

// Use pre-shared keys (skip PBKDF2)
let key = /* from secure storage */;
let encrypted = shield_core::quick_encrypt(&key, data)?;
```

### For Bulk Operations

```rust
// Batch encrypt with same instance
let shield = Shield::new("password", "service");
let encrypted: Vec<_> = messages.iter()
    .map(|m| shield.encrypt(m).unwrap())
    .collect();
```

## Security vs Performance Trade-offs

| Priority | Recommendation |
|----------|----------------|
| Maximum security | Use Shield (EXPTIME guarantee) |
| High throughput + security | Use AES-GCM (hardware accelerated) |
| No hardware AES + security | Use ChaCha20-Poly1305 |
| Cross-language interop | Use Shield (10 identical implementations) |

Shield's ~150-200 MB/s is sufficient for:
- API request/response encryption
- Configuration and secret storage
- Message-level encryption
- Database field encryption

For bulk data (videos, backups, large files), consider:
- `StreamCipher` with chunked processing
- Hardware-accelerated alternatives for transit encryption
- Shield for keys/metadata, AES for bulk content
