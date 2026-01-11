//! Performance benchmarks comparing Shield to AES-GCM and ChaCha20-Poly1305.
//!
//! Run with: `cargo bench`
//!
//! Results show operations per second and throughput in MB/s.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305, AES_256_GCM};
use shield_core::Shield;

const KB: usize = 1024;
const MB: usize = 1024 * KB;

/// Test data sizes
const SIZES: &[usize] = &[
    64,          // Tiny: API token
    256,         // Small: JSON payload
    1 * KB,      // 1 KB: Config file
    16 * KB,     // 16 KB: Small document
    64 * KB,     // 64 KB: Image thumbnail
    1 * MB,      // 1 MB: Document
];

fn generate_data(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 256) as u8).collect()
}

fn shield_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("shield_encrypt");

    let shield = Shield::new("benchmark_password", "benchmark.service");

    for size in SIZES {
        let data = generate_data(*size);
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format_size(*size)),
            &data,
            |b, data| {
                b.iter(|| shield.encrypt(black_box(data)).unwrap());
            },
        );
    }

    group.finish();
}

fn shield_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("shield_decrypt");

    let shield = Shield::new("benchmark_password", "benchmark.service");

    for size in SIZES {
        let data = generate_data(*size);
        let encrypted = shield.encrypt(&data).unwrap();

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format_size(*size)),
            &encrypted,
            |b, encrypted| {
                b.iter(|| shield.decrypt(black_box(encrypted)).unwrap());
            },
        );
    }

    group.finish();
}

fn aes_gcm_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes_gcm_encrypt");

    let key_bytes = [0x42u8; 32];
    let unbound_key = UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap();
    let key = LessSafeKey::new(unbound_key);

    for size in SIZES {
        let data = generate_data(*size);
        let nonce_bytes = [0u8; 12];

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format_size(*size)),
            &data,
            |b, data| {
                b.iter(|| {
                    let mut in_out = data.clone();
                    in_out.reserve(AES_256_GCM.tag_len());
                    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
                    key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
                        .unwrap();
                    black_box(in_out)
                });
            },
        );
    }

    group.finish();
}

fn aes_gcm_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes_gcm_decrypt");

    let key_bytes = [0x42u8; 32];
    let unbound_key = UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap();
    let key = LessSafeKey::new(unbound_key);

    for size in SIZES {
        let data = generate_data(*size);
        let nonce_bytes = [0u8; 12];

        // Pre-encrypt for decrypt benchmark
        let mut encrypted = data.clone();
        encrypted.reserve(AES_256_GCM.tag_len());
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        key.seal_in_place_append_tag(nonce, Aad::empty(), &mut encrypted)
            .unwrap();

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format_size(*size)),
            &encrypted,
            |b, encrypted| {
                b.iter(|| {
                    let mut in_out = encrypted.clone();
                    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
                    key.open_in_place(nonce, Aad::empty(), &mut in_out).unwrap();
                    black_box(in_out)
                });
            },
        );
    }

    group.finish();
}

fn chacha20_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("chacha20_encrypt");

    let key_bytes = [0x42u8; 32];
    let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, &key_bytes).unwrap();
    let key = LessSafeKey::new(unbound_key);

    for size in SIZES {
        let data = generate_data(*size);
        let nonce_bytes = [0u8; 12];

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format_size(*size)),
            &data,
            |b, data| {
                b.iter(|| {
                    let mut in_out = data.clone();
                    in_out.reserve(CHACHA20_POLY1305.tag_len());
                    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
                    key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
                        .unwrap();
                    black_box(in_out)
                });
            },
        );
    }

    group.finish();
}

fn chacha20_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("chacha20_decrypt");

    let key_bytes = [0x42u8; 32];
    let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, &key_bytes).unwrap();
    let key = LessSafeKey::new(unbound_key);

    for size in SIZES {
        let data = generate_data(*size);
        let nonce_bytes = [0u8; 12];

        // Pre-encrypt for decrypt benchmark
        let mut encrypted = data.clone();
        encrypted.reserve(CHACHA20_POLY1305.tag_len());
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        key.seal_in_place_append_tag(nonce, Aad::empty(), &mut encrypted)
            .unwrap();

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format_size(*size)),
            &encrypted,
            |b, encrypted| {
                b.iter(|| {
                    let mut in_out = encrypted.clone();
                    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
                    key.open_in_place(nonce, Aad::empty(), &mut in_out).unwrap();
                    black_box(in_out)
                });
            },
        );
    }

    group.finish();
}

fn shield_key_derivation(c: &mut Criterion) {
    c.bench_function("shield_key_derivation", |b| {
        b.iter(|| {
            Shield::new(
                black_box("benchmark_password"),
                black_box("benchmark.service"),
            )
        });
    });
}

fn format_size(bytes: usize) -> String {
    if bytes >= MB {
        format!("{}MB", bytes / MB)
    } else if bytes >= KB {
        format!("{}KB", bytes / KB)
    } else {
        format!("{}B", bytes)
    }
}

criterion_group!(
    benches,
    shield_encrypt,
    shield_decrypt,
    aes_gcm_encrypt,
    aes_gcm_decrypt,
    chacha20_encrypt,
    chacha20_decrypt,
    shield_key_derivation,
);

criterion_main!(benches);
