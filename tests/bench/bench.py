"""Micro-benchmark for the v4 Shield Python binding.

Measures encrypt/decrypt throughput at several payload sizes plus the
PBKDF2 key-derivation cost. Output is a compact table; numbers are
median of repeated timed batches.

Run: python -X utf8 tests/bench/bench.py
"""

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "python"))

from shield import Shield  # noqa: E402

KB = 1024
MB = 1024 * KB
SIZES = [64, 256, KB, 16 * KB, 64 * KB, MB]


def fmt_size(n):
    if n >= MB:
        return f"{n // MB}MB"
    if n >= KB:
        return f"{n // KB}KB"
    return f"{n}B"


def fmt_thrpt(bytes_per_s):
    if bytes_per_s >= 1e9:
        return f"{bytes_per_s / 1e9:.2f} GB/s"
    return f"{bytes_per_s / 1e6:.0f} MB/s"


def bench_op(fn, payload_size, min_time=0.5):
    """Run fn() repeatedly for >= min_time, return ops/sec."""
    # Warm up
    for _ in range(3):
        fn()
    iters = 0
    start = time.perf_counter()
    while time.perf_counter() - start < min_time:
        for _ in range(50):
            fn()
        iters += 50
    elapsed = time.perf_counter() - start
    return iters / elapsed


def main():
    shield = Shield("benchmark_password", "benchmark.service")

    print(f"# Shield Python binding (v4) — {sys.version.split()[0]}")
    print()
    print(f"{'Size':>6} | {'Encrypt':>12} | {'Decrypt':>12}")
    print(f"{'-'*6}-+-{'-'*12}-+-{'-'*12}")
    for size in SIZES:
        data = bytes((i % 256) for i in range(size))
        ct = shield.encrypt(data)
        enc_ops = bench_op(lambda: shield.encrypt(data), size)
        dec_ops = bench_op(lambda: shield.decrypt(ct), size)
        print(f"{fmt_size(size):>6} | {fmt_thrpt(enc_ops * size):>12} | {fmt_thrpt(dec_ops * size):>12}")

    # KDF cost
    t0 = time.perf_counter()
    n = 5
    for _ in range(n):
        Shield("benchmark_password", "benchmark.service")
    kdf_ms = (time.perf_counter() - t0) / n * 1000
    print()
    print(f"Key derivation (PBKDF2 600k): {kdf_ms:.0f} ms")


if __name__ == "__main__":
    main()
