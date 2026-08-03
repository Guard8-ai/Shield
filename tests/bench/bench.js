// Micro-benchmark for the v4 Shield JS binding.
// Measures encrypt/decrypt throughput at several payload sizes + KDF cost.
// Run: node tests/bench/bench.js

const { Shield } = require('../../javascript/src/shield.js');

const KB = 1024;
const MB = 1024 * KB;
const SIZES = [64, 256, KB, 16 * KB, 64 * KB, MB];

function fmtSize(n) {
    if (n >= MB) return `${n / MB}MB`;
    if (n >= KB) return `${n / KB}KB`;
    return `${n}B`;
}

function fmtThrpt(bps) {
    if (bps >= 1e9) return `${(bps / 1e9).toFixed(2)} GB/s`;
    return `${Math.round(bps / 1e6)} MB/s`;
}

function benchOp(fn, minMs = 500) {
    for (let i = 0; i < 3; i++) fn();
    let iters = 0;
    const start = process.hrtime.bigint();
    while (Number(process.hrtime.bigint() - start) / 1e6 < minMs) {
        for (let i = 0; i < 50; i++) fn();
        iters += 50;
    }
    const elapsed = Number(process.hrtime.bigint() - start) / 1e9;
    return iters / elapsed;
}

function main() {
    const shield = new Shield('benchmark_password', 'benchmark.service');
    console.log(`# Shield JS binding (v4) — Node ${process.version}`);
    console.log();
    console.log(`${'Size'.padStart(6)} | ${'Encrypt'.padStart(12)} | ${'Decrypt'.padStart(12)}`);
    console.log(`${'-'.repeat(6)}-+-${'-'.repeat(12)}-+-${'-'.repeat(12)}`);
    for (const size of SIZES) {
        const data = Buffer.alloc(size);
        for (let i = 0; i < size; i++) data[i] = i % 256;
        const ct = shield.encrypt(data);
        const encOps = benchOp(() => shield.encrypt(data));
        const decOps = benchOp(() => shield.decrypt(ct));
        console.log(`${fmtSize(size).padStart(6)} | ${fmtThrpt(encOps * size).padStart(12)} | ${fmtThrpt(decOps * size).padStart(12)}`);
    }

    const n = 5;
    const t0 = process.hrtime.bigint();
    for (let i = 0; i < n; i++) new Shield('benchmark_password', 'benchmark.service');
    const kdfMs = Number(process.hrtime.bigint() - t0) / 1e6 / n;
    console.log();
    console.log(`Key derivation (PBKDF2 600k): ${Math.round(kdfMs)} ms`);
}

main();
