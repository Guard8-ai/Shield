/**
 * Conformance: reproduce the Rust-generated v4 vectors byte-for-byte.
 *
 * Proves the JS binding derives the same master + AEAD keys, reproduces every
 * deterministic ciphertext BYTE-FOR-BYTE, and decrypts each back to plaintext.
 * This is the cross-language byte-identity gate against silent format drift.
 */

const { test, describe } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const {
    Shield,
    SALT_SIZE,
    _deriveAeadKey,
    _sealDeterministic,
    _openCiphertext,
    SUITE_AES_256_GCM,
    SUITE_CHACHA20_POLY1305
} = require('../src/shield');

const VECTORS = JSON.parse(
    fs.readFileSync(path.join(__dirname, '..', '..', 'tests', 'v4_test_vectors.json'), 'utf8')
);

function allVectors() {
    return [...VECTORS.deterministic_vectors, ...(VECTORS.deterministic_vectors_chacha || [])];
}

function suiteByte(v) {
    return v.suite === '0x02' ? SUITE_CHACHA20_POLY1305 : SUITE_AES_256_GCM;
}

function masterFor(v) {
    if (v.mode === 'password') {
        const s = new Shield(v.password, v.service, {
            salt: Buffer.from(v.salt_hex, 'hex'),
            iterations: v.iterations,
            maxAgeMs: null
        });
        return s.key;
    }
    return Buffer.from(v.key_hex, 'hex');
}

describe('v4 conformance vectors', () => {
    for (const v of allVectors()) {
        test(`KDF matches: ${v.name}`, () => {
            const master = masterFor(v);
            assert.equal(master.toString('hex'), v.master_key_hex, 'master key drift');
            assert.equal(_deriveAeadKey(master).toString('hex'), v.aead_key_hex, 'AEAD key drift');
        });

        test(`reproduces bytes: ${v.name}`, () => {
            const master = masterFor(v);
            const aeadKey = _deriveAeadKey(master);
            const salt = v.mode === 'password' ? Buffer.from(v.salt_hex, 'hex') : null;
            const out = _sealDeterministic(
                aeadKey,
                suiteByte(v),
                salt,
                Buffer.from(v.nonce_hex, 'hex'),
                v.timestamp_ms,
                v.pad_len,
                Buffer.from(v.padding_hex, 'hex'),
                Buffer.from(v.plaintext_hex, 'hex')
            );
            assert.equal(out.toString('hex'), v.expected_output_hex, `BYTE DRIFT in ${v.name}`);
        });

        test(`decrypts: ${v.name}`, () => {
            const master = masterFor(v);
            const aeadKey = _deriveAeadKey(master);
            const encrypted = Buffer.from(v.expected_output_hex, 'hex');
            const aadLen = v.mode === 'password' ? 2 + SALT_SIZE : 2;
            const opened = _openCiphertext(aeadKey, suiteByte(v), encrypted, aadLen, null);
            assert.equal(opened.toString('hex'), v.plaintext_hex, `decrypt failed for ${v.name}`);
        });
    }
});
