'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');

const { StreamCipher, computeEofTag } = require('../src/stream');

describe('StreamCipher authenticated end-of-stream tag', () => {
    const GOLDEN_HEX =
        '52d4dfbeccc364bd69a2f232aa460bd1eb79b0c93903f344dd7b937703918431';

    test('eof_tag_conformance_vector', () => {
        // Cross-language golden vector: master_key = 32 x 0x42,
        // stream_salt = 16 x 0x01, chunk_count = 3.
        const tag = computeEofTag(
            Buffer.alloc(32, 0x42),
            Buffer.alloc(16, 0x01),
            3
        );
        assert.strictEqual(tag.toString('hex'), GOLDEN_HEX);
    });

    test('roundtrip still works', () => {
        const key = crypto.randomBytes(32);
        const cipher = new StreamCipher(key, 16);
        const data = crypto.randomBytes(64);
        const decrypted = cipher.decrypt(cipher.encrypt(data));
        assert.ok(decrypted.equals(data));
    });

    test('truncation_rejected', () => {
        const key = crypto.randomBytes(32);
        const cipher = new StreamCipher(key, 16);
        const encrypted = cipher.encrypt(crypto.randomBytes(64)); // 4 chunks

        // Header (20) + framed chunk (4 + 48 = 52) per chunk. Keep header +
        // first two chunk frames, drop the rest and the trailer.
        const truncated = encrypted.slice(0, 20 + 2 * 52);
        assert.ok(truncated.length < encrypted.length);

        assert.throws(() => cipher.decrypt(truncated));
    });

    test('forged_marker_rejected', () => {
        const key = crypto.randomBytes(32);
        const cipher = new StreamCipher(key, 16);
        const encrypted = cipher.encrypt(crypto.randomBytes(64)); // 4 chunks

        // Same prefix but append a bare 4-zero marker with no valid tag.
        const forged = Buffer.concat([
            encrypted.slice(0, 20 + 2 * 52),
            Buffer.from([0, 0, 0, 0])
        ]);

        assert.throws(() => cipher.decrypt(forged));
    });
});
