'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const { ShieldChannel, ChannelConfig } = require('../src/channel');

const VECTORS_PATH = path.join(__dirname, '..', '..', 'tests', 'channel_session_vectors.json');

describe('ShieldChannel session key', () => {
    test('depends on the service identifier', () => {
        // Same password/salt/contributions but a different service must yield a
        // different session key, so a shared secret provisioned for one service
        // cannot establish a channel for another (domain separation).
        const salt = Buffer.alloc(16, 0x07);
        const contribution = Buffer.alloc(32, 0x09);

        // _computeSessionKey does not use `this`; call it on a bare object.
        const compute = ShieldChannel.prototype._computeSessionKey;
        const keyA = compute.call({}, new ChannelConfig('same-password', 'service-a'), salt, contribution, contribution);
        const keyB = compute.call({}, new ChannelConfig('same-password', 'service-b'), salt, contribution, contribution);

        assert.ok(!keyA.equals(keyB), 'session key must be bound to the service identifier');
    });

    test('reproduces the shared cross-language conformance vectors', () => {
        // Rust (shield-core) is the source of truth; Go/JS/Python/Android all
        // read tests/channel_session_vectors.json and must match byte-for-byte.
        // Anchors PAKEExchange.derive/combine + the session mix vs divergence.
        const doc = JSON.parse(fs.readFileSync(VECTORS_PATH, 'utf8'));
        const compute = ShieldChannel.prototype._computeSessionKey;
        for (const vec of doc.vectors) {
            const config = new ChannelConfig(vec.password, vec.service, vec.iterations);
            const key = compute.call(
                {},
                config,
                Buffer.from(vec.salt_hex, 'hex'),
                Buffer.from(vec.local_contribution_hex, 'hex'),
                Buffer.from(vec.remote_contribution_hex, 'hex'),
            );
            assert.strictEqual(
                Buffer.from(key).toString('hex'),
                vec.expected_session_key_hex,
                vec.name,
            );
        }
    });
});
