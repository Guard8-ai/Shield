'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert');

const { ShieldChannel, ChannelConfig } = require('../src/channel');

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
});
