'use strict';

const { test } = require('node:test');
const assert = require('node:assert');

const { shieldMiddleware } = require('../integrations/express');
const { Shield } = require('../src/shield');

const PASSWORD = 'a-high-entropy-test-password';
const SERVICE = 'express.test';

function makeRes() {
    const res = { statusCode: 200, body: undefined };
    res.status = (code) => {
        res.statusCode = code;
        return res;
    };
    res.json = (data) => {
        res.body = data;
        return res;
    };
    return res;
}

function runMiddleware(res) {
    const mw = shieldMiddleware({ password: PASSWORD, service: SERVICE });
    let called = false;
    mw({ path: '/api/data' }, res, () => {
        called = true;
    });
    assert.strictEqual(called, true, 'next() must be called');
}

test('shieldMiddleware encrypts res.json payloads', () => {
    const res = makeRes();
    runMiddleware(res);

    res.json({ secret: 'top-secret' });

    assert.strictEqual(res.body.encrypted, true);
    assert.ok(typeof res.body.data === 'string' && res.body.data.length > 0);

    // The envelope must actually decrypt back to the original plaintext.
    const shield = new Shield(PASSWORD, SERVICE);
    const decrypted = shield.decrypt(Buffer.from(res.body.data, 'base64'));
    assert.deepStrictEqual(JSON.parse(decrypted.toString()), { secret: 'top-secret' });
});

test('shieldMiddleware fails CLOSED on encryption error (no plaintext leak)', () => {
    const res = makeRes();
    runMiddleware(res);

    // A BigInt makes JSON.stringify throw inside the wrapper, exercising the
    // error path. The response must NOT contain the plaintext.
    res.json({ secret: 'top-secret', big: 10n });

    assert.strictEqual(res.statusCode, 500, 'must respond 500 on encryption error');
    assert.strictEqual(res.body.encrypted, false);
    assert.ok(!('secret' in res.body), 'must not leak the plaintext payload');
    assert.ok(!('big' in res.body), 'must not leak the plaintext payload');
});
