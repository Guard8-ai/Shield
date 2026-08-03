import { test } from 'node:test';
import assert from 'node:assert';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  HybridPrivateKey,
  HybridPublicKey,
  initiate,
  PUBLIC_BUNDLE_SIZE,
  HANDSHAKE_SIZE,
  PRIVATE_KEY_SIZE,
} from '../src/pqhybrid.mjs';

const toHex = (b) => Buffer.from(b).toString('hex');
const fromHex = (h) => Uint8Array.from(Buffer.from(h, 'hex'));

const vectorsPath = fileURLToPath(new URL('../../tests/pq_kex_vectors.json', import.meta.url));
const vectors = JSON.parse(readFileSync(vectorsPath)).vectors;

test('initiate/accept round-trip derives the same key', () => {
  const bob = HybridPrivateKey.generate();
  const { handshake, sharedKey } = initiate(bob.publicKey());
  assert.strictEqual(handshake.length, HANDSHAKE_SIZE);
  assert.strictEqual(sharedKey.length, 32);
  assert.deepStrictEqual(bob.accept(handshake), sharedKey);
});

test('private/public key serialization round-trips', () => {
  const bob = HybridPrivateKey.generate();
  assert.strictEqual(bob.toBytes().length, PRIVATE_KEY_SIZE);
  assert.strictEqual(bob.publicKey().toBytes().length, PUBLIC_BUNDLE_SIZE);

  const restored = HybridPrivateKey.fromBytes(bob.toBytes());
  assert.deepStrictEqual(restored.publicKey().toBytes(), bob.publicKey().toBytes());

  const pub = HybridPublicKey.fromBytes(bob.publicKey().toBytes());
  const { handshake, sharedKey } = initiate(pub);
  assert.deepStrictEqual(restored.accept(handshake), sharedKey);
});

test('rejects wrong sizes', () => {
  const bob = HybridPrivateKey.generate();
  assert.throws(() => bob.accept(new Uint8Array(10)));
  assert.throws(() => HybridPublicKey.fromBytes(new Uint8Array(10)));
  assert.throws(() => HybridPrivateKey.fromBytes(new Uint8Array(10)));
});

test('matches cross-language conformance vectors', () => {
  assert.ok(vectors.length > 0);
  for (const v of vectors) {
    const bob = HybridPrivateKey.fromBytes(fromHex(v.bob_private_hex));
    assert.strictEqual(
      toHex(bob.publicKey().toBytes()),
      v.bob_public_bundle_hex,
      `public bundle mismatch for ${v.name}`,
    );
    const shared = bob.accept(fromHex(v.handshake_hex));
    assert.strictEqual(
      toHex(shared),
      v.expected_shared_key_hex,
      `shared key mismatch for ${v.name}`,
    );
  }
});
