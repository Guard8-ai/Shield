/**
 * Shield tests using Node.js built-in test runner.
 */

const { test, describe } = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');

const { Shield, quickEncrypt, quickDecrypt } = require('../src/shield');
const { StreamCipher } = require('../src/stream');
const { RatchetSession } = require('../src/ratchet');
const { TOTP, RecoveryCodes } = require('../src/totp');

// ============================================================================
// Shield Core Tests
// ============================================================================

describe('Shield', () => {
    test('encrypt and decrypt', () => {
        const s = new Shield('password', 'test.service');
        const plaintext = Buffer.from('Hello, World!');
        const encrypted = s.encrypt(plaintext);
        const decrypted = s.decrypt(encrypted);
        assert.deepEqual(decrypted, plaintext);
    });

    test('different passwords produce different ciphertext', () => {
        const s1 = new Shield('password1', 'service');
        const s2 = new Shield('password2', 'service');
        const plaintext = Buffer.from('secret');
        const enc1 = s1.encrypt(plaintext);
        const enc2 = s2.encrypt(plaintext);
        assert.notDeepEqual(enc1, enc2);
    });

    test('wrong password fails', () => {
        const s1 = new Shield('correct', 'service');
        const s2 = new Shield('wrong', 'service');
        const encrypted = s1.encrypt(Buffer.from('secret'));
        const decrypted = s2.decrypt(encrypted);
        assert.equal(decrypted, null);
    });

    test('tampered ciphertext fails', () => {
        const s = new Shield('password', 'service');
        const encrypted = s.encrypt(Buffer.from('secret'));
        // Tamper with ciphertext
        encrypted[20] ^= 0xFF;
        const decrypted = s.decrypt(encrypted);
        assert.equal(decrypted, null);
    });

    test('withKey creates instance from raw key', () => {
        const key = crypto.randomBytes(32);
        const s = Shield.withKey(key);
        const plaintext = Buffer.from('test');
        const encrypted = s.encrypt(plaintext);
        const decrypted = s.decrypt(encrypted);
        assert.deepEqual(decrypted, plaintext);
    });

    test('withKey rejects invalid key lengths', () => {
        assert.throws(() => Shield.withKey(Buffer.from('short')));
    });

    test('same password/service produces same key', () => {
        const s1 = new Shield('password', 'service');
        const s2 = new Shield('password', 'service');
        assert.deepEqual(s1.key, s2.key);
    });
});

describe('quickEncrypt/quickDecrypt', () => {
    test('basic encrypt/decrypt', () => {
        const key = crypto.randomBytes(32);
        const plaintext = Buffer.from('Hello!');
        const encrypted = quickEncrypt(key, plaintext);
        const decrypted = quickDecrypt(key, encrypted);
        assert.deepEqual(decrypted, plaintext);
    });

    test('wrong key fails', () => {
        const key1 = crypto.randomBytes(32);
        const key2 = crypto.randomBytes(32);
        const encrypted = quickEncrypt(key1, Buffer.from('secret'));
        const decrypted = quickDecrypt(key2, encrypted);
        assert.equal(decrypted, null);
    });

    test('tampered ciphertext fails', () => {
        const key = crypto.randomBytes(32);
        const encrypted = quickEncrypt(key, Buffer.from('secret'));
        encrypted[10] ^= 0xFF;
        const decrypted = quickDecrypt(key, encrypted);
        assert.equal(decrypted, null);
    });
});

// ============================================================================
// StreamCipher Tests
// ============================================================================

describe('StreamCipher', () => {
    test('encrypt and decrypt in memory', () => {
        const key = crypto.randomBytes(32);
        const cipher = new StreamCipher(key);
        const plaintext = Buffer.from('Hello, streaming world!');
        const encrypted = cipher.encrypt(plaintext);
        const decrypted = cipher.decrypt(encrypted);
        assert.deepEqual(decrypted, plaintext);
    });

    test('fromPassword', () => {
        const salt = crypto.randomBytes(16);
        const cipher = StreamCipher.fromPassword('password', salt);
        const plaintext = Buffer.from('secret data');
        const encrypted = cipher.encrypt(plaintext);

        const cipher2 = StreamCipher.fromPassword('password', salt);
        const decrypted = cipher2.decrypt(encrypted);
        assert.deepEqual(decrypted, plaintext);
    });

    test('wrong password throws', () => {
        const salt = crypto.randomBytes(16);
        const cipher1 = StreamCipher.fromPassword('correct', salt);
        const cipher2 = StreamCipher.fromPassword('wrong', salt);
        const encrypted = cipher1.encrypt(Buffer.from('secret'));

        assert.throws(() => cipher2.decrypt(encrypted));
    });

    test('large data with multiple chunks', () => {
        const key = crypto.randomBytes(32);
        const cipher = new StreamCipher(key, 1024);
        const plaintext = crypto.randomBytes(10 * 1024);
        const encrypted = cipher.encrypt(plaintext);
        const decrypted = cipher.decrypt(encrypted);
        assert.deepEqual(decrypted, plaintext);
    });
});

// ============================================================================
// RatchetSession Tests
// ============================================================================

describe('RatchetSession', () => {
    test('basic communication', () => {
        const rootKey = crypto.randomBytes(32);
        const alice = new RatchetSession(rootKey, true);
        const bob = new RatchetSession(rootKey, false);

        const plaintext = Buffer.from('Hello Bob!');
        const encrypted = alice.encrypt(plaintext);
        const decrypted = bob.decrypt(encrypted);
        assert.deepEqual(decrypted, plaintext);
    });

    test('bidirectional messages', () => {
        const rootKey = crypto.randomBytes(32);
        const alice = new RatchetSession(rootKey, true);
        const bob = new RatchetSession(rootKey, false);

        // Alice -> Bob
        const enc1 = alice.encrypt(Buffer.from('Hi Bob!'));
        const dec1 = bob.decrypt(enc1);
        assert.deepEqual(dec1, Buffer.from('Hi Bob!'));

        // Bob -> Alice
        const enc2 = bob.encrypt(Buffer.from('Hi Alice!'));
        const dec2 = alice.decrypt(enc2);
        assert.deepEqual(dec2, Buffer.from('Hi Alice!'));
    });

    test('forward secrecy - same message produces different ciphertext', () => {
        const rootKey = crypto.randomBytes(32);
        const alice = new RatchetSession(rootKey, true);

        const enc1 = alice.encrypt(Buffer.from('same message'));
        const enc2 = alice.encrypt(Buffer.from('same message'));
        assert.notDeepEqual(enc1, enc2);
    });

    test('replay protection', () => {
        const rootKey = crypto.randomBytes(32);
        const alice = new RatchetSession(rootKey, true);
        const bob = new RatchetSession(rootKey, false);

        const encrypted = alice.encrypt(Buffer.from('original'));
        const decrypted = bob.decrypt(encrypted);
        assert.deepEqual(decrypted, Buffer.from('original'));

        // Replay fails
        const replayed = bob.decrypt(encrypted);
        assert.equal(replayed, null);
    });

    test('out of order fails', () => {
        const rootKey = crypto.randomBytes(32);
        const alice = new RatchetSession(rootKey, true);
        const bob = new RatchetSession(rootKey, false);

        const enc1 = alice.encrypt(Buffer.from('message 1'));
        const enc2 = alice.encrypt(Buffer.from('message 2'));

        // Try to decrypt out of order
        const dec2 = bob.decrypt(enc2);
        assert.equal(dec2, null);
    });

    test('counters increment', () => {
        const rootKey = crypto.randomBytes(32);
        const alice = new RatchetSession(rootKey, true);
        const bob = new RatchetSession(rootKey, false);

        assert.equal(alice.sendCounter, 0);
        assert.equal(bob.recvCounter, 0);

        const enc = alice.encrypt(Buffer.from('msg'));
        assert.equal(alice.sendCounter, 1);

        bob.decrypt(enc);
        assert.equal(bob.recvCounter, 1);
    });
});

// ============================================================================
// TOTP Tests
// ============================================================================

describe('TOTP', () => {
    test('generate and verify', () => {
        const secret = TOTP.generateSecret();
        const totp = new TOTP(secret);
        const code = totp.generate();
        assert.equal(totp.verify(code), true);
    });

    test('code length', () => {
        const secret = TOTP.generateSecret();
        const totp = new TOTP(secret, { digits: 6 });
        const code = totp.generate();
        assert.equal(code.length, 6);
        assert.match(code, /^\d+$/);
    });

    test('wrong code fails', () => {
        const secret = TOTP.generateSecret();
        const totp = new TOTP(secret);
        assert.equal(totp.verify('000000'), false);
    });

    test('time window', () => {
        const secret = TOTP.generateSecret();
        const totp = new TOTP(secret, { interval: 30 });
        const now = Math.floor(Date.now() / 1000);

        // Code from 30 seconds ago
        const oldCode = totp.generate(now - 30);
        assert.equal(totp.verify(oldCode, now, 1), true);
    });

    test('base32 roundtrip', () => {
        const secret = TOTP.generateSecret();
        const b32 = TOTP.secretToBase32(secret);
        const decoded = TOTP.secretFromBase32(b32);
        assert.deepEqual(decoded, secret);
    });

    test('provisioning URI', () => {
        const secret = TOTP.generateSecret();
        const totp = new TOTP(secret);
        const uri = totp.provisioningUri('user@example.com', 'MyApp');

        assert.match(uri, /^otpauth:\/\/totp\//);
        assert.match(uri, /MyApp:user@example.com/);
        assert.match(uri, /secret=/);
    });

    test('known test vector', () => {
        // Standard test vector from RFC 6238
        const secret = Buffer.from('12345678901234567890');
        const totp = new TOTP(secret, { digits: 8 });
        const code = totp.generate(59);
        assert.equal(code, '94287082');
    });
});

describe('RecoveryCodes', () => {
    test('generate codes', () => {
        const codes = RecoveryCodes.generateCodes();
        assert.equal(codes.length, 10);
        for (const code of codes) {
            assert.match(code, /^[A-F0-9]{4}-[A-F0-9]{4}$/);
        }
    });

    test('verify code', () => {
        const rc = new RecoveryCodes();
        const codes = rc.codes;
        assert.equal(rc.verify(codes[0]), true);
    });

    test('code consumed after use', () => {
        const rc = new RecoveryCodes();
        const code = rc.codes[0];
        assert.equal(rc.verify(code), true);
        assert.equal(rc.verify(code), false);
    });

    test('remaining count', () => {
        const rc = new RecoveryCodes();
        assert.equal(rc.remaining, 10);
        rc.verify(rc.codes[0]);
        assert.equal(rc.remaining, 9);
    });

    test('wrong code fails', () => {
        const rc = new RecoveryCodes();
        assert.equal(rc.verify('XXXX-XXXX'), false);
    });
});

// ============================================================================
// Signatures Tests
// ============================================================================

const { SymmetricSignature, LamportSignature } = require('../src/signatures');

describe('SymmetricSignature', () => {
    test('sign and verify', () => {
        const signer = SymmetricSignature.generate();
        const message = Buffer.from('Hello, World!');
        const signature = signer.sign(message);
        assert.equal(signer.verify(message, signature, signer.verificationKey), true);
    });

    test('wrong key fails', () => {
        const signer1 = SymmetricSignature.generate();
        const signer2 = SymmetricSignature.generate();
        const message = Buffer.from('test');
        const signature = signer1.sign(message);
        assert.equal(signer2.verify(message, signature, signer2.verificationKey), false);
    });

    test('tampered message fails', () => {
        const signer = SymmetricSignature.generate();
        const message = Buffer.from('original');
        const signature = signer.sign(message);
        assert.equal(signer.verify(Buffer.from('tampered'), signature, signer.verificationKey), false);
    });

    test('fromPassword is deterministic', () => {
        const signer1 = SymmetricSignature.fromPassword('password', 'user@example.com');
        const signer2 = SymmetricSignature.fromPassword('password', 'user@example.com');
        assert.deepEqual(signer1.verificationKey, signer2.verificationKey);
    });

    test('fingerprint is consistent', () => {
        const signer = SymmetricSignature.generate();
        const fp1 = signer.getFingerprint();
        const fp2 = signer.getFingerprint();
        assert.equal(fp1, fp2);
        assert.equal(fp1.length, 16);
    });

    test('timestamp signature with maxAge', () => {
        const signer = SymmetricSignature.generate();
        const message = Buffer.from('data');
        const signature = signer.sign(message, true);
        assert.equal(signature.length, 40); // 8 byte timestamp + 32 byte sig
        assert.equal(signer.verify(message, signature, signer.verificationKey, 300), true);
    });
});

describe('LamportSignature', () => {
    test('sign and verify', () => {
        const lamport = LamportSignature.generate();
        const message = Buffer.from('Test message');
        const signature = lamport.sign(message);
        assert.equal(LamportSignature.verify(message, signature, lamport.publicKey), true);
    });

    test('one-time only', () => {
        const lamport = LamportSignature.generate();
        lamport.sign(Buffer.from('first'));
        assert.throws(() => lamport.sign(Buffer.from('second')));
    });

    test('isUsed property', () => {
        const lamport = LamportSignature.generate();
        assert.equal(lamport.isUsed, false);
        lamport.sign(Buffer.from('message'));
        assert.equal(lamport.isUsed, true);
    });

    test('wrong public key fails', () => {
        const lamport1 = LamportSignature.generate();
        const lamport2 = LamportSignature.generate();
        const signature = lamport1.sign(Buffer.from('message'));
        assert.equal(LamportSignature.verify(Buffer.from('message'), signature, lamport2.publicKey), false);
    });
});

// ============================================================================
// Key Exchange Tests
// ============================================================================

const { PAKEExchange, QRExchange, KeySplitter } = require('../src/exchange');

describe('PAKEExchange', () => {
    test('derive produces 32-byte key', () => {
        const salt = PAKEExchange.generateSalt();
        const key = PAKEExchange.derive('password', salt, 'client');
        assert.equal(key.length, 32);
    });

    test('same inputs produce same key', () => {
        const salt = PAKEExchange.generateSalt();
        const key1 = PAKEExchange.derive('password', salt, 'client');
        const key2 = PAKEExchange.derive('password', salt, 'client');
        assert.deepEqual(key1, key2);
    });

    test('different roles produce different keys', () => {
        const salt = PAKEExchange.generateSalt();
        const client = PAKEExchange.derive('password', salt, 'client');
        const server = PAKEExchange.derive('password', salt, 'server');
        assert.notDeepEqual(client, server);
    });

    test('combine produces shared key', () => {
        const salt = PAKEExchange.generateSalt();
        const client = PAKEExchange.derive('password', salt, 'client');
        const server = PAKEExchange.derive('password', salt, 'server');
        const shared = PAKEExchange.combine(client, server);
        assert.equal(shared.length, 32);
    });

    test('combine is order-independent', () => {
        const salt = PAKEExchange.generateSalt();
        const client = PAKEExchange.derive('password', salt, 'client');
        const server = PAKEExchange.derive('password', salt, 'server');
        const shared1 = PAKEExchange.combine(client, server);
        const shared2 = PAKEExchange.combine(server, client);
        assert.deepEqual(shared1, shared2);
    });
});

describe('QRExchange', () => {
    test('encode/decode roundtrip', () => {
        const key = crypto.randomBytes(32);
        const encoded = QRExchange.encode(key);
        const decoded = QRExchange.decode(encoded);
        assert.deepEqual(decoded, key);
    });

    test('generateExchangeData/parseExchangeData', () => {
        const key = crypto.randomBytes(32);
        const metadata = { name: 'test', version: 1 };
        const data = QRExchange.generateExchangeData(key, metadata);
        const [parsedKey, parsedMeta] = QRExchange.parseExchangeData(data);
        assert.deepEqual(parsedKey, key);
        assert.deepEqual(parsedMeta, metadata);
    });
});

describe('KeySplitter', () => {
    test('split and combine', () => {
        const key = crypto.randomBytes(32);
        const shares = KeySplitter.split(key, 3);
        assert.equal(shares.length, 3);
        const recovered = KeySplitter.combine(shares);
        assert.deepEqual(recovered, key);
    });

    test('requires all shares', () => {
        const key = crypto.randomBytes(32);
        const shares = KeySplitter.split(key, 3);
        const partial = KeySplitter.combine([shares[0], shares[1]]);
        assert.notDeepEqual(partial, key);
    });

    test('minimum 2 shares', () => {
        const key = crypto.randomBytes(32);
        assert.throws(() => KeySplitter.split(key, 1));
    });
});

// ============================================================================
// Key Rotation Tests
// ============================================================================

const { KeyRotationManager } = require('../src/rotation');

describe('KeyRotationManager', () => {
    test('encrypt and decrypt', () => {
        const key = crypto.randomBytes(32);
        const manager = new KeyRotationManager(key);
        const plaintext = Buffer.from('Hello, Rotation!');
        const encrypted = manager.encrypt(plaintext);
        const decrypted = manager.decrypt(encrypted);
        assert.deepEqual(decrypted, plaintext);
    });

    test('version embedded in ciphertext', () => {
        const key = crypto.randomBytes(32);
        const manager = new KeyRotationManager(key, 5);
        const encrypted = manager.encrypt(Buffer.from('test'));
        const version = encrypted.readUInt32LE(0);
        assert.equal(version, 5);
    });

    test('rotate key', () => {
        const key1 = crypto.randomBytes(32);
        const manager = new KeyRotationManager(key1);
        const encrypted1 = manager.encrypt(Buffer.from('message 1'));

        const key2 = crypto.randomBytes(32);
        manager.rotate(key2);
        assert.equal(manager.currentVersion, 2);

        const encrypted2 = manager.encrypt(Buffer.from('message 2'));

        // Both decrypt
        assert.deepEqual(manager.decrypt(encrypted1), Buffer.from('message 1'));
        assert.deepEqual(manager.decrypt(encrypted2), Buffer.from('message 2'));
    });

    test('prune old keys', () => {
        const manager = new KeyRotationManager(crypto.randomBytes(32));
        manager.rotate(crypto.randomBytes(32));
        manager.rotate(crypto.randomBytes(32));
        manager.rotate(crypto.randomBytes(32));

        const encrypted1 = manager.encrypt(Buffer.from('test'));
        const pruned = manager.pruneOldKeys(2);
        assert.ok(pruned.length > 0);
        assert.deepEqual(manager.decrypt(encrypted1), Buffer.from('test'));
    });

    test('reEncrypt', () => {
        const manager = new KeyRotationManager(crypto.randomBytes(32));
        const encrypted = manager.encrypt(Buffer.from('original'));
        manager.rotate(crypto.randomBytes(32));

        const reEncrypted = manager.reEncrypt(encrypted);
        const version = reEncrypted.readUInt32LE(0);
        assert.equal(version, 2);
        assert.deepEqual(manager.decrypt(reEncrypted), Buffer.from('original'));
    });

    test('unknown version fails', () => {
        const manager = new KeyRotationManager(crypto.randomBytes(32));
        const encrypted = manager.encrypt(Buffer.from('test'));
        // Corrupt version to unknown
        encrypted.writeUInt32LE(999, 0);
        assert.throws(() => manager.decrypt(encrypted));
    });
});

// ============================================================================
// Group Encryption Tests
// ============================================================================

const { GroupEncryption, BroadcastEncryption } = require('../src/group');

describe('GroupEncryption', () => {
    test('encrypt for multiple members', () => {
        const group = new GroupEncryption();
        const aliceKey = crypto.randomBytes(32);
        const bobKey = crypto.randomBytes(32);

        group.addMember('alice', aliceKey);
        group.addMember('bob', bobKey);

        const plaintext = Buffer.from('Group message!');
        const encrypted = group.encrypt(plaintext);

        assert.ok(encrypted.keys.alice);
        assert.ok(encrypted.keys.bob);
    });

    test('each member can decrypt', () => {
        const group = new GroupEncryption();
        const aliceKey = crypto.randomBytes(32);
        const bobKey = crypto.randomBytes(32);

        group.addMember('alice', aliceKey);
        group.addMember('bob', bobKey);

        const plaintext = Buffer.from('Secret group message');
        const encrypted = group.encrypt(plaintext);

        const aliceDecrypted = GroupEncryption.decrypt(encrypted, 'alice', aliceKey);
        const bobDecrypted = GroupEncryption.decrypt(encrypted, 'bob', bobKey);

        assert.deepEqual(aliceDecrypted, plaintext);
        assert.deepEqual(bobDecrypted, plaintext);
    });

    test('non-member cannot decrypt', () => {
        const group = new GroupEncryption();
        group.addMember('alice', crypto.randomBytes(32));

        const encrypted = group.encrypt(Buffer.from('secret'));
        const eveDecrypted = GroupEncryption.decrypt(encrypted, 'eve', crypto.randomBytes(32));
        assert.equal(eveDecrypted, null);
    });

    test('remove member', () => {
        const group = new GroupEncryption();
        const aliceKey = crypto.randomBytes(32);
        group.addMember('alice', aliceKey);
        group.addMember('bob', crypto.randomBytes(32));

        assert.equal(group.members.length, 2);
        group.removeMember('bob');
        assert.equal(group.members.length, 1);

        const encrypted = group.encrypt(Buffer.from('message'));
        assert.ok(!encrypted.keys.bob);
    });

    test('rotate key', () => {
        const group = new GroupEncryption();
        const oldKey = group.groupKey;
        const returned = group.rotateKey();
        assert.deepEqual(returned, oldKey);
        assert.notDeepEqual(group.groupKey, oldKey);
    });
});

describe('BroadcastEncryption', () => {
    test('encrypt for broadcast', () => {
        const broadcast = new BroadcastEncryption(null, 2);
        const aliceKey = crypto.randomBytes(32);
        const bobKey = crypto.randomBytes(32);

        broadcast.addMember('alice', aliceKey);
        broadcast.addMember('bob', bobKey);

        const plaintext = Buffer.from('Broadcast message!');
        const encrypted = broadcast.encrypt(plaintext);

        const aliceDecrypted = BroadcastEncryption.decrypt(encrypted, 'alice', aliceKey);
        const bobDecrypted = BroadcastEncryption.decrypt(encrypted, 'bob', bobKey);

        assert.deepEqual(aliceDecrypted, plaintext);
        assert.deepEqual(bobDecrypted, plaintext);
    });

    test('subgroup assignment', () => {
        const broadcast = new BroadcastEncryption(null, 2);
        const sg1 = broadcast.addMember('alice', crypto.randomBytes(32));
        const sg2 = broadcast.addMember('bob', crypto.randomBytes(32));
        const sg3 = broadcast.addMember('carol', crypto.randomBytes(32));

        // First two in same subgroup
        assert.equal(sg1, 0);
        assert.equal(sg2, 0);
        // Third in new subgroup
        assert.equal(sg3, 1);
    });
});

// ============================================================================
// Identity/SSO Tests
// ============================================================================

const { IdentityProvider, SecureSession } = require('../src/identity');

describe('IdentityProvider', () => {
    test('register user', () => {
        const provider = new IdentityProvider(crypto.randomBytes(32));
        const identity = provider.register('alice', 'password123', 'Alice Smith');

        assert.equal(identity.userId, 'alice');
        assert.equal(identity.displayName, 'Alice Smith');
        assert.equal(identity.verificationKey.length, 32);
    });

    test('register duplicate fails', () => {
        const provider = new IdentityProvider(crypto.randomBytes(32));
        provider.register('alice', 'password', 'Alice');
        assert.throws(() => provider.register('alice', 'password2', 'Alice 2'));
    });

    test('authenticate success', () => {
        const provider = new IdentityProvider(crypto.randomBytes(32));
        provider.register('alice', 'password123', 'Alice');
        const token = provider.authenticate('alice', 'password123');
        assert.ok(token);
    });

    test('authenticate wrong password', () => {
        const provider = new IdentityProvider(crypto.randomBytes(32));
        provider.register('alice', 'password123', 'Alice');
        const token = provider.authenticate('alice', 'wrongpassword');
        assert.equal(token, null);
    });

    test('authenticate unknown user', () => {
        const provider = new IdentityProvider(crypto.randomBytes(32));
        const token = provider.authenticate('nobody', 'password');
        assert.equal(token, null);
    });

    test('validate token', () => {
        const provider = new IdentityProvider(crypto.randomBytes(32));
        provider.register('alice', 'password', 'Alice');
        const token = provider.authenticate('alice', 'password');
        const session = provider.validateToken(token);

        assert.ok(session);
        assert.equal(session.userId, 'alice');
        assert.equal(session.isExpired, false);
    });

    test('expired token', async () => {
        const provider = new IdentityProvider(crypto.randomBytes(32), 1);
        provider.register('alice', 'password', 'Alice');
        const token = provider.authenticate('alice', 'password');

        await new Promise(resolve => setTimeout(resolve, 2000));

        const session = provider.validateToken(token);
        assert.equal(session, null);
    });

    test('tampered token', () => {
        const provider = new IdentityProvider(crypto.randomBytes(32));
        provider.register('alice', 'password', 'Alice');
        const token = provider.authenticate('alice', 'password');

        const decoded = Buffer.from(token, 'base64url');
        decoded[10] ^= 0xFF;
        const tampered = decoded.toString('base64url');

        const session = provider.validateToken(tampered);
        assert.equal(session, null);
    });

    test('service token', () => {
        const provider = new IdentityProvider(crypto.randomBytes(32));
        provider.register('alice', 'password', 'Alice');
        const sessionToken = provider.authenticate('alice', 'password');

        const serviceToken = provider.createServiceToken(
            sessionToken,
            'api.example.com',
            ['read', 'write']
        );

        const session = provider.validateServiceToken(serviceToken, 'api.example.com');
        assert.ok(session);
        assert.equal(session.userId, 'alice');
        assert.ok(session.permissions.includes('read'));
    });

    test('service token wrong service', () => {
        const provider = new IdentityProvider(crypto.randomBytes(32));
        provider.register('alice', 'password', 'Alice');
        const sessionToken = provider.authenticate('alice', 'password');
        const serviceToken = provider.createServiceToken(sessionToken, 'api.example.com');

        const session = provider.validateServiceToken(serviceToken, 'other.example.com');
        assert.equal(session, null);
    });

    test('refresh token', () => {
        const provider = new IdentityProvider(crypto.randomBytes(32));
        provider.register('alice', 'password', 'Alice');
        const token1 = provider.authenticate('alice', 'password');
        const token2 = provider.refreshToken(token1);

        assert.ok(token2);
        assert.notEqual(token2, token1);

        const session = provider.validateToken(token2);
        assert.equal(session.userId, 'alice');
    });

    test('revoke user', () => {
        const provider = new IdentityProvider(crypto.randomBytes(32));
        provider.register('alice', 'password', 'Alice');

        assert.ok(provider.getIdentity('alice'));
        provider.revokeUser('alice');
        assert.equal(provider.getIdentity('alice'), null);
    });

    test('permissions in token', () => {
        const provider = new IdentityProvider(crypto.randomBytes(32));
        provider.register('alice', 'password', 'Alice');

        const token = provider.authenticate('alice', 'password', ['admin', 'user']);
        const session = provider.validateToken(token);

        assert.ok(session.permissions.includes('admin'));
        assert.ok(session.permissions.includes('user'));
    });
});

describe('SecureSession', () => {
    test('encrypt decrypt', () => {
        const session = new SecureSession(crypto.randomBytes(32));
        const plaintext = Buffer.from('session data');
        const encrypted = session.encrypt(plaintext);
        const decrypted = session.decrypt(encrypted);
        assert.deepEqual(decrypted, plaintext);
    });

    test('tampered data fails', () => {
        const session = new SecureSession(crypto.randomBytes(32));
        const encrypted = Buffer.from(session.encrypt(Buffer.from('data')));
        encrypted[20] ^= 0xFF;
        const result = session.decrypt(encrypted);
        assert.equal(result, null);
    });

    test('auto rotation', async () => {
        const session = new SecureSession(crypto.randomBytes(32), 1, 2);

        const enc1 = session.encrypt(Buffer.from('message 1'));
        const version1 = session._keyVersion;

        await new Promise(resolve => setTimeout(resolve, 1500));

        const enc2 = session.encrypt(Buffer.from('message 2'));
        const version2 = session._keyVersion;

        assert.ok(version2 > version1);

        // Both still decrypt
        assert.deepEqual(session.decrypt(enc1), Buffer.from('message 1'));
        assert.deepEqual(session.decrypt(enc2), Buffer.from('message 2'));
    });
});
