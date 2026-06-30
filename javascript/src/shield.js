/**
 * Shield - Authenticated Symmetric Encryption (Node.js), wire format v4.
 *
 * v4 replaces the previous custom SHA-256 keystream + HMAC construction with a
 * standard AEAD (AES-256-GCM by default, ChaCha20-Poly1305 optional) from Node's
 * built-in `crypto` (OpenSSL). No cryptography is hand-rolled. The wire format
 * matches every other Shield binding byte-for-byte (see tests/v4_test_vectors.json).
 */

const crypto = require('crypto');

// Key derivation iterations (OWASP 2023 floor for PBKDF2-HMAC-SHA256)
const PBKDF2_ITERATIONS = 600000;

// Sizes in bytes
const NONCE_SIZE = 12; // 96-bit AEAD nonce
const TAG_SIZE = 16;   // 128-bit AEAD tag
const SALT_SIZE = 16;

// Version bytes (authenticated, leading byte of the ciphertext)
const VERSION_PASSWORD = 0x03; // 0x03 || suite || salt(16) || nonce(12) || ct||tag
const VERSION_KEY = 0x13;      // 0x13 || suite || nonce(12) || ct||tag

// Cipher-suite identifiers
const SUITE_AES_256_GCM = 0x01;
const SUITE_CHACHA20_POLY1305 = 0x02;

// Inner-plaintext layout: timestamp_ms(8) || pad_len(1) || padding || message
const INNER_HEADER_SIZE = 9;
const MIN_PADDING = 32;
const MAX_PADDING = 128;

// HKDF-Expand info string deriving the AEAD key from the master key
const HKDF_AEAD_INFO = Buffer.from('shield/aead/v4');

/**
 * Derive the AEAD key via HKDF-SHA256-Expand(master, "shield/aead/v4", 32).
 * For a 32-byte output this is a single HKDF block: HMAC-SHA256(master, info || 0x01).
 */
function deriveAeadKey(masterKey) {
    return crypto.createHmac('sha256', masterKey)
        .update(Buffer.concat([HKDF_AEAD_INFO, Buffer.from([0x01])]))
        .digest()
        .slice(0, 32);
}

/** Node cipher algorithm name for a suite byte, or null if unknown. */
function algoForSuite(suite) {
    if (suite === SUITE_AES_256_GCM) return 'aes-256-gcm';
    if (suite === SUITE_CHACHA20_POLY1305) return 'chacha20-poly1305';
    return null;
}

/** AEAD seal: returns ciphertext||tag. */
function aeadSeal(suite, key, nonce, aad, plaintext) {
    const algo = algoForSuite(suite);
    if (algo === null) throw new Error(`unknown cipher suite: ${suite}`);
    const cipher = crypto.createCipheriv(algo, key, nonce, { authTagLength: TAG_SIZE });
    cipher.setAAD(aad, { plaintextLength: plaintext.length });
    const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return Buffer.concat([ct, cipher.getAuthTag()]);
}

/** AEAD open: returns plaintext, or null on authentication failure / unknown suite. */
function aeadOpen(suite, key, nonce, aad, ctTag) {
    const algo = algoForSuite(suite);
    if (algo === null) return null;
    if (ctTag.length < TAG_SIZE) return null;
    const ct = ctTag.slice(0, ctTag.length - TAG_SIZE);
    const tag = ctTag.slice(ctTag.length - TAG_SIZE);
    try {
        const decipher = crypto.createDecipheriv(algo, key, nonce, { authTagLength: TAG_SIZE });
        decipher.setAAD(aad, { plaintextLength: ct.length });
        decipher.setAuthTag(tag);
        return Buffer.concat([decipher.update(ct), decipher.final()]);
    } catch (e) {
        return null; // authentication failed
    }
}

/** Build AEAD additional data (= wire prefix before the nonce). */
function buildAad(suite, salt) {
    if (salt !== null && salt !== undefined) {
        return Buffer.concat([Buffer.from([VERSION_PASSWORD, suite]), salt]);
    }
    return Buffer.from([VERSION_KEY, suite]);
}

/**
 * Deterministic AEAD seal over fully specified inputs (used for conformance
 * vectors and wrapped by the randomized Shield#encrypt path).
 */
function sealDeterministic(aeadKey, suite, salt, nonce, timestampMs, padLen, padding, plaintext) {
    const aad = buildAad(suite, salt);
    const tsBytes = Buffer.alloc(8);
    tsBytes.writeBigUInt64LE(BigInt(timestampMs));
    const inner = Buffer.concat([tsBytes, Buffer.from([padLen]), padding, plaintext]);
    const ctTag = aeadSeal(suite, aeadKey, nonce, aad, inner);
    return Buffer.concat([aad, nonce, ctTag]);
}

/**
 * Open an AEAD ciphertext, validate the inner layout and freshness window.
 * @returns {Buffer|null}
 */
function openCiphertext(aeadKey, suite, encrypted, aadLen, maxAgeMs) {
    if (encrypted.length < aadLen + NONCE_SIZE + TAG_SIZE) return null;
    const aad = encrypted.slice(0, aadLen);
    const nonce = encrypted.slice(aadLen, aadLen + NONCE_SIZE);
    const ctTag = encrypted.slice(aadLen + NONCE_SIZE);

    const inner = aeadOpen(suite, aeadKey, nonce, aad, ctTag);
    if (inner === null) return null;

    if (inner.length < INNER_HEADER_SIZE) return null;
    const timestampMs = Number(inner.slice(0, 8).readBigUInt64LE());
    const padLen = inner[8];
    if (padLen < MIN_PADDING || padLen > MAX_PADDING) return null;
    const dataStart = INNER_HEADER_SIZE + padLen;
    if (inner.length < dataStart) return null;

    // Freshness window (NOT full replay protection)
    if (maxAgeMs !== null && maxAgeMs !== undefined) {
        const nowMs = Date.now();
        const age = nowMs - timestampMs;
        if (timestampMs > nowMs + 5000 || age > maxAgeMs) return null;
    }

    return inner.slice(dataStart);
}

/** Random padding length in [32, 128] via rejection sampling (no modulo bias). */
function samplePadLen() {
    const padRange = MAX_PADDING - MIN_PADDING + 1; // 97
    for (;;) {
        const val = crypto.randomBytes(1)[0];
        if (val < padRange * Math.floor(256 / padRange)) {
            return (val % padRange) + MIN_PADDING;
        }
    }
}

/**
 * Shield encryption class.
 *
 * @example
 * const shield = new Shield('password', 'github.com');
 * const encrypted = shield.encrypt(Buffer.from('secret'));
 * const decrypted = shield.decrypt(encrypted);
 */
class Shield {
    /**
     * @param {string} password
     * @param {string} service
     * @param {Object} options
     * @param {Buffer} options.salt - Explicit 16-byte salt (default: random per instance)
     * @param {number} options.iterations - PBKDF2 iterations (default 600000)
     * @param {number} options.maxAgeMs - Freshness window ms (default 60000, null = disabled)
     * @param {number} options.suite - Cipher suite (default AES-256-GCM)
     */
    constructor(password, service, options = {}) {
        const salt = options.salt || crypto.randomBytes(SALT_SIZE);
        const iterations = options.iterations || PBKDF2_ITERATIONS;
        const maxAgeMs = options.maxAgeMs !== undefined ? options.maxAgeMs : 60000;
        const suite = options.suite !== undefined ? options.suite : SUITE_AES_256_GCM;

        this._password = Buffer.from(password);
        this._service = Buffer.from(service);
        this._iterations = iterations;
        this._salt = salt;
        this._suite = suite;
        this._keyCache = new Map();

        this._key = this._deriveKey(salt);
        this._aeadKey = deriveAeadKey(this._key);
        this._maxAgeMs = maxAgeMs;
    }

    /** Derive the 32-byte master key for a given salt (cached). */
    _deriveKey(salt) {
        const cacheKey = salt.toString('hex');
        const cached = this._keyCache.get(cacheKey);
        if (cached !== undefined) return cached;
        const key = crypto.pbkdf2Sync(
            this._password,
            Buffer.concat([salt, this._service]),
            this._iterations,
            32,
            'sha256'
        );
        this._keyCache.set(cacheKey, key);
        return key;
    }

    /**
     * Create Shield instance from raw key (no password derivation).
     * @param {Buffer} key - 32-byte symmetric key
     * @param {Object} options - { suite }
     */
    static withKey(key, options = {}) {
        if (key.length !== 32) {
            throw new Error(`Key must be 32 bytes, got ${key.length}`);
        }
        const instance = Object.create(Shield.prototype);
        instance._key = key;
        instance._aeadKey = deriveAeadKey(key);
        instance._suite = options.suite !== undefined ? options.suite : SUITE_AES_256_GCM;
        instance._maxAgeMs = options.maxAgeMs !== undefined ? options.maxAgeMs : 60000;
        // Pre-shared-key mode: no password, no salt.
        instance._password = null;
        instance._service = null;
        instance._iterations = null;
        instance._salt = null;
        instance._keyCache = new Map();
        return instance;
    }

    /**
     * Create Shield with hardware fingerprinting (device-bound encryption).
     * @param {string} password
     * @param {string} service
     * @param {Object} options - { mode }
     */
    static withFingerprint(password, service, options = {}) {
        const { FingerprintMode, collectFingerprint } = require('./fingerprint');
        const mode = options.mode || FingerprintMode.COMBINED;
        const fingerprint = collectFingerprint(mode);
        const combinedPassword = fingerprint ? `${password}:${fingerprint}` : password;
        return new Shield(combinedPassword, service, options);
    }

    /**
     * Encrypt data with a standard AEAD and length obfuscation.
     *
     * Output (password mode): 0x03 || suite || salt(16) || nonce(12) || ct||tag
     * Output (key mode):      0x13 || suite || nonce(12) || ct||tag
     *
     * @param {Buffer} plaintext
     * @returns {Buffer}
     */
    encrypt(plaintext) {
        const nonce = crypto.randomBytes(NONCE_SIZE);
        const padLen = samplePadLen();
        const padding = crypto.randomBytes(padLen);
        return sealDeterministic(
            this._aeadKey, this._suite, this._salt, nonce, Date.now(), padLen, padding, plaintext
        );
    }

    /**
     * Decrypt and verify data, dispatching on the leading authenticated version byte.
     * @param {Buffer} encrypted
     * @returns {Buffer|null}
     */
    decrypt(encrypted) {
        if (encrypted.length < 1) return null;
        const version = encrypted[0];

        if (version === VERSION_PASSWORD) {
            const aadLen = 2 + SALT_SIZE;
            if (encrypted.length < aadLen + NONCE_SIZE + TAG_SIZE) return null;
            if (this._salt === null || this._salt === undefined) return null;
            const suite = encrypted[1];
            const salt = encrypted.slice(2, 2 + SALT_SIZE);
            const master = this._deriveKey(salt);
            const aeadKey = deriveAeadKey(master);
            return openCiphertext(aeadKey, suite, encrypted, aadLen, this._maxAgeMs);
        }
        if (version === VERSION_KEY) {
            const suite = encrypted[1];
            return openCiphertext(this._aeadKey, suite, encrypted, 2, this._maxAgeMs);
        }
        return null;
    }

    /** Get the derived master key (for testing/debugging). */
    get key() {
        return this._key;
    }
}

/**
 * One-shot encrypt with a pre-shared key. Equivalent to Shield.withKey(key).encrypt(data):
 * same authenticated, length-obfuscated v4 wire format and HKDF-derived AEAD key as the
 * instance API and the Rust source of truth.
 */
function quickEncrypt(key, data) {
    return Shield.withKey(key).encrypt(data);
}

/**
 * One-shot decrypt with a pre-shared key. Applies the default 60-second freshness window.
 */
function quickDecrypt(key, encrypted) {
    return Shield.withKey(key).decrypt(encrypted);
}

module.exports = {
    Shield,
    quickEncrypt,
    quickDecrypt,
    // Constants
    PBKDF2_ITERATIONS,
    VERSION_PASSWORD,
    VERSION_KEY,
    SUITE_AES_256_GCM,
    SUITE_CHACHA20_POLY1305,
    SALT_SIZE,
    NONCE_SIZE,
    TAG_SIZE,
    INNER_HEADER_SIZE,
    MIN_PADDING,
    MAX_PADDING,
    // Internal: exposed for interop/conformance tests only, not part of public API
    _deriveAeadKey: deriveAeadKey,
    _sealDeterministic: sealDeterministic,
    _openCiphertext: openCiphertext
};
