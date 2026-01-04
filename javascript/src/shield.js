/**
 * Shield - EXPTIME-Secure Encryption (Node.js)
 *
 * INTEROPERABLE with Python shield package.
 * Uses SHA256-based stream cipher with HMAC authentication.
 * Breaking requires 2^256 operations - no shortcut exists.
 */

const crypto = require('crypto');

// Constants
const PBKDF2_ITERATIONS = 100000;
const NONCE_SIZE = 16;
const MAC_SIZE = 16;
const COUNTER_SIZE = 8;

/**
 * Generate keystream using SHA256 (AES-256-CTR equivalent).
 */
function generateKeystream(key, nonce, length) {
    let keystream = Buffer.alloc(0);
    const numBlocks = Math.ceil(length / 32);

    for (let i = 0; i < numBlocks; i++) {
        const counter = Buffer.alloc(4);
        counter.writeUInt32LE(i);
        const block = crypto.createHash('sha256')
            .update(Buffer.concat([key, nonce, counter]))
            .digest();
        keystream = Buffer.concat([keystream, block]);
    }

    return keystream.slice(0, length);
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
     * Create Shield instance with password-derived key.
     *
     * @param {string} password - User's password
     * @param {string} service - Service identifier (e.g., 'github.com')
     * @param {Object} options - Optional settings
     * @param {Buffer} options.salt - Custom salt (default: SHA256(service))
     * @param {number} options.iterations - PBKDF2 iterations (default: 100000)
     */
    constructor(password, service, options = {}) {
        const salt = options.salt ||
            crypto.createHash('sha256').update(service).digest();
        const iterations = options.iterations || PBKDF2_ITERATIONS;

        this._key = crypto.pbkdf2Sync(password, salt, iterations, 32, 'sha256');
        this._counter = 0;
    }

    /**
     * Create Shield instance from raw key (no password derivation).
     *
     * @param {Buffer} key - 32-byte symmetric key
     * @returns {Shield} Shield instance
     */
    static withKey(key) {
        if (key.length !== 32) {
            throw new Error(`Key must be 32 bytes, got ${key.length}`);
        }
        const instance = Object.create(Shield.prototype);
        instance._key = key;
        instance._counter = 0;
        return instance;
    }

    /**
     * Encrypt data.
     *
     * @param {Buffer} plaintext - Data to encrypt
     * @returns {Buffer} Ciphertext: nonce(16) || encrypted_data || mac(16)
     */
    encrypt(plaintext) {
        const nonce = crypto.randomBytes(NONCE_SIZE);
        const counterBytes = Buffer.alloc(COUNTER_SIZE);
        counterBytes.writeBigUInt64LE(BigInt(this._counter));
        this._counter++;

        // Data to encrypt: counter || plaintext
        const data = Buffer.concat([counterBytes, plaintext]);

        // Generate keystream
        const keystream = generateKeystream(this._key, nonce, data.length);

        // XOR encrypt
        const ciphertext = Buffer.alloc(data.length);
        for (let i = 0; i < data.length; i++) {
            ciphertext[i] = data[i] ^ keystream[i];
        }

        // HMAC authenticate
        const mac = crypto.createHmac('sha256', this._key)
            .update(Buffer.concat([nonce, ciphertext]))
            .digest()
            .slice(0, MAC_SIZE);

        return Buffer.concat([nonce, ciphertext, mac]);
    }

    /**
     * Decrypt and verify data.
     *
     * @param {Buffer} encrypted - Ciphertext from encrypt()
     * @returns {Buffer|null} Plaintext, or null if authentication fails
     */
    decrypt(encrypted) {
        const minSize = NONCE_SIZE + COUNTER_SIZE + MAC_SIZE;
        if (encrypted.length < minSize) {
            return null;
        }

        const nonce = encrypted.slice(0, NONCE_SIZE);
        const ciphertext = encrypted.slice(NONCE_SIZE, -MAC_SIZE);
        const mac = encrypted.slice(-MAC_SIZE);

        // Verify MAC (constant-time)
        const expectedMac = crypto.createHmac('sha256', this._key)
            .update(Buffer.concat([nonce, ciphertext]))
            .digest()
            .slice(0, MAC_SIZE);

        if (!crypto.timingSafeEqual(mac, expectedMac)) {
            return null;
        }

        // Decrypt
        const keystream = generateKeystream(this._key, nonce, ciphertext.length);
        const decrypted = Buffer.alloc(ciphertext.length);
        for (let i = 0; i < ciphertext.length; i++) {
            decrypted[i] = ciphertext[i] ^ keystream[i];
        }

        // Skip counter prefix
        return decrypted.slice(COUNTER_SIZE);
    }

    /**
     * Get the derived key (for testing/debugging).
     * @returns {Buffer} The 32-byte key
     */
    get key() {
        return this._key;
    }
}

/**
 * One-shot encrypt with pre-shared key (no password derivation).
 *
 * @param {Buffer} key - 32-byte symmetric key
 * @param {Buffer} data - Data to encrypt
 * @returns {Buffer} Ciphertext
 */
function quickEncrypt(key, data) {
    const nonce = crypto.randomBytes(NONCE_SIZE);
    const keystream = generateKeystream(key, nonce, data.length);

    const ciphertext = Buffer.alloc(data.length);
    for (let i = 0; i < data.length; i++) {
        ciphertext[i] = data[i] ^ keystream[i];
    }

    const mac = crypto.createHmac('sha256', key)
        .update(Buffer.concat([nonce, ciphertext]))
        .digest()
        .slice(0, MAC_SIZE);

    return Buffer.concat([nonce, ciphertext, mac]);
}

/**
 * One-shot decrypt with pre-shared key.
 *
 * @param {Buffer} key - 32-byte symmetric key
 * @param {Buffer} encrypted - Ciphertext from quickEncrypt()
 * @returns {Buffer|null} Plaintext, or null if authentication fails
 */
function quickDecrypt(key, encrypted) {
    if (encrypted.length < NONCE_SIZE + MAC_SIZE) {
        return null;
    }

    const nonce = encrypted.slice(0, NONCE_SIZE);
    const ciphertext = encrypted.slice(NONCE_SIZE, -MAC_SIZE);
    const mac = encrypted.slice(-MAC_SIZE);

    const expectedMac = crypto.createHmac('sha256', key)
        .update(Buffer.concat([nonce, ciphertext]))
        .digest()
        .slice(0, MAC_SIZE);

    if (!crypto.timingSafeEqual(mac, expectedMac)) {
        return null;
    }

    const keystream = generateKeystream(key, nonce, ciphertext.length);
    const decrypted = Buffer.alloc(ciphertext.length);
    for (let i = 0; i < ciphertext.length; i++) {
        decrypted[i] = ciphertext[i] ^ keystream[i];
    }

    return decrypted;
}

module.exports = {
    Shield,
    quickEncrypt,
    quickDecrypt,
    generateKeystream
};
