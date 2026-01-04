/**
 * Shield Key Rotation - Version-based key management.
 */

const crypto = require('crypto');

/**
 * Generate keystream using SHA256.
 */
function generateKeystream(key, nonce, length) {
    let keystream = Buffer.alloc(0);
    for (let i = 0; i < Math.ceil(length / 32); i++) {
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
 * Manages multiple key versions for seamless rotation.
 */
class KeyRotationManager {
    /**
     * Initialize with current key.
     * @param {Buffer} key - 32-byte encryption key
     * @param {number} version - Key version number
     */
    constructor(key, version = 1) {
        this._keys = new Map([[version, key]]);
        this._currentVersion = version;
    }

    /**
     * Get current key version.
     * @returns {number}
     */
    get currentVersion() {
        return this._currentVersion;
    }

    /**
     * Get all available versions.
     * @returns {number[]}
     */
    get versions() {
        return Array.from(this._keys.keys()).sort((a, b) => a - b);
    }

    /**
     * Add historical key.
     * @param {Buffer} key - 32-byte key
     * @param {number} version - Version number
     */
    addKey(key, version) {
        if (this._keys.has(version)) {
            throw new Error(`Version ${version} already exists`);
        }
        this._keys.set(version, key);
    }

    /**
     * Rotate to new key.
     * @param {Buffer} newKey - New 32-byte key
     * @param {number} newVersion - Version number
     * @returns {number} New version
     */
    rotate(newKey, newVersion = null) {
        if (newVersion === null) {
            newVersion = this._currentVersion + 1;
        }
        if (newVersion <= this._currentVersion) {
            throw new Error('New version must be greater than current');
        }
        this._keys.set(newVersion, newKey);
        this._currentVersion = newVersion;
        return newVersion;
    }

    /**
     * Encrypt with current key.
     * @param {Buffer} plaintext - Data to encrypt
     * @returns {Buffer} Versioned ciphertext
     */
    encrypt(plaintext) {
        const key = this._keys.get(this._currentVersion);
        const nonce = crypto.randomBytes(16);

        const keystream = generateKeystream(key, nonce, plaintext.length);
        const ciphertext = Buffer.alloc(plaintext.length);
        for (let i = 0; i < plaintext.length; i++) {
            ciphertext[i] = plaintext[i] ^ keystream[i];
        }

        const versionBytes = Buffer.alloc(4);
        versionBytes.writeUInt32LE(this._currentVersion);

        const mac = crypto.createHmac('sha256', key)
            .update(Buffer.concat([versionBytes, nonce, ciphertext]))
            .digest()
            .slice(0, 16);

        return Buffer.concat([versionBytes, nonce, ciphertext, mac]);
    }

    /**
     * Decrypt with appropriate key version.
     * @param {Buffer} encrypted - Versioned ciphertext
     * @returns {Buffer} Plaintext
     */
    decrypt(encrypted) {
        if (encrypted.length < 36) {
            throw new Error('Ciphertext too short');
        }

        const version = encrypted.readUInt32LE(0);
        const nonce = encrypted.slice(4, 20);
        const ciphertext = encrypted.slice(20, -16);
        const mac = encrypted.slice(-16);

        if (!this._keys.has(version)) {
            throw new Error(`Unknown key version: ${version}`);
        }

        const key = this._keys.get(version);

        const expectedMac = crypto.createHmac('sha256', key)
            .update(encrypted.slice(0, -16))
            .digest()
            .slice(0, 16);

        if (!crypto.timingSafeEqual(mac, expectedMac)) {
            throw new Error('Authentication failed');
        }

        const keystream = generateKeystream(key, nonce, ciphertext.length);
        const plaintext = Buffer.alloc(ciphertext.length);
        for (let i = 0; i < ciphertext.length; i++) {
            plaintext[i] = ciphertext[i] ^ keystream[i];
        }

        return plaintext;
    }

    /**
     * Remove old keys.
     * @param {number} keepVersions - Number to keep
     * @returns {number[]} Pruned versions
     */
    pruneOldKeys(keepVersions = 2) {
        if (keepVersions < 1) {
            throw new Error('Must keep at least 1 version');
        }

        const versions = this.versions.reverse();
        const toKeep = new Set(versions.slice(0, keepVersions));
        toKeep.add(this._currentVersion);

        const pruned = [];
        for (const v of this._keys.keys()) {
            if (!toKeep.has(v)) {
                this._keys.delete(v);
                pruned.push(v);
            }
        }

        return pruned;
    }

    /**
     * Re-encrypt with current key.
     * @param {Buffer} encrypted - Old ciphertext
     * @returns {Buffer} New ciphertext
     */
    reEncrypt(encrypted) {
        const plaintext = this.decrypt(encrypted);
        return this.encrypt(plaintext);
    }
}

module.exports = { KeyRotationManager };
