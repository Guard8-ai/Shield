/**
 * Shield Ratchet - Forward secrecy through key ratcheting.
 *
 * Each message uses a new key derived from previous.
 * Compromise of current key doesn't reveal past messages.
 *
 * Based on Signal's Double Ratchet (simplified symmetric version).
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
 * Ratcheting session for forward secrecy.
 */
class RatchetSession {
    /**
     * Create a new ratchet session from shared root key.
     *
     * @param {Buffer} rootKey - 32-byte shared secret from key exchange
     * @param {boolean} isInitiator - True if this party initiated the session
     */
    constructor(rootKey, isInitiator) {
        const sendLabel = isInitiator ? Buffer.from('send') : Buffer.from('recv');
        const recvLabel = isInitiator ? Buffer.from('recv') : Buffer.from('send');

        this._sendChain = this._deriveChainKey(rootKey, sendLabel);
        this._recvChain = this._deriveChainKey(rootKey, recvLabel);
        this._sendCounter = 0;
        this._recvCounter = 0;
    }

    _deriveChainKey(root, label) {
        return crypto.createHash('sha256')
            .update(Buffer.concat([root, label]))
            .digest();
    }

    _ratchetChain(chainKey) {
        const newChain = crypto.createHash('sha256')
            .update(Buffer.concat([chainKey, Buffer.from('chain')]))
            .digest();
        const msgKey = crypto.createHash('sha256')
            .update(Buffer.concat([chainKey, Buffer.from('message')]))
            .digest();
        return [newChain, msgKey];
    }

    /**
     * Encrypt a message with forward secrecy.
     *
     * @param {Buffer} plaintext - Message to encrypt
     * @returns {Buffer} Encrypted message
     */
    encrypt(plaintext) {
        // Ratchet send chain
        const [newChain, msgKey] = this._ratchetChain(this._sendChain);
        this._sendChain = newChain;

        const counter = this._sendCounter;
        this._sendCounter++;

        return this._encryptWithKey(msgKey, plaintext, counter);
    }

    /**
     * Decrypt a message with forward secrecy.
     *
     * @param {Buffer} ciphertext - Encrypted message
     * @returns {Buffer|null} Decrypted message, or null if failed
     */
    decrypt(ciphertext) {
        // Ratchet receive chain
        const [newChain, msgKey] = this._ratchetChain(this._recvChain);
        this._recvChain = newChain;

        const result = this._decryptWithKey(msgKey, ciphertext);
        if (result === null) {
            return null;
        }

        const [plaintext, counter] = result;

        // Verify counter (replay protection)
        if (counter !== this._recvCounter) {
            return null;
        }

        this._recvCounter++;
        return plaintext;
    }

    _encryptWithKey(key, plaintext, counter) {
        const nonce = crypto.randomBytes(16);
        const counterBytes = Buffer.alloc(8);
        counterBytes.writeBigUInt64LE(BigInt(counter));

        // Data: counter || plaintext
        const data = Buffer.concat([counterBytes, plaintext]);

        // Generate keystream
        const keystream = generateKeystream(key, nonce, data.length);

        // XOR encrypt
        const ciphertext = Buffer.alloc(data.length);
        for (let i = 0; i < data.length; i++) {
            ciphertext[i] = data[i] ^ keystream[i];
        }

        // HMAC authenticate
        const mac = crypto.createHmac('sha256', key)
            .update(Buffer.concat([nonce, ciphertext]))
            .digest()
            .slice(0, 16);

        return Buffer.concat([nonce, ciphertext, mac]);
    }

    _decryptWithKey(key, encrypted) {
        if (encrypted.length < 40) { // 16 nonce + 8 counter + 16 mac
            return null;
        }

        const nonce = encrypted.slice(0, 16);
        const ciphertext = encrypted.slice(16, -16);
        const mac = encrypted.slice(-16);

        // Verify MAC
        const expectedMac = crypto.createHmac('sha256', key)
            .update(Buffer.concat([nonce, ciphertext]))
            .digest()
            .slice(0, 16);

        if (!crypto.timingSafeEqual(mac, expectedMac)) {
            return null;
        }

        // Decrypt
        const keystream = generateKeystream(key, nonce, ciphertext.length);
        const decrypted = Buffer.alloc(ciphertext.length);
        for (let i = 0; i < ciphertext.length; i++) {
            decrypted[i] = ciphertext[i] ^ keystream[i];
        }

        // Parse counter
        const counter = Number(decrypted.readBigUInt64LE(0));

        return [decrypted.slice(8), counter];
    }

    /**
     * Get current send counter.
     * @returns {number}
     */
    get sendCounter() {
        return this._sendCounter;
    }

    /**
     * Get current receive counter.
     * @returns {number}
     */
    get recvCounter() {
        return this._recvCounter;
    }
}

module.exports = { RatchetSession };
