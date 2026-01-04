/**
 * Shield Signatures - Digital signatures without public-key crypto.
 *
 * Two signature types:
 * 1. SymmetricSignature: HMAC-based, requires shared verification key
 * 2. LamportSignature: One-time hash-chain signatures (post-quantum)
 */

const crypto = require('crypto');

/**
 * HMAC-based digital signatures.
 */
class SymmetricSignature {
    /**
     * Initialize with signing key.
     * @param {Buffer} signingKey - 32-byte secret signing key
     */
    constructor(signingKey) {
        this.signingKey = signingKey;
        this.verificationKey = crypto.createHash('sha256')
            .update(Buffer.concat([Buffer.from('verify:'), signingKey]))
            .digest();
    }

    /**
     * Generate new signing identity.
     * @returns {SymmetricSignature}
     */
    static generate() {
        return new SymmetricSignature(crypto.randomBytes(32));
    }

    /**
     * Derive signing key from password and identity.
     * @param {string} password - User's password
     * @param {string} identity - Identity string
     * @returns {SymmetricSignature}
     */
    static fromPassword(password, identity) {
        const salt = crypto.createHash('sha256')
            .update(`sign:${identity}`)
            .digest();
        const key = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
        return new SymmetricSignature(key);
    }

    /**
     * Sign a message.
     * @param {Buffer} message - Message to sign
     * @param {boolean} includeTimestamp - Include timestamp for replay protection
     * @returns {Buffer} Signature bytes
     */
    sign(message, includeTimestamp = true) {
        if (includeTimestamp) {
            const timestamp = Buffer.alloc(8);
            timestamp.writeBigUInt64LE(BigInt(Math.floor(Date.now() / 1000)));
            const sigData = Buffer.concat([timestamp, message]);
            const signature = crypto.createHmac('sha256', this.signingKey)
                .update(sigData)
                .digest();
            return Buffer.concat([timestamp, signature]);
        } else {
            return crypto.createHmac('sha256', this.signingKey)
                .update(message)
                .digest();
        }
    }

    /**
     * Verify a signature.
     * @param {Buffer} message - Original message
     * @param {Buffer} signature - Signature from sign()
     * @param {Buffer} verificationKey - Signer's verification key
     * @param {number} maxAge - Maximum signature age in seconds (0 = no check)
     * @returns {boolean}
     */
    verify(message, signature, verificationKey, maxAge = 300) {
        if (!crypto.timingSafeEqual(verificationKey, this.verificationKey)) {
            return false;
        }

        if (signature.length === 40) {
            const timestamp = Number(signature.readBigUInt64LE(0));
            const sig = signature.slice(8);

            if (maxAge > 0) {
                const now = Math.floor(Date.now() / 1000);
                if (Math.abs(now - timestamp) > maxAge) {
                    return false;
                }
            }

            const sigData = Buffer.concat([signature.slice(0, 8), message]);
            const expected = crypto.createHmac('sha256', this.signingKey)
                .update(sigData)
                .digest();
            return crypto.timingSafeEqual(sig, expected);
        } else {
            const expected = crypto.createHmac('sha256', this.signingKey)
                .update(message)
                .digest();
            return crypto.timingSafeEqual(signature, expected);
        }
    }

    /**
     * Get key fingerprint.
     * @returns {string}
     */
    getFingerprint() {
        return crypto.createHash('sha256')
            .update(this.verificationKey)
            .digest('hex')
            .slice(0, 16);
    }
}

/**
 * Lamport one-time signatures (post-quantum secure).
 */
class LamportSignature {
    static BITS = 256;

    /**
     * Initialize with private key or generate new.
     * @param {Array|null} privateKey - List of [chain0, chain1] pairs
     */
    constructor(privateKey = null) {
        if (privateKey === null) {
            privateKey = this._generatePrivateKey();
        }
        this._privateKey = privateKey;
        this._used = false;
        this.publicKey = this._computePublicKey();
    }

    /**
     * Generate new Lamport key pair.
     * @returns {LamportSignature}
     */
    static generate() {
        return new LamportSignature();
    }

    _generatePrivateKey() {
        const keys = [];
        for (let i = 0; i < LamportSignature.BITS; i++) {
            keys.push([crypto.randomBytes(32), crypto.randomBytes(32)]);
        }
        return keys;
    }

    _hash(data) {
        return crypto.createHash('sha256').update(data).digest();
    }

    _computePublicKey() {
        const parts = [];
        for (const [chain0, chain1] of this._privateKey) {
            parts.push(this._hash(chain0));
            parts.push(this._hash(chain1));
        }
        return Buffer.concat(parts);
    }

    /**
     * Sign a message (ONE TIME ONLY).
     * @param {Buffer} message - Message to sign
     * @returns {Buffer} Signature bytes
     */
    sign(message) {
        if (this._used) {
            throw new Error('Lamport key already used - generate new key pair');
        }
        this._used = true;

        const msgHash = crypto.createHash('sha256').update(message).digest();
        const signatureParts = [];

        for (let i = 0; i < LamportSignature.BITS; i++) {
            const byteIdx = Math.floor(i / 8);
            const bitIdx = i % 8;
            const bit = (msgHash[byteIdx] >> bitIdx) & 1;

            const [chain0, chain1] = this._privateKey[i];
            signatureParts.push(bit ? chain1 : chain0);
        }

        return Buffer.concat(signatureParts);
    }

    /**
     * Verify a Lamport signature.
     * @param {Buffer} message - Original message
     * @param {Buffer} signature - Signature from sign()
     * @param {Buffer} publicKey - Signer's public key
     * @returns {boolean}
     */
    static verify(message, signature, publicKey) {
        if (signature.length !== 256 * 32) return false;
        if (publicKey.length !== 256 * 64) return false;

        const msgHash = crypto.createHash('sha256').update(message).digest();

        for (let i = 0; i < 256; i++) {
            const byteIdx = Math.floor(i / 8);
            const bitIdx = i % 8;
            const bit = (msgHash[byteIdx] >> bitIdx) & 1;

            const revealed = signature.slice(i * 32, (i + 1) * 32);
            const hashed = crypto.createHash('sha256').update(revealed).digest();

            let expected;
            if (bit) {
                expected = publicKey.slice(i * 64 + 32, i * 64 + 64);
            } else {
                expected = publicKey.slice(i * 64, i * 64 + 32);
            }

            if (!hashed.equals(expected)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Check if key has been used.
     * @returns {boolean}
     */
    get isUsed() {
        return this._used;
    }

    /**
     * Get public key fingerprint.
     * @returns {string}
     */
    getFingerprint() {
        return crypto.createHash('sha256')
            .update(this.publicKey)
            .digest('hex')
            .slice(0, 16);
    }
}

module.exports = { SymmetricSignature, LamportSignature };
