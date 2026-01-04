/**
 * Shield Key Exchange - Key exchange without public-key crypto.
 */

const crypto = require('crypto');

/**
 * Password-Authenticated Key Exchange.
 */
class PAKEExchange {
    static ITERATIONS = 200000;

    /**
     * Derive key contribution from password.
     * @param {string} password - Shared password
     * @param {Buffer} salt - Public salt
     * @param {string} role - Role identifier
     * @param {number} iterations - PBKDF2 iterations
     * @returns {Buffer}
     */
    static derive(password, salt, role, iterations = null) {
        if (iterations === null) iterations = PAKEExchange.ITERATIONS;
        const baseKey = crypto.pbkdf2Sync(password, salt, iterations, 32, 'sha256');
        return crypto.createHash('sha256')
            .update(Buffer.concat([baseKey, Buffer.from(role)]))
            .digest();
    }

    /**
     * Combine key contributions into session key.
     * @param {...Buffer} contributions - Key contributions
     * @returns {Buffer}
     */
    static combine(...contributions) {
        const sorted = contributions.sort(Buffer.compare);
        const combined = Buffer.concat(sorted);
        return crypto.createHash('sha256').update(combined).digest();
    }

    /**
     * Generate random salt.
     * @returns {Buffer}
     */
    static generateSalt() {
        return crypto.randomBytes(16);
    }
}

/**
 * Key exchange via QR codes or manual transfer.
 */
class QRExchange {
    /**
     * Encode key for QR code.
     * @param {Buffer} key - Key bytes
     * @returns {string}
     */
    static encode(key) {
        return key.toString('base64url');
    }

    /**
     * Decode key from QR code.
     * @param {string} encoded - Base64 string
     * @returns {Buffer}
     */
    static decode(encoded) {
        return Buffer.from(encoded, 'base64url');
    }

    /**
     * Generate complete exchange data with metadata.
     * @param {Buffer} key - Key to exchange
     * @param {Object} metadata - Optional metadata
     * @returns {string}
     */
    static generateExchangeData(key, metadata = null) {
        const data = {
            v: 1,
            k: key.toString('base64url')
        };
        if (metadata) data.m = metadata;
        return JSON.stringify(data);
    }

    /**
     * Parse exchange data.
     * @param {string} data - JSON string
     * @returns {Array} [key, metadata]
     */
    static parseExchangeData(data) {
        const parsed = JSON.parse(data);
        const key = Buffer.from(parsed.k, 'base64url');
        return [key, parsed.m || null];
    }
}

/**
 * Split keys into shares.
 */
class KeySplitter {
    /**
     * Split key into shares (all required).
     * @param {Buffer} key - Key to split
     * @param {number} numShares - Number of shares
     * @returns {Buffer[]}
     */
    static split(key, numShares) {
        if (numShares < 2) throw new Error('Need at least 2 shares');

        const shares = [];
        for (let i = 0; i < numShares - 1; i++) {
            shares.push(crypto.randomBytes(key.length));
        }

        // Final share = XOR of key with all others
        let final = Buffer.from(key);
        for (const share of shares) {
            final = Buffer.from(final.map((b, i) => b ^ share[i]));
        }
        shares.push(final);

        return shares;
    }

    /**
     * Combine shares to recover key.
     * @param {Buffer[]} shares - All shares
     * @returns {Buffer}
     */
    static combine(shares) {
        if (shares.length < 2) throw new Error('Need at least 2 shares');

        let result = Buffer.from(shares[0]);
        for (let i = 1; i < shares.length; i++) {
            result = Buffer.from(result.map((b, j) => b ^ shares[i][j]));
        }
        return result;
    }
}

module.exports = { PAKEExchange, QRExchange, KeySplitter };
