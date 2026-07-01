/**
 * Shield Key Exchange - Key exchange without public-key crypto.
 */

const crypto = require('crypto');

/**
 * Pre-shared-key handshake (NOT a true PAKE despite the name).
 *
 * Both parties derive a shared key from a common pre-shared secret, with role
 * binding to prevent reflection attacks.
 *
 * SECURITY: The handshake contribution HMAC(PBKDF2(secret, salt), role) is sent
 * on the wire together with the salt, so a recorded handshake permits an OFFLINE
 * DICTIONARY ATTACK against a low-entropy secret (PBKDF2 iterations only slow
 * each guess). Safe ONLY with a high-entropy shared secret (>=128 bits). For
 * password-based or forward-secret key establishment, use the X25519 +
 * ML-KEM-768 hybrid KEX (pqhybrid) instead. Type name retained for API
 * compatibility.
 */
class PAKEExchange {
    static ITERATIONS = 600000;

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
        // Keyed HMAC (not SHA256(key || role)) to match the Rust source of truth
        // byte-for-byte and avoid length-extension.
        // Locked by tests/channel_session_vectors.json.
        return crypto.createHmac('sha256', baseKey).update(Buffer.from(role)).digest();
    }

    /**
     * Combine key contributions into session key.
     * @param {...Buffer} contributions - Key contributions
     * @returns {Buffer}
     */
    static combine(...contributions) {
        // Sort so the result is order-independent, then combine with a keyed
        // HMAC: HMAC-SHA256(sorted[0], sorted[1] || sorted[2] ...). Matches the
        // Rust source of truth byte-for-byte (not SHA256(concat)).
        const sorted = contributions.sort(Buffer.compare);
        const data = Buffer.concat(sorted.slice(1));
        return crypto.createHmac('sha256', sorted[0]).update(data).digest();
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
