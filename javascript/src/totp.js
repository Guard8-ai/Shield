/**
 * Shield TOTP - Time-based One-Time Passwords (RFC 6238).
 *
 * Compatible with Google Authenticator, Authy, Microsoft Authenticator, etc.
 */

const crypto = require('crypto');

/**
 * TOTP generator/verifier.
 */
class TOTP {
    /**
     * Initialize TOTP generator.
     *
     * @param {Buffer} secret - Shared secret (typically 20 bytes)
     * @param {Object} options - Optional settings
     * @param {number} options.digits - OTP length (6 or 8)
     * @param {number} options.interval - Time step in seconds
     * @param {string} options.algorithm - 'sha1' (compatible) or 'sha256'
     */
    constructor(secret, options = {}) {
        this.secret = secret;
        this.digits = options.digits || 6;
        this.interval = options.interval || 30;
        this.algorithm = options.algorithm || 'sha1';
    }

    /**
     * Generate random secret for new 2FA setup.
     *
     * @param {number} length - Secret length in bytes
     * @returns {Buffer}
     */
    static generateSecret(length = 20) {
        return crypto.randomBytes(length);
    }

    /**
     * Convert secret to base32 for QR codes.
     *
     * @param {Buffer} secret - Secret bytes
     * @returns {string} Base32 encoded string (without padding)
     */
    static secretToBase32(secret) {
        const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        let bits = '';
        for (const byte of secret) {
            bits += byte.toString(2).padStart(8, '0');
        }
        let result = '';
        for (let i = 0; i < bits.length; i += 5) {
            const chunk = bits.substr(i, 5).padEnd(5, '0');
            result += alphabet[parseInt(chunk, 2)];
        }
        return result;
    }

    /**
     * Parse base32 secret from authenticator app.
     *
     * @param {string} b32 - Base32 encoded secret
     * @returns {Buffer} Secret bytes
     */
    static secretFromBase32(b32) {
        const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        let bits = '';
        for (const char of b32.toUpperCase().replace(/=/g, '')) {
            const val = alphabet.indexOf(char);
            if (val >= 0) bits += val.toString(2).padStart(5, '0');
        }
        const bytes = [];
        for (let i = 0; i + 8 <= bits.length; i += 8) {
            bytes.push(parseInt(bits.substr(i, 8), 2));
        }
        return Buffer.from(bytes);
    }

    /**
     * Generate current TOTP code.
     *
     * @param {number} timestamp - Unix timestamp (default: current time)
     * @returns {string} OTP code
     */
    generate(timestamp = null) {
        if (timestamp === null) {
            timestamp = Math.floor(Date.now() / 1000);
        }
        const counter = Math.floor(timestamp / this.interval);
        return this._hotp(counter);
    }

    /**
     * Verify TOTP code with time window.
     *
     * @param {string} code - User-provided code
     * @param {number} timestamp - Time to verify against
     * @param {number} window - Number of intervals to check before/after
     * @returns {boolean}
     */
    verify(code, timestamp = null, window = 1) {
        if (timestamp === null) {
            timestamp = Math.floor(Date.now() / 1000);
        }
        const counter = Math.floor(timestamp / this.interval);

        for (let offset = -window; offset <= window; offset++) {
            const expected = this._hotp(counter + offset);
            if (crypto.timingSafeEqual(
                Buffer.from(code),
                Buffer.from(expected)
            )) {
                return true;
            }
        }
        return false;
    }

    _hotp(counter) {
        // Counter as 8-byte big-endian
        const counterBytes = Buffer.alloc(8);
        counterBytes.writeBigUInt64BE(BigInt(counter));

        // HMAC
        const h = crypto.createHmac(this.algorithm, this.secret)
            .update(counterBytes)
            .digest();

        // Dynamic truncation
        const offset = h[h.length - 1] & 0x0F;
        const code = (h.readUInt32BE(offset) & 0x7FFFFFFF) %
            Math.pow(10, this.digits);

        return code.toString().padStart(this.digits, '0');
    }

    /**
     * Generate URI for QR code.
     *
     * @param {string} account - User account identifier
     * @param {string} issuer - Service name
     * @returns {string} otpauth:// URI
     */
    provisioningUri(account, issuer = 'Shield') {
        const secret = TOTP.secretToBase32(this.secret);
        return `otpauth://totp/${issuer}:${account}` +
            `?secret=${secret}&issuer=${issuer}` +
            `&algorithm=${this.algorithm.toUpperCase()}&digits=${this.digits}`;
    }
}

/**
 * Recovery codes for 2FA backup.
 */
class RecoveryCodes {
    /**
     * Initialize with existing codes or generate new ones.
     *
     * @param {string[]} codes - List of existing codes
     */
    constructor(codes = null) {
        if (codes === null) {
            codes = RecoveryCodes.generateCodes();
        }
        this._codes = new Set(codes);
        this._used = new Set();
    }

    /**
     * Generate recovery codes.
     *
     * @param {number} count - Number of codes
     * @param {number} length - Length of each code
     * @returns {string[]}
     */
    static generateCodes(count = 10, length = 8) {
        const codes = [];
        for (let i = 0; i < count; i++) {
            const code = crypto.randomBytes(length / 2).toString('hex').toUpperCase();
            codes.push(`${code.slice(0, 4)}-${code.slice(4)}`);
        }
        return codes;
    }

    /**
     * Verify and consume a recovery code.
     *
     * @param {string} code - Recovery code to verify
     * @returns {boolean}
     */
    verify(code) {
        // Normalize format
        let normalized = code.toUpperCase().replace(/-/g, '').replace(/ /g, '');
        if (normalized.length === 8) {
            normalized = `${normalized.slice(0, 4)}-${normalized.slice(4)}`;
        }

        if (this._codes.has(normalized) && !this._used.has(normalized)) {
            this._used.add(normalized);
            return true;
        }
        return false;
    }

    /**
     * Number of unused recovery codes.
     * @returns {number}
     */
    get remaining() {
        return this._codes.size - this._used.size;
    }

    /**
     * Get all recovery codes.
     * @returns {string[]}
     */
    get codes() {
        return Array.from(this._codes).sort();
    }
}

module.exports = { TOTP, RecoveryCodes };
