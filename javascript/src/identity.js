/**
 * Shield Identity - SSO/Identity Provider without public-key crypto.
 *
 * Provides secure identity management, session tokens, and service tokens
 * using only symmetric cryptography.
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
 * User identity.
 */
class Identity {
    constructor(userId, displayName, verificationKey, attributes = {}) {
        this.userId = userId;
        this.displayName = displayName;
        this.verificationKey = verificationKey;
        this.attributes = attributes;
        this.createdAt = Math.floor(Date.now() / 1000);
    }
}

/**
 * Session information.
 */
class Session {
    constructor(userId, permissions = [], expiresAt = null, attributes = {}) {
        this.userId = userId;
        this.permissions = permissions;
        this.expiresAt = expiresAt;
        this.attributes = attributes;
    }

    get isExpired() {
        if (this.expiresAt === null) return false;
        return Math.floor(Date.now() / 1000) > this.expiresAt;
    }

    hasPermission(permission) {
        return this.permissions.includes(permission);
    }
}

/**
 * Identity Provider - manages users and sessions.
 */
class IdentityProvider {
    static ITERATIONS = 100000;

    /**
     * Initialize identity provider.
     * @param {Buffer} masterKey - 32-byte master key
     * @param {number} tokenTtl - Default token TTL in seconds
     */
    constructor(masterKey, tokenTtl = 3600) {
        this._masterKey = masterKey;
        this._tokenTtl = tokenTtl;
        this._users = new Map(); // userId -> {passwordHash, salt, identity}
    }

    /**
     * Derive key for specific purpose.
     */
    _deriveKey(purpose) {
        return crypto.createHash('sha256')
            .update(Buffer.concat([this._masterKey, Buffer.from(purpose)]))
            .digest();
    }

    /**
     * Register new user.
     * @param {string} userId - Unique user ID
     * @param {string} password - User's password
     * @param {string} displayName - Display name
     * @param {Object} attributes - Additional attributes
     * @returns {Identity}
     */
    register(userId, password, displayName = null, attributes = {}) {
        if (this._users.has(userId)) {
            throw new Error(`User ${userId} already exists`);
        }

        const salt = crypto.randomBytes(16);
        const passwordHash = crypto.pbkdf2Sync(
            password, salt, IdentityProvider.ITERATIONS, 32, 'sha256'
        );

        // Generate verification key
        const verificationKey = crypto.createHash('sha256')
            .update(Buffer.concat([this._deriveKey('verify'), Buffer.from(userId)]))
            .digest();

        const identity = new Identity(
            userId,
            displayName || userId,
            verificationKey,
            attributes
        );

        this._users.set(userId, {
            passwordHash,
            salt,
            identity
        });

        return identity;
    }

    /**
     * Authenticate user.
     * @param {string} userId - User ID
     * @param {string} password - Password
     * @param {string[]} permissions - Permissions to include
     * @param {number} ttl - Token TTL
     * @returns {string|null} Session token or null
     */
    authenticate(userId, password, permissions = [], ttl = null) {
        const user = this._users.get(userId);
        if (!user) return null;

        const passwordHash = crypto.pbkdf2Sync(
            password, user.salt, IdentityProvider.ITERATIONS, 32, 'sha256'
        );

        if (!crypto.timingSafeEqual(passwordHash, user.passwordHash)) {
            return null;
        }

        return this._createToken(userId, permissions, ttl || this._tokenTtl);
    }

    /**
     * Create session token.
     */
    _createToken(userId, permissions, ttl) {
        const expiresAt = Math.floor(Date.now() / 1000) + ttl;
        const nonce = crypto.randomBytes(16);

        // Token data: userId length (2) + userId + permissions JSON + expires (8)
        const userIdBuf = Buffer.from(userId);
        const permsBuf = Buffer.from(JSON.stringify(permissions));
        const expiresBuf = Buffer.alloc(8);
        expiresBuf.writeBigUInt64LE(BigInt(expiresAt));

        const userIdLen = Buffer.alloc(2);
        userIdLen.writeUInt16LE(userIdBuf.length);

        const permsLen = Buffer.alloc(2);
        permsLen.writeUInt16LE(permsBuf.length);

        const tokenData = Buffer.concat([userIdLen, userIdBuf, permsLen, permsBuf, expiresBuf]);

        // Encrypt
        const key = this._deriveKey('session');
        const keystream = generateKeystream(key, nonce, tokenData.length);
        const encrypted = Buffer.alloc(tokenData.length);
        for (let i = 0; i < tokenData.length; i++) {
            encrypted[i] = tokenData[i] ^ keystream[i];
        }

        // MAC
        const mac = crypto.createHmac('sha256', key)
            .update(Buffer.concat([nonce, encrypted]))
            .digest()
            .slice(0, 16);

        return Buffer.concat([nonce, encrypted, mac]).toString('base64url');
    }

    /**
     * Validate session token.
     * @param {string} token - Session token
     * @returns {Session|null}
     */
    validateToken(token) {
        try {
            const data = Buffer.from(token, 'base64url');
            if (data.length < 34) return null;

            const nonce = data.slice(0, 16);
            const encrypted = data.slice(16, -16);
            const mac = data.slice(-16);

            const key = this._deriveKey('session');

            // Verify MAC
            const expectedMac = crypto.createHmac('sha256', key)
                .update(Buffer.concat([nonce, encrypted]))
                .digest()
                .slice(0, 16);

            if (!crypto.timingSafeEqual(mac, expectedMac)) return null;

            // Decrypt
            const keystream = generateKeystream(key, nonce, encrypted.length);
            const tokenData = Buffer.alloc(encrypted.length);
            for (let i = 0; i < encrypted.length; i++) {
                tokenData[i] = encrypted[i] ^ keystream[i];
            }

            // Parse
            const userIdLen = tokenData.readUInt16LE(0);
            const userId = tokenData.slice(2, 2 + userIdLen).toString();
            const permsLen = tokenData.readUInt16LE(2 + userIdLen);
            const permissions = JSON.parse(tokenData.slice(4 + userIdLen, 4 + userIdLen + permsLen).toString());
            const expiresAt = Number(tokenData.readBigUInt64LE(4 + userIdLen + permsLen));

            const session = new Session(userId, permissions, expiresAt);
            if (session.isExpired) return null;

            return session;
        } catch (e) {
            return null;
        }
    }

    /**
     * Create service-specific token.
     * @param {string} sessionToken - Valid session token
     * @param {string} service - Service identifier
     * @param {string[]} permissions - Service permissions
     * @param {number} ttl - Token TTL
     * @returns {string|null}
     */
    createServiceToken(sessionToken, service, permissions = [], ttl = 300) {
        const session = this.validateToken(sessionToken);
        if (!session) return null;

        const expiresAt = Math.floor(Date.now() / 1000) + ttl;
        const nonce = crypto.randomBytes(16);

        // Token data
        const userIdBuf = Buffer.from(session.userId);
        const serviceBuf = Buffer.from(service);
        const permsBuf = Buffer.from(JSON.stringify(permissions));
        const expiresBuf = Buffer.alloc(8);
        expiresBuf.writeBigUInt64LE(BigInt(expiresAt));

        const userIdLen = Buffer.alloc(2);
        userIdLen.writeUInt16LE(userIdBuf.length);

        const serviceLen = Buffer.alloc(2);
        serviceLen.writeUInt16LE(serviceBuf.length);

        const permsLen = Buffer.alloc(2);
        permsLen.writeUInt16LE(permsBuf.length);

        const tokenData = Buffer.concat([
            userIdLen, userIdBuf,
            serviceLen, serviceBuf,
            permsLen, permsBuf,
            expiresBuf
        ]);

        // Encrypt with service-specific key
        const key = this._deriveKey(`service:${service}`);
        const keystream = generateKeystream(key, nonce, tokenData.length);
        const encrypted = Buffer.alloc(tokenData.length);
        for (let i = 0; i < tokenData.length; i++) {
            encrypted[i] = tokenData[i] ^ keystream[i];
        }

        const mac = crypto.createHmac('sha256', key)
            .update(Buffer.concat([nonce, encrypted]))
            .digest()
            .slice(0, 16);

        return Buffer.concat([nonce, encrypted, mac]).toString('base64url');
    }

    /**
     * Validate service token.
     * @param {string} token - Service token
     * @param {string} service - Expected service
     * @returns {Session|null}
     */
    validateServiceToken(token, service) {
        try {
            const data = Buffer.from(token, 'base64url');
            if (data.length < 34) return null;

            const nonce = data.slice(0, 16);
            const encrypted = data.slice(16, -16);
            const mac = data.slice(-16);

            const key = this._deriveKey(`service:${service}`);

            // Verify MAC
            const expectedMac = crypto.createHmac('sha256', key)
                .update(Buffer.concat([nonce, encrypted]))
                .digest()
                .slice(0, 16);

            if (!crypto.timingSafeEqual(mac, expectedMac)) return null;

            // Decrypt
            const keystream = generateKeystream(key, nonce, encrypted.length);
            const tokenData = Buffer.alloc(encrypted.length);
            for (let i = 0; i < encrypted.length; i++) {
                tokenData[i] = encrypted[i] ^ keystream[i];
            }

            // Parse
            let offset = 0;
            const userIdLen = tokenData.readUInt16LE(offset);
            offset += 2;
            const userId = tokenData.slice(offset, offset + userIdLen).toString();
            offset += userIdLen;

            const serviceLen = tokenData.readUInt16LE(offset);
            offset += 2;
            const tokenService = tokenData.slice(offset, offset + serviceLen).toString();
            offset += serviceLen;

            if (tokenService !== service) return null;

            const permsLen = tokenData.readUInt16LE(offset);
            offset += 2;
            const permissions = JSON.parse(tokenData.slice(offset, offset + permsLen).toString());
            offset += permsLen;

            const expiresAt = Number(tokenData.readBigUInt64LE(offset));

            const session = new Session(userId, permissions, expiresAt);
            if (session.isExpired) return null;

            return session;
        } catch (e) {
            return null;
        }
    }

    /**
     * Refresh session token.
     * @param {string} token - Current token
     * @returns {string|null}
     */
    refreshToken(token) {
        const session = this.validateToken(token);
        if (!session) return null;
        return this._createToken(session.userId, session.permissions, this._tokenTtl);
    }

    /**
     * Get user identity.
     * @param {string} userId - User ID
     * @returns {Identity|null}
     */
    getIdentity(userId) {
        const user = this._users.get(userId);
        return user ? user.identity : null;
    }

    /**
     * Revoke user.
     * @param {string} userId - User ID
     */
    revokeUser(userId) {
        this._users.delete(userId);
    }
}

/**
 * Secure session with automatic key rotation.
 */
class SecureSession {
    /**
     * Initialize secure session.
     * @param {Buffer} masterKey - Master key
     * @param {number} rotationInterval - Key rotation interval in seconds
     * @param {number} maxOldKeys - Number of old keys to keep
     */
    constructor(masterKey, rotationInterval = 3600, maxOldKeys = 3) {
        this._masterKey = masterKey;
        this._rotationInterval = rotationInterval;
        this._maxOldKeys = maxOldKeys;
        this._keyVersion = 1;
        this._keys = new Map([[1, this._deriveKey(1)]]);
        this._lastRotation = Date.now();
    }

    _deriveKey(version) {
        return crypto.createHash('sha256')
            .update(Buffer.concat([
                this._masterKey,
                Buffer.from(`session:${version}`)
            ]))
            .digest();
    }

    _maybeRotate() {
        const elapsed = (Date.now() - this._lastRotation) / 1000;
        if (elapsed >= this._rotationInterval) {
            this._keyVersion++;
            this._keys.set(this._keyVersion, this._deriveKey(this._keyVersion));
            this._lastRotation = Date.now();

            // Prune old keys
            const versions = Array.from(this._keys.keys()).sort((a, b) => b - a);
            for (const v of versions.slice(this._maxOldKeys + 1)) {
                this._keys.delete(v);
            }
        }
    }

    /**
     * Encrypt session data.
     * @param {Buffer} data - Data to encrypt
     * @returns {Buffer}
     */
    encrypt(data) {
        this._maybeRotate();

        const key = this._keys.get(this._keyVersion);
        const nonce = crypto.randomBytes(16);

        const keystream = generateKeystream(key, nonce, data.length);
        const ciphertext = Buffer.alloc(data.length);
        for (let i = 0; i < data.length; i++) {
            ciphertext[i] = data[i] ^ keystream[i];
        }

        const versionBuf = Buffer.alloc(4);
        versionBuf.writeUInt32LE(this._keyVersion);

        const mac = crypto.createHmac('sha256', key)
            .update(Buffer.concat([versionBuf, nonce, ciphertext]))
            .digest()
            .slice(0, 16);

        return Buffer.concat([versionBuf, nonce, ciphertext, mac]);
    }

    /**
     * Decrypt session data.
     * @param {Buffer} encrypted - Encrypted data
     * @returns {Buffer|null}
     */
    decrypt(encrypted) {
        this._maybeRotate();

        if (encrypted.length < 36) return null;

        const version = encrypted.readUInt32LE(0);
        const nonce = encrypted.slice(4, 20);
        const ciphertext = encrypted.slice(20, -16);
        const mac = encrypted.slice(-16);

        const key = this._keys.get(version);
        if (!key) return null;

        // Verify MAC
        const expectedMac = crypto.createHmac('sha256', key)
            .update(encrypted.slice(0, -16))
            .digest()
            .slice(0, 16);

        if (!crypto.timingSafeEqual(mac, expectedMac)) return null;

        const keystream = generateKeystream(key, nonce, ciphertext.length);
        const plaintext = Buffer.alloc(ciphertext.length);
        for (let i = 0; i < ciphertext.length; i++) {
            plaintext[i] = ciphertext[i] ^ keystream[i];
        }

        return plaintext;
    }
}

module.exports = { IdentityProvider, Identity, Session, SecureSession };
