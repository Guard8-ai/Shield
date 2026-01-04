/**
 * Shield Group Encryption - Multi-recipient encryption.
 *
 * Encrypt once for multiple recipients, each can decrypt with their own key.
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
 * Encrypt a block with HMAC authentication.
 */
function encryptBlock(key, data) {
    const nonce = crypto.randomBytes(16);
    const keystream = generateKeystream(key, nonce, data.length);
    const ciphertext = Buffer.alloc(data.length);
    for (let i = 0; i < data.length; i++) {
        ciphertext[i] = data[i] ^ keystream[i];
    }
    const mac = crypto.createHmac('sha256', key)
        .update(Buffer.concat([nonce, ciphertext]))
        .digest()
        .slice(0, 16);
    return Buffer.concat([nonce, ciphertext, mac]);
}

/**
 * Decrypt a block with HMAC verification.
 */
function decryptBlock(key, encrypted) {
    if (encrypted.length < 32) return null;

    const nonce = encrypted.slice(0, 16);
    const ciphertext = encrypted.slice(16, -16);
    const mac = encrypted.slice(-16);

    const expectedMac = crypto.createHmac('sha256', key)
        .update(Buffer.concat([nonce, ciphertext]))
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

/**
 * Multi-recipient encryption.
 *
 * Uses a group key for message encryption, then encrypts
 * the group key separately for each member.
 */
class GroupEncryption {
    /**
     * Initialize group encryption.
     * @param {Buffer} groupKey - 32-byte group key (generated if not provided)
     */
    constructor(groupKey = null) {
        this.groupKey = groupKey || crypto.randomBytes(32);
        this._members = new Map();
    }

    /**
     * Add a member to the group.
     * @param {string} memberId - Unique member identifier
     * @param {Buffer} sharedKey - Pre-shared key with this member
     */
    addMember(memberId, sharedKey) {
        this._members.set(memberId, sharedKey);
    }

    /**
     * Remove a member from the group.
     * @param {string} memberId - Member to remove
     * @returns {boolean} True if member was removed
     */
    removeMember(memberId) {
        return this._members.delete(memberId);
    }

    /**
     * Get list of member IDs.
     * @returns {string[]}
     */
    get members() {
        return Array.from(this._members.keys());
    }

    /**
     * Encrypt for all group members.
     * @param {Buffer} plaintext - Message to encrypt
     * @returns {Object} Dictionary with ciphertext and per-member encrypted keys
     */
    encrypt(plaintext) {
        // Encrypt message with group key
        const ciphertext = encryptBlock(this.groupKey, plaintext);

        // Encrypt group key for each member
        const encryptedKeys = {};
        for (const [memberId, memberKey] of this._members) {
            encryptedKeys[memberId] = encryptBlock(memberKey, this.groupKey).toString('base64url');
        }

        return {
            version: 1,
            ciphertext: ciphertext.toString('base64url'),
            keys: encryptedKeys
        };
    }

    /**
     * Decrypt as a group member.
     * @param {Object} encrypted - Encrypted message from encrypt()
     * @param {string} memberId - Your member ID
     * @param {Buffer} memberKey - Your shared key
     * @returns {Buffer|null} Decrypted message, or null if decryption fails
     */
    static decrypt(encrypted, memberId, memberKey) {
        if (!encrypted.keys || !encrypted.keys[memberId]) {
            return null;
        }

        // Decrypt group key
        const encryptedGroupKey = Buffer.from(encrypted.keys[memberId], 'base64url');
        const groupKey = decryptBlock(memberKey, encryptedGroupKey);
        if (groupKey === null) return null;

        // Decrypt message
        const ciphertext = Buffer.from(encrypted.ciphertext, 'base64url');
        return decryptBlock(groupKey, ciphertext);
    }

    /**
     * Rotate the group key.
     * @returns {Buffer} Old group key
     */
    rotateKey() {
        const oldKey = this.groupKey;
        this.groupKey = crypto.randomBytes(32);
        return oldKey;
    }
}

/**
 * Efficient broadcast encryption for large groups.
 *
 * Uses a key hierarchy to reduce per-message overhead.
 * Members are organized into subgroups with shared subgroup keys.
 */
class BroadcastEncryption {
    /**
     * Initialize broadcast encryption.
     * @param {Buffer} masterKey - Master key for the broadcast
     * @param {number} subgroupSize - Members per subgroup
     */
    constructor(masterKey = null, subgroupSize = 16) {
        this.masterKey = masterKey || crypto.randomBytes(32);
        this.subgroupSize = subgroupSize;
        this._members = new Map(); // memberId -> {subgroupId, memberKey}
        this._subgroupKeys = new Map();
        this._nextSubgroup = 0;
    }

    /**
     * Add member to broadcast group.
     * @param {string} memberId - Unique member ID
     * @param {Buffer} memberKey - Shared key with member
     * @returns {number} Subgroup ID assigned
     */
    addMember(memberId, memberKey) {
        // Find subgroup with space
        let subgroupId = null;
        for (const [sgId, sgKey] of this._subgroupKeys) {
            let membersInSg = 0;
            for (const [, data] of this._members) {
                if (data.subgroupId === sgId) membersInSg++;
            }
            if (membersInSg < this.subgroupSize) {
                subgroupId = sgId;
                break;
            }
        }

        if (subgroupId === null) {
            subgroupId = this._nextSubgroup;
            this._subgroupKeys.set(subgroupId, crypto.randomBytes(32));
            this._nextSubgroup++;
        }

        this._members.set(memberId, { subgroupId, memberKey });
        return subgroupId;
    }

    /**
     * Encrypt for broadcast.
     * @param {Buffer} plaintext - Message to encrypt
     * @returns {Object} Encrypted broadcast message
     */
    encrypt(plaintext) {
        const messageKey = crypto.randomBytes(32);

        // Encrypt message
        const ciphertext = encryptBlock(messageKey, plaintext);

        // Encrypt message key for each subgroup
        const subgroupKeysEnc = {};
        for (const [sgId, sgKey] of this._subgroupKeys) {
            subgroupKeysEnc[String(sgId)] = encryptBlock(sgKey, messageKey).toString('base64url');
        }

        // Encrypt subgroup keys for each member
        const memberKeysEnc = {};
        for (const [memberId, { subgroupId, memberKey }] of this._members) {
            const sgKey = this._subgroupKeys.get(subgroupId);
            memberKeysEnc[memberId] = {
                sg: subgroupId,
                key: encryptBlock(memberKey, sgKey).toString('base64url')
            };
        }

        return {
            version: 1,
            ciphertext: ciphertext.toString('base64url'),
            subgroups: subgroupKeysEnc,
            members: memberKeysEnc
        };
    }

    /**
     * Decrypt broadcast as member.
     * @param {Object} encrypted - Encrypted broadcast
     * @param {string} memberId - Your member ID
     * @param {Buffer} memberKey - Your shared key
     * @returns {Buffer|null} Decrypted message
     */
    static decrypt(encrypted, memberId, memberKey) {
        if (!encrypted.members || !encrypted.members[memberId]) {
            return null;
        }

        const memberData = encrypted.members[memberId];
        const sgId = memberData.sg;

        // Decrypt subgroup key
        const sgKeyEnc = Buffer.from(memberData.key, 'base64url');
        const sgKey = decryptBlock(memberKey, sgKeyEnc);
        if (sgKey === null) return null;

        // Decrypt message key
        const msgKeyEnc = Buffer.from(encrypted.subgroups[String(sgId)], 'base64url');
        const msgKey = decryptBlock(sgKey, msgKeyEnc);
        if (msgKey === null) return null;

        // Decrypt message
        const ciphertext = Buffer.from(encrypted.ciphertext, 'base64url');
        return decryptBlock(msgKey, ciphertext);
    }
}

module.exports = { GroupEncryption, BroadcastEncryption };
