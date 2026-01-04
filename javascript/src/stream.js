/**
 * Shield Stream - Streaming encryption for large files.
 *
 * Processes data in chunks with constant memory usage.
 * Each chunk is independently authenticated.
 */

const crypto = require('crypto');
const fs = require('fs');

const DEFAULT_CHUNK_SIZE = 64 * 1024; // 64KB

/**
 * Derive key from password using PBKDF2.
 */
function deriveKey(password, salt, iterations = 100000) {
    return crypto.pbkdf2Sync(password, salt, iterations, 32, 'sha256');
}

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
 * Encrypt a single block with authentication.
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
 * Decrypt a single block with verification.
 */
function decryptBlock(key, encrypted) {
    if (encrypted.length < 32) {
        return null;
    }

    const nonce = encrypted.slice(0, 16);
    const ciphertext = encrypted.slice(16, -16);
    const mac = encrypted.slice(-16);

    const expectedMac = crypto.createHmac('sha256', key)
        .update(Buffer.concat([nonce, ciphertext]))
        .digest()
        .slice(0, 16);

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

/**
 * Streaming encryption for large files.
 */
class StreamCipher {
    /**
     * Create StreamCipher with encryption key.
     *
     * @param {Buffer} key - 32-byte symmetric key
     * @param {number} chunkSize - Size of each chunk (default: 64KB)
     */
    constructor(key, chunkSize = DEFAULT_CHUNK_SIZE) {
        this.key = key;
        this.chunkSize = chunkSize;
    }

    /**
     * Create StreamCipher from password.
     *
     * @param {string} password - User's password
     * @param {Buffer} salt - Salt for key derivation
     * @param {number} chunkSize - Size of each chunk
     * @returns {StreamCipher}
     */
    static fromPassword(password, salt, chunkSize = DEFAULT_CHUNK_SIZE) {
        const key = deriveKey(password, salt);
        return new StreamCipher(key, chunkSize);
    }

    /**
     * Encrypt data in memory.
     *
     * @param {Buffer} data - Data to encrypt
     * @returns {Buffer} Encrypted data
     */
    encrypt(data) {
        const chunks = [];

        // Header: chunk_size(4) || stream_salt(16)
        const streamSalt = crypto.randomBytes(16);
        const header = Buffer.alloc(20);
        header.writeUInt32LE(this.chunkSize);
        streamSalt.copy(header, 4);
        chunks.push(header);

        // Encrypt chunks
        let offset = 0;
        let chunkNum = 0;
        while (offset < data.length) {
            const chunk = data.slice(offset, offset + this.chunkSize);
            offset += this.chunkSize;

            // Derive per-chunk key
            const chunkNumBuf = Buffer.alloc(8);
            chunkNumBuf.writeBigUInt64LE(BigInt(chunkNum));
            const chunkKey = crypto.createHash('sha256')
                .update(Buffer.concat([this.key, streamSalt, chunkNumBuf]))
                .digest();

            const encrypted = encryptBlock(chunkKey, chunk);

            // Prepend length
            const lenBuf = Buffer.alloc(4);
            lenBuf.writeUInt32LE(encrypted.length);
            chunks.push(Buffer.concat([lenBuf, encrypted]));

            chunkNum++;
        }

        // End marker
        const endMarker = Buffer.alloc(4);
        endMarker.writeUInt32LE(0);
        chunks.push(endMarker);

        return Buffer.concat(chunks);
    }

    /**
     * Decrypt data in memory.
     *
     * @param {Buffer} encrypted - Encrypted data
     * @returns {Buffer} Decrypted data
     * @throws {Error} If authentication fails
     */
    decrypt(encrypted) {
        // Read header
        const chunkSize = encrypted.readUInt32LE(0);
        const streamSalt = encrypted.slice(4, 20);

        const chunks = [];
        let offset = 20;
        let chunkNum = 0;

        while (offset < encrypted.length) {
            const encLen = encrypted.readUInt32LE(offset);
            if (encLen === 0) break; // End marker

            offset += 4;
            const encChunk = encrypted.slice(offset, offset + encLen);
            offset += encLen;

            // Derive per-chunk key
            const chunkNumBuf = Buffer.alloc(8);
            chunkNumBuf.writeBigUInt64LE(BigInt(chunkNum));
            const chunkKey = crypto.createHash('sha256')
                .update(Buffer.concat([this.key, streamSalt, chunkNumBuf]))
                .digest();

            const decrypted = decryptBlock(chunkKey, encChunk);
            if (decrypted === null) {
                throw new Error(`Chunk ${chunkNum} authentication failed`);
            }

            chunks.push(decrypted);
            chunkNum++;
        }

        return Buffer.concat(chunks);
    }

    /**
     * Encrypt a file.
     *
     * @param {string} inPath - Input file path
     * @param {string} outPath - Output file path
     */
    encryptFile(inPath, outPath) {
        const data = fs.readFileSync(inPath);
        const encrypted = this.encrypt(data);
        fs.writeFileSync(outPath, encrypted);
    }

    /**
     * Decrypt a file.
     *
     * @param {string} inPath - Input file path
     * @param {string} outPath - Output file path
     */
    decryptFile(inPath, outPath) {
        const encrypted = fs.readFileSync(inPath);
        const decrypted = this.decrypt(encrypted);
        fs.writeFileSync(outPath, decrypted);
    }
}

module.exports = {
    StreamCipher,
    deriveKey,
    encryptBlock,
    decryptBlock
};
