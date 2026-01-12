/**
 * Shield Secure Channel - TLS/SSH-like secure transport using symmetric crypto.
 *
 * Provides encrypted bidirectional communication with:
 * - PAKE-based handshake (no certificates needed)
 * - Forward secrecy via key ratcheting
 * - Message authentication and replay protection
 *
 * @example
 * const { ShieldChannel, ChannelConfig } = require('@guard8/shield');
 * const net = require('net');
 *
 * // Both parties share a password
 * const config = new ChannelConfig('shared-secret', 'my-service');
 *
 * // Client side
 * const socket = net.connect(8080, 'localhost');
 * const client = await ShieldChannel.connect(socket, config);
 * await client.send(Buffer.from('Hello server!'));
 */

const crypto = require('crypto');
const { PAKEExchange } = require('./exchange');
const { RatchetSession } = require('./ratchet');

// Protocol constants
const PROTOCOL_VERSION = 1;
const MAX_MESSAGE_SIZE = 16 * 1024 * 1024; // 16 MB

// Handshake message types
const HANDSHAKE_CLIENT_HELLO = 1;
const HANDSHAKE_SERVER_HELLO = 2;
const HANDSHAKE_FINISHED = 3;

/**
 * Channel configuration.
 */
class ChannelConfig {
    /**
     * Create channel configuration.
     * @param {string} password - Shared password for PAKE
     * @param {string} service - Service identifier for domain separation
     * @param {number} iterations - PBKDF2 iterations (default: 200000)
     * @param {number} handshakeTimeoutMs - Handshake timeout (default: 30000)
     */
    constructor(password, service, iterations = 200000, handshakeTimeoutMs = 30000) {
        this.password = password;
        this.service = service;
        this.iterations = iterations;
        this.handshakeTimeoutMs = handshakeTimeoutMs;
    }

    /**
     * Set custom iterations.
     * @param {number} iterations
     * @returns {ChannelConfig}
     */
    withIterations(iterations) {
        this.iterations = iterations;
        return this;
    }

    /**
     * Set handshake timeout.
     * @param {number} timeoutMs
     * @returns {ChannelConfig}
     */
    withTimeout(timeoutMs) {
        this.handshakeTimeoutMs = timeoutMs;
        return this;
    }
}

/**
 * Shield secure channel for encrypted communication.
 *
 * Provides TLS-like security using only symmetric cryptography:
 * - PAKE handshake establishes shared key from password
 * - RatchetSession provides forward secrecy
 * - All messages authenticated with HMAC
 */
class ShieldChannel {
    constructor(stream, session, service) {
        this._stream = stream;
        this._session = session;
        this._service = service;
        this._readBuffer = Buffer.alloc(0);
    }

    /**
     * Connect as client (initiator).
     * @param {net.Socket} stream - Underlying transport
     * @param {ChannelConfig} config - Channel configuration
     * @returns {Promise<ShieldChannel>}
     */
    static async connect(stream, config) {
        const channel = new ShieldChannel(stream, null, config.service);

        // Step 1: Generate client salt and send ClientHello
        const clientSalt = crypto.randomBytes(16);
        await channel._sendHandshake(HANDSHAKE_CLIENT_HELLO, clientSalt);

        // Step 2: Receive ServerHello
        const serverHello = await channel._recvHandshake(HANDSHAKE_SERVER_HELLO);
        if (serverHello.length !== 48) {
            throw new Error('Invalid ServerHello');
        }

        const finalSalt = serverHello.slice(0, 16);
        const serverContribution = serverHello.slice(16, 48);

        // Step 3: Derive our contribution and send it
        const clientContribution = PAKEExchange.derive(
            config.password, finalSalt, 'client', config.iterations
        );
        await channel._sendHandshake(HANDSHAKE_FINISHED, clientContribution);

        // Compute session key
        const sessionKey = channel._computeSessionKey(
            config, finalSalt, clientContribution, serverContribution
        );

        // Create ratchet session
        channel._session = new RatchetSession(sessionKey, true);

        // Exchange confirmations
        await channel._sendConfirmation(sessionKey, true);
        await channel._verifyConfirmation(sessionKey, false);

        return channel;
    }

    /**
     * Accept connection as server.
     * @param {net.Socket} stream - Underlying transport
     * @param {ChannelConfig} config - Channel configuration
     * @returns {Promise<ShieldChannel>}
     */
    static async accept(stream, config) {
        const channel = new ShieldChannel(stream, null, config.service);

        // Step 1: Receive ClientHello
        const clientHello = await channel._recvHandshake(HANDSHAKE_CLIENT_HELLO);
        if (clientHello.length !== 16) {
            throw new Error('Invalid ClientHello');
        }

        // Mix salts
        const serverSalt = crypto.randomBytes(16);
        const finalSalt = Buffer.alloc(16);
        for (let i = 0; i < 16; i++) {
            finalSalt[i] = serverSalt[i] ^ clientHello[i];
        }

        // Derive server contribution
        const serverContribution = PAKEExchange.derive(
            config.password, finalSalt, 'server', config.iterations
        );

        // Step 2: Send ServerHello
        const serverHello = Buffer.concat([finalSalt, serverContribution]);
        await channel._sendHandshake(HANDSHAKE_SERVER_HELLO, serverHello);

        // Step 3: Receive client contribution
        const clientFinished = await channel._recvHandshake(HANDSHAKE_FINISHED);
        if (clientFinished.length !== 32) {
            throw new Error('Invalid Finished');
        }

        // Compute session key
        const sessionKey = channel._computeSessionKey(
            config, finalSalt, serverContribution, clientFinished
        );

        // Create ratchet session
        channel._session = new RatchetSession(sessionKey, false);

        // Exchange confirmations
        await channel._verifyConfirmation(sessionKey, true);
        await channel._sendConfirmation(sessionKey, false);

        return channel;
    }

    /**
     * Send encrypted message.
     * @param {Buffer} data - Data to send
     * @returns {Promise<void>}
     */
    async send(data) {
        if (data.length > MAX_MESSAGE_SIZE) {
            throw new Error(`Message too large: ${data.length} > ${MAX_MESSAGE_SIZE}`);
        }

        const encrypted = this._session.encrypt(data);
        await this._writeFrame(encrypted);
    }

    /**
     * Receive and decrypt message.
     * @returns {Promise<Buffer>}
     */
    async recv() {
        const encrypted = await this._readFrame();
        return this._session.decrypt(encrypted);
    }

    /**
     * Get service identifier.
     * @returns {string}
     */
    get service() {
        return this._service;
    }

    /**
     * Get send message count.
     * @returns {number}
     */
    get messagesSent() {
        return this._session.sendCounter;
    }

    /**
     * Get receive message count.
     * @returns {number}
     */
    get messagesReceived() {
        return this._session.recvCounter;
    }

    /**
     * Close channel.
     */
    close() {
        this._stream.destroy();
    }

    // --- Internal helpers ---

    _computeSessionKey(config, salt, localContribution, remoteContribution) {
        const baseKey = PAKEExchange.combine(localContribution, remoteContribution);
        const passwordKey = PAKEExchange.derive(
            config.password, salt, 'session', config.iterations
        );

        const combined = Buffer.concat([baseKey, passwordKey]);
        return crypto.createHash('sha256').update(combined).digest();
    }

    async _sendHandshake(msgType, data) {
        const frame = Buffer.alloc(4 + data.length);
        frame[0] = PROTOCOL_VERSION;
        frame[1] = msgType;
        frame.writeUInt16BE(data.length, 2);
        data.copy(frame, 4);

        return new Promise((resolve, reject) => {
            this._stream.write(frame, (err) => {
                if (err) reject(err);
                else resolve();
            });
        });
    }

    async _recvHandshake(expectedType) {
        const header = await this._readBytes(4);

        if (header[0] !== PROTOCOL_VERSION) {
            throw new Error(`Unsupported protocol version: ${header[0]}`);
        }

        if (header[1] !== expectedType) {
            throw new Error(`Unexpected message type: expected ${expectedType}, got ${header[1]}`);
        }

        const length = header.readUInt16BE(2);
        if (length > 1024) {
            throw new Error('Handshake message too large');
        }

        return this._readBytes(length);
    }

    async _sendConfirmation(sessionKey, isClient) {
        const label = isClient ? 'client-confirm' : 'server-confirm';
        const confirm = crypto.createHmac('sha256', sessionKey)
            .update(label)
            .digest()
            .slice(0, 16);
        await this._writeFrameRaw(confirm);
    }

    async _verifyConfirmation(sessionKey, expectClient) {
        const received = await this._readFrameRaw();
        if (received.length !== 16) {
            throw new Error('Invalid confirmation');
        }

        const label = expectClient ? 'client-confirm' : 'server-confirm';
        const expected = crypto.createHmac('sha256', sessionKey)
            .update(label)
            .digest()
            .slice(0, 16);

        if (!crypto.timingSafeEqual(received, expected)) {
            throw new Error('Authentication failed');
        }
    }

    async _writeFrame(data) {
        return this._writeFrameRaw(data);
    }

    async _readFrame() {
        return this._readFrameRaw();
    }

    async _writeFrameRaw(data) {
        const header = Buffer.alloc(4);
        header.writeUInt32BE(data.length, 0);

        return new Promise((resolve, reject) => {
            this._stream.write(Buffer.concat([header, data]), (err) => {
                if (err) reject(err);
                else resolve();
            });
        });
    }

    async _readFrameRaw() {
        const lenBuf = await this._readBytes(4);
        const length = lenBuf.readUInt32BE(0);

        if (length > MAX_MESSAGE_SIZE) {
            throw new Error(`Frame too large: ${length} > ${MAX_MESSAGE_SIZE}`);
        }

        return this._readBytes(length);
    }

    async _readBytes(count) {
        return new Promise((resolve, reject) => {
            const tryRead = () => {
                if (this._readBuffer.length >= count) {
                    const result = this._readBuffer.slice(0, count);
                    this._readBuffer = this._readBuffer.slice(count);
                    resolve(result);
                    return;
                }

                this._stream.once('data', (chunk) => {
                    this._readBuffer = Buffer.concat([this._readBuffer, chunk]);
                    tryRead();
                });

                this._stream.once('error', reject);
                this._stream.once('close', () => reject(new Error('Connection closed')));
            };

            tryRead();
        });
    }
}

/**
 * Channel listener for accepting multiple connections.
 */
class ShieldListener {
    /**
     * Create listener.
     * @param {net.Server} server - TCP server
     * @param {ChannelConfig} config - Channel configuration
     */
    constructor(server, config) {
        this._server = server;
        this._config = config;
    }

    /**
     * Accept next connection.
     * @returns {Promise<ShieldChannel>}
     */
    async accept() {
        return new Promise((resolve, reject) => {
            this._server.once('connection', async (socket) => {
                try {
                    const channel = await ShieldChannel.accept(socket, this._config);
                    resolve(channel);
                } catch (err) {
                    reject(err);
                }
            });

            this._server.once('error', reject);
        });
    }

    /**
     * Get configuration.
     * @returns {ChannelConfig}
     */
    get config() {
        return this._config;
    }

    /**
     * Close listener.
     */
    close() {
        this._server.close();
    }
}

module.exports = { ShieldChannel, ChannelConfig, ShieldListener };
