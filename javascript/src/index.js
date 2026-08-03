/**
 * Shield - Authenticated Symmetric Encryption Library
 *
 * Symmetric authenticated encryption with 256-bit keys (~128-bit post-quantum security).
 * Brute-forcing a full 256-bit key requires 2^256 operations; this relies on the standard assumption that SHA-256/HMAC have no exploitable structure (an assumption, not a mathematical proof).
 *
 * @example
 * const { Shield, quickEncrypt, quickDecrypt } = require('@dikestra/shield');
 *
 * // Password-based encryption
 * const s = new Shield('password', 'service.com');
 * const encrypted = s.encrypt(Buffer.from('secret data'));
 * const decrypted = s.decrypt(encrypted);
 *
 * // Pre-shared key encryption
 * const key = crypto.randomBytes(32);
 * const enc = quickEncrypt(key, Buffer.from('data'));
 * const dec = quickDecrypt(key, enc);
 */

const { Shield, quickEncrypt, quickDecrypt } = require('./shield');
const { StreamCipher } = require('./stream');
const { RatchetSession } = require('./ratchet');
const { TOTP, RecoveryCodes } = require('./totp');
const { SymmetricSignature, LamportSignature } = require('./signatures');
const { PAKEExchange, QRExchange, KeySplitter } = require('./exchange');
const { KeyRotationManager } = require('./rotation');
const { GroupEncryption, BroadcastEncryption } = require('./group');
const { IdentityProvider, Identity, Session, SecureSession } = require('./identity');
const { ShieldChannel, ChannelConfig, ShieldListener } = require('./channel');

module.exports = {
    // Core encryption
    Shield,
    quickEncrypt,
    quickDecrypt,

    // Streaming encryption
    StreamCipher,

    // Forward secrecy
    RatchetSession,

    // 2FA
    TOTP,
    RecoveryCodes,

    // Digital signatures
    SymmetricSignature,
    LamportSignature,

    // Key exchange
    PAKEExchange,
    QRExchange,
    KeySplitter,

    // Key rotation
    KeyRotationManager,

    // Group encryption
    GroupEncryption,
    BroadcastEncryption,

    // Identity/SSO
    IdentityProvider,
    Identity,
    Session,
    SecureSession,

    // Secure channel
    ShieldChannel,
    ChannelConfig,
    ShieldListener
};
