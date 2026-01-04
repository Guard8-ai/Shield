/**
 * Shield - EXPTIME-Secure Encryption Library
 * TypeScript declarations
 */

export interface ShieldOptions {
    salt?: Buffer;
    iterations?: number;
}

export interface TOTPOptions {
    digits?: number;
    interval?: number;
    algorithm?: 'sha1' | 'sha256';
}

/**
 * Password-based symmetric encryption.
 */
export class Shield {
    constructor(password: string, service: string, options?: ShieldOptions);
    static withKey(key: Buffer): Shield;
    encrypt(plaintext: Buffer): Buffer;
    decrypt(encrypted: Buffer): Buffer | null;
    readonly key: Buffer;
}

/**
 * Streaming encryption for large files.
 */
export class StreamCipher {
    constructor(key: Buffer, chunkSize?: number);
    static fromPassword(password: string, salt: Buffer, chunkSize?: number): StreamCipher;
    encrypt(data: Buffer): Buffer;
    decrypt(encrypted: Buffer): Buffer;
    encryptFile(inPath: string, outPath: string): void;
    decryptFile(inPath: string, outPath: string): void;
}

/**
 * Ratcheting session for forward secrecy.
 */
export class RatchetSession {
    constructor(rootKey: Buffer, isInitiator: boolean);
    encrypt(plaintext: Buffer): Buffer;
    decrypt(ciphertext: Buffer): Buffer | null;
    readonly sendCounter: number;
    readonly recvCounter: number;
}

/**
 * Time-based One-Time Password generator.
 */
export class TOTP {
    constructor(secret: Buffer, options?: TOTPOptions);
    static generateSecret(length?: number): Buffer;
    static secretToBase32(secret: Buffer): string;
    static secretFromBase32(b32: string): Buffer;
    generate(timestamp?: number): string;
    verify(code: string, timestamp?: number, window?: number): boolean;
    provisioningUri(account: string, issuer?: string): string;
}

/**
 * Recovery codes for 2FA backup.
 */
export class RecoveryCodes {
    constructor(codes?: string[]);
    static generateCodes(count?: number, length?: number): string[];
    verify(code: string): boolean;
    readonly remaining: number;
    readonly codes: string[];
}

/**
 * One-shot encrypt with pre-shared key.
 */
export function quickEncrypt(key: Buffer, data: Buffer): Buffer;

/**
 * One-shot decrypt with pre-shared key.
 */
export function quickDecrypt(key: Buffer, encrypted: Buffer): Buffer | null;
