/**
 * Shield - Authenticated Symmetric Encryption Library
 *
 * This library uses only symmetric cryptographic primitives — 256-bit keys
 * give ~128-bit post-quantum security: PBKDF2-SHA256, HMAC-SHA256, and SHA256-based
 * stream cipher. Brute-forcing a full 256-bit key requires 2^256 operations; this relies on the standard assumption that SHA-256/HMAC have no exploitable structure (an assumption, not a mathematical proof).
 */

#ifndef SHIELD_H
#define SHIELD_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Constants */
#define SHIELD_KEY_SIZE      32
/* Nonce/MAC size for the auxiliary keystream layers (ratchet/stream). The base
 * AEAD cipher uses its own 12-byte nonce and 16-byte tag (below). */
#define SHIELD_NONCE_SIZE    16
#define SHIELD_MAC_SIZE      16
#define SHIELD_SALT_SIZE     16
#define SHIELD_ITERATIONS    600000

/* Authenticated version byte (leading byte of every ciphertext) — wire format v4 */
#define SHIELD_VERSION_PASSWORD 0x03  /* 0x03 || suite(1) || salt(16) || nonce(12) || ct||tag */
#define SHIELD_VERSION_KEY      0x13  /* 0x13 || suite(1) || nonce(12) || ct||tag */

/* Cipher-suite identifiers */
#define SHIELD_SUITE_AES_GCM            0x01
#define SHIELD_SUITE_CHACHA20_POLY1305  0x02

/* Base-AEAD sizes */
#define SHIELD_AEAD_NONCE_SIZE 12  /* 96-bit AEAD nonce */
#define SHIELD_TAG_SIZE        16  /* 128-bit AEAD tag */
#define SHIELD_INNER_HEADER_SIZE 9 /* timestamp_ms(8) + pad_len(1) */
#define SHIELD_MIN_PADDING     32
#define SHIELD_MAX_PADDING     128
#define SHIELD_DEFAULT_MAX_AGE_MS 60000LL

/* HKDF-Expand info string deriving the AEAD key from the master key */
#define SHIELD_HKDF_AEAD_INFO "shield/aead/v4"

/* Minimum valid ciphertext sizes (version + suite + body + inner header + tag).
 * Password mode also carries the 16-byte salt in the header. */
#define SHIELD_MIN_CIPHERTEXT_SIZE_KEY \
    (2 + SHIELD_AEAD_NONCE_SIZE + SHIELD_TAG_SIZE)
#define SHIELD_MIN_CIPHERTEXT_SIZE_PASSWORD \
    (2 + SHIELD_SALT_SIZE + SHIELD_AEAD_NONCE_SIZE + SHIELD_TAG_SIZE)

/* Maximum stored password/service length for password-mode re-derivation. */
#define SHIELD_MAX_SECRET_LEN 256

/* Error codes */
typedef enum {
    SHIELD_OK = 0,
    SHIELD_ERR_INVALID_KEY_SIZE = -1,
    SHIELD_ERR_CIPHERTEXT_TOO_SHORT = -2,
    SHIELD_ERR_AUTHENTICATION_FAILED = -3,
    SHIELD_ERR_ALLOC_FAILED = -4,
    SHIELD_ERR_RANDOM_FAILED = -5,
    SHIELD_ERR_LAMPORT_KEY_USED = -6,
    SHIELD_ERR_REPLAY_DETECTED = -7,
    SHIELD_ERR_OUT_OF_ORDER = -8,
    SHIELD_ERR_INVALID_SIGNATURE = -9,
    SHIELD_ERR_TOKEN_EXPIRED = -10,
    SHIELD_ERR_INVALID_TOKEN = -11,
    SHIELD_ERR_SESSION_EXPIRED = -12,
    SHIELD_ERR_INVALID_VERSION = -13,  /* unrecognized leading version byte */
    SHIELD_ERR_NO_PASSWORD = -14       /* password-mode ciphertext given to key-mode instance */
} shield_error_t;

/* Shield context.
 *
 * Password mode (shield_init): has_password is true and password/service/salt
 * are populated so the key can be re-derived from a salt carried in a received
 * ciphertext header. The instance's own master + AEAD key are pre-derived.
 * Pre-shared-key mode (shield_init_with_key): has_password is false, a single
 * fixed key is used, and ciphertexts carry no salt.
 */
typedef struct {
    uint8_t key[SHIELD_KEY_SIZE];
    uint8_t aead_key[SHIELD_KEY_SIZE];  /* HKDF-derived AEAD key */
    uint8_t suite;                      /* cipher suite used on encrypt */
    int64_t max_age_ms;  /* -1 = disabled */

    /* Password-mode fields (unused in pre-shared-key mode) */
    bool has_password;
    uint8_t salt[SHIELD_SALT_SIZE];               /* per-instance random salt */
    char password[SHIELD_MAX_SECRET_LEN];         /* NUL-terminated */
    size_t password_len;
    char service[SHIELD_MAX_SECRET_LEN];          /* NUL-terminated */
    size_t service_len;
    int iterations;
} shield_t;

/* Stream cipher context */
typedef struct {
    uint8_t key[SHIELD_KEY_SIZE];
    size_t chunk_size;
} shield_stream_t;

/* Ratchet session context */
typedef struct {
    uint8_t send_key[SHIELD_KEY_SIZE];
    uint8_t recv_key[SHIELD_KEY_SIZE];
    uint64_t send_counter;
    uint64_t recv_counter;
    bool is_initiator;
} shield_ratchet_t;

/* TOTP context */
typedef struct {
    uint8_t *secret;
    size_t secret_len;
    int digits;
    int64_t interval;
} shield_totp_t;

/* Symmetric signature context */
typedef struct {
    uint8_t signing_key[SHIELD_KEY_SIZE];
    uint8_t verification_key[SHIELD_KEY_SIZE];
} shield_signature_t;

/* Lamport signature context */
typedef struct {
    uint8_t private_key[256][2][SHIELD_KEY_SIZE];
    uint8_t *public_key;  /* 256 * 64 = 16384 bytes */
    bool used;
} shield_lamport_t;

/* Recovery codes context */
#define SHIELD_RECOVERY_CODE_LEN 10  /* "XXXX-XXXX" + null = 10 bytes */
#define SHIELD_MAX_RECOVERY_CODES 20

typedef struct {
    char codes[SHIELD_MAX_RECOVERY_CODES][SHIELD_RECOVERY_CODE_LEN];
    bool used[SHIELD_MAX_RECOVERY_CODES];
    int count;
} shield_recovery_t;

/* ============== Core Functions ============== */

/**
 * Initialize Shield from password and service name (password mode).
 *
 * Generates a cryptographically random 16-byte salt for this instance and
 * derives the key as PBKDF2-HMAC-SHA256(password, salt || service, 600000, 32).
 * The salt is written into the ciphertext header (version 0x03) so a recipient
 * with the same password+service can re-derive the key. service is retained as
 * a domain separator. This fixes the original deterministic-salt bug where
 * every user of a service shared the same key.
 *
 * Uses PBKDF2-SHA256 with 600,000 iterations.
 * max_age_ms: -1 to disable replay protection, or milliseconds (default: 60000)
 */
void shield_init(shield_t *ctx, const char *password, const char *service, int64_t max_age_ms);

/**
 * Initialize Shield from password and service with an explicit 16-byte salt.
 * Same as shield_init but pins the salt (for testing / deterministic vectors).
 * The salt is stored in the ciphertext header exactly as in shield_init.
 */
void shield_init_with_salt(shield_t *ctx, const char *password, const char *service, const uint8_t *salt, int64_t max_age_ms);

/**
 * Initialize Shield with a pre-shared key (pre-shared-key mode, version 0x13).
 * Key must be exactly SHIELD_KEY_SIZE bytes. Ciphertexts carry no salt.
 * max_age_ms: -1 to disable replay protection, or milliseconds (default: 60000)
 */
shield_error_t shield_init_with_key(shield_t *ctx, const uint8_t *key, size_t key_len, int64_t max_age_ms);

/**
 * Initialize Shield with hardware fingerprinting (device-bound encryption).
 *
 * Derives keys from password + hardware identifier, binding encryption to
 * the physical device. Keys cannot be transferred to other hardware.
 *
 * Requires: #include "shield_fingerprint.h"
 *
 * @param ctx Shield context to initialize
 * @param password User's password
 * @param service Service identifier
 * @param fp_mode Fingerprint mode (see shield_fingerprint.h)
 * @param max_age_ms Maximum message age (-1 to disable)
 * @return SHIELD_OK on success, error code on failure
 *
 * Example:
 *   shield_t ctx;
 *   shield_init_with_fingerprint(&ctx, "password", "github.com",
 *                                 SHIELD_FP_COMBINED, 60000);
 */
shield_error_t shield_init_with_fingerprint(
    shield_t *ctx,
    const char *password,
    const char *service,
    int fp_mode,  /* shield_fp_mode_t from shield_fingerprint.h */
    int64_t max_age_ms
);

/**
 * Encrypt plaintext.
 *
 * Password mode output: 0x03 || suite(1) || salt(16) || nonce(12) || ciphertext||tag(16).
 * Pre-shared-key mode output: 0x13 || suite(1) || nonce(12) || ciphertext||tag(16).
 * The MAC covers version || [salt] || nonce || ciphertext.
 *
 * Returns allocated ciphertext. Caller must free.
 * out_len receives the ciphertext length.
 */
uint8_t *shield_encrypt(const shield_t *ctx, const uint8_t *plaintext, size_t plaintext_len, size_t *out_len);

/* ===== v4 AEAD building blocks (also used by conformance vectors) ===== */

/* aead_key = HKDF-SHA256-Expand(master_key, "shield/aead/v4", 32). out_aead_key
 * must be 32 bytes. */
void shield_derive_aead_key(const uint8_t *master_key, uint8_t *out_aead_key);

/* Deterministic AEAD seal over fully specified inputs. salt is 16 bytes for
 * password mode (version 0x03) or NULL for key mode (0x13). nonce is 12 bytes,
 * padding is pad_len bytes (32..128). Returns a malloc'd buffer (caller frees)
 * of length *out_len, or NULL on failure. Only suite 0x01 (AES-256-GCM) is
 * supported by the CNG backend. */
uint8_t *shield_seal_deterministic(const uint8_t *aead_key, uint8_t suite,
                                   const uint8_t *salt, const uint8_t *nonce,
                                   int64_t timestamp_ms, uint8_t pad_len,
                                   const uint8_t *padding,
                                   const uint8_t *plaintext, size_t plaintext_len,
                                   size_t *out_len);

/* Open an AEAD ciphertext (verify tag, decrypt, validate inner layout +
 * freshness). aad_len is the nonce offset (= len(version||suite||[salt])).
 * max_age_ms < 0 disables the freshness window. Returns a malloc'd plaintext
 * buffer (caller frees) of length *out_len, or NULL with *err set. */
uint8_t *shield_open_ciphertext(const uint8_t *aead_key, uint8_t suite,
                                const uint8_t *encrypted, size_t encrypted_len,
                                size_t aad_len, int64_t max_age_ms,
                                size_t *out_len, shield_error_t *err);

/**
 * Decrypt and verify ciphertext, dispatching on the leading authenticated
 * version byte. 0x03 = password mode (re-derives the key from the header salt),
 * 0x13 = pre-shared-key mode. Any other version is hard-rejected
 * (SHIELD_ERR_INVALID_VERSION) — there is no legacy v1/v2 heuristic fallback.
 * Returns allocated plaintext. Caller must free.
 * out_len receives the plaintext length.
 */
uint8_t *shield_decrypt(const shield_t *ctx, const uint8_t *ciphertext, size_t ciphertext_len, size_t *out_len, shield_error_t *err);

/**
 * Quick encrypt with explicit key.
 */
uint8_t *shield_quick_encrypt(const uint8_t *key, size_t key_len, const uint8_t *plaintext, size_t plaintext_len, size_t *out_len, shield_error_t *err);

/**
 * Quick decrypt with explicit key.
 */
uint8_t *shield_quick_decrypt(const uint8_t *key, size_t key_len, const uint8_t *ciphertext, size_t ciphertext_len, size_t *out_len, shield_error_t *err);

/* shield_get_key removed in v2.1 - exposing derived key is a security risk */

/**
 * Securely wipe Shield context.
 */
void shield_wipe(shield_t *ctx);

/* ============== Stream Cipher Functions ============== */

/**
 * Initialize stream cipher.
 */
shield_error_t shield_stream_init(shield_stream_t *ctx, const uint8_t *key, size_t key_len, size_t chunk_size);

/**
 * Initialize stream cipher from password.
 */
void shield_stream_init_password(shield_stream_t *ctx, const char *password, const uint8_t *salt, size_t salt_len, size_t chunk_size);

/**
 * Stream encrypt large data.
 */
uint8_t *shield_stream_encrypt(const shield_stream_t *ctx, const uint8_t *plaintext, size_t plaintext_len, size_t *out_len, shield_error_t *err);

/**
 * Stream decrypt large data.
 */
uint8_t *shield_stream_decrypt(const shield_stream_t *ctx, const uint8_t *ciphertext, size_t ciphertext_len, size_t *out_len, shield_error_t *err);

/**
 * Wipe stream cipher context.
 */
void shield_stream_wipe(shield_stream_t *ctx);

/* ============== Ratchet Session Functions ============== */

/**
 * Initialize ratchet session for forward secrecy.
 */
shield_error_t shield_ratchet_init(shield_ratchet_t *ctx, const uint8_t *root_key, size_t key_len, bool is_initiator);

/**
 * Ratchet encrypt with forward secrecy.
 */
uint8_t *shield_ratchet_encrypt(shield_ratchet_t *ctx, const uint8_t *plaintext, size_t plaintext_len, size_t *out_len, shield_error_t *err);

/**
 * Ratchet decrypt with replay protection.
 */
uint8_t *shield_ratchet_decrypt(shield_ratchet_t *ctx, const uint8_t *ciphertext, size_t ciphertext_len, size_t *out_len, shield_error_t *err);

/**
 * Get send counter.
 */
uint64_t shield_ratchet_send_counter(const shield_ratchet_t *ctx);

/**
 * Get receive counter.
 */
uint64_t shield_ratchet_recv_counter(const shield_ratchet_t *ctx);

/**
 * Wipe ratchet context.
 */
void shield_ratchet_wipe(shield_ratchet_t *ctx);

/* ============== TOTP Functions ============== */

/**
 * Initialize TOTP.
 */
void shield_totp_init(shield_totp_t *ctx, const uint8_t *secret, size_t secret_len, int digits, int interval);

/**
 * Generate TOTP secret.
 */
shield_error_t shield_totp_generate_secret(uint8_t *secret, size_t secret_len);

/**
 * Generate TOTP code for timestamp.
 * If timestamp is 0, uses current time.
 */
void shield_totp_generate(const shield_totp_t *ctx, int64_t timestamp, char *code, size_t code_len);

/**
 * Verify TOTP code with time window.
 */
bool shield_totp_verify(const shield_totp_t *ctx, const char *code, int64_t timestamp, int window);

/**
 * Encode secret to base32.
 */
size_t shield_totp_to_base32(const uint8_t *secret, size_t secret_len, char *out, size_t out_len);

/**
 * Decode secret from base32.
 */
size_t shield_totp_from_base32(const char *encoded, uint8_t *out, size_t out_len);

/**
 * Free TOTP context.
 */
void shield_totp_free(shield_totp_t *ctx);

/* ============== Signature Functions ============== */

/**
 * Generate symmetric signature key pair.
 */
shield_error_t shield_signature_generate(shield_signature_t *ctx);

/**
 * Initialize signature from password and identity.
 */
void shield_signature_from_password(shield_signature_t *ctx, const char *password, const char *identity);

/**
 * Sign message (without timestamp).
 * Returns 32-byte signature. Caller must provide buffer.
 */
void shield_signature_sign(const shield_signature_t *ctx, const uint8_t *message, size_t message_len, uint8_t *signature);

/**
 * Sign message with timestamp.
 * Returns 40-byte signature (8-byte timestamp + 32-byte sig). Caller must provide buffer.
 */
void shield_signature_sign_timestamped(const shield_signature_t *ctx, const uint8_t *message, size_t message_len, uint8_t *signature);

/**
 * Verify signature.
 */
bool shield_signature_verify(const shield_signature_t *ctx, const uint8_t *message, size_t message_len, const uint8_t *signature, size_t sig_len, const uint8_t *verification_key, int64_t max_age);

/**
 * Get verification key.
 */
const uint8_t *shield_signature_verification_key(const shield_signature_t *ctx);

/**
 * Wipe signature context.
 */
void shield_signature_wipe(shield_signature_t *ctx);

/* ============== Lamport Signature Functions ============== */

/**
 * Generate Lamport key pair.
 */
shield_error_t shield_lamport_generate(shield_lamport_t *ctx);

/**
 * Sign message with Lamport signature (ONE TIME ONLY).
 * Signature is 256*32 = 8192 bytes.
 */
shield_error_t shield_lamport_sign(shield_lamport_t *ctx, const uint8_t *message, size_t message_len, uint8_t *signature);

/**
 * Verify Lamport signature.
 */
bool shield_lamport_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, const uint8_t *public_key);

/**
 * Check if Lamport key is used.
 */
bool shield_lamport_is_used(const shield_lamport_t *ctx);

/**
 * Get Lamport public key.
 */
const uint8_t *shield_lamport_public_key(const shield_lamport_t *ctx);

/**
 * Free Lamport context.
 */
void shield_lamport_free(shield_lamport_t *ctx);

/* ============== Recovery Codes Functions ============== */

/**
 * Initialize recovery codes with generated codes.
 * @param ctx Recovery context
 * @param count Number of codes to generate (max SHIELD_MAX_RECOVERY_CODES)
 * @param length Length of each code (must be even, default 8)
 * @return SHIELD_OK on success
 */
shield_error_t shield_recovery_init(shield_recovery_t *ctx, int count, int length);

/**
 * Initialize recovery codes from existing codes.
 * @param ctx Recovery context
 * @param codes Array of code strings (XXXX-XXXX format)
 * @param count Number of codes
 */
void shield_recovery_init_from(shield_recovery_t *ctx, const char **codes, int count);

/**
 * Verify and consume a recovery code.
 * @param ctx Recovery context
 * @param code Code to verify (with or without dash)
 * @return true if valid (code is now consumed)
 */
bool shield_recovery_verify(shield_recovery_t *ctx, const char *code);

/**
 * Get remaining code count.
 */
int shield_recovery_remaining(const shield_recovery_t *ctx);

/**
 * Get a specific remaining code.
 * @param ctx Recovery context
 * @param index Index (0-based) into remaining codes
 * @param out Buffer to receive code (SHIELD_RECOVERY_CODE_LEN bytes)
 * @return true if code exists at index
 */
bool shield_recovery_get_code(const shield_recovery_t *ctx, int index, char *out);

/**
 * Wipe recovery codes from memory.
 */
void shield_recovery_wipe(shield_recovery_t *ctx);

/* ============== Utility Functions ============== */

/**
 * Secure memory comparison (constant time).
 */
int shield_secure_compare(const uint8_t *a, const uint8_t *b, size_t len);

/**
 * Secure memory wipe.
 */
void shield_secure_wipe(void *ptr, size_t len);

/**
 * Generate random bytes.
 */
shield_error_t shield_random_bytes(uint8_t *buf, size_t len);

/**
 * Compute SHA256 hash.
 */
void shield_sha256(const uint8_t *data, size_t len, uint8_t *hash);

/**
 * Compute HMAC-SHA256.
 */
void shield_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t *mac);

/**
 * Derive key with PBKDF2-SHA256.
 */
void shield_pbkdf2(const char *password, const uint8_t *salt, size_t salt_len, int iterations, uint8_t *key, size_t key_len);

#ifdef __cplusplus
}
#endif

#endif /* SHIELD_H */
