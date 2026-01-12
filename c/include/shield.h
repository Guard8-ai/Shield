/**
 * Shield - EXPTIME-Secure Symmetric Encryption Library
 *
 * This library uses only symmetric cryptographic primitives with proven
 * exponential-time security: PBKDF2-SHA256, HMAC-SHA256, and SHA256-based
 * stream cipher. Breaking requires 2^256 operations - no shortcut exists.
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
#define SHIELD_NONCE_SIZE    16
#define SHIELD_MAC_SIZE      16
#define SHIELD_ITERATIONS    100000
#define SHIELD_MIN_CIPHERTEXT_SIZE (SHIELD_NONCE_SIZE + 8 + SHIELD_MAC_SIZE)

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
    SHIELD_ERR_SESSION_EXPIRED = -12
} shield_error_t;

/* Shield context */
typedef struct {
    uint8_t key[SHIELD_KEY_SIZE];
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
 * Initialize Shield from password and service name.
 * Uses PBKDF2-SHA256 with 100,000 iterations.
 */
void shield_init(shield_t *ctx, const char *password, const char *service);

/**
 * Initialize Shield with a pre-shared key.
 * Key must be exactly SHIELD_KEY_SIZE bytes.
 */
shield_error_t shield_init_with_key(shield_t *ctx, const uint8_t *key, size_t key_len);

/**
 * Encrypt plaintext.
 * Returns allocated ciphertext. Caller must free.
 * out_len receives the ciphertext length.
 */
uint8_t *shield_encrypt(const shield_t *ctx, const uint8_t *plaintext, size_t plaintext_len, size_t *out_len);

/**
 * Decrypt ciphertext.
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

/**
 * Get the derived key from Shield context.
 */
const uint8_t *shield_get_key(const shield_t *ctx);

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
