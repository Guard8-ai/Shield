/*
 * Shield — post-quantum hybrid key exchange (C binding)
 * ======================================================
 *
 * Hybrid X25519 + ML-KEM-768 (FIPS 203 / RFC 7748), byte-identical to the
 * other Shield bindings and gated against tests/pq_kex_vectors.json.
 *
 * Unlike the base C cipher (Windows CNG), this module is built on:
 *   - liboqs            for ML-KEM-768 (deterministic keygen + decapsulation)
 *   - OpenSSL >= 3.0    for X25519 and HKDF-SHA256
 * so it targets POSIX hosts (Linux/macOS). No hand-rolled lattice or curve
 * math — same discipline as the Rust `pq` feature and the Bouncy Castle ports.
 *
 * Serialized layouts (identical across all bindings):
 *   private key       : mlkem768_seed(64, d||z) || x25519_scalar(32)   =   96
 *   public bundle     : mlkem768_public(1184)   || x25519_public(32)   = 1216
 *   handshake         : ephemeral_x25519_pub(32)|| mlkem_ciphertext(1088) = 1120
 *
 * Shared-key derivation:
 *   HKDF-SHA256(salt = "shield/pq-hybrid/v1",
 *               ikm  = x25519_ss || mlkem_ss,
 *               info = bob_public_bundle || ephemeral_x25519_pub || mlkem_ct,
 *               L    = 32)
 */
#ifndef SHIELD_PQHYBRID_H
#define SHIELD_PQHYBRID_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SHIELD_PQ_MLKEM_SEED_SIZE     64
#define SHIELD_PQ_MLKEM_PUBLIC_SIZE   1184
#define SHIELD_PQ_MLKEM_CIPHERTEXT_SIZE 1088
#define SHIELD_PQ_X25519_SIZE         32
#define SHIELD_PQ_PRIVATE_SIZE        (SHIELD_PQ_MLKEM_SEED_SIZE + SHIELD_PQ_X25519_SIZE)      /* 96   */
#define SHIELD_PQ_PUBLIC_BUNDLE_SIZE  (SHIELD_PQ_MLKEM_PUBLIC_SIZE + SHIELD_PQ_X25519_SIZE)    /* 1216 */
#define SHIELD_PQ_HANDSHAKE_SIZE      (SHIELD_PQ_X25519_SIZE + SHIELD_PQ_MLKEM_CIPHERTEXT_SIZE)/* 1120 */
#define SHIELD_PQ_SHARED_KEY_SIZE     32

typedef enum {
    SHIELD_PQ_OK = 0,
    SHIELD_PQ_ERR_NULL = 1,
    SHIELD_PQ_ERR_SIZE = 2,
    SHIELD_PQ_ERR_MLKEM = 3,
    SHIELD_PQ_ERR_X25519 = 4,
    SHIELD_PQ_ERR_KDF = 5
} shield_pq_status_t;

/*
 * Reconstruct the public bundle (mlkem_public || x25519_public) from a
 * serialized 96-byte private key. Writes SHIELD_PQ_PUBLIC_BUNDLE_SIZE bytes.
 */
shield_pq_status_t shield_pq_public_bundle(const uint8_t *private_key,
                                           size_t private_key_len,
                                           uint8_t *out_bundle,
                                           size_t out_bundle_len);

/*
 * Accept (recipient side): given the recipient's serialized 96-byte private key
 * and a sender's 1120-byte handshake, derive the 32-byte shared key. Writes
 * SHIELD_PQ_SHARED_KEY_SIZE bytes to out_shared_key.
 */
shield_pq_status_t shield_pq_accept(const uint8_t *private_key,
                                    size_t private_key_len,
                                    const uint8_t *handshake,
                                    size_t handshake_len,
                                    uint8_t *out_shared_key,
                                    size_t out_shared_key_len);

#ifdef __cplusplus
}
#endif

#endif /* SHIELD_PQHYBRID_H */
