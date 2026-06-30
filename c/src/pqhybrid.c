/*
 * Shield — post-quantum hybrid key exchange (C binding)
 *
 * ML-KEM-768 via liboqs; X25519 + HKDF-SHA256 via OpenSSL >= 3.0. No
 * hand-rolled lattice or curve math. Byte-identical to the Rust/Go/Python/JS/
 * JVM bindings; verified against tests/pq_kex_vectors.json.
 *
 * Build (Linux/macOS):
 *   cc -O2 -I include src/pqhybrid.c ... -loqs -lcrypto
 */
#include "pqhybrid.h"

#include <string.h>

#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>

static const char SHIELD_PQ_KDF_SALT[] = "shield/pq-hybrid/v1";

/* Derive the X25519 public key for a raw 32-byte private scalar. */
static int x25519_public_from_scalar(const uint8_t *scalar, uint8_t *out_pub) {
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL,
                                                  scalar, SHIELD_PQ_X25519_SIZE);
    if (!pkey) {
        return 0;
    }
    size_t publen = SHIELD_PQ_X25519_SIZE;
    int ok = EVP_PKEY_get_raw_public_key(pkey, out_pub, &publen) == 1 &&
             publen == SHIELD_PQ_X25519_SIZE;
    EVP_PKEY_free(pkey);
    return ok;
}

/* X25519 ECDH: shared = scalar * peer_public. */
static int x25519_ecdh(const uint8_t *scalar, const uint8_t *peer_pub,
                       uint8_t *out_ss) {
    EVP_PKEY *priv = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL,
                                                  scalar, SHIELD_PQ_X25519_SIZE);
    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL,
                                                 peer_pub, SHIELD_PQ_X25519_SIZE);
    EVP_PKEY_CTX *ctx = NULL;
    int ok = 0;
    size_t sslen = SHIELD_PQ_X25519_SIZE;

    if (!priv || !peer) {
        goto done;
    }
    ctx = EVP_PKEY_CTX_new(priv, NULL);
    if (!ctx || EVP_PKEY_derive_init(ctx) != 1 ||
        EVP_PKEY_derive_set_peer(ctx, peer) != 1 ||
        EVP_PKEY_derive(ctx, out_ss, &sslen) != 1 ||
        sslen != SHIELD_PQ_X25519_SIZE) {
        goto done;
    }
    ok = 1;

done:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer);
    EVP_PKEY_free(priv);
    return ok;
}

/* HKDF-SHA256 (extract-and-expand). */
static int hkdf_sha256(const uint8_t *salt, size_t salt_len,
                       const uint8_t *ikm, size_t ikm_len,
                       const uint8_t *info, size_t info_len,
                       uint8_t *out, size_t out_len) {
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    EVP_KDF_CTX *kctx = NULL;
    int ok = 0;
    OSSL_PARAM params[5];
    size_t i = 0;

    if (!kdf) {
        goto done;
    }
    kctx = EVP_KDF_CTX_new(kdf);
    if (!kctx) {
        goto done;
    }
    params[i++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                                   (char *)"SHA256", 0);
    params[i++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                                    (void *)ikm, ikm_len);
    params[i++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                                    (void *)salt, salt_len);
    params[i++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                                                    (void *)info, info_len);
    params[i] = OSSL_PARAM_construct_end();

    ok = EVP_KDF_derive(kctx, out, out_len, params) == 1;

done:
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    return ok;
}

/* Reconstruct ML-KEM keypair from the 64-byte FIPS-203 seed (d||z). */
static int mlkem_keypair_from_seed(const uint8_t *seed, uint8_t *mlkem_pub,
                                   uint8_t *mlkem_sk) {
    return OQS_KEM_ml_kem_768_keypair_derand(mlkem_pub, mlkem_sk, seed) ==
           OQS_SUCCESS;
}

shield_pq_status_t shield_pq_public_bundle(const uint8_t *private_key,
                                           size_t private_key_len,
                                           uint8_t *out_bundle,
                                           size_t out_bundle_len) {
    if (!private_key || !out_bundle) {
        return SHIELD_PQ_ERR_NULL;
    }
    if (private_key_len != SHIELD_PQ_PRIVATE_SIZE ||
        out_bundle_len != SHIELD_PQ_PUBLIC_BUNDLE_SIZE) {
        return SHIELD_PQ_ERR_SIZE;
    }

    const uint8_t *seed = private_key;
    const uint8_t *scalar = private_key + SHIELD_PQ_MLKEM_SEED_SIZE;
    uint8_t mlkem_sk[OQS_KEM_ml_kem_768_length_secret_key];
    shield_pq_status_t rc = SHIELD_PQ_ERR_MLKEM;

    if (!mlkem_keypair_from_seed(seed, out_bundle, mlkem_sk)) {
        goto done;
    }
    if (!x25519_public_from_scalar(scalar,
                                   out_bundle + SHIELD_PQ_MLKEM_PUBLIC_SIZE)) {
        rc = SHIELD_PQ_ERR_X25519;
        goto done;
    }
    rc = SHIELD_PQ_OK;

done:
    OPENSSL_cleanse(mlkem_sk, sizeof(mlkem_sk));
    return rc;
}

shield_pq_status_t shield_pq_accept(const uint8_t *private_key,
                                    size_t private_key_len,
                                    const uint8_t *handshake,
                                    size_t handshake_len,
                                    uint8_t *out_shared_key,
                                    size_t out_shared_key_len) {
    if (!private_key || !handshake || !out_shared_key) {
        return SHIELD_PQ_ERR_NULL;
    }
    if (private_key_len != SHIELD_PQ_PRIVATE_SIZE ||
        handshake_len != SHIELD_PQ_HANDSHAKE_SIZE ||
        out_shared_key_len != SHIELD_PQ_SHARED_KEY_SIZE) {
        return SHIELD_PQ_ERR_SIZE;
    }

    const uint8_t *seed = private_key;
    const uint8_t *scalar = private_key + SHIELD_PQ_MLKEM_SEED_SIZE;
    const uint8_t *eph_xpub = handshake;
    const uint8_t *kem_ct = handshake + SHIELD_PQ_X25519_SIZE;

    uint8_t mlkem_sk[OQS_KEM_ml_kem_768_length_secret_key];
    uint8_t bundle[SHIELD_PQ_PUBLIC_BUNDLE_SIZE];
    uint8_t ikm[SHIELD_PQ_X25519_SIZE + SHIELD_PQ_SHARED_KEY_SIZE]; /* x25519_ss || mlkem_ss */
    uint8_t info[SHIELD_PQ_PUBLIC_BUNDLE_SIZE + SHIELD_PQ_X25519_SIZE +
                 SHIELD_PQ_MLKEM_CIPHERTEXT_SIZE];
    shield_pq_status_t rc = SHIELD_PQ_ERR_MLKEM;

    /* Rebuild ML-KEM keypair + public bundle (the bundle binds the transcript). */
    if (!mlkem_keypair_from_seed(seed, bundle, mlkem_sk)) {
        goto done;
    }
    if (!x25519_public_from_scalar(scalar, bundle + SHIELD_PQ_MLKEM_PUBLIC_SIZE)) {
        rc = SHIELD_PQ_ERR_X25519;
        goto done;
    }

    /* mlkem_ss = decaps(ct, sk)  -> second half of ikm */
    if (OQS_KEM_ml_kem_768_decaps(ikm + SHIELD_PQ_X25519_SIZE, kem_ct, mlkem_sk) !=
        OQS_SUCCESS) {
        rc = SHIELD_PQ_ERR_MLKEM;
        goto done;
    }
    /* x25519_ss = ECDH(scalar, eph_xpub) -> first half of ikm */
    if (!x25519_ecdh(scalar, eph_xpub, ikm)) {
        rc = SHIELD_PQ_ERR_X25519;
        goto done;
    }

    /* info = bundle || eph_xpub || kem_ct */
    memcpy(info, bundle, SHIELD_PQ_PUBLIC_BUNDLE_SIZE);
    memcpy(info + SHIELD_PQ_PUBLIC_BUNDLE_SIZE, eph_xpub, SHIELD_PQ_X25519_SIZE);
    memcpy(info + SHIELD_PQ_PUBLIC_BUNDLE_SIZE + SHIELD_PQ_X25519_SIZE, kem_ct,
           SHIELD_PQ_MLKEM_CIPHERTEXT_SIZE);

    if (!hkdf_sha256((const uint8_t *)SHIELD_PQ_KDF_SALT,
                     sizeof(SHIELD_PQ_KDF_SALT) - 1, ikm, sizeof(ikm), info,
                     sizeof(info), out_shared_key, out_shared_key_len)) {
        rc = SHIELD_PQ_ERR_KDF;
        goto done;
    }
    rc = SHIELD_PQ_OK;

done:
    OPENSSL_cleanse(mlkem_sk, sizeof(mlkem_sk));
    OPENSSL_cleanse(ikm, sizeof(ikm));
    return rc;
}
