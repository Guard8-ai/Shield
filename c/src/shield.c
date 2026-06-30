/**
 * Shield - Authenticated Symmetric Encryption Library
 * Pure C implementation with no external dependencies except standard library.
 */

#include "shield.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>   /* Windows CNG: vetted AES-256-GCM AEAD (link -lbcrypt) */
#ifndef BCRYPT_SUCCESS
#define BCRYPT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
#else
#include <fcntl.h>
#include <unistd.h>
/* The v4 base cipher needs a vetted AEAD. Windows uses CNG (BCrypt) below; on
 * other platforms wire OpenSSL EVP (EVP_aes_256_gcm) — not yet implemented here.
 * We refuse to hand-roll AES-GCM. */
#error "Shield C v4 requires a vetted AEAD backend on this platform (wire OpenSSL EVP)."
#endif

/* ============== SHA256 Implementation ============== */

static const uint32_t sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static inline uint32_t rotr32(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

static inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

static inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

static inline uint32_t sig0(uint32_t x) {
    return rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22);
}

static inline uint32_t sig1(uint32_t x) {
    return rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25);
}

static inline uint32_t gamma0(uint32_t x) {
    return rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3);
}

static inline uint32_t gamma1(uint32_t x) {
    return rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10);
}

typedef struct {
    uint32_t state[8];
    uint8_t buffer[64];
    uint64_t total;
} sha256_ctx;

static void sha256_init(sha256_ctx *ctx) {
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
    ctx->total = 0;
}

static void sha256_transform(sha256_ctx *ctx, const uint8_t *data) {
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h;
    int i;

    for (i = 0; i < 16; i++) {
        w[i] = ((uint32_t)data[i*4] << 24) |
               ((uint32_t)data[i*4+1] << 16) |
               ((uint32_t)data[i*4+2] << 8) |
               ((uint32_t)data[i*4+3]);
    }
    for (i = 16; i < 64; i++) {
        w[i] = gamma1(w[i-2]) + w[i-7] + gamma0(w[i-15]) + w[i-16];
    }

    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];

    for (i = 0; i < 64; i++) {
        uint32_t t1 = h + sig1(e) + ch(e, f, g) + sha256_k[i] + w[i];
        uint32_t t2 = sig0(a) + maj(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len) {
    size_t fill = ctx->total & 63;
    size_t left = len;

    ctx->total += len;

    if (fill && fill + len >= 64) {
        memcpy(ctx->buffer + fill, data, 64 - fill);
        sha256_transform(ctx, ctx->buffer);
        data += 64 - fill;
        left -= 64 - fill;
        fill = 0;
    }

    while (left >= 64) {
        sha256_transform(ctx, data);
        data += 64;
        left -= 64;
    }

    if (left) {
        memcpy(ctx->buffer + fill, data, left);
    }
}

static void sha256_final(sha256_ctx *ctx, uint8_t *hash) {
    uint8_t pad[64];
    uint64_t bits = ctx->total * 8;
    size_t fill = ctx->total & 63;
    size_t pad_len = (fill < 56) ? (56 - fill) : (120 - fill);
    int i;

    memset(pad, 0, pad_len);
    pad[0] = 0x80;
    sha256_update(ctx, pad, pad_len);

    pad[0] = (uint8_t)(bits >> 56);
    pad[1] = (uint8_t)(bits >> 48);
    pad[2] = (uint8_t)(bits >> 40);
    pad[3] = (uint8_t)(bits >> 32);
    pad[4] = (uint8_t)(bits >> 24);
    pad[5] = (uint8_t)(bits >> 16);
    pad[6] = (uint8_t)(bits >> 8);
    pad[7] = (uint8_t)(bits);
    sha256_update(ctx, pad, 8);

    for (i = 0; i < 8; i++) {
        hash[i*4] = (uint8_t)(ctx->state[i] >> 24);
        hash[i*4+1] = (uint8_t)(ctx->state[i] >> 16);
        hash[i*4+2] = (uint8_t)(ctx->state[i] >> 8);
        hash[i*4+3] = (uint8_t)(ctx->state[i]);
    }
}

void shield_sha256(const uint8_t *data, size_t len, uint8_t *hash) {
    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, hash);
}

/* ============== HMAC-SHA256 Implementation ============== */

void shield_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t *mac) {
    uint8_t k_ipad[64], k_opad[64];
    uint8_t tk[32];
    sha256_ctx ctx;
    size_t i;

    if (key_len > 64) {
        shield_sha256(key, key_len, tk);
        key = tk;
        key_len = 32;
    }

    memset(k_ipad, 0x36, 64);
    memset(k_opad, 0x5c, 64);

    for (i = 0; i < key_len; i++) {
        k_ipad[i] ^= key[i];
        k_opad[i] ^= key[i];
    }

    sha256_init(&ctx);
    sha256_update(&ctx, k_ipad, 64);
    sha256_update(&ctx, data, data_len);
    sha256_final(&ctx, mac);

    sha256_init(&ctx);
    sha256_update(&ctx, k_opad, 64);
    sha256_update(&ctx, mac, 32);
    sha256_final(&ctx, mac);
}

/* ============== PBKDF2-SHA256 Implementation ============== */

void shield_pbkdf2(const char *password, const uint8_t *salt, size_t salt_len, int iterations, uint8_t *key, size_t key_len) {
    uint8_t U[32], T[32];
    uint8_t *salt_ext;
    size_t password_len = strlen(password);
    size_t blocks = (key_len + 31) / 32;
    size_t i, j, k;

    salt_ext = (uint8_t *)malloc(salt_len + 4);
    memcpy(salt_ext, salt, salt_len);

    for (i = 0; i < blocks; i++) {
        salt_ext[salt_len] = (uint8_t)((i + 1) >> 24);
        salt_ext[salt_len + 1] = (uint8_t)((i + 1) >> 16);
        salt_ext[salt_len + 2] = (uint8_t)((i + 1) >> 8);
        salt_ext[salt_len + 3] = (uint8_t)(i + 1);

        shield_hmac_sha256((const uint8_t *)password, password_len, salt_ext, salt_len + 4, U);
        memcpy(T, U, 32);

        for (j = 1; j < (size_t)iterations; j++) {
            shield_hmac_sha256((const uint8_t *)password, password_len, U, 32, U);
            for (k = 0; k < 32; k++) {
                T[k] ^= U[k];
            }
        }

        size_t copy_len = (key_len - i * 32 < 32) ? (key_len - i * 32) : 32;
        memcpy(key + i * 32, T, copy_len);
    }

    free(salt_ext);
    shield_secure_wipe(U, 32);
    shield_secure_wipe(T, 32);
}

/* ============== Utility Functions ============== */

int shield_secure_compare(const uint8_t *a, const uint8_t *b, size_t len) {
    volatile uint8_t result = 0;
    size_t i;
    for (i = 0; i < len; i++) {
        result |= a[i] ^ b[i];
    }
    return result == 0;
}

void shield_secure_wipe(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) {
        *p++ = 0;
    }
}

shield_error_t shield_random_bytes(uint8_t *buf, size_t len) {
#ifdef _WIN32
    HCRYPTPROV hProv;
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        return SHIELD_ERR_RANDOM_FAILED;
    }
    if (!CryptGenRandom(hProv, (DWORD)len, buf)) {
        CryptReleaseContext(hProv, 0);
        return SHIELD_ERR_RANDOM_FAILED;
    }
    CryptReleaseContext(hProv, 0);
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return SHIELD_ERR_RANDOM_FAILED;
    }
    ssize_t n = read(fd, buf, len);
    close(fd);
    if (n != (ssize_t)len) {
        return SHIELD_ERR_RANDOM_FAILED;
    }
#endif
    return SHIELD_OK;
}

/* ============== Keystream Generation ============== */

static void generate_keystream(const uint8_t *key, const uint8_t *nonce, size_t length, uint8_t *keystream) {
    size_t num_blocks = (length + 31) / 32;
    uint8_t block[32 + SHIELD_NONCE_SIZE + 4];
    uint8_t hash[32];
    size_t i, j;

    for (i = 0; i < num_blocks; i++) {
        memcpy(block, key, SHIELD_KEY_SIZE);
        memcpy(block + SHIELD_KEY_SIZE, nonce, SHIELD_NONCE_SIZE);
        block[SHIELD_KEY_SIZE + SHIELD_NONCE_SIZE] = (uint8_t)(i);
        block[SHIELD_KEY_SIZE + SHIELD_NONCE_SIZE + 1] = (uint8_t)(i >> 8);
        block[SHIELD_KEY_SIZE + SHIELD_NONCE_SIZE + 2] = (uint8_t)(i >> 16);
        block[SHIELD_KEY_SIZE + SHIELD_NONCE_SIZE + 3] = (uint8_t)(i >> 24);

        shield_sha256(block, SHIELD_KEY_SIZE + SHIELD_NONCE_SIZE + 4, hash);

        size_t copy_len = (length - i * 32 < 32) ? (length - i * 32) : 32;
        for (j = 0; j < copy_len; j++) {
            keystream[i * 32 + j] = hash[j];
        }
    }
}

/* ============== AEAD key derivation (HKDF-SHA256-Expand) ============== */

/* aead_key = HKDF-SHA256-Expand(master_key, info="shield/aead/v4", L=32).
 * For a 32-byte output this is a single HKDF block:
 *   T(1) = HMAC-SHA256(master_key, info || 0x01); OKM = T(1)[:32].
 * This uses the standard HMAC primitive (the kept hardened path), matching the
 * other bindings byte-for-byte. */
void shield_derive_aead_key(const uint8_t *master_key, uint8_t *out_aead_key) {
    uint8_t info[sizeof(SHIELD_HKDF_AEAD_INFO) - 1 + 1];
    size_t info_len = sizeof(SHIELD_HKDF_AEAD_INFO) - 1; /* exclude NUL */
    memcpy(info, SHIELD_HKDF_AEAD_INFO, info_len);
    info[info_len] = 0x01;
    shield_hmac_sha256(master_key, SHIELD_KEY_SIZE, info, info_len + 1, out_aead_key);
}

/* ============== Standard AEAD (AES-256-GCM via Windows CNG) ============== */

/* Seal: encrypts pt_len bytes into out_ct and writes the 16-byte tag into out_tag.
 * Returns 0 on success. Only AES-256-GCM (suite 0x01) is supported by the CNG
 * backend; ChaCha20-Poly1305 (0x02) is not available in CNG and returns an error. */
static int aead_seal(uint8_t suite, const uint8_t *key,
                     const uint8_t *nonce, size_t nonce_len,
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t *plaintext, size_t pt_len,
                     uint8_t *out_ct, uint8_t *out_tag) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    ULONG outLen = 0;
    int rc = -1;

    if (suite != SHIELD_SUITE_AES_GCM) return -1;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0))) goto done;
    if (!BCRYPT_SUCCESS(BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
            (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0))) goto done;
    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0,
            (PUCHAR)key, SHIELD_KEY_SIZE, 0))) goto done;

    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = (PUCHAR)nonce;       info.cbNonce = (ULONG)nonce_len;
    info.pbAuthData = (PUCHAR)aad;      info.cbAuthData = (ULONG)aad_len;
    info.pbTag = out_tag;               info.cbTag = SHIELD_TAG_SIZE;

    if (!BCRYPT_SUCCESS(BCryptEncrypt(hKey, (PUCHAR)plaintext, (ULONG)pt_len, &info,
            NULL, 0, out_ct, (ULONG)pt_len, &outLen, 0))) goto done;
    rc = 0;
done:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return rc;
}

/* Open: verifies the tag over aad and decrypts ct_len bytes into out_pt.
 * Returns 0 on success, nonzero on authentication failure or error. */
static int aead_open(uint8_t suite, const uint8_t *key,
                     const uint8_t *nonce, size_t nonce_len,
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t *ct, size_t ct_len, const uint8_t *tag,
                     uint8_t *out_pt) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    ULONG outLen = 0;
    int rc = -1;

    if (suite != SHIELD_SUITE_AES_GCM) return -1;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0))) goto done;
    if (!BCRYPT_SUCCESS(BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
            (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0))) goto done;
    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0,
            (PUCHAR)key, SHIELD_KEY_SIZE, 0))) goto done;

    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = (PUCHAR)nonce;       info.cbNonce = (ULONG)nonce_len;
    info.pbAuthData = (PUCHAR)aad;      info.cbAuthData = (ULONG)aad_len;
    info.pbTag = (PUCHAR)tag;           info.cbTag = SHIELD_TAG_SIZE;

    /* BCryptDecrypt returns STATUS_AUTH_TAG_MISMATCH (negative) if the tag fails. */
    if (!BCRYPT_SUCCESS(BCryptDecrypt(hKey, (PUCHAR)ct, (ULONG)ct_len, &info,
            NULL, 0, out_pt, (ULONG)ct_len, &outLen, 0))) goto done;
    rc = 0;
done:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return rc;
}

/* Build the AEAD additional data (= wire prefix before the nonce):
 * version || suite || [salt]. Writes into aad (>= 2+16) and returns its length. */
static size_t build_aad(uint8_t suite, const uint8_t *salt, uint8_t *aad) {
    if (salt) {
        aad[0] = SHIELD_VERSION_PASSWORD;
        aad[1] = suite;
        memcpy(aad + 2, salt, SHIELD_SALT_SIZE);
        return 2 + SHIELD_SALT_SIZE;
    }
    aad[0] = SHIELD_VERSION_KEY;
    aad[1] = suite;
    return 2;
}

/* Deterministic AEAD seal over fully specified inputs (used for conformance
 * vectors and wrapped by the randomized shield_encrypt). Returns a malloc'd
 * buffer (caller frees) of length *out_len, or NULL on failure. */
uint8_t *shield_seal_deterministic(const uint8_t *aead_key, uint8_t suite,
                                   const uint8_t *salt, const uint8_t *nonce,
                                   int64_t timestamp_ms, uint8_t pad_len,
                                   const uint8_t *padding,
                                   const uint8_t *plaintext, size_t plaintext_len,
                                   size_t *out_len) {
    uint8_t aad[2 + SHIELD_SALT_SIZE];
    size_t aad_len = build_aad(suite, salt, aad);
    size_t inner_len = SHIELD_INNER_HEADER_SIZE + pad_len + plaintext_len;
    size_t total = aad_len + SHIELD_AEAD_NONCE_SIZE + inner_len + SHIELD_TAG_SIZE;
    uint8_t *inner;
    uint8_t *result;

    inner = (uint8_t *)malloc(inner_len);
    if (!inner) return NULL;
    memcpy(inner, &timestamp_ms, 8); /* little-endian host (x64) */
    inner[8] = pad_len;
    memcpy(inner + SHIELD_INNER_HEADER_SIZE, padding, pad_len);
    memcpy(inner + SHIELD_INNER_HEADER_SIZE + pad_len, plaintext, plaintext_len);

    result = (uint8_t *)malloc(total);
    if (!result) { free(inner); return NULL; }
    memcpy(result, aad, aad_len);
    memcpy(result + aad_len, nonce, SHIELD_AEAD_NONCE_SIZE);

    /* ciphertext||tag = AEAD_Seal(aead_key, nonce, inner, aad). */
    if (aead_seal(suite, aead_key, nonce, SHIELD_AEAD_NONCE_SIZE, aad, aad_len,
                  inner, inner_len,
                  result + aad_len + SHIELD_AEAD_NONCE_SIZE,
                  result + aad_len + SHIELD_AEAD_NONCE_SIZE + inner_len) != 0) {
        shield_secure_wipe(inner, inner_len);
        free(inner);
        free(result);
        return NULL;
    }
    shield_secure_wipe(inner, inner_len);
    free(inner);
    *out_len = total;
    return result;
}

/* Open an AEAD ciphertext, validate the inner layout and freshness window.
 * aad_len is the offset of the nonce (= len(version||suite||[salt])). Returns a
 * malloc'd plaintext buffer (caller frees) of length *out_len, or NULL with *err. */
uint8_t *shield_open_ciphertext(const uint8_t *aead_key, uint8_t suite,
                                const uint8_t *encrypted, size_t encrypted_len,
                                size_t aad_len, int64_t max_age_ms,
                                size_t *out_len, shield_error_t *err) {
    const uint8_t *nonce;
    const uint8_t *ct;
    const uint8_t *tag;
    size_t ct_len;
    uint8_t *inner;
    int64_t timestamp_ms;
    size_t pad_len, data_start;
    uint8_t *result;

    if (encrypted_len < aad_len + SHIELD_AEAD_NONCE_SIZE + SHIELD_TAG_SIZE) {
        if (err) *err = SHIELD_ERR_CIPHERTEXT_TOO_SHORT;
        return NULL;
    }
    nonce = encrypted + aad_len;
    ct = encrypted + aad_len + SHIELD_AEAD_NONCE_SIZE;
    ct_len = encrypted_len - aad_len - SHIELD_AEAD_NONCE_SIZE - SHIELD_TAG_SIZE;
    tag = encrypted + encrypted_len - SHIELD_TAG_SIZE;

    inner = (uint8_t *)malloc(ct_len ? ct_len : 1);
    if (!inner) { if (err) *err = SHIELD_ERR_ALLOC_FAILED; return NULL; }

    if (aead_open(suite, aead_key, nonce, SHIELD_AEAD_NONCE_SIZE,
                  encrypted, aad_len, ct, ct_len, tag, inner) != 0) {
        shield_secure_wipe(inner, ct_len);
        free(inner);
        if (err) *err = SHIELD_ERR_AUTHENTICATION_FAILED;
        return NULL;
    }

    /* Inner layout: timestamp_ms(8 LE) || pad_len(1) || padding || message. */
    if (ct_len < SHIELD_INNER_HEADER_SIZE) {
        shield_secure_wipe(inner, ct_len); free(inner);
        if (err) *err = SHIELD_ERR_AUTHENTICATION_FAILED;
        return NULL;
    }
    memcpy(&timestamp_ms, inner, 8);
    pad_len = inner[8];
    if (pad_len < SHIELD_MIN_PADDING || pad_len > SHIELD_MAX_PADDING) {
        shield_secure_wipe(inner, ct_len); free(inner);
        if (err) *err = SHIELD_ERR_AUTHENTICATION_FAILED;
        return NULL;
    }
    data_start = SHIELD_INNER_HEADER_SIZE + pad_len;
    if (ct_len < data_start) {
        shield_secure_wipe(inner, ct_len); free(inner);
        if (err) *err = SHIELD_ERR_CIPHERTEXT_TOO_SHORT;
        return NULL;
    }

    /* Freshness window (NOT full replay protection). */
    if (max_age_ms >= 0) {
        int64_t now_ms;
#ifdef _WIN32
        {
            FILETIME ft; ULARGE_INTEGER uli;
            GetSystemTimeAsFileTime(&ft);
            uli.LowPart = ft.dwLowDateTime; uli.HighPart = ft.dwHighDateTime;
            now_ms = (int64_t)((uli.QuadPart - 116444736000000000ULL) / 10000);
        }
#else
        {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            now_ms = (int64_t)ts.tv_sec * 1000 + (int64_t)(ts.tv_nsec / 1000000);
        }
#endif
        if (timestamp_ms > now_ms + 5000 || (now_ms - timestamp_ms) > max_age_ms) {
            shield_secure_wipe(inner, ct_len); free(inner);
            if (err) *err = SHIELD_ERR_AUTHENTICATION_FAILED;
            return NULL;
        }
    }

    *out_len = ct_len - data_start;
    result = (uint8_t *)malloc(*out_len ? *out_len : 1);
    if (!result) {
        shield_secure_wipe(inner, ct_len); free(inner);
        if (err) *err = SHIELD_ERR_ALLOC_FAILED;
        return NULL;
    }
    memcpy(result, inner + data_start, *out_len);
    shield_secure_wipe(inner, ct_len);
    free(inner);
    if (err) *err = SHIELD_OK;
    return result;
}

/* ============== Core Shield Functions ============== */

/* Derive the 32-byte master key from a given salt.
 * PBKDF2 input salt is salt(16) || service, mirroring the reference. */
static void shield_derive_key(const shield_t *ctx, const uint8_t *salt, uint8_t *out_key) {
    uint8_t salt_input[SHIELD_SALT_SIZE + SHIELD_MAX_SECRET_LEN];
    size_t salt_input_len = SHIELD_SALT_SIZE + ctx->service_len;
    memcpy(salt_input, salt, SHIELD_SALT_SIZE);
    memcpy(salt_input + SHIELD_SALT_SIZE, ctx->service, ctx->service_len);
    shield_pbkdf2(ctx->password, salt_input, salt_input_len, ctx->iterations, out_key, SHIELD_KEY_SIZE);
    shield_secure_wipe(salt_input, sizeof(salt_input));
}

void shield_init_with_salt(shield_t *ctx, const char *password, const char *service, const uint8_t *salt, int64_t max_age_ms) {
    size_t pw_len = strlen(password);
    size_t svc_len = strlen(service);

    if (pw_len >= SHIELD_MAX_SECRET_LEN) pw_len = SHIELD_MAX_SECRET_LEN - 1;
    if (svc_len >= SHIELD_MAX_SECRET_LEN) svc_len = SHIELD_MAX_SECRET_LEN - 1;

    ctx->has_password = true;
    ctx->iterations = SHIELD_ITERATIONS;
    ctx->max_age_ms = max_age_ms;

    memcpy(ctx->password, password, pw_len);
    ctx->password[pw_len] = '\0';
    ctx->password_len = pw_len;

    memcpy(ctx->service, service, svc_len);
    ctx->service[svc_len] = '\0';
    ctx->service_len = svc_len;

    memcpy(ctx->salt, salt, SHIELD_SALT_SIZE);

    /* Pre-derive this instance's own master key and AEAD key from its salt. */
    shield_derive_key(ctx, ctx->salt, ctx->key);
    shield_derive_aead_key(ctx->key, ctx->aead_key);
    ctx->suite = SHIELD_SUITE_AES_GCM;
}

void shield_init(shield_t *ctx, const char *password, const char *service, int64_t max_age_ms) {
    uint8_t salt[SHIELD_SALT_SIZE];
    /* Per-instance random salt (CSPRNG, same source as nonces). */
    if (shield_random_bytes(salt, SHIELD_SALT_SIZE) != SHIELD_OK) {
        /* CSPRNG failure: zero the salt deterministically so the context is in a
         * defined state. (Mirrors panic-on-failure in the Go reference.) */
        memset(salt, 0, SHIELD_SALT_SIZE);
    }
    shield_init_with_salt(ctx, password, service, salt, max_age_ms);
    shield_secure_wipe(salt, SHIELD_SALT_SIZE);
}

shield_error_t shield_init_with_key(shield_t *ctx, const uint8_t *key, size_t key_len, int64_t max_age_ms) {
    if (key_len != SHIELD_KEY_SIZE) {
        return SHIELD_ERR_INVALID_KEY_SIZE;
    }
    ctx->has_password = false;
    ctx->iterations = 0;
    ctx->password_len = 0;
    ctx->service_len = 0;
    memset(ctx->salt, 0, SHIELD_SALT_SIZE);
    memcpy(ctx->key, key, SHIELD_KEY_SIZE);
    shield_derive_aead_key(ctx->key, ctx->aead_key);
    ctx->suite = SHIELD_SUITE_AES_GCM;
    ctx->max_age_ms = max_age_ms;
    return SHIELD_OK;
}

uint8_t *shield_encrypt(const shield_t *ctx, const uint8_t *plaintext, size_t plaintext_len, size_t *out_len) {
    uint8_t nonce[SHIELD_AEAD_NONCE_SIZE];
    uint8_t pad_len_byte;
    uint8_t *padding;
    uint8_t *result;
    int64_t timestamp_ms;
    size_t pad_len;

    if (shield_random_bytes(nonce, SHIELD_AEAD_NONCE_SIZE) != SHIELD_OK) {
        return NULL;
    }

    /* Timestamp in milliseconds since Unix epoch (true millisecond precision) */
#ifdef _WIN32
    {
        FILETIME ft;
        ULARGE_INTEGER uli;
        GetSystemTimeAsFileTime(&ft);
        uli.LowPart = ft.dwLowDateTime;
        uli.HighPart = ft.dwHighDateTime;
        timestamp_ms = (int64_t)((uli.QuadPart - 116444736000000000ULL) / 10000);
    }
#else
    {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        timestamp_ms = (int64_t)ts.tv_sec * 1000 + (int64_t)(ts.tv_nsec / 1000000);
    }
#endif

    /* Random padding: 32-128 bytes (rejection sampling to avoid modulo bias) */
    {
        int pad_range = SHIELD_MAX_PADDING - SHIELD_MIN_PADDING + 1; /* 97 */
        do {
            if (shield_random_bytes(&pad_len_byte, 1) != SHIELD_OK) {
                return NULL;
            }
            if ((int)pad_len_byte < pad_range * (256 / pad_range)) {
                pad_len = ((int)pad_len_byte % pad_range) + SHIELD_MIN_PADDING;
                break;
            }
        } while (1);
    }
    padding = (uint8_t *)malloc(pad_len);
    if (!padding) return NULL;
    if (shield_random_bytes(padding, pad_len) != SHIELD_OK) {
        free(padding);
        return NULL;
    }

    /* Seal: password mode carries the salt; key mode does not. */
    result = shield_seal_deterministic(
        ctx->aead_key, ctx->suite,
        ctx->has_password ? ctx->salt : NULL,
        nonce, timestamp_ms, (uint8_t)pad_len, padding,
        plaintext, plaintext_len, out_len);

    shield_secure_wipe(padding, pad_len);
    free(padding);
    return result;
}

uint8_t *shield_decrypt(const shield_t *ctx, const uint8_t *ciphertext, size_t ciphertext_len, size_t *out_len, shield_error_t *err) {
    uint8_t version;

    if (ciphertext_len < 1) {
        if (err) *err = SHIELD_ERR_CIPHERTEXT_TOO_SHORT;
        return NULL;
    }

    version = ciphertext[0];

    if (version == SHIELD_VERSION_PASSWORD) {
        /* Password mode: re-derive the key from the salt carried in the header. */
        uint8_t key[SHIELD_KEY_SIZE];
        uint8_t aead_key[SHIELD_KEY_SIZE];
        uint8_t suite;
        uint8_t *result;

        if (!ctx->has_password) {
            if (err) *err = SHIELD_ERR_NO_PASSWORD;
            return NULL;
        }
        if (ciphertext_len < SHIELD_MIN_CIPHERTEXT_SIZE_PASSWORD) {
            if (err) *err = SHIELD_ERR_CIPHERTEXT_TOO_SHORT;
            return NULL;
        }

        suite = ciphertext[1];
        shield_derive_key(ctx, ciphertext + 2, key); /* salt at offset 2 */
        shield_derive_aead_key(key, aead_key);

        result = shield_open_ciphertext(aead_key, suite, ciphertext, ciphertext_len,
                                        2 + SHIELD_SALT_SIZE, ctx->max_age_ms,
                                        out_len, err);
        shield_secure_wipe(key, SHIELD_KEY_SIZE);
        shield_secure_wipe(aead_key, SHIELD_KEY_SIZE);
        return result;

    } else if (version == SHIELD_VERSION_KEY) {
        if (ciphertext_len < SHIELD_MIN_CIPHERTEXT_SIZE_KEY) {
            if (err) *err = SHIELD_ERR_CIPHERTEXT_TOO_SHORT;
            return NULL;
        }
        return shield_open_ciphertext(ctx->aead_key, ciphertext[1], ciphertext, ciphertext_len,
                                      2, ctx->max_age_ms, out_len, err);
    }

    /* Clean break: any other version byte is hard-rejected (no legacy path). */
    if (err) *err = SHIELD_ERR_INVALID_VERSION;
    return NULL;
}

uint8_t *shield_quick_encrypt(const uint8_t *key, size_t key_len, const uint8_t *plaintext, size_t plaintext_len, size_t *out_len, shield_error_t *err) {
    shield_t ctx;
    /* Pre-shared-key mode: emits the 0x12 key-mode format (no salt). */
    if (shield_init_with_key(&ctx, key, key_len, -1) != SHIELD_OK) {
        if (err) *err = SHIELD_ERR_INVALID_KEY_SIZE;
        return NULL;
    }
    uint8_t *result = shield_encrypt(&ctx, plaintext, plaintext_len, out_len);
    shield_wipe(&ctx);
    if (err) *err = result ? SHIELD_OK : SHIELD_ERR_RANDOM_FAILED;
    return result;
}

uint8_t *shield_quick_decrypt(const uint8_t *key, size_t key_len, const uint8_t *ciphertext, size_t ciphertext_len, size_t *out_len, shield_error_t *err) {
    shield_t ctx;
    if (shield_init_with_key(&ctx, key, key_len, -1) != SHIELD_OK) {
        if (err) *err = SHIELD_ERR_INVALID_KEY_SIZE;
        return NULL;
    }
    uint8_t *result = shield_decrypt(&ctx, ciphertext, ciphertext_len, out_len, err);
    shield_wipe(&ctx);
    return result;
}

/* shield_get_key removed - exposing derived key is a security risk.
 * Use shield_encrypt/shield_decrypt instead.
 * If needed for testing, access ctx->key directly in test code. */

void shield_wipe(shield_t *ctx) {
    shield_secure_wipe(ctx->key, SHIELD_KEY_SIZE);
    shield_secure_wipe(ctx->aead_key, SHIELD_KEY_SIZE);
    shield_secure_wipe(ctx->salt, SHIELD_SALT_SIZE);
    shield_secure_wipe(ctx->password, SHIELD_MAX_SECRET_LEN);
    shield_secure_wipe(ctx->service, SHIELD_MAX_SECRET_LEN);
    ctx->password_len = 0;
    ctx->service_len = 0;
    ctx->has_password = false;
}

/* ============== Stream Cipher Functions ============== */

shield_error_t shield_stream_init(shield_stream_t *ctx, const uint8_t *key, size_t key_len, size_t chunk_size) {
    if (key_len != SHIELD_KEY_SIZE) {
        return SHIELD_ERR_INVALID_KEY_SIZE;
    }
    memcpy(ctx->key, key, SHIELD_KEY_SIZE);
    ctx->chunk_size = chunk_size > 0 ? chunk_size : 65536;
    return SHIELD_OK;
}

void shield_stream_init_password(shield_stream_t *ctx, const char *password, const uint8_t *salt, size_t salt_len, size_t chunk_size) {
    shield_pbkdf2(password, salt, salt_len, SHIELD_ITERATIONS, ctx->key, SHIELD_KEY_SIZE);
    ctx->chunk_size = chunk_size > 0 ? chunk_size : 65536;
}

void shield_stream_wipe(shield_stream_t *ctx) {
    shield_secure_wipe(ctx->key, SHIELD_KEY_SIZE);
}

/* ============== Ratchet Session Functions ============== */

static void derive_chain_key(const uint8_t *key, const char *info, uint8_t *out) {
    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, key, SHIELD_KEY_SIZE);
    sha256_update(&ctx, (const uint8_t *)info, strlen(info));
    sha256_final(&ctx, out);
}

shield_error_t shield_ratchet_init(shield_ratchet_t *ctx, const uint8_t *root_key, size_t key_len, bool is_initiator) {
    if (key_len != SHIELD_KEY_SIZE) {
        return SHIELD_ERR_INVALID_KEY_SIZE;
    }

    ctx->is_initiator = is_initiator;
    ctx->send_counter = 0;
    ctx->recv_counter = 0;

    if (is_initiator) {
        derive_chain_key(root_key, "init_send", ctx->send_key);
        derive_chain_key(root_key, "init_recv", ctx->recv_key);
    } else {
        derive_chain_key(root_key, "init_recv", ctx->send_key);
        derive_chain_key(root_key, "init_send", ctx->recv_key);
    }

    return SHIELD_OK;
}

uint8_t *shield_ratchet_encrypt(shield_ratchet_t *ctx, const uint8_t *plaintext, size_t plaintext_len, size_t *out_len, shield_error_t *err) {
    uint8_t message_key[SHIELD_KEY_SIZE];
    uint8_t nonce[SHIELD_NONCE_SIZE];
    uint8_t *keystream;
    uint8_t *ciphertext;
    uint8_t mac[32];
    uint8_t counter_bytes[8];
    size_t result_len;
    uint8_t *result;
    size_t i;

    derive_chain_key(ctx->send_key, "message", message_key);

    if (shield_random_bytes(nonce, SHIELD_NONCE_SIZE) != SHIELD_OK) {
        if (err) *err = SHIELD_ERR_RANDOM_FAILED;
        return NULL;
    }

    keystream = (uint8_t *)malloc(plaintext_len);
    generate_keystream(message_key, nonce, plaintext_len, keystream);

    ciphertext = (uint8_t *)malloc(plaintext_len);
    for (i = 0; i < plaintext_len; i++) {
        ciphertext[i] = plaintext[i] ^ keystream[i];
    }
    free(keystream);

    /* Counter */
    for (i = 0; i < 8; i++) {
        counter_bytes[i] = (uint8_t)(ctx->send_counter >> (i * 8));
    }

    /* MAC over counter || nonce || ciphertext */
    uint8_t *mac_data = (uint8_t *)malloc(8 + SHIELD_NONCE_SIZE + plaintext_len);
    memcpy(mac_data, counter_bytes, 8);
    memcpy(mac_data + 8, nonce, SHIELD_NONCE_SIZE);
    memcpy(mac_data + 8 + SHIELD_NONCE_SIZE, ciphertext, plaintext_len);
    shield_hmac_sha256(message_key, SHIELD_KEY_SIZE, mac_data, 8 + SHIELD_NONCE_SIZE + plaintext_len, mac);
    free(mac_data);

    /* Ratchet */
    derive_chain_key(ctx->send_key, "ratchet", ctx->send_key);
    ctx->send_counter++;

    /* Format: counter(8) || nonce(16) || ciphertext || mac(16) */
    result_len = 8 + SHIELD_NONCE_SIZE + plaintext_len + SHIELD_MAC_SIZE;
    result = (uint8_t *)malloc(result_len);
    memcpy(result, counter_bytes, 8);
    memcpy(result + 8, nonce, SHIELD_NONCE_SIZE);
    memcpy(result + 8 + SHIELD_NONCE_SIZE, ciphertext, plaintext_len);
    memcpy(result + 8 + SHIELD_NONCE_SIZE + plaintext_len, mac, SHIELD_MAC_SIZE);

    free(ciphertext);
    shield_secure_wipe(message_key, SHIELD_KEY_SIZE);

    *out_len = result_len;
    if (err) *err = SHIELD_OK;
    return result;
}

uint8_t *shield_ratchet_decrypt(shield_ratchet_t *ctx, const uint8_t *encrypted, size_t encrypted_len, size_t *out_len, shield_error_t *err) {
    uint64_t counter;
    uint8_t *nonce;
    uint8_t *ciphertext;
    size_t ciphertext_len;
    uint8_t *received_mac;
    uint8_t message_key[SHIELD_KEY_SIZE];
    uint8_t mac[32];
    uint8_t *keystream;
    uint8_t *plaintext;
    size_t i;

    if (encrypted_len < 8 + SHIELD_NONCE_SIZE + SHIELD_MAC_SIZE) {
        if (err) *err = SHIELD_ERR_CIPHERTEXT_TOO_SHORT;
        return NULL;
    }

    counter = 0;
    for (i = 0; i < 8; i++) {
        counter |= ((uint64_t)encrypted[i]) << (i * 8);
    }

    if (counter < ctx->recv_counter) {
        if (err) *err = SHIELD_ERR_REPLAY_DETECTED;
        return NULL;
    }
    if (counter > ctx->recv_counter) {
        if (err) *err = SHIELD_ERR_OUT_OF_ORDER;
        return NULL;
    }

    nonce = (uint8_t *)encrypted + 8;
    ciphertext_len = encrypted_len - 8 - SHIELD_NONCE_SIZE - SHIELD_MAC_SIZE;
    ciphertext = (uint8_t *)encrypted + 8 + SHIELD_NONCE_SIZE;
    received_mac = (uint8_t *)encrypted + encrypted_len - SHIELD_MAC_SIZE;

    derive_chain_key(ctx->recv_key, "message", message_key);

    /* Verify MAC */
    uint8_t *mac_data = (uint8_t *)malloc(8 + SHIELD_NONCE_SIZE + ciphertext_len);
    memcpy(mac_data, encrypted, 8);
    memcpy(mac_data + 8, nonce, SHIELD_NONCE_SIZE);
    memcpy(mac_data + 8 + SHIELD_NONCE_SIZE, ciphertext, ciphertext_len);
    shield_hmac_sha256(message_key, SHIELD_KEY_SIZE, mac_data, 8 + SHIELD_NONCE_SIZE + ciphertext_len, mac);
    free(mac_data);

    if (!shield_secure_compare(received_mac, mac, SHIELD_MAC_SIZE)) {
        shield_secure_wipe(message_key, SHIELD_KEY_SIZE);
        if (err) *err = SHIELD_ERR_AUTHENTICATION_FAILED;
        return NULL;
    }

    /* Decrypt */
    keystream = (uint8_t *)malloc(ciphertext_len);
    generate_keystream(message_key, nonce, ciphertext_len, keystream);

    plaintext = (uint8_t *)malloc(ciphertext_len);
    for (i = 0; i < ciphertext_len; i++) {
        plaintext[i] = ciphertext[i] ^ keystream[i];
    }
    free(keystream);

    /* Ratchet */
    derive_chain_key(ctx->recv_key, "ratchet", ctx->recv_key);
    ctx->recv_counter++;

    shield_secure_wipe(message_key, SHIELD_KEY_SIZE);

    *out_len = ciphertext_len;
    if (err) *err = SHIELD_OK;
    return plaintext;
}

uint64_t shield_ratchet_send_counter(const shield_ratchet_t *ctx) {
    return ctx->send_counter;
}

uint64_t shield_ratchet_recv_counter(const shield_ratchet_t *ctx) {
    return ctx->recv_counter;
}

void shield_ratchet_wipe(shield_ratchet_t *ctx) {
    shield_secure_wipe(ctx->send_key, SHIELD_KEY_SIZE);
    shield_secure_wipe(ctx->recv_key, SHIELD_KEY_SIZE);
}

/* ============== TOTP Functions ============== */

void shield_totp_init(shield_totp_t *ctx, const uint8_t *secret, size_t secret_len, int digits, int interval) {
    ctx->secret = (uint8_t *)malloc(secret_len);
    memcpy(ctx->secret, secret, secret_len);
    ctx->secret_len = secret_len;
    ctx->digits = digits > 0 ? digits : 6;
    ctx->interval = interval > 0 ? interval : 30;
}

shield_error_t shield_totp_generate_secret(uint8_t *secret, size_t secret_len) {
    return shield_random_bytes(secret, secret_len);
}

/* SHA1 for TOTP compatibility */
static const uint32_t sha1_k[4] = {0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6};

static inline uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

static void sha1_hash(const uint8_t *data, size_t len, uint8_t *hash) {
    uint32_t h[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
    uint8_t *padded;
    size_t padded_len;
    size_t i;

    padded_len = ((len + 8) / 64 + 1) * 64;
    padded = (uint8_t *)calloc(padded_len, 1);
    memcpy(padded, data, len);
    padded[len] = 0x80;
    uint64_t bits = len * 8;
    for (i = 0; i < 8; i++) {
        padded[padded_len - 1 - i] = (uint8_t)(bits >> (i * 8));
    }

    for (size_t block = 0; block < padded_len / 64; block++) {
        uint32_t w[80];
        for (i = 0; i < 16; i++) {
            w[i] = ((uint32_t)padded[block*64 + i*4] << 24) |
                   ((uint32_t)padded[block*64 + i*4+1] << 16) |
                   ((uint32_t)padded[block*64 + i*4+2] << 8) |
                   ((uint32_t)padded[block*64 + i*4+3]);
        }
        for (i = 16; i < 80; i++) {
            w[i] = rotl32(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
        }

        uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
        for (i = 0; i < 80; i++) {
            uint32_t f, k;
            if (i < 20) { f = (b & c) | ((~b) & d); k = sha1_k[0]; }
            else if (i < 40) { f = b ^ c ^ d; k = sha1_k[1]; }
            else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = sha1_k[2]; }
            else { f = b ^ c ^ d; k = sha1_k[3]; }

            uint32_t temp = rotl32(a, 5) + f + e + k + w[i];
            e = d; d = c; c = rotl32(b, 30); b = a; a = temp;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
    }

    for (i = 0; i < 5; i++) {
        hash[i*4] = (uint8_t)(h[i] >> 24);
        hash[i*4+1] = (uint8_t)(h[i] >> 16);
        hash[i*4+2] = (uint8_t)(h[i] >> 8);
        hash[i*4+3] = (uint8_t)(h[i]);
    }

    free(padded);
}

static void hmac_sha1(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t *mac) {
    uint8_t k_ipad[64], k_opad[64];
    uint8_t tk[20];
    uint8_t *tmp;
    size_t i;

    if (key_len > 64) {
        sha1_hash(key, key_len, tk);
        key = tk;
        key_len = 20;
    }

    memset(k_ipad, 0x36, 64);
    memset(k_opad, 0x5c, 64);

    for (i = 0; i < key_len; i++) {
        k_ipad[i] ^= key[i];
        k_opad[i] ^= key[i];
    }

    tmp = (uint8_t *)malloc(64 + data_len);
    memcpy(tmp, k_ipad, 64);
    memcpy(tmp + 64, data, data_len);
    sha1_hash(tmp, 64 + data_len, mac);
    free(tmp);

    tmp = (uint8_t *)malloc(64 + 20);
    memcpy(tmp, k_opad, 64);
    memcpy(tmp + 64, mac, 20);
    sha1_hash(tmp, 64 + 20, mac);
    free(tmp);
}

void shield_totp_generate(const shield_totp_t *ctx, int64_t timestamp, char *code, size_t code_len) {
    uint8_t counter_bytes[8];
    uint8_t hash[20];
    uint32_t truncated;
    uint32_t modulo;
    int64_t counter;
    int i;

    if (timestamp == 0) {
        timestamp = (int64_t)time(NULL);
    }
    counter = timestamp / ctx->interval;

    for (i = 7; i >= 0; i--) {
        counter_bytes[i] = (uint8_t)(counter);
        counter >>= 8;
    }

    hmac_sha1(ctx->secret, ctx->secret_len, counter_bytes, 8, hash);

    int offset = hash[19] & 0x0f;
    truncated = ((uint32_t)(hash[offset] & 0x7f) << 24) |
                ((uint32_t)(hash[offset+1]) << 16) |
                ((uint32_t)(hash[offset+2]) << 8) |
                ((uint32_t)(hash[offset+3]));

    modulo = 1;
    for (i = 0; i < ctx->digits; i++) {
        modulo *= 10;
    }

    snprintf(code, code_len, "%0*u", ctx->digits, truncated % modulo);
}

bool shield_totp_verify(const shield_totp_t *ctx, const char *code, int64_t timestamp, int window) {
    char generated[16];
    int i;

    if (timestamp == 0) {
        timestamp = (int64_t)time(NULL);
    }
    if (window <= 0) {
        window = 1;
    }

    for (i = 0; i <= window; i++) {
        shield_totp_generate(ctx, timestamp - i * ctx->interval, generated, sizeof(generated));
        if (strcmp(generated, code) == 0) {
            return true;
        }
        if (i > 0) {
            shield_totp_generate(ctx, timestamp + i * ctx->interval, generated, sizeof(generated));
            if (strcmp(generated, code) == 0) {
                return true;
            }
        }
    }
    return false;
}

void shield_totp_free(shield_totp_t *ctx) {
    if (ctx->secret) {
        shield_secure_wipe(ctx->secret, ctx->secret_len);
        free(ctx->secret);
        ctx->secret = NULL;
    }
}

/* ============== Signature Functions ============== */

shield_error_t shield_signature_generate(shield_signature_t *ctx) {
    if (shield_random_bytes(ctx->signing_key, SHIELD_KEY_SIZE) != SHIELD_OK) {
        return SHIELD_ERR_RANDOM_FAILED;
    }

    sha256_ctx hash;
    sha256_init(&hash);
    sha256_update(&hash, (const uint8_t *)"verify:", 7);
    sha256_update(&hash, ctx->signing_key, SHIELD_KEY_SIZE);
    sha256_final(&hash, ctx->verification_key);

    return SHIELD_OK;
}

void shield_signature_from_password(shield_signature_t *ctx, const char *password, const char *identity) {
    uint8_t salt[32];
    char salt_input[256];
    snprintf(salt_input, sizeof(salt_input), "sign:%s", identity);
    shield_sha256((const uint8_t *)salt_input, strlen(salt_input), salt);
    shield_pbkdf2(password, salt, 32, SHIELD_ITERATIONS, ctx->signing_key, SHIELD_KEY_SIZE);

    sha256_ctx hash;
    sha256_init(&hash);
    sha256_update(&hash, (const uint8_t *)"verify:", 7);
    sha256_update(&hash, ctx->signing_key, SHIELD_KEY_SIZE);
    sha256_final(&hash, ctx->verification_key);
}

void shield_signature_sign(const shield_signature_t *ctx, const uint8_t *message, size_t message_len, uint8_t *signature) {
    shield_hmac_sha256(ctx->signing_key, SHIELD_KEY_SIZE, message, message_len, signature);
}

void shield_signature_sign_timestamped(const shield_signature_t *ctx, const uint8_t *message, size_t message_len, uint8_t *signature) {
    int64_t timestamp = (int64_t)time(NULL);
    uint8_t *sig_data;
    size_t i;

    for (i = 0; i < 8; i++) {
        signature[i] = (uint8_t)(timestamp >> (i * 8));
    }

    sig_data = (uint8_t *)malloc(8 + message_len);
    memcpy(sig_data, signature, 8);
    memcpy(sig_data + 8, message, message_len);

    shield_hmac_sha256(ctx->signing_key, SHIELD_KEY_SIZE, sig_data, 8 + message_len, signature + 8);
    free(sig_data);
}

bool shield_signature_verify(const shield_signature_t *ctx, const uint8_t *message, size_t message_len, const uint8_t *signature, size_t sig_len, const uint8_t *verification_key, int64_t max_age) {
    uint8_t expected[32];

    if (!shield_secure_compare(verification_key, ctx->verification_key, SHIELD_KEY_SIZE)) {
        return false;
    }

    if (sig_len == 40) {
        int64_t timestamp = 0;
        size_t i;
        for (i = 0; i < 8; i++) {
            timestamp |= ((int64_t)signature[i]) << (i * 8);
        }

        if (max_age > 0) {
            int64_t now = (int64_t)time(NULL);
            int64_t diff = now - timestamp;
            if (diff < 0) diff = -diff;
            if (diff > max_age) {
                return false;
            }
        }

        uint8_t *sig_data = (uint8_t *)malloc(8 + message_len);
        memcpy(sig_data, signature, 8);
        memcpy(sig_data + 8, message, message_len);
        shield_hmac_sha256(ctx->signing_key, SHIELD_KEY_SIZE, sig_data, 8 + message_len, expected);
        free(sig_data);

        return shield_secure_compare(signature + 8, expected, 32);
    }

    if (sig_len == 32) {
        shield_hmac_sha256(ctx->signing_key, SHIELD_KEY_SIZE, message, message_len, expected);
        return shield_secure_compare(signature, expected, 32);
    }

    return false;
}

const uint8_t *shield_signature_verification_key(const shield_signature_t *ctx) {
    return ctx->verification_key;
}

void shield_signature_wipe(shield_signature_t *ctx) {
    shield_secure_wipe(ctx->signing_key, SHIELD_KEY_SIZE);
    shield_secure_wipe(ctx->verification_key, SHIELD_KEY_SIZE);
}

/* ============== Lamport Signature Functions ============== */

shield_error_t shield_lamport_generate(shield_lamport_t *ctx) {
    int i;

    ctx->public_key = (uint8_t *)malloc(256 * 64);
    if (!ctx->public_key) {
        return SHIELD_ERR_ALLOC_FAILED;
    }
    ctx->used = false;

    for (i = 0; i < 256; i++) {
        if (shield_random_bytes(ctx->private_key[i][0], SHIELD_KEY_SIZE) != SHIELD_OK ||
            shield_random_bytes(ctx->private_key[i][1], SHIELD_KEY_SIZE) != SHIELD_OK) {
            free(ctx->public_key);
            return SHIELD_ERR_RANDOM_FAILED;
        }

        uint8_t h0[32], h1[32];
        shield_sha256(ctx->private_key[i][0], SHIELD_KEY_SIZE, h0);
        shield_sha256(ctx->private_key[i][1], SHIELD_KEY_SIZE, h1);

        memcpy(ctx->public_key + i * 64, h0, 32);
        memcpy(ctx->public_key + i * 64 + 32, h1, 32);
    }

    return SHIELD_OK;
}

shield_error_t shield_lamport_sign(shield_lamport_t *ctx, const uint8_t *message, size_t message_len, uint8_t *signature) {
    uint8_t msg_hash[32];
    int i;

    if (ctx->used) {
        return SHIELD_ERR_LAMPORT_KEY_USED;
    }
    ctx->used = true;

    shield_sha256(message, message_len, msg_hash);

    for (i = 0; i < 256; i++) {
        int byte_idx = i / 8;
        int bit_idx = i % 8;
        int bit = (msg_hash[byte_idx] >> bit_idx) & 1;

        memcpy(signature + i * 32, ctx->private_key[i][bit], 32);
    }

    return SHIELD_OK;
}

bool shield_lamport_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, const uint8_t *public_key) {
    uint8_t msg_hash[32];
    uint8_t hashed[32];
    int i;

    shield_sha256(message, message_len, msg_hash);

    for (i = 0; i < 256; i++) {
        int byte_idx = i / 8;
        int bit_idx = i % 8;
        int bit = (msg_hash[byte_idx] >> bit_idx) & 1;

        shield_sha256(signature + i * 32, 32, hashed);

        const uint8_t *expected;
        if (bit == 1) {
            expected = public_key + i * 64 + 32;
        } else {
            expected = public_key + i * 64;
        }

        if (!shield_secure_compare(hashed, expected, 32)) {
            return false;
        }
    }

    return true;
}

bool shield_lamport_is_used(const shield_lamport_t *ctx) {
    return ctx->used;
}

const uint8_t *shield_lamport_public_key(const shield_lamport_t *ctx) {
    return ctx->public_key;
}

void shield_lamport_free(shield_lamport_t *ctx) {
    if (ctx->public_key) {
        free(ctx->public_key);
        ctx->public_key = NULL;
    }
    shield_secure_wipe(ctx->private_key, sizeof(ctx->private_key));
}

/* ============== Recovery Codes Functions ============== */

static const char HEX_CHARS[] = "0123456789ABCDEF";

shield_error_t shield_recovery_init(shield_recovery_t *ctx, int count, int length) {
    int i, j;
    uint8_t *bytes;
    int byte_len;

    if (count <= 0) count = 10;
    if (count > SHIELD_MAX_RECOVERY_CODES) count = SHIELD_MAX_RECOVERY_CODES;
    if (length <= 0) length = 8;
    if (length % 2 != 0) length++;
    /* Cap length so the formatted code (length hex chars + '-' + NUL) fits in
     * ctx->codes[i] (SHIELD_RECOVERY_CODE_LEN bytes). Without this, length > 8
     * overflows the fixed buffer (stack/heap corruption). LEN-2 is even (8). */
    if (length > SHIELD_RECOVERY_CODE_LEN - 2) {
        length = SHIELD_RECOVERY_CODE_LEN - 2;
    }

    byte_len = length / 2;
    bytes = (uint8_t *)malloc(byte_len);
    if (!bytes) return SHIELD_ERR_ALLOC_FAILED;

    ctx->count = count;
    memset(ctx->used, false, sizeof(ctx->used));

    for (i = 0; i < count; i++) {
        if (shield_random_bytes(bytes, byte_len) != SHIELD_OK) {
            free(bytes);
            return SHIELD_ERR_RANDOM_FAILED;
        }

        /* Convert to hex: first half, dash, second half */
        int half = byte_len / 2;
        int pos = 0;

        /* First half */
        for (j = 0; j < half; j++) {
            ctx->codes[i][pos++] = HEX_CHARS[(bytes[j] >> 4) & 0x0F];
            ctx->codes[i][pos++] = HEX_CHARS[bytes[j] & 0x0F];
        }

        /* Dash */
        ctx->codes[i][pos++] = '-';

        /* Second half */
        for (j = half; j < byte_len; j++) {
            ctx->codes[i][pos++] = HEX_CHARS[(bytes[j] >> 4) & 0x0F];
            ctx->codes[i][pos++] = HEX_CHARS[bytes[j] & 0x0F];
        }

        ctx->codes[i][pos] = '\0';
    }

    free(bytes);
    return SHIELD_OK;
}

void shield_recovery_init_from(shield_recovery_t *ctx, const char **codes, int count) {
    int i;

    if (count > SHIELD_MAX_RECOVERY_CODES) count = SHIELD_MAX_RECOVERY_CODES;

    ctx->count = count;
    memset(ctx->used, false, sizeof(ctx->used));

    for (i = 0; i < count; i++) {
        strncpy(ctx->codes[i], codes[i], SHIELD_RECOVERY_CODE_LEN - 1);
        ctx->codes[i][SHIELD_RECOVERY_CODE_LEN - 1] = '\0';
    }
}

static void normalize_code(const char *code, char *out) {
    char normalized[16];
    int j = 0;

    /* Remove dashes and uppercase */
    for (int i = 0; code[i] && j < 15; i++) {
        if (code[i] != '-') {
            char c = code[i];
            if (c >= 'a' && c <= 'z') c = c - 'a' + 'A';
            normalized[j++] = c;
        }
    }
    normalized[j] = '\0';

    /* Format as XXXX-XXXX */
    if (j >= 8) {
        out[0] = normalized[0];
        out[1] = normalized[1];
        out[2] = normalized[2];
        out[3] = normalized[3];
        out[4] = '-';
        out[5] = normalized[4];
        out[6] = normalized[5];
        out[7] = normalized[6];
        out[8] = normalized[7];
        out[9] = '\0';
    } else {
        out[0] = '\0';
    }
}

bool shield_recovery_verify(shield_recovery_t *ctx, const char *code) {
    char formatted[16];
    int i;

    normalize_code(code, formatted);
    if (formatted[0] == '\0') return false;

    for (i = 0; i < ctx->count; i++) {
        if (!ctx->used[i] && strcmp(ctx->codes[i], formatted) == 0) {
            ctx->used[i] = true;
            return true;
        }
    }

    return false;
}

int shield_recovery_remaining(const shield_recovery_t *ctx) {
    int count = 0;
    for (int i = 0; i < ctx->count; i++) {
        if (!ctx->used[i]) count++;
    }
    return count;
}

bool shield_recovery_get_code(const shield_recovery_t *ctx, int index, char *out) {
    int remaining_index = 0;
    for (int i = 0; i < ctx->count; i++) {
        if (!ctx->used[i]) {
            if (remaining_index == index) {
                strcpy(out, ctx->codes[i]);
                return true;
            }
            remaining_index++;
        }
    }
    return false;
}

void shield_recovery_wipe(shield_recovery_t *ctx) {
    shield_secure_wipe(ctx->codes, sizeof(ctx->codes));
    memset(ctx->used, false, sizeof(ctx->used));
    ctx->count = 0;
}
