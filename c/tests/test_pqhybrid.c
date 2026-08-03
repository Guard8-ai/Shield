/*
 * Shield C post-quantum hybrid KEX — conformance test.
 *
 * Loads tests/pq_kex_vectors.json (shared across all bindings) and, for each
 * vector, (1) reconstructs the public bundle from the private key and checks it
 * byte-for-byte, and (2) runs Accept(handshake) and checks the derived shared
 * key byte-for-byte. A different ML-KEM/X25519/HKDF result would fail loudly.
 *
 * Build (Linux/macOS):
 *   cc -O2 -I include src/pqhybrid.c tests/test_pqhybrid.c -loqs -lcrypto -o t
 */
#include "pqhybrid.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int hex_val(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Decode a hex string into out; returns the byte count, or (size_t)-1 on error. */
static size_t hex_decode(const char *hex, size_t hex_len, uint8_t *out,
                         size_t out_cap) {
    if (hex_len % 2 != 0 || hex_len / 2 > out_cap) return (size_t)-1;
    for (size_t i = 0; i < hex_len; i += 2) {
        int hi = hex_val(hex[i]);
        int lo = hex_val(hex[i + 1]);
        if (hi < 0 || lo < 0) return (size_t)-1;
        out[i / 2] = (uint8_t)((hi << 4) | lo);
    }
    return hex_len / 2;
}

/*
 * From *cursor, find "field"<whitespace>:<whitespace>"<hex>" and decode it.
 * Advances *cursor past the value. Returns decoded byte count or (size_t)-1.
 */
static size_t next_hex_field(const char *buf, size_t *cursor, const char *field,
                             uint8_t *out, size_t out_cap) {
    char needle[64];
    snprintf(needle, sizeof(needle), "\"%s\"", field);
    const char *p = strstr(buf + *cursor, needle);
    if (!p) return (size_t)-1;
    p = strchr(p, ':');
    if (!p) return (size_t)-1;
    p = strchr(p, '"');
    if (!p) return (size_t)-1;
    p++; /* first hex char */
    const char *end = strchr(p, '"');
    if (!end) return (size_t)-1;
    *cursor = (size_t)(end - buf) + 1;
    return hex_decode(p, (size_t)(end - p), out, out_cap);
}

static char *read_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = (char *)malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t n = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[n] = '\0';
    *out_len = n;
    return buf;
}

int main(int argc, char **argv) {
    const char *path = (argc > 1) ? argv[1] : "../tests/pq_kex_vectors.json";
    size_t len = 0;
    char *buf = read_file(path, &len);
    if (!buf) {
        fprintf(stderr, "FAIL: cannot read %s\n", path);
        return 1;
    }

    size_t cursor = 0;
    int passed = 0, failed = 0, vec = 0;

    for (;;) {
        uint8_t priv[SHIELD_PQ_PRIVATE_SIZE];
        uint8_t expected_bundle[SHIELD_PQ_PUBLIC_BUNDLE_SIZE];
        uint8_t handshake[SHIELD_PQ_HANDSHAKE_SIZE];
        uint8_t expected_key[SHIELD_PQ_SHARED_KEY_SIZE];

        size_t c0 = cursor;
        size_t n = next_hex_field(buf, &cursor, "bob_private_hex", priv, sizeof(priv));
        if (n == (size_t)-1) break; /* no more vectors */
        if (n != sizeof(priv)) { fprintf(stderr, "FAIL: priv size\n"); failed++; continue; }

        if (next_hex_field(buf, &cursor, "bob_public_bundle_hex", expected_bundle,
                           sizeof(expected_bundle)) != sizeof(expected_bundle) ||
            next_hex_field(buf, &cursor, "handshake_hex", handshake,
                           sizeof(handshake)) != sizeof(handshake) ||
            next_hex_field(buf, &cursor, "expected_shared_key_hex", expected_key,
                           sizeof(expected_key)) != sizeof(expected_key)) {
            fprintf(stderr, "FAIL: vector %d malformed near offset %zu\n", vec, c0);
            failed++;
            continue;
        }
        vec++;

        /* (1) public bundle reconstruction */
        uint8_t bundle[SHIELD_PQ_PUBLIC_BUNDLE_SIZE];
        shield_pq_status_t rc =
            shield_pq_public_bundle(priv, sizeof(priv), bundle, sizeof(bundle));
        if (rc != SHIELD_PQ_OK || memcmp(bundle, expected_bundle, sizeof(bundle)) != 0) {
            fprintf(stderr, "FAIL: vector %d public bundle mismatch (rc=%d)\n", vec, rc);
            failed++;
            continue;
        }

        /* (2) Accept -> shared key */
        uint8_t shared[SHIELD_PQ_SHARED_KEY_SIZE];
        rc = shield_pq_accept(priv, sizeof(priv), handshake, sizeof(handshake),
                              shared, sizeof(shared));
        if (rc != SHIELD_PQ_OK || memcmp(shared, expected_key, sizeof(shared)) != 0) {
            fprintf(stderr, "FAIL: vector %d shared-key mismatch (rc=%d)\n", vec, rc);
            failed++;
            continue;
        }

        printf("  ok  vector %d: bundle + shared key byte-identical\n", vec);
        passed++;
    }

    free(buf);
    printf("\nPQ hybrid (C): %d passed, %d failed\n", passed, failed);
    if (passed == 0 || failed != 0) return 1;
    return 0;
}
