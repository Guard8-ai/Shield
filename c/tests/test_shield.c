/**
 * Shield C Library Tests
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../include/shield.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do { printf("  Testing %s... ", name); } while(0)
#define PASS() do { printf("PASS\n"); tests_passed++; } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); tests_failed++; } while(0)

/* ============== Core Tests ============== */

void test_shield_encrypt_decrypt(void) {
    TEST("shield_encrypt_decrypt");

    shield_t ctx;
    shield_init(&ctx, "password123", "test-service", SHIELD_DEFAULT_MAX_AGE_MS);

    const char *plaintext = "Hello, Shield!";
    size_t plaintext_len = strlen(plaintext);

    size_t encrypted_len;
    uint8_t *encrypted = shield_encrypt(&ctx, (const uint8_t *)plaintext, plaintext_len, &encrypted_len);
    assert(encrypted != NULL);

    size_t decrypted_len;
    shield_error_t err;
    uint8_t *decrypted = shield_decrypt(&ctx, encrypted, encrypted_len, &decrypted_len, &err);
    assert(decrypted != NULL);
    assert(err == SHIELD_OK);

    assert(decrypted_len == plaintext_len);
    assert(memcmp(decrypted, plaintext, plaintext_len) == 0);

    free(encrypted);
    free(decrypted);
    shield_wipe(&ctx);

    PASS();
}

void test_shield_with_key(void) {
    TEST("shield_with_key");

    uint8_t key[SHIELD_KEY_SIZE];
    for (int i = 0; i < SHIELD_KEY_SIZE; i++) key[i] = (uint8_t)i;

    shield_t ctx;
    shield_error_t err = shield_init_with_key(&ctx, key, SHIELD_KEY_SIZE, SHIELD_DEFAULT_MAX_AGE_MS);
    assert(err == SHIELD_OK);

    const char *plaintext = "Test message";
    size_t plaintext_len = strlen(plaintext);

    size_t encrypted_len;
    uint8_t *encrypted = shield_encrypt(&ctx, (const uint8_t *)plaintext, plaintext_len, &encrypted_len);
    assert(encrypted != NULL);

    size_t decrypted_len;
    uint8_t *decrypted = shield_decrypt(&ctx, encrypted, encrypted_len, &decrypted_len, &err);
    assert(decrypted != NULL);
    assert(memcmp(decrypted, plaintext, plaintext_len) == 0);

    free(encrypted);
    free(decrypted);
    shield_wipe(&ctx);

    PASS();
}

void test_quick_encrypt_decrypt(void) {
    TEST("quick_encrypt_decrypt");

    uint8_t key[SHIELD_KEY_SIZE] = {0};
    const char *plaintext = "Quick test";
    size_t plaintext_len = strlen(plaintext);

    size_t encrypted_len;
    shield_error_t err;
    uint8_t *encrypted = shield_quick_encrypt(key, SHIELD_KEY_SIZE, (const uint8_t *)plaintext, plaintext_len, &encrypted_len, &err);
    assert(encrypted != NULL);

    size_t decrypted_len;
    uint8_t *decrypted = shield_quick_decrypt(key, SHIELD_KEY_SIZE, encrypted, encrypted_len, &decrypted_len, &err);
    assert(decrypted != NULL);
    assert(memcmp(decrypted, plaintext, plaintext_len) == 0);

    free(encrypted);
    free(decrypted);

    PASS();
}

void test_invalid_key_size(void) {
    TEST("invalid_key_size");

    shield_t ctx;
    shield_error_t err = shield_init_with_key(&ctx, (uint8_t *)"short", 5, SHIELD_DEFAULT_MAX_AGE_MS);
    assert(err == SHIELD_ERR_INVALID_KEY_SIZE);

    PASS();
}

void test_authentication_failed(void) {
    TEST("authentication_failed");

    shield_t ctx;
    shield_init(&ctx, "password", "service", SHIELD_DEFAULT_MAX_AGE_MS);

    size_t encrypted_len;
    uint8_t *encrypted = shield_encrypt(&ctx, (const uint8_t *)"test", 4, &encrypted_len);

    /* Tamper with ciphertext */
    encrypted[encrypted_len - 1] ^= 0xFF;

    size_t decrypted_len;
    shield_error_t err;
    uint8_t *decrypted = shield_decrypt(&ctx, encrypted, encrypted_len, &decrypted_len, &err);
    assert(decrypted == NULL);
    assert(err == SHIELD_ERR_AUTHENTICATION_FAILED);

    free(encrypted);
    shield_wipe(&ctx);

    PASS();
}

/* ============== Security-Fix Tests (CR-1 / CR-2 / CR-3) ============== */

/* CR-1: two instances with the same password+service must derive DIFFERENT
 * keys (each gets a fresh random salt), and produce different ciphertexts. */
void test_same_password_service_different_keys(void) {
    TEST("same_password_service_different_keys");

    shield_t a, b;
    shield_init(&a, "hunter2", "github.com", SHIELD_DEFAULT_MAX_AGE_MS);
    shield_init(&b, "hunter2", "github.com", SHIELD_DEFAULT_MAX_AGE_MS);

    /* Salts live at bytes [1 .. 1+16) of a password-mode ciphertext. */
    size_t la, lb;
    uint8_t *ca = shield_encrypt(&a, (const uint8_t *)"identical plaintext", 19, &la);
    uint8_t *cb = shield_encrypt(&b, (const uint8_t *)"identical plaintext", 19, &lb);
    assert(ca && cb);

    assert(ca[0] == SHIELD_VERSION_PASSWORD);
    assert(cb[0] == SHIELD_VERSION_PASSWORD);

    /* Salts differ. */
    assert(memcmp(ca + 2, cb + 2, SHIELD_SALT_SIZE) != 0);
    /* Derived master keys differ (the deterministic-key bug is gone). */
    assert(memcmp(a.key, b.key, SHIELD_KEY_SIZE) != 0);

    free(ca);
    free(cb);
    shield_wipe(&a);
    shield_wipe(&b);
    PASS();
}

/* CR-1: a recipient created independently with the same password+service must
 * decrypt the sender, because the salt travels in the header. */
void test_cross_instance_roundtrip(void) {
    TEST("cross_instance_roundtrip");

    shield_t alice, bob;
    shield_init(&alice, "correct horse battery staple", "service.example", SHIELD_DEFAULT_MAX_AGE_MS);
    shield_init(&bob, "correct horse battery staple", "service.example", SHIELD_DEFAULT_MAX_AGE_MS);

    const char *msg = "hello from alice";
    size_t mlen = strlen(msg);

    size_t clen;
    uint8_t *ct = shield_encrypt(&alice, (const uint8_t *)msg, mlen, &clen);
    assert(ct != NULL);

    size_t plen;
    shield_error_t err;
    uint8_t *pt = shield_decrypt(&bob, ct, clen, &plen, &err);
    assert(pt != NULL);
    assert(err == SHIELD_OK);
    assert(plen == mlen && memcmp(pt, msg, mlen) == 0);

    free(ct);
    free(pt);
    shield_wipe(&alice);
    shield_wipe(&bob);
    PASS();
}

/* CR-1: a different password (same service) must NOT decrypt. */
void test_wrong_password_fails(void) {
    TEST("wrong_password_fails");

    shield_t sender, wrong;
    shield_init(&sender, "right-password", "example.com", SHIELD_DEFAULT_MAX_AGE_MS);
    shield_init(&wrong, "wrong-password", "example.com", SHIELD_DEFAULT_MAX_AGE_MS);

    size_t clen;
    uint8_t *ct = shield_encrypt(&sender, (const uint8_t *)"secret", 6, &clen);
    assert(ct != NULL);

    size_t plen;
    shield_error_t err;
    uint8_t *pt = shield_decrypt(&wrong, ct, clen, &plen, &err);
    assert(pt == NULL);

    free(ct);
    shield_wipe(&sender);
    shield_wipe(&wrong);
    PASS();
}

/* CR-2: PBKDF2 iteration count must be 600,000. */
void test_iterations_600k(void) {
    TEST("iterations_600k");
    assert(SHIELD_ITERATIONS == 600000);
    PASS();
}

/* CR-3: password-mode ciphertext starts with 0x03; key-mode with 0x13. */
void test_version_bytes(void) {
    TEST("version_bytes");

    shield_t pw;
    shield_init(&pw, "pw", "svc", SHIELD_DEFAULT_MAX_AGE_MS);
    size_t l1;
    uint8_t *c1 = shield_encrypt(&pw, (const uint8_t *)"x", 1, &l1);
    assert(c1 && c1[0] == SHIELD_VERSION_PASSWORD && c1[0] == 0x03);
    assert(l1 >= 1 + SHIELD_SALT_SIZE + SHIELD_NONCE_SIZE + SHIELD_MAC_SIZE);
    free(c1);
    shield_wipe(&pw);

    uint8_t key[SHIELD_KEY_SIZE];
    shield_random_bytes(key, SHIELD_KEY_SIZE);

    size_t l2;
    shield_error_t err;
    uint8_t *c2 = shield_quick_encrypt(key, SHIELD_KEY_SIZE, (const uint8_t *)"x", 1, &l2, &err);
    assert(c2 && c2[0] == SHIELD_VERSION_KEY && c2[0] == 0x13);
    free(c2);

    shield_t ks;
    shield_init_with_key(&ks, key, SHIELD_KEY_SIZE, SHIELD_DEFAULT_MAX_AGE_MS);
    size_t l3;
    uint8_t *c3 = shield_encrypt(&ks, (const uint8_t *)"x", 1, &l3);
    assert(c3 && c3[0] == SHIELD_VERSION_KEY && c3[0] == 0x13);
    free(c3);
    shield_wipe(&ks);

    PASS();
}

/* CR-3: tampering with ANY byte (version, salt, nonce, ct, mac) fails auth. */
void test_tamper_detection_all_bytes(void) {
    TEST("tamper_detection_all_bytes");

    shield_t s;
    shield_init(&s, "pw", "svc", SHIELD_DEFAULT_MAX_AGE_MS);

    size_t clen;
    uint8_t *ct = shield_encrypt(&s, (const uint8_t *)"secret payload", 14, &clen);
    assert(ct != NULL);

    /* Sanity: untampered decrypts. */
    size_t plen;
    shield_error_t err;
    uint8_t *pt = shield_decrypt(&s, ct, clen, &plen, &err);
    assert(pt != NULL && plen == 14 && memcmp(pt, "secret payload", 14) == 0);
    free(pt);

    for (size_t i = 0; i < clen; i++) {
        uint8_t *tampered = (uint8_t *)malloc(clen);
        memcpy(tampered, ct, clen);
        tampered[i] ^= 0xFF;
        size_t tplen;
        shield_error_t terr;
        uint8_t *tpt = shield_decrypt(&s, tampered, clen, &tplen, &terr);
        assert(tpt == NULL);  /* every byte is authenticated or routes to rejection */
        free(tampered);
    }

    free(ct);
    shield_wipe(&s);
    PASS();
}

/* CR-3: tampering with the authenticated salt must fail authentication. */
void test_tamper_salt_detected(void) {
    TEST("tamper_salt_detected");

    shield_t s;
    shield_init(&s, "password", "service", SHIELD_DEFAULT_MAX_AGE_MS);

    size_t clen;
    uint8_t *ct = shield_encrypt(&s, (const uint8_t *)"authenticated salt", 18, &clen);
    assert(ct != NULL);

    ct[1] ^= 0xFF;  /* flip a salt byte (region [1 .. 1+16)) */

    size_t plen;
    shield_error_t err;
    uint8_t *pt = shield_decrypt(&s, ct, clen, &plen, &err);
    assert(pt == NULL);
    assert(err == SHIELD_ERR_AUTHENTICATION_FAILED);

    free(ct);
    shield_wipe(&s);
    PASS();
}

/* CR-3: tampering with the version byte (0x03 -> 0x13) must be rejected. */
void test_tamper_version_detected(void) {
    TEST("tamper_version_detected");

    shield_t s;
    shield_init(&s, "password", "service", SHIELD_DEFAULT_MAX_AGE_MS);

    size_t clen;
    uint8_t *ct = shield_encrypt(&s, (const uint8_t *)"authenticated version", 21, &clen);
    assert(ct != NULL);

    ct[0] = SHIELD_VERSION_KEY;  /* flip dispatch; MAC over version must reject */

    size_t plen;
    shield_error_t err;
    uint8_t *pt = shield_decrypt(&s, ct, clen, &plen, &err);
    assert(pt == NULL);

    free(ct);
    shield_wipe(&s);
    PASS();
}

/* CR-3: an unknown version byte is hard-rejected (no legacy fallback). */
void test_unknown_version_rejected(void) {
    TEST("unknown_version_rejected");

    shield_t s;
    shield_init(&s, "password", "service", SHIELD_DEFAULT_MAX_AGE_MS);

    size_t clen;
    uint8_t *ct = shield_encrypt(&s, (const uint8_t *)"x", 1, &clen);
    assert(ct != NULL);

    ct[0] = 0x7F;

    size_t plen;
    shield_error_t err;
    uint8_t *pt = shield_decrypt(&s, ct, clen, &plen, &err);
    assert(pt == NULL);
    assert(err == SHIELD_ERR_INVALID_VERSION);

    free(ct);
    shield_wipe(&s);
    PASS();
}

/* A pre-shared-key instance must not accept a password-mode (0x03) ciphertext. */
void test_key_mode_rejects_password_ciphertext(void) {
    TEST("key_mode_rejects_password_ciphertext");

    shield_t pw;
    shield_init(&pw, "password", "service", SHIELD_DEFAULT_MAX_AGE_MS);
    size_t clen;
    uint8_t *ct = shield_encrypt(&pw, (const uint8_t *)"pw secret", 9, &clen);
    assert(ct != NULL);

    uint8_t key[SHIELD_KEY_SIZE] = {0};
    shield_t ks;
    shield_init_with_key(&ks, key, SHIELD_KEY_SIZE, SHIELD_DEFAULT_MAX_AGE_MS);

    size_t plen;
    shield_error_t err;
    uint8_t *pt = shield_decrypt(&ks, ct, clen, &plen, &err);
    assert(pt == NULL);
    assert(err == SHIELD_ERR_NO_PASSWORD);

    free(ct);
    shield_wipe(&pw);
    shield_wipe(&ks);
    PASS();
}

/* Key-mode (0x13) roundtrip via shield_init_with_key. */
void test_key_mode_roundtrip(void) {
    TEST("key_mode_roundtrip");

    uint8_t key[SHIELD_KEY_SIZE];
    for (int i = 0; i < SHIELD_KEY_SIZE; i++) key[i] = (uint8_t)i;

    shield_t s;
    shield_init_with_key(&s, key, SHIELD_KEY_SIZE, SHIELD_DEFAULT_MAX_AGE_MS);

    size_t clen;
    uint8_t *ct = shield_encrypt(&s, (const uint8_t *)"key mode roundtrip", 18, &clen);
    assert(ct != NULL && ct[0] == SHIELD_VERSION_KEY);

    size_t plen;
    shield_error_t err;
    uint8_t *pt = shield_decrypt(&s, ct, clen, &plen, &err);
    assert(pt != NULL && err == SHIELD_OK);
    assert(plen == 18 && memcmp(pt, "key mode roundtrip", 18) == 0);

    free(ct);
    free(pt);
    shield_wipe(&s);
    PASS();
}

/* Explicit salt is honored, stored in the header, and shared keys match. */
void test_explicit_salt_honored_and_stored(void) {
    TEST("explicit_salt_honored_and_stored");

    uint8_t salt[SHIELD_SALT_SIZE];
    shield_random_bytes(salt, SHIELD_SALT_SIZE);

    shield_t a, b;
    shield_init_with_salt(&a, "pw", "svc", salt, SHIELD_DEFAULT_MAX_AGE_MS);
    shield_init_with_salt(&b, "pw", "svc", salt, SHIELD_DEFAULT_MAX_AGE_MS);

    /* Same salt -> same key. */
    assert(memcmp(a.key, b.key, SHIELD_KEY_SIZE) == 0);

    size_t clen;
    uint8_t *ct = shield_encrypt(&a, (const uint8_t *)"data", 4, &clen);
    assert(ct != NULL);
    /* Salt is stored verbatim in the header. */
    assert(memcmp(ct + 2, salt, SHIELD_SALT_SIZE) == 0);

    size_t plen;
    shield_error_t err;
    uint8_t *pt = shield_decrypt(&b, ct, clen, &plen, &err);
    assert(pt != NULL && plen == 4 && memcmp(pt, "data", 4) == 0);

    free(ct);
    free(pt);
    shield_wipe(&a);
    shield_wipe(&b);
    PASS();
}

/* ============== V2 Format Tests ============== */

void test_v2_roundtrip(void) {
    TEST("v2_roundtrip");

    shield_t ctx;
    shield_init(&ctx, "password", "service", 60000);

    const char *plaintext = "Test v2 message";
    size_t plaintext_len = strlen(plaintext);

    size_t encrypted_len;
    uint8_t *encrypted = shield_encrypt(&ctx, (const uint8_t *)plaintext, plaintext_len, &encrypted_len);
    assert(encrypted != NULL);

    size_t decrypted_len;
    shield_error_t err;
    uint8_t *decrypted = shield_decrypt(&ctx, encrypted, encrypted_len, &decrypted_len, &err);
    assert(decrypted != NULL);
    assert(err == SHIELD_OK);
    assert(memcmp(decrypted, plaintext, plaintext_len) == 0);

    free(encrypted);
    free(decrypted);
    shield_wipe(&ctx);

    PASS();
}

void test_v2_length_variation(void) {
    TEST("v2_length_variation");

    shield_t ctx;
    shield_init(&ctx, "password", "service", 60000);

    const char *plaintext = "Same message";
    size_t plaintext_len = strlen(plaintext);

    size_t lengths[10];
    int unique_lengths = 0;

    for (int i = 0; i < 10; i++) {
        size_t encrypted_len;
        uint8_t *encrypted = shield_encrypt(&ctx, (const uint8_t *)plaintext, plaintext_len, &encrypted_len);
        assert(encrypted != NULL);

        lengths[i] = encrypted_len;
        free(encrypted);

        /* Check if this length is unique */
        int is_unique = 1;
        for (int j = 0; j < i; j++) {
            if (lengths[j] == encrypted_len) {
                is_unique = 0;
                break;
            }
        }
        if (is_unique) unique_lengths++;
    }

    /* Should have multiple different lengths due to random padding */
    assert(unique_lengths > 1);

    shield_wipe(&ctx);
    PASS();
}

void test_v2_disabled_replay_protection(void) {
    TEST("v2_disabled_replay_protection");

    shield_t ctx;
    shield_init(&ctx, "password", "service", -1);  /* Disabled */

    const char *plaintext = "old but valid";
    size_t plaintext_len = strlen(plaintext);

    size_t encrypted_len;
    uint8_t *encrypted = shield_encrypt(&ctx, (const uint8_t *)plaintext, plaintext_len, &encrypted_len);
    assert(encrypted != NULL);

    size_t decrypted_len;
    shield_error_t err;
    uint8_t *decrypted = shield_decrypt(&ctx, encrypted, encrypted_len, &decrypted_len, &err);
    assert(decrypted != NULL);
    assert(err == SHIELD_OK);
    assert(memcmp(decrypted, plaintext, plaintext_len) == 0);

    free(encrypted);
    free(decrypted);
    shield_wipe(&ctx);

    PASS();
}

/* ============== Ratchet Tests ============== */

void test_ratchet_session(void) {
    TEST("ratchet_session");

    uint8_t root_key[SHIELD_KEY_SIZE] = {0};

    shield_ratchet_t alice, bob;
    assert(shield_ratchet_init(&alice, root_key, SHIELD_KEY_SIZE, true) == SHIELD_OK);
    assert(shield_ratchet_init(&bob, root_key, SHIELD_KEY_SIZE, false) == SHIELD_OK);

    /* Alice sends to Bob */
    const char *msg = "Hello Bob!";
    size_t msg_len = strlen(msg);

    size_t encrypted_len;
    shield_error_t err;
    uint8_t *encrypted = shield_ratchet_encrypt(&alice, (const uint8_t *)msg, msg_len, &encrypted_len, &err);
    assert(encrypted != NULL);

    size_t decrypted_len;
    uint8_t *decrypted = shield_ratchet_decrypt(&bob, encrypted, encrypted_len, &decrypted_len, &err);
    assert(decrypted != NULL);
    assert(memcmp(decrypted, msg, msg_len) == 0);

    assert(shield_ratchet_send_counter(&alice) == 1);
    assert(shield_ratchet_recv_counter(&bob) == 1);

    free(encrypted);
    free(decrypted);
    shield_ratchet_wipe(&alice);
    shield_ratchet_wipe(&bob);

    PASS();
}

void test_ratchet_replay_protection(void) {
    TEST("ratchet_replay_protection");

    uint8_t root_key[SHIELD_KEY_SIZE] = {0};

    shield_ratchet_t alice, bob;
    shield_ratchet_init(&alice, root_key, SHIELD_KEY_SIZE, true);
    shield_ratchet_init(&bob, root_key, SHIELD_KEY_SIZE, false);

    size_t encrypted_len;
    shield_error_t err;
    uint8_t *encrypted = shield_ratchet_encrypt(&alice, (const uint8_t *)"test", 4, &encrypted_len, &err);

    size_t decrypted_len;
    uint8_t *decrypted = shield_ratchet_decrypt(&bob, encrypted, encrypted_len, &decrypted_len, &err);
    free(decrypted);

    /* Try to replay */
    decrypted = shield_ratchet_decrypt(&bob, encrypted, encrypted_len, &decrypted_len, &err);
    assert(decrypted == NULL);
    assert(err == SHIELD_ERR_REPLAY_DETECTED);

    free(encrypted);
    shield_ratchet_wipe(&alice);
    shield_ratchet_wipe(&bob);

    PASS();
}

/* ============== TOTP Tests ============== */

void test_totp_generate_verify(void) {
    TEST("totp_generate_verify");

    uint8_t secret[20];
    assert(shield_totp_generate_secret(secret, 20) == SHIELD_OK);

    shield_totp_t totp;
    shield_totp_init(&totp, secret, 20, 6, 30);

    char code[16];
    shield_totp_generate(&totp, 0, code, sizeof(code));

    assert(strlen(code) == 6);
    assert(shield_totp_verify(&totp, code, 0, 1));

    shield_totp_free(&totp);

    PASS();
}

/* ============== Signature Tests ============== */

void test_symmetric_signature(void) {
    TEST("symmetric_signature");

    shield_signature_t sig;
    assert(shield_signature_generate(&sig) == SHIELD_OK);

    const char *message = "Sign this message";
    size_t msg_len = strlen(message);

    uint8_t signature[32];
    shield_signature_sign(&sig, (const uint8_t *)message, msg_len, signature);

    assert(shield_signature_verify(&sig, (const uint8_t *)message, msg_len, signature, 32,
                                    shield_signature_verification_key(&sig), 0));

    shield_signature_wipe(&sig);

    PASS();
}

void test_signature_timestamped(void) {
    TEST("signature_timestamped");

    shield_signature_t sig;
    shield_signature_generate(&sig);

    const char *message = "Timestamped message";
    size_t msg_len = strlen(message);

    uint8_t signature[40];
    shield_signature_sign_timestamped(&sig, (const uint8_t *)message, msg_len, signature);

    assert(shield_signature_verify(&sig, (const uint8_t *)message, msg_len, signature, 40,
                                    shield_signature_verification_key(&sig), 60));

    shield_signature_wipe(&sig);

    PASS();
}

void test_signature_from_password(void) {
    TEST("signature_from_password");

    shield_signature_t sig;
    shield_signature_from_password(&sig, "password", "user@example.com");

    const char *message = "Test message";
    size_t msg_len = strlen(message);

    uint8_t signature[32];
    shield_signature_sign(&sig, (const uint8_t *)message, msg_len, signature);

    assert(shield_signature_verify(&sig, (const uint8_t *)message, msg_len, signature, 32,
                                    shield_signature_verification_key(&sig), 0));

    shield_signature_wipe(&sig);

    PASS();
}

/* ============== Lamport Tests ============== */

void test_lamport_signature(void) {
    TEST("lamport_signature");

    shield_lamport_t lamport;
    assert(shield_lamport_generate(&lamport) == SHIELD_OK);

    const char *message = "Lamport signed message";
    size_t msg_len = strlen(message);

    uint8_t signature[256 * 32];
    assert(shield_lamport_sign(&lamport, (const uint8_t *)message, msg_len, signature) == SHIELD_OK);

    assert(shield_lamport_verify((const uint8_t *)message, msg_len, signature,
                                  shield_lamport_public_key(&lamport)));

    shield_lamport_free(&lamport);

    PASS();
}

void test_lamport_one_time_use(void) {
    TEST("lamport_one_time_use");

    shield_lamport_t lamport;
    shield_lamport_generate(&lamport);

    uint8_t signature[256 * 32];
    shield_lamport_sign(&lamport, (const uint8_t *)"first", 5, signature);

    assert(shield_lamport_is_used(&lamport));

    shield_error_t err = shield_lamport_sign(&lamport, (const uint8_t *)"second", 6, signature);
    assert(err == SHIELD_ERR_LAMPORT_KEY_USED);

    shield_lamport_free(&lamport);

    PASS();
}

/* ============== Recovery Codes Tests ============== */

void test_recovery_codes(void) {
    TEST("recovery_codes");

    shield_recovery_t recovery;
    assert(shield_recovery_init(&recovery, 10, 8) == SHIELD_OK);

    assert(shield_recovery_remaining(&recovery) == 10);

    /* Get first code */
    char code[SHIELD_RECOVERY_CODE_LEN];
    assert(shield_recovery_get_code(&recovery, 0, code));

    /* Verify it works */
    assert(shield_recovery_verify(&recovery, code));
    assert(shield_recovery_remaining(&recovery) == 9);

    /* Can't use same code again */
    assert(!shield_recovery_verify(&recovery, code));

    /* Invalid code fails */
    assert(!shield_recovery_verify(&recovery, "ZZZZ-ZZZZ"));

    shield_recovery_wipe(&recovery);

    PASS();
}

void test_recovery_codes_normalize(void) {
    TEST("recovery_codes_normalize");

    const char *codes[] = {"ABCD-1234"};
    shield_recovery_t recovery;
    shield_recovery_init_from(&recovery, codes, 1);

    /* Should accept lowercase */
    assert(shield_recovery_verify(&recovery, "abcd-1234"));
    assert(shield_recovery_remaining(&recovery) == 0);

    /* Test without dash */
    const char *codes2[] = {"EFGH-5678"};
    shield_recovery_init_from(&recovery, codes2, 1);
    assert(shield_recovery_verify(&recovery, "efgh5678"));

    shield_recovery_wipe(&recovery);

    PASS();
}

/* ============== Utility Tests ============== */

void test_secure_compare(void) {
    TEST("secure_compare");

    uint8_t a[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    uint8_t b[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    uint8_t c[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,17};

    assert(shield_secure_compare(a, b, 16) == 1);
    assert(shield_secure_compare(a, c, 16) == 0);

    PASS();
}

void test_sha256(void) {
    TEST("sha256");

    /* Test vector: SHA256("abc") */
    const uint8_t expected[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };

    uint8_t hash[32];
    shield_sha256((const uint8_t *)"abc", 3, hash);

    assert(memcmp(hash, expected, 32) == 0);

    PASS();
}

void test_random_bytes(void) {
    TEST("random_bytes");

    uint8_t buf1[32], buf2[32];

    assert(shield_random_bytes(buf1, 32) == SHIELD_OK);
    assert(shield_random_bytes(buf2, 32) == SHIELD_OK);

    /* Should be different (overwhelmingly likely) */
    assert(memcmp(buf1, buf2, 32) != 0);

    PASS();
}

/* ============== v4 Conformance Vectors ============== */

/* Reproduce the Rust-generated v4 vectors byte-for-byte. The C binding uses the
 * Windows CNG AEAD which supports AES-256-GCM only, so we verify the AES
 * "deterministic_vectors" array (suite 0x01) and skip the ChaCha array. */

static int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static size_t hex2bin(const char *hex, uint8_t *out, size_t out_max) {
    size_t n = strlen(hex) / 2, i;
    if (n > out_max) n = out_max;
    for (i = 0; i < n; i++) {
        out[i] = (uint8_t)((hex_val(hex[i * 2]) << 4) | hex_val(hex[i * 2 + 1]));
    }
    return n;
}

static void bin2hex(const uint8_t *bin, size_t len, char *out) {
    static const char *d = "0123456789abcdef";
    size_t i;
    for (i = 0; i < len; i++) { out[i * 2] = d[bin[i] >> 4]; out[i * 2 + 1] = d[bin[i] & 0xF]; }
    out[len * 2] = '\0';
}

/* Find "field":"value" within [start,end); copy value into out. Returns 1 on success. */
/* Anchor on the KEY (`"field":`), not just `"field"` — otherwise a string value
 * equal to the field name (e.g. "mode": "password") would mis-match. */
static int find_str(const char *start, const char *end, const char *field, char *out, size_t outsz) {
    char key[64];
    snprintf(key, sizeof(key), "\"%s\":", field);
    const char *p = strstr(start, key);
    if (!p || p >= end) return 0;
    p += strlen(key);
    while (p < end && (*p == ' ' || *p == '\t')) p++;
    if (p >= end || *p != '"') return 0;
    p++;
    size_t i = 0;
    while (p < end && *p != '"' && i + 1 < outsz) out[i++] = *p++;
    out[i] = '\0';
    return 1;
}

static long long find_num(const char *start, const char *end, const char *field) {
    char key[64];
    snprintf(key, sizeof(key), "\"%s\":", field);
    const char *p = strstr(start, key);
    if (!p || p >= end) return -1;
    p += strlen(key);
    return atoll(p);
}

static void test_v4_vectors(void) {
    TEST("v4_vectors_byte_for_byte (AES-256-GCM)");

    const char *paths[] = {
        "../tests/v4_test_vectors.json",
        "tests/v4_test_vectors.json",
        "../../tests/v4_test_vectors.json"
    };
    FILE *f = NULL;
    size_t pi;
    for (pi = 0; pi < sizeof(paths) / sizeof(paths[0]); pi++) {
        f = fopen(paths[pi], "rb");
        if (f) break;
    }
    if (!f) { FAIL("cannot open v4_test_vectors.json"); return; }

    fseek(f, 0, SEEK_END);
    long fsz = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *json = (char *)malloc((size_t)fsz + 1);
    if (!json) { fclose(f); FAIL("alloc"); return; }
    size_t rd = fread(json, 1, (size_t)fsz, f);
    json[rd] = '\0';
    fclose(f);

    /* Bound to the AES "deterministic_vectors" array (skip the ChaCha array). */
    char *arr = strstr(json, "\"deterministic_vectors\"");
    if (!arr) { free(json); FAIL("no deterministic_vectors"); return; }
    char *arr_start = strchr(arr, '[');
    int depth = 0; char *arr_end = NULL;
    for (char *p = arr_start; *p; p++) {
        if (*p == '[') depth++;
        else if (*p == ']') { depth--; if (depth == 0) { arr_end = p; break; } }
    }
    if (!arr_end) { free(json); FAIL("array end"); return; }

    int count = 0, ok = 1;
    char *p = arr_start;
    while (p < arr_end) {
        char *obj = strchr(p, '{');
        if (!obj || obj >= arr_end) break;
        int d = 0; char *obj_end = NULL;
        for (char *q = obj; q < arr_end + 1; q++) {
            if (*q == '{') d++;
            else if (*q == '}') { d--; if (d == 0) { obj_end = q; break; } }
        }
        if (!obj_end) break;

        char mode[16], suite_s[8], name[64];
        char pw[128], svc[128], salt_hex[64], key_hex[128], nonce_hex[64];
        char pad_hex[512], pt_hex[512], master_hex[128], aead_hex[128], exp_hex[1024];
        find_str(obj, obj_end, "name", name, sizeof(name));
        find_str(obj, obj_end, "mode", mode, sizeof(mode));
        find_str(obj, obj_end, "suite", suite_s, sizeof(suite_s));
        find_str(obj, obj_end, "nonce_hex", nonce_hex, sizeof(nonce_hex));
        find_str(obj, obj_end, "padding_hex", pad_hex, sizeof(pad_hex));
        find_str(obj, obj_end, "plaintext_hex", pt_hex, sizeof(pt_hex));
        find_str(obj, obj_end, "master_key_hex", master_hex, sizeof(master_hex));
        find_str(obj, obj_end, "aead_key_hex", aead_hex, sizeof(aead_hex));
        find_str(obj, obj_end, "expected_output_hex", exp_hex, sizeof(exp_hex));
        long long ts = find_num(obj, obj_end, "timestamp_ms");
        long long pad_len = find_num(obj, obj_end, "pad_len");

        uint8_t suite = (uint8_t)strtol(suite_s, NULL, 16);

        uint8_t master[32], aead_key[32], nonce[12], salt[16];
        uint8_t padding[128], plaintext[256], expected[1024];
        size_t pt_len = hex2bin(pt_hex, plaintext, sizeof(plaintext));
        size_t exp_len = hex2bin(exp_hex, expected, sizeof(expected));
        hex2bin(nonce_hex, nonce, sizeof(nonce));
        hex2bin(pad_hex, padding, sizeof(padding));

        const uint8_t *salt_ptr = NULL;
        size_t aad_len;
        if (strcmp(mode, "password") == 0) {
            find_str(obj, obj_end, "password", pw, sizeof(pw));
            find_str(obj, obj_end, "service", svc, sizeof(svc));
            find_str(obj, obj_end, "salt_hex", salt_hex, sizeof(salt_hex));
            long long iters = find_num(obj, obj_end, "iterations");
            hex2bin(salt_hex, salt, sizeof(salt));
            uint8_t salt_input[16 + 128];
            size_t svc_len = strlen(svc);
            memcpy(salt_input, salt, 16);
            memcpy(salt_input + 16, svc, svc_len);
            shield_pbkdf2(pw, salt_input, 16 + svc_len, (int)iters, master, 32);
            salt_ptr = salt;
            aad_len = 2 + 16;
        } else {
            find_str(obj, obj_end, "key_hex", key_hex, sizeof(key_hex));
            hex2bin(key_hex, master, 32);
            aad_len = 2;
        }

        /* KDF check. */
        char got[256];
        bin2hex(master, 32, got);
        if (strcmp(got, master_hex) != 0) { printf("\n    master drift %s ", name); ok = 0; }
        shield_derive_aead_key(master, aead_key);
        bin2hex(aead_key, 32, got);
        if (strcmp(got, aead_hex) != 0) { printf("\n    aead drift %s ", name); ok = 0; }

        /* Byte-for-byte reproduction. */
        size_t out_len = 0;
        uint8_t *produced = shield_seal_deterministic(aead_key, suite, salt_ptr, nonce,
                                ts, (uint8_t)pad_len, padding, plaintext, pt_len, &out_len);
        if (!produced) { printf("\n    seal NULL %s ", name); ok = 0; }
        else {
            char *produced_hex = (char *)malloc(out_len * 2 + 1);
            bin2hex(produced, out_len, produced_hex);
            if (strcmp(produced_hex, exp_hex) != 0) { printf("\n    BYTE DRIFT %s ", name); ok = 0; }
            free(produced_hex);
            free(produced);
        }

        /* Decrypt check. */
        size_t plen = 0; shield_error_t derr = SHIELD_OK;
        uint8_t *opened = shield_open_ciphertext(aead_key, suite, expected, exp_len,
                                                 aad_len, -1, &plen, &derr);
        if (!opened || plen != pt_len || memcmp(opened, plaintext, pt_len) != 0) {
            printf("\n    decrypt mismatch %s ", name); ok = 0;
        }
        free(opened);

        count++;
        p = obj_end + 1;
    }

    free(json);
    if (ok && count >= 6) PASS();
    else { printf("(verified %d) ", count); FAIL("vector mismatch"); }
}

/* ============== Main ============== */

int main(void) {
    printf("\n=== Shield C Library Tests ===\n\n");

    printf("Core Tests:\n");
    test_shield_encrypt_decrypt();
    test_shield_with_key();
    test_quick_encrypt_decrypt();
    test_invalid_key_size();
    test_authentication_failed();

    printf("\nSecurity-Fix Tests (CR-1 / CR-2 / CR-3):\n");
    test_same_password_service_different_keys();
    test_cross_instance_roundtrip();
    test_wrong_password_fails();
    test_iterations_600k();
    test_version_bytes();
    test_tamper_detection_all_bytes();
    test_tamper_salt_detected();
    test_tamper_version_detected();
    test_unknown_version_rejected();
    test_key_mode_rejects_password_ciphertext();
    test_key_mode_roundtrip();
    test_explicit_salt_honored_and_stored();

    printf("\nV2 Format Tests:\n");
    test_v2_roundtrip();
    test_v2_length_variation();
    test_v2_disabled_replay_protection();

    printf("\nv4 Conformance Vectors:\n");
    test_v4_vectors();

    printf("\nRatchet Tests:\n");
    test_ratchet_session();
    test_ratchet_replay_protection();

    printf("\nTOTP Tests:\n");
    test_totp_generate_verify();

    printf("\nSignature Tests:\n");
    test_symmetric_signature();
    test_signature_timestamped();
    test_signature_from_password();

    printf("\nLamport Tests:\n");
    test_lamport_signature();
    test_lamport_one_time_use();

    printf("\nRecovery Codes Tests:\n");
    test_recovery_codes();
    test_recovery_codes_normalize();

    printf("\nUtility Tests:\n");
    test_secure_compare();
    test_sha256();
    test_random_bytes();

    printf("\n=== Results ===\n");
    printf("Passed: %d\n", tests_passed);
    printf("Failed: %d\n", tests_failed);
    printf("Total:  %d\n\n", tests_passed + tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
