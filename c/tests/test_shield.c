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
    shield_init(&ctx, "password123", "test-service");

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
    shield_error_t err = shield_init_with_key(&ctx, key, SHIELD_KEY_SIZE);
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
    shield_error_t err = shield_init_with_key(&ctx, (uint8_t *)"short", 5);
    assert(err == SHIELD_ERR_INVALID_KEY_SIZE);

    PASS();
}

void test_authentication_failed(void) {
    TEST("authentication_failed");

    shield_t ctx;
    shield_init(&ctx, "password", "service");

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

/* ============== Main ============== */

int main(void) {
    printf("\n=== Shield C Library Tests ===\n\n");

    printf("Core Tests:\n");
    test_shield_encrypt_decrypt();
    test_shield_with_key();
    test_quick_encrypt_decrypt();
    test_invalid_key_size();
    test_authentication_failed();

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
