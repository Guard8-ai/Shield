#ifndef SHIELD_FINGERPRINT_H
#define SHIELD_FINGERPRINT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Fingerprint collection mode.
 */
typedef enum {
    SHIELD_FP_NONE = 0,        /** No fingerprinting */
    SHIELD_FP_MOTHERBOARD = 1, /** Motherboard serial only */
    SHIELD_FP_CPU = 2,          /** CPU identifier only */
    SHIELD_FP_COMBINED = 3     /** Motherboard + CPU (recommended) */
} shield_fp_mode_t;

/**
 * Fingerprint error codes.
 */
typedef enum {
    SHIELD_FP_OK = 0,
    SHIELD_FP_ERR_UNAVAILABLE = 1,
    SHIELD_FP_ERR_BUFFER_TOO_SMALL = 2,
    SHIELD_FP_ERR_UNKNOWN_MODE = 3
} shield_fp_error_t;

/**
 * Collect hardware fingerprint.
 *
 * @param mode Fingerprint mode
 * @param buffer Output buffer for fingerprint (33 bytes for MD5 hex + null terminator)
 * @param buffer_len Size of output buffer
 * @return Error code (SHIELD_FP_OK on success)
 */
shield_fp_error_t shield_fp_collect(
    shield_fp_mode_t mode,
    char *buffer,
    size_t buffer_len
);

#ifdef __cplusplus
}
#endif

#endif /* SHIELD_FINGERPRINT_H */
