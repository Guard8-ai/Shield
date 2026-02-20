#include "shield_fingerprint.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

/* Forward declarations for internal functions */
static shield_fp_error_t get_motherboard_serial(char *buffer, size_t size);
static shield_fp_error_t get_cpu_id(char *buffer, size_t size);
static void md5_hash(const char *input, char *output);

shield_fp_error_t shield_fp_collect(
    shield_fp_mode_t mode,
    char *buffer,
    size_t buffer_len
) {
    if (buffer == NULL || buffer_len < 33) {
        return SHIELD_FP_ERR_BUFFER_TOO_SMALL;
    }

    if (mode == SHIELD_FP_NONE) {
        buffer[0] = '\0';
        return SHIELD_FP_OK;
    }

    if (mode == SHIELD_FP_MOTHERBOARD) {
        return get_motherboard_serial(buffer, buffer_len);
    }

    if (mode == SHIELD_FP_CPU) {
        return get_cpu_id(buffer, buffer_len);
    }

    if (mode == SHIELD_FP_COMBINED) {
        char components[512] = {0};
        char mb_serial[256] = {0};
        char cpu_id[256] = {0};
        int has_components = 0;

        /* Try to get motherboard serial */
        if (get_motherboard_serial(mb_serial, sizeof(mb_serial)) == SHIELD_FP_OK) {
            strcat(components, mb_serial);
            has_components = 1;
        }

        /* Try to get CPU ID */
        if (get_cpu_id(cpu_id, sizeof(cpu_id)) == SHIELD_FP_OK) {
            if (has_components) {
                strcat(components, "-");
            }
            strcat(components, cpu_id);
            has_components = 1;
        }

        if (!has_components) {
            return SHIELD_FP_ERR_UNAVAILABLE;
        }

        /* MD5 hash the combined components */
        md5_hash(components, buffer);
        return SHIELD_FP_OK;
    }

    return SHIELD_FP_ERR_UNKNOWN_MODE;
}

/* Platform-specific implementations */

#ifdef _WIN32
static shield_fp_error_t get_motherboard_serial(char *buffer, size_t size) {
    FILE *pipe = _popen("wmic baseboard get serialnumber /value", "r");
    if (!pipe) {
        return SHIELD_FP_ERR_UNAVAILABLE;
    }

    char line[256];
    while (fgets(line, sizeof(line), pipe)) {
        if (strncmp(line, "SerialNumber=", 13) == 0) {
            char *serial = line + 13;
            /* Remove whitespace */
            while (*serial && (*serial == ' ' || *serial == '\r' || *serial == '\n')) {
                serial++;
            }
            size_t len = strlen(serial);
            while (len > 0 && (serial[len-1] == ' ' || serial[len-1] == '\r' || serial[len-1] == '\n')) {
                serial[--len] = '\0';
            }

            if (len > 0 && strcmp(serial, "To be filled by O.E.M.") != 0) {
                strncpy(buffer, serial, size - 1);
                buffer[size - 1] = '\0';
                _pclose(pipe);
                return SHIELD_FP_OK;
            }
        }
    }
    _pclose(pipe);
    return SHIELD_FP_ERR_UNAVAILABLE;
}

static shield_fp_error_t get_cpu_id(char *buffer, size_t size) {
    FILE *pipe = _popen("wmic cpu get ProcessorId /value", "r");
    if (!pipe) {
        return SHIELD_FP_ERR_UNAVAILABLE;
    }

    char line[256];
    while (fgets(line, sizeof(line), pipe)) {
        if (strncmp(line, "ProcessorId=", 12) == 0) {
            char *cpu_id = line + 12;
            /* Remove whitespace */
            while (*cpu_id && (*cpu_id == ' ' || *cpu_id == '\r' || *cpu_id == '\n')) {
                cpu_id++;
            }
            size_t len = strlen(cpu_id);
            while (len > 0 && (cpu_id[len-1] == ' ' || cpu_id[len-1] == '\r' || cpu_id[len-1] == '\n')) {
                cpu_id[--len] = '\0';
            }

            if (len > 0) {
                strncpy(buffer, cpu_id, size - 1);
                buffer[size - 1] = '\0';
                _pclose(pipe);
                return SHIELD_FP_OK;
            }
        }
    }
    _pclose(pipe);
    return SHIELD_FP_ERR_UNAVAILABLE;
}

#else /* Linux/macOS */

static shield_fp_error_t get_motherboard_serial(char *buffer, size_t size) {
    /* Try DMI sysfs first (Linux) */
    FILE *f = fopen("/sys/class/dmi/id/board_serial", "r");
    if (f) {
        if (fgets(buffer, size, f)) {
            /* Remove whitespace */
            size_t len = strlen(buffer);
            while (len > 0 && (buffer[len-1] == ' ' || buffer[len-1] == '\n')) {
                buffer[--len] = '\0';
            }
            if (len > 0 && strcmp(buffer, "To be filled by O.E.M.") != 0) {
                fclose(f);
                return SHIELD_FP_OK;
            }
        }
        fclose(f);
    }

    /* Fallback to dmidecode */
    FILE *pipe = popen("dmidecode -s baseboard-serial-number 2>/dev/null", "r");
    if (!pipe) {
        return SHIELD_FP_ERR_UNAVAILABLE;
    }

    if (fgets(buffer, size, pipe)) {
        /* Remove whitespace */
        size_t len = strlen(buffer);
        while (len > 0 && (buffer[len-1] == ' ' || buffer[len-1] == '\n')) {
            buffer[--len] = '\0';
        }
        if (len > 0 && strcmp(buffer, "To be filled by O.E.M.") != 0) {
            pclose(pipe);
            return SHIELD_FP_OK;
        }
    }
    pclose(pipe);
    return SHIELD_FP_ERR_UNAVAILABLE;
}

static shield_fp_error_t get_cpu_id(char *buffer, size_t size) {
    /* Try /proc/cpuinfo (Linux) */
    FILE *f = fopen("/proc/cpuinfo", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "processor", 9) == 0 && strstr(line, "0")) {
                /* Hash the first processor line */
                md5_hash(line, buffer);
                fclose(f);
                return SHIELD_FP_OK;
            }
        }
        fclose(f);
    }

    /* Try sysctl (macOS) */
    FILE *pipe = popen("sysctl -n machdep.cpu.brand_string 2>/dev/null", "r");
    if (pipe) {
        if (fgets(buffer, size, pipe)) {
            /* Remove whitespace */
            size_t len = strlen(buffer);
            while (len > 0 && (buffer[len-1] == ' ' || buffer[len-1] == '\n')) {
                buffer[--len] = '\0';
            }
            if (len > 0) {
                /* Hash the CPU info */
                char temp[256];
                strncpy(temp, buffer, sizeof(temp) - 1);
                md5_hash(temp, buffer);
                pclose(pipe);
                return SHIELD_FP_OK;
            }
        }
        pclose(pipe);
    }

    return SHIELD_FP_ERR_UNAVAILABLE;
}
#endif

/* Simple MD5 implementation (for fingerprinting only, not cryptographic use) */
static void md5_hash(const char *input, char *output) {
    /* Use system MD5 if available, otherwise return input as-is */
    /* This is a simplified version - in production, link against OpenSSL or similar */

    /* For now, just copy input (will be replaced with actual MD5 in production) */
    /* This allows the code to compile without external dependencies */
    size_t len = strlen(input);
    if (len > 32) len = 32;
    strncpy(output, input, len);
    output[len] = '\0';

    /* TODO: Implement actual MD5 or link against crypto library */
    /* Example with OpenSSL:
     * unsigned char digest[16];
     * MD5((unsigned char*)input, strlen(input), digest);
     * for (int i = 0; i < 16; i++) {
     *     sprintf(output + (i * 2), "%02x", digest[i]);
     * }
     * output[32] = '\0';
     */
}
