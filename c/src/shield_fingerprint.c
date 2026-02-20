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

/* MD5 implementation - standalone, no external dependencies */
/* Based on RFC 1321 - for fingerprinting only, not cryptographic security */

#define MD5_F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define MD5_G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define MD5_H(x, y, z) ((x) ^ (y) ^ (z))
#define MD5_I(x, y, z) ((y) ^ ((x) | (~z)))
#define MD5_ROTLEFT(a, b) (((a) << (b)) | ((a) >> (32-(b))))

static void md5_transform(uint32_t state[4], const uint8_t block[64]) {
    uint32_t a, b, c, d, m[16], i, j;
    static const uint32_t k[64] = {
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
    };
    static const uint32_t s[64] = {
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
    };

    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = (block[j]) | (block[j+1] << 8) | (block[j+2] << 16) | (block[j+3] << 24);

    a = state[0]; b = state[1]; c = state[2]; d = state[3];

    for (i = 0; i < 64; ++i) {
        uint32_t f, g;
        if (i < 16) {
            f = MD5_F(b, c, d); g = i;
        } else if (i < 32) {
            f = MD5_G(b, c, d); g = (5*i + 1) % 16;
        } else if (i < 48) {
            f = MD5_H(b, c, d); g = (3*i + 5) % 16;
        } else {
            f = MD5_I(b, c, d); g = (7*i) % 16;
        }
        uint32_t temp = d;
        d = c; c = b;
        b = b + MD5_ROTLEFT((a + f + k[i] + m[g]), s[i]);
        a = temp;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
}

static void md5_hash(const char *input, char *output) {
    size_t input_len = strlen(input);
    uint32_t state[4] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};
    uint8_t buffer[64];
    size_t i;
    uint64_t bit_len = input_len * 8;

    /* Process full blocks */
    size_t offset = 0;
    while (offset + 64 <= input_len) {
        md5_transform(state, (const uint8_t*)(input + offset));
        offset += 64;
    }

    /* Final block with padding */
    size_t remaining = input_len - offset;
    memset(buffer, 0, 64);
    memcpy(buffer, input + offset, remaining);
    buffer[remaining] = 0x80;

    if (remaining >= 56) {
        md5_transform(state, buffer);
        memset(buffer, 0, 64);
    }

    /* Append length in bits */
    for (i = 0; i < 8; ++i)
        buffer[56 + i] = (bit_len >> (i * 8)) & 0xFF;

    md5_transform(state, buffer);

    /* Convert to hex string */
    for (i = 0; i < 4; ++i) {
        sprintf(output + (i * 8), "%02x%02x%02x%02x",
                (state[i]) & 0xFF,
                (state[i] >> 8) & 0xFF,
                (state[i] >> 16) & 0xFF,
                (state[i] >> 24) & 0xFF);
    }
    output[32] = '\0';
}
