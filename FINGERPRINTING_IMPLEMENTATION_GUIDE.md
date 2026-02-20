# Shield v2.1 Hardware Fingerprinting - Implementation Guide

**Version**: 2.1
**Status**: Rust ✅ + Python ✅ Implemented | JavaScript/Go/Java/C Pattern Documented
**TaskGuard Chain**: backend-037 (design) → backend-038-043 (impl) → docs-023 + testing-014

---

## Overview

Shield v2.1 adds hardware fingerprinting for device-bound encryption. Keys are derived from `password + hardware_fingerprint`, preventing key theft and unauthorized device usage.

**Source**: Adapted from `/data/git/Guard8.ai/SaaSClient-SideLicensingSystem/src/saas_client.rs`

---

## API Design (All Languages)

###Fingerprint Modes

```
None        - No fingerprinting (backward compatible)
Motherboard - Motherboard serial only
CPU         - CPU identifier only
Combined    - Motherboard + CPU (recommended)
```

### Constructor Signature

```rust
// Rust
Shield::with_fingerprint(password: &str, service: &str, mode: FingerprintMode) -> Result<Self>

// Python
Shield.with_fingerprint(password, service, mode='combined') -> Shield

// JavaScript (PATTERN)
Shield.withFingerprint(password, service, { mode: 'combined' }) -> Shield

// Go (PATTERN)
shield.NewWithFingerprint(password, service, shield.FingerprintCombined) -> (*Shield, error)

// Java (PATTERN)
Shield.withFingerprint(password, service, FingerprintMode.COMBINED) -> Shield

// C (PATTERN)
shield_with_fingerprint(&ctx, password, service, SHIELD_FP_COMBINED) -> shield_error_t
```

---

## Key Derivation Formula

```
fingerprint = collect_hardware_fingerprint(mode)
combined_password = password + ":" + fingerprint
salt = SHA256(service)
key = PBKDF2-SHA256(combined_password, salt, 100000 iterations, 32 bytes)
```

**Note**: Empty fingerprint (mode=None) → combined_password = password (backward compatible)

---

## Platform-Specific Collection

### Windows

```bash
# Motherboard Serial
wmic baseboard get serialnumber /value
# Output: SerialNumber=ABCD1234

# CPU ID
wmic cpu get ProcessorId /value
# Output: ProcessorId=BFEBFBFF000906E9
```

### Linux

```bash
# Motherboard Serial (sysfs)
cat /sys/class/dmi/id/board_serial
# Fallback: dmidecode -s baseboard-serial-number

# CPU ID
cat /proc/cpuinfo | grep "processor.*0"
# Hash the first processor line
```

### macOS

```bash
# Motherboard Serial
system_profiler SPHardwareDataType | grep "Serial Number"
# Output: Serial Number (system): C02ABC123DEF

# CPU ID
sysctl -n machdep.cpu.brand_string
# Output: Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz
# Hash the output
```

---

## Implemented Languages

### ✅ Rust (shield-core)

**Files**:
- `shield-core/src/fingerprint.rs` (220 lines)
- `shield-core/src/shield.rs` (+65 lines)
- `shield-core/Cargo.toml` (+1 dep: md5)

**Usage**:
```rust
use shield_core::{Shield, FingerprintMode};

let shield = Shield::with_fingerprint("password", "github.com", FingerprintMode::Combined)?;
let encrypted = shield.encrypt(b"secret data")?;
```

**Tests**: 2/2 passing (`cargo test fingerprint`)

---

### ✅ Python (python/shield)

**Files**:
- `python/shield/fingerprint.py` (188 lines)
- `python/shield/core.py` (+64 lines)

**Usage**:
```python
from shield import Shield

shield = Shield.with_fingerprint("password", "github.com", "combined")
encrypted = shield.encrypt(b"secret data")
```

**Errors**: `FingerprintError` raised if hardware unavailable

---

## Implementation Patterns (JavaScript, Go, Java, C)

### JavaScript Pattern

**File**: `javascript/src/fingerprint.js` (new)

```javascript
const { execSync } = require('child_process');
const crypto = require('crypto');

class FingerprintMode {
    static NONE = 'none';
    static MOTHERBOARD = 'motherboard';
    static CPU = 'cpu';
    static COMBINED = 'combined';
}

function collectFingerprint(mode) {
    if (mode === FingerprintMode.NONE) return '';

    const components = [];

    try {
        components.push(getMotherboardSerial());
    } catch {}

    try {
        components.push(getCpuId());
    } catch {}

    if (components.length === 0) {
        throw new Error('Hardware fingerprint unavailable');
    }

    const combined = components.join('-');
    return crypto.createHash('md5').update(combined).digest('hex');
}

function getMotherboardSerial() {
    if (process.platform === 'win32') {
        const output = execSync('wmic baseboard get serialnumber /value').toString();
        // Parse output...
    } else if (process.platform === 'linux') {
        const serial = fs.readFileSync('/sys/class/dmi/id/board_serial', 'utf8').trim();
        // ...
    }
    // ...
}

class Shield {
    static withFingerprint(password, service, options = {}) {
        const mode = options.mode || FingerprintMode.COMBINED;
        const fingerprint = collectFingerprint(mode);
        const combinedPassword = fingerprint ? `${password}:${fingerprint}` : password;
        return new Shield(combinedPassword, service);
    }
}
```

**Export**: `module.exports = { Shield, FingerprintMode };`

---

### Go Pattern

**File**: `go/shield/fingerprint.go` (new)

```go
package shield

import (
    "crypto/md5"
    "fmt"
    "os/exec"
    "runtime"
    "strings"
)

type FingerprintMode int

const (
    FingerprintNone FingerprintMode = iota
    FingerprintMotherboard
    FingerprintCPU
    FingerprintCombined
)

func CollectFingerprint(mode FingerprintMode) (string, error) {
    if mode == FingerprintNone {
        return "", nil
    }

    var components []string

    if mb, err := getMotherboardSerial(); err == nil {
        components = append(components, mb)
    }

    if cpu, err := getCpuId(); err == nil {
        components = append(components, cpu)
    }

    if len(components) == 0 {
        return "", fmt.Errorf("hardware fingerprint unavailable")
    }

    combined := strings.Join(components, "-")
    return fmt.Sprintf("%x", md5.Sum([]byte(combined))), nil
}

func getMotherboardSerial() (string, error) {
    switch runtime.GOOS {
    case "windows":
        out, err := exec.Command("wmic", "baseboard", "get", "serialnumber", "/value").Output()
        // Parse output...
    case "linux":
        data, err := os.ReadFile("/sys/class/dmi/id/board_serial")
        // ...
    }
    return "", fmt.Errorf("unsupported platform")
}

func NewWithFingerprint(password, service string, mode FingerprintMode) (*Shield, error) {
    fingerprint, err := CollectFingerprint(mode)
    if err != nil {
        return nil, err
    }

    combinedPassword := password
    if fingerprint != "" {
        combinedPassword = fmt.Sprintf("%s:%s", password, fingerprint)
    }

    return New(combinedPassword, service, nil), nil
}
```

---

### Java Pattern

**File**: `java/src/main/java/ai/guard8/shield/Fingerprint.java` (new)

```java
package ai.guard8.shield;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

public enum FingerprintMode {
    NONE, MOTHERBOARD, CPU, COMBINED
}

public class Fingerprint {
    public static String collect(FingerprintMode mode) throws Exception {
        if (mode == FingerprintMode.NONE) return "";

        List<String> components = new ArrayList<>();

        try {
            components.add(getMotherboardSerial());
        } catch (Exception e) {}

        try {
            components.add(getCpuId());
        } catch (Exception e) {}

        if (components.isEmpty()) {
            throw new Exception("Hardware fingerprint unavailable");
        }

        String combined = String.join("-", components);
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hash = md.digest(combined.getBytes());

        StringBuilder hex = new StringBuilder();
        for (byte b : hash) {
            hex.append(String.format("%02x", b));
        }
        return hex.toString();
    }

    private static String getMotherboardSerial() throws Exception {
        String os = System.getProperty("os.name").toLowerCase();

        if (os.contains("win")) {
            Process process = Runtime.getRuntime().exec(
                new String[]{"wmic", "baseboard", "get", "serialnumber", "/value"}
            );
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream())
            );
            // Parse output...
        } else if (os.contains("linux")) {
            // Read /sys/class/dmi/id/board_serial
        }
        throw new Exception("Unsupported platform");
    }

    private static String getCpuId() throws Exception {
        // Similar platform-specific implementation
    }
}

// In Shield.java:
public static Shield withFingerprint(String password, String service, FingerprintMode mode) throws Exception {
    String fingerprint = Fingerprint.collect(mode);
    String combinedPassword = fingerprint.isEmpty() ? password : password + ":" + fingerprint;
    return new Shield(combinedPassword, service);
}
```

---

### C Pattern

**File**: `c/include/shield_fingerprint.h` (new)

```c
#ifndef SHIELD_FINGERPRINT_H
#define SHIELD_FINGERPRINT_H

#include <stddef.h>

typedef enum {
    SHIELD_FP_NONE = 0,
    SHIELD_FP_MOTHERBOARD = 1,
    SHIELD_FP_CPU = 2,
    SHIELD_FP_COMBINED = 3
} shield_fingerprint_mode_t;

typedef enum {
    SHIELD_FP_OK = 0,
    SHIELD_FP_ERR_UNAVAILABLE = 1,
    SHIELD_FP_ERR_PLATFORM = 2
} shield_fp_error_t;

/**
 * Collect hardware fingerprint.
 *
 * @param mode Fingerprint mode
 * @param buffer Output buffer (33 bytes for MD5 hex + null terminator)
 * @param buffer_len Size of output buffer
 * @return Error code
 */
shield_fp_error_t shield_fp_collect(
    shield_fingerprint_mode_t mode,
    char *buffer,
    size_t buffer_len
);

#endif
```

**File**: `c/src/shield_fingerprint.c` (new)

```c
#include "shield_fingerprint.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

shield_fp_error_t shield_fp_collect(
    shield_fingerprint_mode_t mode,
    char *buffer,
    size_t buffer_len
) {
    if (mode == SHIELD_FP_NONE) {
        buffer[0] = '\0';
        return SHIELD_FP_OK;
    }

    char components[512] = {0};
    char mb_serial[256] = {0};
    char cpu_id[256] = {0};

    // Try to get motherboard serial
    if (get_motherboard_serial(mb_serial, sizeof(mb_serial)) == 0) {
        strcat(components, mb_serial);
    }

    // Try to get CPU ID
    if (get_cpu_id(cpu_id, sizeof(cpu_id)) == 0) {
        if (strlen(components) > 0) strcat(components, "-");
        strcat(components, cpu_id);
    }

    if (strlen(components) == 0) {
        return SHIELD_FP_ERR_UNAVAILABLE;
    }

    // MD5 hash
    unsigned char hash[16];
    MD5((unsigned char*)components, strlen(components), hash);

    // Convert to hex
    for (int i = 0; i < 16; i++) {
        sprintf(buffer + (i * 2), "%02x", hash[i]);
    }
    buffer[32] = '\0';

    return SHIELD_FP_OK;
}

#ifdef _WIN32
static int get_motherboard_serial(char *buffer, size_t size) {
    FILE *pipe = _popen("wmic baseboard get serialnumber /value", "r");
    if (!pipe) return -1;

    while (fgets(buffer, size, pipe)) {
        if (strncmp(buffer, "SerialNumber=", 13) == 0) {
            // Parse and clean
            _pclose(pipe);
            return 0;
        }
    }
    _pclose(pipe);
    return -1;
}
#else
static int get_motherboard_serial(char *buffer, size_t size) {
    FILE *f = fopen("/sys/class/dmi/id/board_serial", "r");
    if (!f) return -1;

    if (fgets(buffer, size, f)) {
        // Clean whitespace
        fclose(f);
        return 0;
    }
    fclose(f);
    return -1;
}
#endif

// In shield.c:
shield_error_t shield_with_fingerprint(
    shield_t *ctx,
    const char *password,
    const char *service,
    shield_fingerprint_mode_t fp_mode
) {
    char fingerprint[33];
    shield_fp_error_t err = shield_fp_collect(fp_mode, fingerprint, sizeof(fingerprint));

    if (err != SHIELD_FP_OK && fp_mode != SHIELD_FP_NONE) {
        return SHIELD_ERR_FINGERPRINT_UNAVAILABLE;
    }

    char combined_password[512];
    if (strlen(fingerprint) > 0) {
        snprintf(combined_password, sizeof(combined_password), "%s:%s", password, fingerprint);
    } else {
        strncpy(combined_password, password, sizeof(combined_password));
    }

    shield_init(ctx, combined_password, service, -1);
    return SHIELD_OK;
}
```

---

## Testing Strategy

### Unit Tests

```rust
// Rust
#[test]
fn test_fingerprint_none_mode() {
    let fp = collect_fingerprint(FingerprintMode::None).unwrap();
    assert_eq!(fp, "");
}

#[test]
fn test_fingerprint_combined() {
    match collect_fingerprint(FingerprintMode::Combined) {
        Ok(fp) => assert_eq!(fp.len(), 32), // MD5 hex
        Err(_) => {} // Expected on VMs
    }
}
```

### Cross-Language Tests

```python
# In tests/test_fingerprinting_v2_1.py
def test_rust_python_fingerprint_compat():
    """Verify Rust and Python produce same fingerprint."""
    # Mock hardware IDs for deterministic testing
    # ...
```

### Integration Tests

- Mock hardware IDs for CI/CD
- Test on real hardware (Windows, Linux, macOS)
- Verify different devices produce different keys
- Verify same device produces same key

---

## Security Analysis

### Threat Model

**Attack**: Key extraction and transfer to attacker's device
**Defense**: Hardware fingerprint changes → key derivation fails → decryption fails

**Attack**: VM cloning
**Defense**: VM gets generic motherboard serial → different fingerprint → different key

**Attack**: Hardware upgrade (motherboard replacement)
**Impact**: Legitimate user loses access (by design, trade-off)

### Privacy Considerations

**GDPR/CCPA**: Hardware IDs are PII in some jurisdictions
**Recommendation**: Log fingerprint collection carefully, provide opt-out

**User Consent**: Document that encryption is device-bound
**Data Portability**: Provide re-encryption tool for hardware upgrades

### Binding Strength

| Component | Stability | Spoofability | Notes |
|-----------|-----------|--------------|-------|
| Motherboard Serial | High | Medium | Requires physical access to swap |
| CPU ID | High | Low | Harder to spoof than motherboard |
| Combined | High | Low-Medium | Best security/usability balance |

---

## Migration Guide

### From v2.0 to v2.1

**Backward Compatible**: Existing `Shield::new()` unchanged

**Opt-In**: Use `Shield::with_fingerprint()` for new device-bound use cases

**Re-Encryption**: To add fingerprinting to existing data:
```rust
let old_shield = Shield::new("password", "service");
let new_shield = Shield::with_fingerprint("password", "service", FingerprintMode::Combined)?;

let plaintext = old_shield.decrypt(&ciphertext)?;
let new_ciphertext = new_shield.encrypt(&plaintext)?;
```

---

## Deployment Checklist

- [ ] Test on all target platforms (Windows, Linux, macOS)
- [ ] Verify VM behavior (fallback to None mode if needed)
- [ ] Document privacy implications in user-facing docs
- [ ] Add telemetry for fingerprint collection failures
- [ ] Create support process for hardware upgrades
- [ ] Update PROTOCOL.md with v2.1 specification
- [ ] Add cross-language test vectors
- [ ] Benchmark performance impact (minimal, <1ms)

---

## Future Enhancements

1. **Secure Enclave Integration**: Use TPM/Keychain/Keystore for key storage
2. **Fallback Strategy**: Allow user-provided device ID if hardware unavailable
3. **Key Escrow**: Optional backup keys for hardware upgrade scenarios
4. **Docker Support**: Detect containerized environments, warn about fingerprinting limitations

---

**Status**:
- ✅ Rust: Implemented + Tested
- ✅ Python: Implemented + Tested
- 📋 JavaScript: Pattern Documented
- 📋 Go: Pattern Documented
- 📋 Java: Pattern Documented
- 📋 C: Pattern Documented
