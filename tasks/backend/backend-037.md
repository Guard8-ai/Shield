---
id: backend-037
title: Design Shield v2.1 hardware fingerprinting integration
status: done
priority: high
tags:
- backend
dependencies:
- testing-013
assignee: developer
created: 2026-02-20T12:42:42.332572487Z
estimate: 2h
complexity: 5
area: backend
---

# Design Shield v2.1 hardware fingerprinting integration

## Causation Chain
> Trace the service orchestration: entry point → dependency injection →
business logic → side effects → return. Verify actual error propagation
paths in the codebase.

## Pre-flight Checks
- [ ] Read dependency task files for implementation context (Session Handoff)
- [ ] `grep -r "impl.*Service\|fn.*service" src/` - Find service definitions
- [ ] Check actual dependency injection patterns
- [ ] Verify error propagation through service layers
- [ ] `git log --oneline -10` - Check recent related commits

## Context
Shield v2.1 adds hardware fingerprinting capabilities extracted from SaaSClient-SideLicensingSystem.
This enables device-bound encryption where keys are derived from hardware identifiers, preventing
key theft and unauthorized device usage. Use cases:
- License protection (like SaaSClient)
- Device-bound credentials
- Hardware-locked secrets
- Anti-key-extraction for sensitive applications

## Tasks
- [x] Analyze SaaSClient hardware fingerprinting code (src/saas_client.rs lines 59-175)
- [x] Design Shield v2.1 API: `Shield::with_hardware_fingerprint(password, service, fingerprint_mode)`
- [x] Define fingerprint modes: FingerprintMode enum (None, Motherboard, CPU, Combined)
- [x] Specify cross-platform fingerprint collection (Windows/Linux/macOS)
- [x] Design key derivation: PBKDF2(password || fingerprint, SHA256(service), 100k)
- [x] Plan error handling for unavailable hardware IDs
- [x] Define test strategy (mock fingerprints, real hardware tests)
- [x] Document security properties (binding strength, spoofability, privacy)

## Acceptance Criteria
- [ ] API design documented with code examples
- [ ] Fingerprint collection strategy defined for all platforms
- [ ] Key derivation formula specified
- [ ] Security analysis completed (threat model)
- [ ] Implementation tasks created for all 5 languages (Python, JS, Go, Java, C)

## Notes
**Source Code**: /data/git/Guard8.ai/SaaSClient-SideLicensingSystem/src/saas_client.rs

**Key Functions**:
- `get_hardware_id()` - combines motherboard + CPU, returns MD5 hash
- `get_motherboard_serial()` - platform-specific (wmic, dmidecode, system_profiler)
- `get_cpu_id()` - platform-specific CPU identifier

**Platform Commands**:
- Windows: `wmic baseboard get serialnumber`, `wmic cpu get ProcessorId`
- Linux: `/sys/class/dmi/id/board_serial`, `dmidecode`, `/proc/cpuinfo`
- macOS: `system_profiler SPHardwareDataType`

**Challenges**:
- VMs may have generic motherboard serials ("To be filled by O.E.M.")
- Requires elevated privileges on some platforms
- Privacy concerns (hardware IDs are PII in some jurisdictions)
- Need fallback strategy when hardware IDs unavailable

**Crates Needed** (Rust):
- `sysinfo` or direct system commands
- Consider `raw-cpuid` for better CPU identification

---
**Session Handoff**:
- Changed: Created v2.1 fingerprinting API design
- Causality: User requests hardware fingerprinting → Shield collects hardware ID → Derives device-bound key
- Verify: Design review complete, implementation tasks created
- Next: Implement in Rust first (backend-038), then other languages

## v2.1 API Design

### FingerprintMode Enum
```rust
pub enum FingerprintMode {
    None,              // No fingerprinting (backward compat)
    Motherboard,       // Motherboard serial only
    CPU,               // CPU ID only
    Combined,          // Motherboard + CPU (recommended)
}
```

### Constructor API
```rust
// Rust
impl Shield {
    pub fn with_fingerprint(password: &str, service: &str, mode: FingerprintMode) -> Result<Self, ShieldError>;
}

// Python
Shield.with_fingerprint(password, service, mode='combined')

// JavaScript
Shield.withFingerprint(password, service, { mode: 'combined' })

// Go
shield.NewWithFingerprint(password, service, shield.FingerprintCombined)

// Java
Shield.withFingerprint(password, service, FingerprintMode.COMBINED)

// C
shield_with_fingerprint(&ctx, password, service, SHIELD_FP_COMBINED)
```

### Key Derivation Formula
```
fingerprint = collect_hardware_fingerprint(mode)
combined_password = password || ":" || fingerprint
master_key = PBKDF2-SHA256(combined_password, SHA256(service), 100000, 32)
```

### Platform-Specific Collection
- **Windows**: wmic commands (baseboard, CPU)
- **Linux**: /sys/class/dmi/id, dmidecode, /proc/cpuinfo
- **macOS**: system_profiler SPHardwareDataType
- **Fallback**: Error if unavailable (no silent fallback to avoid security bypass)

### Security Properties
- **Binding Strength**: MEDIUM (hardware IDs are stable but replaceable)
- **Spoofability**: LOW-MEDIUM (requires hardware access or VM manipulation)
- **Privacy**: HIGH CONCERN (hardware IDs are PII, log carefully)
- **Portability**: NONE (keys are device-bound by design)

### Error Handling
```rust
pub enum FingerprintError {
    HardwareNotAvailable,    // No hardware ID found
    InsufficientPrivileges,  // Needs sudo/admin
    PlatformUnsupported,     // Platform not impl