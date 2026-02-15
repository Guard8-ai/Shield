---
id: backend-026
title: Rust Intel SGX Attestation Provider
status: done
priority: high
tags:
- backend
- rust
- confidential-computing
- intel-sgx
dependencies:
- backend-022
assignee: developer
created: 2026-01-16T14:00:00Z
estimate: 1d
complexity: 8
area: backend
---

# Rust Intel SGX Attestation Provider

## Context
Implement Intel SGX attestation verification in Rust. Parse DCAP quotes, verify MRENCLAVE/MRSIGNER measurements, and support Gramine/Occlum sealed storage.

## Tasks
- [ ] Implement `SGXAttestationProvider` struct
- [ ] Parse DCAP quote format (header + report body)
- [ ] Verify MRENCLAVE and MRSIGNER measurements
- [ ] Add PCCS integration for quote verification
- [ ] Implement Gramine attestation interface (/dev/attestation)
- [ ] Create sealed storage for persistent secrets
- [ ] Add Gramine manifest generator helper
- [ ] Write tests with sample quotes

## Key Components
```rust
pub struct SGXAttestationProvider {
    expected_mrenclave: Option<String>,
    expected_mrsigner: Option<String>,
    min_isv_svn: u16,
    pccs_url: Option<String>,
}

pub struct SealedStorage {
    seal_to: SealPolicy, // MRENCLAVE or MRSIGNER
    storage_path: PathBuf,
}
```

## Dependencies
- `sgx-isa` for SGX structures
- `dcap-quoteverify` (optional) for DCAP verification

## Acceptance Criteria
- [ ] DCAP quote parsing works correctly
- [ ] MRENCLAVE/MRSIGNER verification accurate
- [ ] Sealed storage works in Gramine
- [ ] Works with both Gramine and Occlum