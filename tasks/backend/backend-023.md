---
id: backend-023
title: Rust AWS Nitro Enclaves Attestation Provider
status: todo
priority: high
tags:
- backend
- rust
- confidential-computing
- aws
dependencies:
- backend-022
assignee: developer
created: 2026-01-16T14:00:00Z
estimate: 1d
complexity: 7
area: backend
---

# Rust AWS Nitro Enclaves Attestation Provider

## Context
Implement AWS Nitro Enclaves attestation verification in Rust. Parse COSE-signed attestation documents, verify PCR measurements, and communicate via vsock.

## Tasks
- [ ] Implement `NitroAttestationProvider` struct
- [ ] Parse CBOR-encoded COSE Sign1 attestation documents
- [ ] Verify PCR measurements against expected values
- [ ] Implement vsock client for enclave communication
- [ ] Implement vsock server for parent instance
- [ ] Add NSM (Nitro Secure Module) communication
- [ ] Create attestation document generation
- [ ] Write integration tests with mock attestation

## Key Components
```rust
pub struct NitroAttestationProvider {
    expected_pcrs: HashMap<u8, String>,
    max_age_seconds: u64,
    verify_certificate: bool,
}

pub struct NitroVsockClient {
    cid: u32,
    port: u32,
}
```

## Dependencies
- `ciborium` for CBOR parsing
- `vsock` crate for vsock communication
- `aws-nitro-enclaves-nsm-api` (optional) for NSM

## Acceptance Criteria
- [ ] Parses real Nitro attestation documents
- [ ] PCR validation works correctly
- [ ] Vsock communication functional
- [ ] Works in both enclave and parent instance
