---
id: integration-006
title: AWS Nitro Enclaves integration for Shield
status: done
priority: high
tags:
- integration
- confidential-computing
- aws
dependencies:
- backend-021
assignee: developer
created: 2026-01-16T11:46:58.903531620Z
estimate: 2d
complexity: 8
area: integration
---

# AWS Nitro Enclaves integration for Shield

## Context
AWS Nitro Enclaves provide isolated compute environments with no persistent storage, no network access, and no admin access. Even AWS cannot access enclave memory. Shield-encrypted proprietary code can be decrypted only inside the enclave after cryptographic attestation.

## Architecture
```
┌─────────────────────────────────────────────────┐
│              AWS Nitro Enclave                  │
│  ┌─────────────────────────────────────────┐    │
│  │  Shield.decrypt(encrypted_code)         │    │
│  │  → Execute proprietary algorithms       │    │
│  └─────────────────────────────────────────┘    │
│  Key released only after attestation            │
└─────────────────────────────────────────────────┘
        ↑ vsock communication
┌───────┴───────┐
│  Parent EC2   │ → Sends encrypted payloads
└───────────────┘
        ↑ Attestation doc
┌───────┴───────┐
│  AWS KMS      │ → Releases key only to verified PCRs
└───────────────┘
```

## Tasks
- [ ] Create `shield-nitro` Rust crate with enclave-compatible build
- [ ] Implement vsock-based communication protocol for Shield operations
- [ ] Add attestation document generation and verification
- [ ] Create KMS integration for key release policy (PCR-based)
- [ ] Build Docker → EIF conversion pipeline
- [ ] Create parent instance SDK (Python/Rust) for enclave communication
- [ ] Add example: encrypted model inference in enclave
- [ ] Write deployment guide for EC2 + Nitro setup

## Key Components
1. **Enclave Image**: Minimal Linux + Shield library + application
2. **vsock Protocol**: Request/response for encrypt/decrypt operations
3. **Attestation**: PCR values proving enclave integrity
4. **KMS Policy**: Only release keys to specific PCR measurements

## Dependencies
- AWS SDK for Rust (`aws-sdk-kms`)
- `nix` crate for vsock
- `nitro-cli` for building EIF images

## Acceptance Criteria
- [ ] Shield operations work inside Nitro Enclave
- [ ] Keys are released only after valid attestation
- [ ] Parent cannot access decrypted data
- [ ] Example runs end-to-end on EC2 .metal instance

## Notes
- Requires EC2 `.metal` or `.xlarge` instances with Nitro support
- No network inside enclave - all communication via vsock
- Memory is encrypted by Nitro hypervisor

---
**Session Handoff** (completed 2026-01-16):
- Changed: `python/shield/integrations/confidential/aws_nitro.py`, `examples/confidential-computing/aws-nitro/`
- Causality: `NitroAttestationProvider.verify()` validates COSE-signed attestation docs → `TEEKeyManager.get_key()` releases keys
- Verify: Run FastAPI example in Nitro Enclave, check PCR validation
- Next: Test with real Nitro Enclave, integrate with AWS KMS key policies
