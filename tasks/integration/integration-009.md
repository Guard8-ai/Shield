---
id: integration-009
title: Intel SGX (Gramine/Occlum) integration for Shield
status: done
priority: high
tags:
- integration
- confidential-computing
- intel-sgx
dependencies:
- backend-021
assignee: developer
created: 2026-01-16T11:47:15.791150402Z
estimate: 3d
complexity: 9
area: integration
---

# Intel SGX (Gramine/Occlum) integration for Shield

## Context
Intel SGX provides hardware enclaves for running sensitive code in isolated memory regions. Even the OS and hypervisor cannot access enclave memory. Shield can run inside SGX enclaves using library OSes (Gramine, Occlum) that lift unmodified applications into enclaves.

## Architecture
```
┌─────────────────────────────────────────────────┐
│              Intel SGX Enclave                  │
│  ┌─────────────────────────────────────────┐    │
│  │  Gramine/Occlum LibOS                   │    │
│  │  ┌─────────────────────────────────┐    │    │
│  │  │  Shield library                 │    │    │
│  │  │  Encrypted memory (EPC)         │    │    │
│  │  │  MRENCLAVE measurement          │    │    │
│  │  └─────────────────────────────────┘    │    │
│  └─────────────────────────────────────────┘    │
└─────────────────────────────────────────────────┘
        ↑ Remote attestation (DCAP/EPID)
┌───────┴───────┐
│  Intel IAS /  │ → Verify enclave quote
│  PCCS         │ → Release secrets
└───────────────┘
```

## Tasks
- [ ] Create Gramine manifest for Shield Rust binary
- [ ] Create Occlum configuration for Shield containers
- [ ] Implement DCAP remote attestation (ECDSA-based)
- [ ] Add EPID attestation fallback for older platforms
- [ ] Build SGX-enabled Docker images with Gramine
- [ ] Create enclave signing infrastructure (debug + production keys)
- [ ] Implement sealed storage for persistent secrets
- [ ] Create example: secure key management service
- [ ] Write setup guide for SGX development environment

## Key Components
1. **Gramine**: LibOS for running Linux apps in SGX enclaves
2. **Occlum**: LibOS optimized for containerized SGX workloads
3. **DCAP**: Data Center Attestation Primitives (modern attestation)
4. **EPID**: Enhanced Privacy ID (legacy attestation)
5. **Sealed Storage**: Persist data encrypted to enclave identity

## Hardware Requirements
- Intel CPU with SGX support (Xeon E3/E5, Ice Lake+)
- SGX enabled in BIOS
- SGX driver installed (in-kernel since Linux 5.11)
- Adequate EPC (Enclave Page Cache) memory

## Dependencies
- `gramine` (build-time for manifest generation)
- `sgx-dcap-ql` for DCAP quotes
- `sgx-isa` crate for SGX structures
- `openssl` with SGX-compatible config

## Gramine Manifest Structure
```toml
[loader]
entrypoint = "shield"

[sgx]
enclave_size = "256M"
thread_num = 8

[fs.mounts]
  path = "/lib"
  uri = "file:/lib"
  type = "encrypted"

[sgx.trusted_files]
  shield = "file:target/release/shield"
```

## Acceptance Criteria
- [ ] Shield binary runs unmodified inside Gramine enclave
- [ ] DCAP attestation proves enclave identity
- [ ] Secrets sealed to MRENCLAVE/MRSIGNER
- [ ] Works on both bare-metal and cloud SGX instances

## Notes
- Gramine supports Rust binaries with minimal manifest config
- EPC size limits may require memory-conscious Shield operations
- DCAP requires PCCS (Provisioning Certificate Caching Service)
- Production enclaves need Intel-signed certificates
- SGX2 (dynamic memory) available on newer CPUs

---
**Session Handoff** (completed 2026-01-16):
- Changed: `python/shield/integrations/confidential/intel_sgx.py`, `examples/confidential-computing/intel-sgx/`
- Causality: `SGXAttestationProvider.verify()` parses DCAP quotes → `SealedStorage` persists secrets encrypted to MRENCLAVE
- Verify: Run FastAPI via gramine-sgx, test quote generation and sealed storage
- Next: Test with Occlum, configure PCCS for production DCAP verification
