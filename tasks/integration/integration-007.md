---
id: integration-007
title: GCP Confidential VMs (AMD SEV) integration for Shield
status: done
priority: high
tags:
- integration
- confidential-computing
- gcp
dependencies:
- backend-021
assignee: developer
created: 2026-01-16T11:47:04.472859990Z
estimate: 2d
complexity: 7
area: integration
---

# GCP Confidential VMs (AMD SEV) integration for Shield

## Context
GCP Confidential VMs use AMD SEV-SNP to encrypt VM memory at the hardware level. Google cannot read the VM's memory. Shield can run unmodified inside these VMs, with attestation proving the VM is genuinely confidential.

## Architecture
```
┌─────────────────────────────────────────────────┐
│        GCP Confidential VM (AMD SEV-SNP)        │
│  ┌─────────────────────────────────────────┐    │
│  │  Standard Docker container              │    │
│  │  with Shield library                    │    │
│  │  Memory encrypted by AMD SEV            │    │
│  └─────────────────────────────────────────┘    │
└─────────────────────────────────────────────────┘
        ↑ Attestation report
┌───────┴───────┐
│  GCP KMS /    │ → Verify VM is Confidential
│  Secret Mgr   │ → Release Shield keys
└───────────────┘
```

## Tasks
- [ ] Create attestation verification library for AMD SEV-SNP reports
- [ ] Integrate with GCP Confidential Space for serverless workloads
- [ ] Add GCP Secret Manager integration for key release
- [ ] Create Terraform module for Confidential VM deployment
- [ ] Build container image optimized for Confidential VMs
- [ ] Add runtime attestation check in Shield initialization
- [ ] Create example: secure data processing pipeline
- [ ] Write deployment guide with gcloud commands

## Key Components
1. **SEV-SNP Attestation**: Hardware-signed report proving confidentiality
2. **vTPM**: Virtual TPM for measured boot
3. **Secret Manager**: Release secrets only to attested VMs
4. **Confidential Space**: Serverless confidential containers

## GCP Machine Types
- `n2d-standard-*` with `--confidential-compute-type=SEV_SNP`
- Confidential Space for containerized workloads

## Dependencies
- `gcp-auth` crate for GCP authentication
- `tss-esapi` for TPM operations
- `sevctl` for SEV attestation

## Acceptance Criteria
- [ ] Shield runs in Confidential VM with encrypted memory
- [ ] Attestation report verifies SEV-SNP is active
- [ ] Keys released only to verified Confidential VMs
- [ ] Works with both VMs and Confidential Space

## Notes
- No code changes needed for basic operation - SEV encrypts transparently
- Attestation adds cryptographic proof of confidentiality
- Confidential Space simplifies deployment for containers

---
**Session Handoff** (completed 2026-01-16):
- Changed: `python/shield/integrations/confidential/gcp_sev.py`, `examples/confidential-computing/gcp-sev/`
- Causality: `SEVAttestationProvider.verify()` validates GCP JWT tokens → `GCPSecretManager.get_secret()` retrieves secrets
- Verify: Deploy FastAPI on n2d-* Confidential VM, check attestation JWT validation
- Next: Test with Confidential Space, integrate with GCP Secret Manager access policies
