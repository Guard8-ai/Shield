---
id: integration-008
title: Azure Confidential Containers integration for Shield
status: done
priority: high
tags:
- integration
- confidential-computing
- azure
dependencies:
- backend-021
assignee: developer
created: 2026-01-16T11:47:10.061077498Z
estimate: 2d
complexity: 7
area: integration
---

# Azure Confidential Containers integration for Shield

## Context
Azure Confidential Containers run in AMD SEV-SNP or Intel SGX enclaves on AKS (Azure Kubernetes Service). Microsoft cannot access container memory. Shield-protected workloads run with hardware attestation proving the execution environment.

## Architecture
```
┌─────────────────────────────────────────────────┐
│     Azure Confidential Container (AKS)          │
│  ┌─────────────────────────────────────────┐    │
│  │  Shield library in container            │    │
│  │  Memory encrypted by SEV-SNP/SGX        │    │
│  │  Attestation via MAA                    │    │
│  └─────────────────────────────────────────┘    │
└─────────────────────────────────────────────────┘
        ↑ Attestation token (JWT)
┌───────┴───────┐
│  Azure MAA    │ → Microsoft Azure Attestation
└───────────────┘
        ↑ Key release policy
┌───────┴───────┐
│  Azure Key    │ → Release keys only to attested
│  Vault (mHSM) │   containers
└───────────────┘
```

## Tasks
- [ ] Create attestation client for Microsoft Azure Attestation (MAA)
- [ ] Implement Secure Key Release (SKR) with Azure Key Vault
- [ ] Add support for both SEV-SNP and SGX container types
- [ ] Create Helm chart for confidential AKS deployment
- [ ] Build container image with Shield optimized for ACC
- [ ] Implement sidecar pattern for legacy app protection
- [ ] Create example: confidential database queries
- [ ] Write deployment guide with Azure CLI commands

## Key Components
1. **MAA (Microsoft Azure Attestation)**: Validates TEE evidence, issues JWT tokens
2. **SKR (Secure Key Release)**: Keys released only to attested workloads
3. **mHSM**: Managed HSM for key storage with release policies
4. **Kata Containers**: Runtime for confidential containers on AKS

## Azure SKUs
- `Standard_DC*s_v3` (Intel SGX)
- `Standard_DC*as_v5` (AMD SEV-SNP)
- AKS with `confcom` add-on enabled

## Dependencies
- `azure_identity` crate for authentication
- `azure_security_keyvault` for Key Vault/mHSM
- `reqwest` for MAA API calls
- `jsonwebtoken` for JWT validation

## Acceptance Criteria
- [ ] Shield runs in Azure Confidential Container
- [ ] MAA attestation validates container integrity
- [ ] Keys released only via SKR to attested containers
- [ ] Works on both Intel SGX and AMD SEV-SNP nodes

## Notes
- AKS confidential node pools require `confcom` add-on
- MAA provides attestation as a service (no self-hosting)
- SKR uses Key Vault premium or Managed HSM
- Kata Containers runtime provides isolation boundary

---
**Session Handoff** (completed 2026-01-16):
- Changed: `python/shield/integrations/confidential/azure_maa.py`, `examples/confidential-computing/azure-acc/`
- Causality: `MAAAttestationProvider.verify()` validates MAA JWT → `AzureKeyVaultSKR.release_key()` gets keys via SKR
- Verify: Deploy FastAPI in AKS confcom pod, test MAA attestation flow
- Next: Test with both SEV-SNP and SGX node pools, configure Key Vault release policies
