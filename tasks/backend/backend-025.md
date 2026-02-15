---
id: backend-025
title: Rust Azure MAA Attestation Provider
status: done
priority: high
tags:
- backend
- rust
- confidential-computing
- azure
dependencies:
- backend-022
assignee: developer
created: 2026-01-16T14:00:00Z
estimate: 1d
complexity: 6
area: backend
---

# Rust Azure MAA Attestation Provider

## Context
Implement Microsoft Azure Attestation (MAA) provider in Rust. Validate MAA-signed JWT tokens and integrate with Azure Key Vault Secure Key Release (SKR).

## Tasks
- [ ] Implement `MAAAttestationProvider` struct
- [ ] Parse Microsoft-signed MAA JWT tokens
- [ ] Extract SEV-SNP and SGX measurements
- [ ] Implement Azure IMDS client for evidence generation
- [ ] Add Key Vault SKR integration
- [ ] Create sidecar pattern helper for legacy apps
- [ ] Write tests with sample MAA tokens

## Key Components
```rust
pub struct MAAAttestationProvider {
    attestation_uri: String,
    expected_measurements: HashMap<String, String>,
    allowed_tee_types: Vec<String>,
}

pub struct AzureKeyVaultSKR {
    vault_url: String,
    provider: Arc<dyn AttestationProvider>,
}
```

## Dependencies
- `jsonwebtoken` for JWT parsing
- `reqwest` for MAA API calls
- `azure_identity` (optional) for Azure auth
- `azure_security_keyvault` (optional) for Key Vault

## Acceptance Criteria
- [ ] MAA token validation works correctly
- [ ] Supports both SEV-SNP and SGX TEE types
- [ ] SKR key release functional
- [ ] Works in Azure Confidential Container