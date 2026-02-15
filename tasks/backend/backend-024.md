---
id: backend-024
title: Rust GCP Confidential VMs (SEV-SNP) Attestation Provider
status: done
priority: high
tags:
- backend
- rust
- confidential-computing
- gcp
dependencies:
- backend-022
assignee: developer
created: 2026-01-16T14:00:00Z
estimate: 1d
complexity: 6
area: backend
---

# Rust GCP Confidential VMs (SEV-SNP) Attestation Provider

## Context
Implement GCP Confidential VM attestation verification in Rust. Validate Google-signed JWT tokens containing SEV-SNP measurements and vTPM PCR values.

## Tasks
- [ ] Implement `SEVAttestationProvider` struct
- [ ] Parse and validate Google-signed JWT tokens
- [ ] Extract SEV-SNP measurements from token claims
- [ ] Extract vTPM PCR values
- [ ] Implement metadata service client for evidence generation
- [ ] Add Confidential Space support
- [ ] Create Secret Manager integration
- [ ] Write tests with sample tokens

## Key Components
```rust
pub struct SEVAttestationProvider {
    project_id: Option<String>,
    expected_measurements: HashMap<String, String>,
    allowed_zones: Vec<String>,
}

pub struct GCPSecretManager {
    project_id: String,
    provider: Arc<dyn AttestationProvider>,
}
```

## Dependencies
- `jsonwebtoken` for JWT parsing
- `reqwest` for HTTP requests to metadata service
- `gcp-auth` (optional) for GCP authentication

## Acceptance Criteria
- [ ] JWT validation works correctly
- [ ] SEV-SNP measurements extracted accurately
- [ ] Metadata service communication functional
- [ ] Works on real GCP Confidential VM