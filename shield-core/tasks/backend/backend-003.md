---
id: backend-003
title: Implement GCP Secret Manager retrieval in GCPSecretManager
status: done
priority: high
tags:
- confidential-computing
- gcp
dependencies:
- backend-001
assignee: claude
created: 2026-03-01T09:07:32.633731705Z
estimate: 1h
complexity: 6
area: backend
---

# Implement GCP Secret Manager retrieval in GCPSecretManager

## Causation Chain
```
GCPSecretManager::get_secret(secret_id, attestation_evidence, version)
  → provider.verify(attestation_evidence)   ← works (real implementation)
  → if verified: fetch secret               ← PLACEHOLDER: returns MissingDependency
  → should: call GCP Secret Manager REST API via reqwest
```

## Pre-flight Checks
- [x] `src/confidential/sev.rs:398-420` — `get_secret()` returns placeholder error after verification
- [x] `reqwest` is already in Cargo.toml (async feature, which confidential depends on)
- [x] `self.project_id` field exists but is marked `#[allow(dead_code)]`

## Context
`GCPSecretManager::get_secret()` verifies attestation correctly but then returns a placeholder
error instead of actually fetching the secret. The GCP Secret Manager REST API is straightforward:
`GET https://secretmanager.googleapis.com/v1/projects/{project}/secrets/{secret}/versions/{version}:access`
with a bearer token from the metadata service.

## Tasks
- [ ] Implement secret retrieval using GCP REST API via reqwest
  - Get access token from metadata service: `GET http://metadata.google.internal/.../token`
  - Call Secret Manager API: `GET .../projects/{project_id}/secrets/{secret_id}/versions/{version}:access`
  - Parse JSON response, base64-decode the `payload.data` field
  - Return decoded secret bytes
- [ ] Remove `#[allow(dead_code)]` from `project_id` field (it's now used)
- [ ] Remove "placeholder" and "For now" comments
- [ ] Use proper error types for HTTP failures and parsing errors
- [ ] `cargo test --features confidential` passes
- [ ] `cargo clippy --tests --features confidential -- -D warnings` passes

## Acceptance Criteria
- No placeholder errors in `get_secret()`
- No `#[allow(dead_code)]` on `project_id` field
- Secret retrieval uses GCP metadata token + Secret Manager REST API
- Proper error mapping (network, auth, parsing)

## Notes
- GCP metadata token endpoint: `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token`
- Header: `Metadata-Flavor: Google`
- Secret Manager API base: `https://secretmanager.googleapis.com/v1`
- Response format: `{"payload": {"data": "<base64>"}}`
- reqwest is already available via the `async` feature dependency chain

---
**Session Handoff** (fill when done):
- Changed: [files/functions modified]
- Causality: [what triggers what]
- Verify: [how to test this works]
- Next: [context for dependent tasks]