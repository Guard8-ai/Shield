---
id: backend-022
title: Rust Confidential Computing - Base Types and Traits
status: todo
priority: high
tags:
- backend
- rust
- confidential-computing
dependencies:
- backend-021
assignee: developer
created: 2026-01-16T14:00:00Z
estimate: 1d
complexity: 6
area: backend
---

# Rust Confidential Computing - Base Types and Traits

## Context
Implement the core attestation types and traits in Rust for confidential computing support. This provides the foundation for all TEE-specific providers.

## Tasks
- [ ] Create `confidential` module in shield-core
- [ ] Define `AttestationProvider` trait with async verification
- [ ] Implement `AttestationResult` struct with measurements and claims
- [ ] Create `TEEType` enum for all supported TEE types
- [ ] Implement `TEEKeyManager` for attestation-gated key release
- [ ] Add `KeyReleasePolicy` for configurable key release rules
- [ ] Add feature flag `confidential` for optional compilation
- [ ] Write unit tests for base types

## Key Types
```rust
pub trait AttestationProvider: Send + Sync {
    fn tee_type(&self) -> TEEType;
    async fn verify(&self, evidence: &[u8]) -> Result<AttestationResult>;
    async fn generate_evidence(&self, user_data: Option<&[u8]>) -> Result<Vec<u8>>;
}

pub struct AttestationResult {
    pub verified: bool,
    pub tee_type: TEEType,
    pub measurements: HashMap<String, String>,
    pub claims: HashMap<String, serde_json::Value>,
    pub timestamp: u64,
    pub error: Option<String>,
}
```

## Dependencies
- `serde` for serialization
- `async-trait` for async traits
- `thiserror` for error handling

## Acceptance Criteria
- [ ] All types compile with no warnings
- [ ] Trait is object-safe for dynamic dispatch
- [ ] Works with all async runtimes via feature flags
- [ ] Comprehensive test coverage
