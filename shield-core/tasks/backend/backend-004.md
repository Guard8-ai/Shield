---
id: backend-004
title: Remove OpenAPI stub functions and dead_code allows
status: done
priority: high
tags:
- openapi
- cleanup
dependencies:
- backend-001
assignee: claude
created: 2026-03-01T09:07:36.074875889Z
estimate: 1h
complexity: 4
area: backend
---

# Remove OpenAPI stub functions and dead_code allows

## Causation Chain
```
openapi.rs:
  openapi_stubs module contains 5 empty async fns used only for utoipa path annotations
  → verify_attestation(), get_attestation(), encrypt_data(), decrypt_data(), health_check()
  → These are referenced by #[openapi(paths(...))] on ShieldConfidentialApi
  → utoipa requires functions with #[utoipa::path] annotations to exist
  → The functions themselves can have real signatures with proper parameter types
```

## Pre-flight Checks
- [x] `src/confidential/openapi.rs:202-289` — stub module with `#[allow(dead_code)]`
- [x] `src/confidential/openapi.rs:147` — `#[allow(dead_code)]` on `OpenAPISchemas::components()`
- [x] `src/confidential/openapi.rs:199` — `#[allow(dead_code)]` on `ShieldConfidentialApi`

## Context
The `openapi_stubs` module contains empty async functions annotated with `#[utoipa::path]`.
These exist solely for OpenAPI documentation generation. utoipa requires actual functions
to generate path documentation, but they don't need to be empty stubs — they should have
proper typed parameters matching the request/response schemas and return proper types.
The `#[allow(dead_code)]` attributes mask the fact that nothing calls these functions.

## Tasks
- [ ] Give stub functions proper typed parameters and return types
  - `verify_attestation(body: Json<AttestationRequest>) -> Json<AttestationResponse>`
  - `get_attestation(query: Query<UserDataQuery>) -> Json<AttestationResponse>`
  - `encrypt_data(body: Json<EncryptRequest>) -> Json<EncryptResponse>`
  - `decrypt_data(body: Json<DecryptRequest>) -> Json<DecryptResponse>`
  - `health_check() -> Json<HealthResponse>`
- [ ] Remove `#[allow(dead_code)]` from `openapi_stubs` module
- [ ] Remove `#[allow(dead_code)]` from `ShieldConfidentialApi`
- [ ] Remove `#[allow(dead_code)]` from `OpenAPISchemas::components()`
- [ ] Remove `#[allow(unused_imports)]` in stubs module
- [ ] Rename module from `openapi_stubs` to `openapi_handlers`
- [ ] Since utoipa generates docs from annotations, the function bodies return
      default/example responses (not empty) — this makes them usable as actual handlers
- [ ] `cargo test --features openapi` passes
- [ ] `cargo clippy --tests --features openapi -- -D warnings` passes

## Acceptance Criteria
- No `#[allow(dead_code)]` in openapi.rs
- No `#[allow(unused_imports)]`
- No empty function bodies
- Functions have proper typed signatures
- Module renamed from "stubs" to "handlers"
- utoipa OpenAPI generation still works

## Notes
- utoipa path macros work with any function signature — they read the annotations, not the fn body
- The functions need `#[cfg(feature = "openapi")]` to stay feature-gated
- serde_json is already available for constructing responses
- These handlers can serve as reference implementations for users building attestation APIs

---
**Session Handoff** (fill when done):
- Changed: [files/functions modified]
- Causality: [what triggers what]
- Verify: [how to test this works]
- Next: [context for dependent tasks]