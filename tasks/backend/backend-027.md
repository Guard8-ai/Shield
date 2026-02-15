---
id: backend-027
title: FIDO2/WebAuthn core implementation
status: todo
priority: high
tags:
- backend
- auth
- fido2
- webauthn
dependencies:
- setup-001
assignee: developer
created: 2026-02-15T12:43:35.828033023Z
estimate: 4h
complexity: 8
area: backend
---

# FIDO2/WebAuthn core implementation

## Causation Chain
> Trace the service orchestration: entry point → dependency injection →
business logic → side effects → return. Verify actual error propagation
paths in the codebase.

## Pre-flight Checks
- [ ] Read dependency task files for implementation context (Session Handoff)
- [ ] `grep -r "impl.*Service\|fn.*service" src/` - Find service definitions
- [ ] Check actual dependency injection patterns
- [ ] Verify error propagation through service layers
- [ ] `git log --oneline -10` - Check recent related commits

## Context
Implement FIDO2/WebAuthn passwordless authentication as a Rust module in shield-core. This provides phishing-resistant authentication using hardware security keys, platform authenticators (Face ID, Touch ID, Windows Hello), and biometrics. Shield will act as a WebAuthn Relying Party, managing credential storage encrypted with Shield's EXPTIME-secure encryption.

**Dependency on setup-001**: Requires feature flags and dependencies defined in setup-001.

## Tasks
- [ ] Add `fido2` feature to Cargo.toml with webauthn-rs dependencies
- [ ] Create `shield-core/src/fido2/mod.rs` module structure
- [ ] Implement `WebAuthnConfig` struct (relying party ID, origin, timeout)
- [ ] Implement `CredentialStore` trait (backed by Shield encryption)
- [ ] Implement registration flow:
  - [ ] `generate_registration_challenge()` - random 32-byte challenge
  - [ ] `verify_registration()` - validate attestation, extract public key
  - [ ] `store_credential()` - Shield-encrypt credential + metadata
- [ ] Implement authentication flow:
  - [ ] `generate_authentication_challenge()` - random challenge + allowed credentials
  - [ ] `verify_authentication()` - validate signature with stored public key
- [ ] Implement `Fido2Manager` struct with Shield integration
- [ ] Add unit tests for registration and authentication flows
- [ ] Add integration tests with mock authenticators
- [ ] Build + test with `cargo test --features fido2`

## Acceptance Criteria
- [ ] `cargo build --features fido2` compiles without errors
- [ ] `cargo test --features fido2` passes all tests (minimum 10 tests)
- [ ] Registration flow creates and stores credentials
- [ ] Authentication flow verifies signatures correctly
- [ ] Credentials stored encrypted with Shield (verify MAC + nonce)
- [ ] Challenge generation uses cryptographically secure randomness
- [ ] Origin validation prevents cross-origin attacks
- [ ] User verification flag properly checked
- [ ] Attestation verification rejects invalid attestations
- [ ] Code follows Shield's quality standards (no clippy warnings)

## Notes

### File Structure
```
shield-core/src/fido2/
├── mod.rs              # Public API and re-exports
├── config.rs           # WebAuthnConfig, CredentialStore trait
├── registration.rs     # Registration challenge/verification
├── authentication.rs   # Authentication challenge/verification
├── credential.rs       # Credential types, Shield encryption integration
└── error.rs            # Fido2Error types
```

### Core Types
```rust
// config.rs
pub struct WebAuthnConfig {
    pub rp_id: String,          // example.com
    pub rp_name: String,        // "Shield Demo"
    pub origin: String,         // https://example.com
    pub timeout_ms: u32,        // 60000 (60 seconds)
}

pub trait CredentialStore: Send + Sync {
    fn store(&mut self, user_id: &[u8], credential: &StoredCredential) -> Result<(), Fido2Error>;
    fn get(&self, user_id: &[u8]) -> Result<Vec<StoredCredential>, Fido2Error>;
    fn delete(&mut self, user_id: &[u8], credential_id: &[u8]) -> Result<(), Fido2Error>;
}

// credential.rs
pub struct StoredCredential {
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,     // COSE encoded public key
    pub counter: u32,            // Signature counter for replay detection
    pub user_id: Vec<u8>,
    pub rp_id: String,
    pub created_at: u64,         // Unix timestamp
}

// Shield-encrypted storage wrapper
pub struct ShieldCredentialStore {
    shield: Shield,
    storage: HashMap<Vec<u8>, Vec<u8>>,  // user_id -> encrypted credentials
}
```

### Registration Flow
```rust
// 1. Client requests registration
let challenge = manager.generate_registration_challenge(&user_id, &user_name)?;
// Returns: challenge (32 random bytes), user_id, rp info

// 2. Client calls navigator.credentials.create() with challenge

// 3. Server verifies response
let credential = manager.verify_registration(
    &challenge,
    &client_data_json,
    &attestation_object,
    &expected_origin,
)?;
// Validates: challenge matches, origin matches, attestation signature valid

// 4. Store credential (encrypted with Shield)
manager.store_credential(&user_id, credential)?;
```

### Authentication Flow
```rust
// 1. Client requests authentication
let challenge_data = manager.generate_authentication_challenge(&user_id)?;
// Returns: challenge (32 random bytes), allowed_credentials list

// 2. Client calls navigator.credentials.get() with challenge

// 3. Server verifies response
let auth_result = manager.verify_authentication(
    &challenge,
    &user_id,
    &client_data_json,
    &authenticator_data,
    &signature,
)?;
// Validates: signature matches stored public key, counter incremented, user verified

// 4. Update credential counter
manager.update_counter(&user_id, &credential_id, new_counter)?;
```

### Dependencies (add to Cargo.toml)
```toml
[features]
fido2 = ["dep:webauthn-rs", "dep:webauthn-rs-proto", "std"]

[dependencies]
webauthn-rs = { version = "0.4", optional = true }
webauthn-rs-proto = { version = "0.4", optional = true }
```

### Security Requirements
1. **Challenge Generation**: Use `getrandom` with 32 random bytes minimum
2. **Origin Validation**: Strict comparison, no wildcard matching
3. **Attestation Verification**: Check certificate chain, validate signature
4. **Counter Validation**: Reject if counter decreases (replay attack)
5. **User Verification**: Check UV flag in authenticator data
6. **Timeout**: Enforce challenge expiration (default 60s)
7. **Shield Integration**: All credentials encrypted with Shield.encrypt()

### Integration with Existing Shield
- Use `Shield::new()` with dedicated password for credential encryption
- Store encrypted credentials in `ShieldCredentialStore`
- Use `RatchetSession` for multi-device credential sync (optional)
- Use `SymmetricSignature` for additional validation layer

### Testing Strategy
1. Unit tests: Challenge generation, credential encoding/decoding
2. Mock authenticator tests: Valid/invalid attestations, signatures
3. Integration tests: Full registration + authentication flow
4. Security tests: Replay attacks, counter validation, origin mismatch
5. Interoperability tests: Test vectors from FIDO Alliance

---
**Session Handoff** (fill when done):
- Changed: [files/functions modified]
- Causality: [what triggers what]
- Verify: [how to test this works]
- Next: [context for dependent tasks]
