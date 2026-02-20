---
id: setup-001
title: FIDO and pgvector integration foundation
status: done
priority: high
tags:
- setup
dependencies: []
assignee: developer
created: 2026-02-15T12:41:07.343073319Z
estimate: 2h
complexity: 5
area: setup
---

# FIDO and pgvector integration foundation

## Causation Chain
> Trace the initialization chain: env detection → dependency check →
config load → service bootstrap → ready state. Verify actual failure
modes and error messages in bootstrap code.

## Pre-flight Checks
- [ ] Read dependency task files for implementation context (Session Handoff)
- [ ] `grep -r "init\|bootstrap\|main" src/` - Find initialization
- [ ] Check actual failure modes and error messages
- [ ] Verify dependency checks are comprehensive
- [ ] `git log --oneline -10` - Check recent related commits

## Context
Shield needs two critical integrations to expand its capabilities:

1. **FIDO2/WebAuthn Authentication**: Passwordless authentication using hardware security keys, biometrics, and platform authenticators. This provides phishing-resistant authentication superior to passwords.

2. **pgvector PostgreSQL Extension**: Vector similarity search for encrypted AI embeddings, enabling semantic search over encrypted data without exposing plaintext to the database.

Both integrations maintain Shield's EXPTIME security guarantees while adding modern authentication and AI capabilities.

## Tasks
- [ ] Research FIDO2/WebAuthn standards (W3C WebAuthn Level 2, CTAP2)
- [ ] Research pgvector PostgreSQL extension API
- [ ] Define integration points with Shield's existing architecture
- [ ] Create Cargo.toml feature flags: `fido2`, `pgvector`
- [ ] Identify required dependencies (webauthn-rs, postgres, pgvector client)
- [ ] Design authentication flow: registration → challenge → verification
- [ ] Design vector storage: Shield encryption → pgvector indexing
- [ ] Plan database schema for FIDO2 credentials and vector embeddings
- [ ] Document security model and threat analysis
- [ ] Build + test + run to verify dependencies compile

## Acceptance Criteria
- [ ] setup-001.md contains comprehensive integration design
- [ ] Cargo.toml includes `fido2` and `pgvector` feature flags
- [ ] Dependencies identified and documented
- [ ] Architecture diagrams/flow documented in Notes section
- [ ] Security model documented (how Shield encryption protects keys/vectors)
- [ ] Backend task files created with proper dependencies
- [ ] All tests pass with new features disabled (no regressions)

## Notes

### FIDO2/WebAuthn Architecture
**Flow**: Client → Relying Party (Shield) → Authenticator (hardware key/biometric)

**Registration**:
1. User requests registration
2. Shield generates challenge (random bytes)
3. Client calls `navigator.credentials.create()` with challenge
4. Authenticator creates key pair, returns public key + attestation
5. Shield verifies attestation, stores public key + credential ID

**Authentication**:
1. User requests login
2. Shield generates challenge, retrieves allowed credentials
3. Client calls `navigator.credentials.get()` with challenge
4. Authenticator signs challenge with private key
5. Shield verifies signature with stored public key

**Shield Integration**:
- Encrypt credential storage with Shield
- Use Shield's symmetric signatures for additional validation
- Support RatchetSession for multi-device sync of credentials

### pgvector Architecture
**PostgreSQL Extension**: Enables vector similarity search using HNSW/IVFFlat indexes

**Vector Operations**:
- `<->` L2 distance (Euclidean)
- `<#>` negative inner product
- `<=>` cosine distance

**Shield Integration**:
1. **Encrypted Storage**: AI embeddings encrypted with Shield before storage
2. **Searchable Encryption**: Use deterministic encryption for vector components
3. **Index Support**: pgvector indexes work on encrypted numeric values
4. **Query Flow**:
   - Client: plaintext query → embedding model → vector
   - Shield: encrypt vector components
   - PostgreSQL: pgvector similarity search on encrypted vectors
   - Shield: decrypt results
   - Client: receive decrypted matches

**Schema Example**:
```sql
CREATE TABLE encrypted_embeddings (
  id SERIAL PRIMARY KEY,
  shield_nonce BYTEA NOT NULL,
  encrypted_vector vector(1536),  -- pgvector type
  shield_mac BYTEA NOT NULL,
  metadata JSONB
);
CREATE INDEX ON encrypted_embeddings USING hnsw (encrypted_vector vector_cosine_ops);
```

### Dependencies
**FIDO2**:
- `webauthn-rs = "0.4"` - WebAuthn relying party implementation
- `webauthn-rs-proto = "0.4"` - Protocol types

**pgvector**:
- `tokio-postgres = "0.7"` - Async PostgreSQL client (already have tokio)
- `postgres-types = "0.2"` - Custom type support for pgvector
- `pgvector` crate - Rust bindings for pgvector types

### Security Considerations
**FIDO2**:
- Attestation verification prevents malicious authenticators
- Challenge must be cryptographically random (use Shield's RNG)
- Origin validation prevents phishing
- User presence/verification flags must be checked

**pgvector**:
- Vector components are deterministically encrypted (same vector → same ciphertext for indexing)
- MAC prevents tampering with encrypted vectors
- Nonce prevents rainbow table attacks on vector space
- Query vectors encrypted same way for similarity search

---
**Session Handoff**:
- Changed:
  - `shield-core/Cargo.toml` - Added `fido2` and `pgvector` feature flags
  - Added dependencies: webauthn-rs 0.4, webauthn-rs-proto 0.4, tokio-postgres 0.7, postgres-types 0.2, chrono 0.4
- Causality:
  - Feature flags enable conditional compilation of FIDO2 and pgvector modules
  - `fido2` feature includes webauthn-rs for relying party implementation
  - `pgvector` feature includes async PostgreSQL client with vector support
  - Both integrate with Shield's existing encryption primitives
- Verify:
  - `cargo build` - Compiles successfully with new dependencies ✅
  - `cargo build --features fido2` - Will enable FIDO2 module (pending backend-027)
  - `cargo build --features pgvector` - Will enable pgvector module (pending backend-028)
- Next:
  - **backend-027**: Implement Fido2Manager with Shield-encrypted credential storage
  - **backend-028**: Implement PgVectorClient with deterministic encryption for searchable vectors
  - Both tasks can proceed in parallel once this foundation is complete