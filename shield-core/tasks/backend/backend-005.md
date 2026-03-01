---
id: backend-005
title: Remove all remaining dead_code allows and rust,ignore doctests
status: done
priority: high
tags:
- cleanup
- quality
dependencies:
- backend-001
- backend-002
- backend-003
- backend-004
assignee: claude
created: 2026-03-01T09:07:39.509728144Z
estimate: 1h
complexity: 5
area: backend
---

# Remove all remaining dead_code allows and rust,ignore doctests

## Causation Chain
```
After backend-001 through backend-004, remaining issues:
  dead_code allows:
    group.rs:212      — BroadcastEncryption::master_key field
    shield.rs:60      — Shield::counter field
    confidential/sgx.rs:256   — QuoteHeader struct
    confidential/base.rs:301  — TEEKeyManager::cache_ttl field
    confidential/maa.rs:298   — AzureKeyVaultSKR::vault_url field

  rust,ignore doctests:
    channel_async.rs:7    — AsyncShieldChannel module doctest
    confidential/mod.rs:11 — confidential module doctest
```

## Pre-flight Checks
- [x] All 5 `#[allow(dead_code)]` locations identified
- [x] All 2 `rust,ignore` doctest locations identified
- [x] Dependent tasks (001-004) must complete first as they remove some allows

## Context
After completing the main cleanup tasks, some `#[allow(dead_code)]` annotations and
`rust,ignore` doctests remain. Each must be resolved by either using the field/making
it public, or writing a proper `no_run` doctest.

## Tasks
- [ ] `group.rs:212` — `master_key` in `BroadcastEncryption`: check if truly unused, use or remove
- [ ] `shield.rs:60` — `counter` in `Shield`: check if truly unused, use or remove
- [ ] `confidential/sgx.rs:256` — `QuoteHeader` struct: check if used in parsing, make pub or use
- [ ] `confidential/base.rs:301` — `cache_ttl` in `TEEKeyManager`: implement TTL caching or remove
- [ ] `confidential/maa.rs:298` — `vault_url` in `AzureKeyVaultSKR`: use in API calls or remove
- [ ] `channel_async.rs:7` — write proper `no_run` doctest (same pattern as channel.rs fix)
- [ ] `confidential/mod.rs:11` — write proper `no_run` doctest
- [ ] `cargo test --features confidential` passes
- [ ] `cargo clippy --tests --features confidential -- -D warnings` passes

## Acceptance Criteria
- Zero `#[allow(dead_code)]` in entire codebase
- Zero `rust,ignore` doctests in entire codebase
- All fields either used or removed
- All doctests either `no_run` or runnable

## Notes
- For fields that store configuration but aren't read: implement the feature or remove the field
- `cache_ttl` likely should be used in `TEEKeyManager::get_key()` for caching attestation results
- `vault_url` should be used in Azure Key Vault API calls
- Doctest patterns established in channel.rs fix (TcpListener/TcpStream, full main fn)

---
**Session Handoff** (fill when done):
- Changed: [files/functions modified]
- Causality: [what triggers what]
- Verify: [how to test this works]
- Next: [context for dependent tasks]