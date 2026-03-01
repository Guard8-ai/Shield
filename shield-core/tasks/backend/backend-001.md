---
id: backend-001
title: Remove deprecated .key() and add master_key() accessor
status: done
priority: critical
tags:
- security
- api-cleanup
dependencies:
- setup-001
assignee: claude
created: 2026-03-01T09:07:26.178058423Z
estimate: 1h
complexity: 5
area: backend
---

# Remove deprecated .key() and add master_key() accessor

## Causation Chain
```
Shield::new() → derives master key → stores in self.key
  → TEEKeyManager::derive_key() calls self.shield.key() to mix master key into attestation-bound key
  → tests/interop.rs calls shield.key() for cross-language key verification
```
Removing `#[deprecated]` and renaming to `master_key()` requires updating all call sites.

## Pre-flight Checks
- [x] `src/shield.rs:444` — `#[deprecated]` attr + "Will be removed in v3" comment
- [x] `src/confidential/base.rs:368-369` — `#[allow(deprecated)]` + `self.shield.key()`
- [x] `tests/interop.rs:26` — `#[allow(deprecated)]` + `shield.key()`

## Context
The `Shield::key()` method was marked deprecated with a "Will be removed in v3" comment.
There is no v3 — this is the next v2 minor release. No deprecated APIs, no placeholders.
The method has legitimate internal uses (TEE key derivation, interop verification).

## Tasks
- [ ] Rename `key()` to `master_key()` in `src/shield.rs`
- [ ] Remove `#[deprecated]` attribute
- [ ] Remove "Will be removed in v3" doc comment
- [ ] Keep `#[must_use]` and `pub` (needed by integration tests)
- [ ] Update `src/confidential/base.rs:369` — `self.shield.key()` → `self.shield.master_key()`
- [ ] Remove `#[allow(deprecated)]` from `src/confidential/base.rs:368`
- [ ] Update `tests/interop.rs:26` — `shield.key()` → `shield.master_key()`
- [ ] Remove `#[allow(deprecated)]` from `tests/interop.rs:23`
- [ ] `cargo test` passes
- [ ] `cargo clippy --tests -- -D warnings` passes

## Acceptance Criteria
- No `#[deprecated]` attributes in codebase
- No "v3" references in comments
- `master_key()` works in all call sites
- All 100 tests pass, 0 ignored

## Notes
- `tests/interop.rs` is an integration test (outside crate) so accessor must be `pub`
- The `master_key()` method is intentionally public for interop verification + confidential computing
- No `#[doc(hidden)]` needed — it's a valid API for advanced use

---
**Session Handoff** (fill when done):
- Changed: [files/functions modified]
- Causality: [what triggers what]
- Verify: [how to test this works]
- Next: [context for dependent tasks]