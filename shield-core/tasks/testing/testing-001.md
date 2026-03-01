---
id: testing-001
title: Verify cargo test + clippy clean pass
status: done
priority: critical
tags:
- testing
- verification
dependencies:
- backend-005
assignee: claude
created: 2026-03-01T09:07:43.078358178Z
estimate: 30m
complexity: 3
area: testing
---

# Verify cargo test + clippy clean pass

## Causation Chain
```
After all backend tasks complete:
  cargo test                                           → all tests pass, 0 ignored
  cargo test --features confidential                   → confidential tests pass
  cargo test --features openapi                        → openapi tests pass
  cargo clippy --tests -- -D warnings                  → 0 warnings
  cargo clippy --tests --features confidential -- -D warnings → 0 warnings
  cargo clippy --tests --features openapi -- -D warnings      → 0 warnings
```

## Pre-flight Checks
- [ ] All backend tasks (001-005) marked done
- [ ] No uncommitted changes from previous tasks

## Context
Final verification gate. All code changes from backend-001 through backend-005 must
result in a clean build with zero warnings and zero test failures across all feature
combinations.

## Tasks
- [ ] Run `cargo test` — verify 0 failures, 0 ignored
- [ ] Run `cargo test --features confidential` — verify pass
- [ ] Run `cargo test --features openapi` — verify pass
- [ ] Run `cargo clippy --tests -- -D warnings` — verify 0 warnings
- [ ] Run `cargo clippy --tests --features confidential -- -D warnings` — verify 0 warnings
- [ ] Run `cargo clippy --tests --features openapi -- -D warnings` — verify 0 warnings
- [ ] Grep for remaining issues: `#[allow(dead_code)]`, `rust,ignore`, `deprecated`, `placeholder`, `stub`, `v3`

## Acceptance Criteria
- All test suites pass with 0 failures, 0 ignored
- All clippy runs produce 0 warnings
- No `#[allow(dead_code)]`, `#[deprecated]`, `rust,ignore`, placeholder/stub comments remain

## Notes
- If any test fails, trace back to the responsible backend task and fix there
- Feature combinations: default, confidential, openapi, confidential+openapi

---
**Session Handoff** (fill when done):
- Changed: [files/functions modified]
- Causality: [what triggers what]
- Verify: [how to test this works]
- Next: [context for dependent tasks]