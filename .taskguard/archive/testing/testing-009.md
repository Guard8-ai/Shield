---
id: testing-009
title: Add Browser SDK unit tests
status: done
priority: high
tags:
- browser
- tests
- wasm
dependencies:
- testing-008
assignee: shield-team
created: 2026-01-11T21:00:00Z
estimate: 3h
complexity: 5
area: testing
---

# Add Browser SDK unit tests

## Problem
Browser SDK (`browser/`) has zero unit tests. Cannot verify:
- WASM initialization
- Fetch hook interception
- Decrypt functionality
- Key management
- Error handling

## Tasks
- [x] Set up Jest or Vitest testing framework
- [x] Create test for ShieldClient initialization
- [x] Create test for key fetching and storage
- [x] Create test for fetch hook installation
- [x] Create test for response decryption
- [x] Create test for non-encrypted response passthrough
- [x] Create test for error handling scenarios
- [x] Add test script to package.json
- [x] Integrate with CI workflow

## Files to Create
- `browser/tests/shield-client.test.ts`
- `browser/tests/fetch-hook.test.ts`
- `browser/jest.config.js` or `browser/vitest.config.ts`

## Acceptance Criteria
- [ ] At least 10 unit tests covering core functionality
- [ ] All tests pass
- [ ] Tests run in CI pipeline
- [ ] Coverage > 70% for core modules

---
**Session Handoff**:
- Changed: `browser/package.json`, `browser/vitest.config.ts`, `browser/tests/fetch-hook.test.ts`, `browser/tests/shield-browser.test.ts`, `.github/workflows/ci.yml`
- Causality: Vitest runs tests that mock WASM client and fetch API
- Verify: `cd browser && npm install && npm test`
- Next: Add integration tests with Python server
