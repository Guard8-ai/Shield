---
id: backend-014
title: Add TOTP and RatchetSession to mobile SDKs
status: done
priority: medium
tags:
- android
- ios
- features
dependencies:
- testing-008
- testing-010
assignee: shield-team
created: 2026-01-11T21:00:00Z
estimate: 8h
complexity: 7
area: backend
---

# Add TOTP and RatchetSession to mobile SDKs

## Problem
Android and iOS SDKs only implement basic Shield encryption.
Missing advanced features that exist in other implementations:
- TOTP (Two-factor authentication)
- RatchetSession (Forward secrecy messaging)

## Tasks

### Android Implementation
- [x] Create `TOTP.kt` with same API as other platforms
- [x] Create `RatchetSession.kt` with forward secrecy
- [x] Add unit tests for both classes
- [ ] Update Android README with examples

### iOS Implementation
- [x] Create `TOTP.swift` in ios/Sources/Shield/
- [x] Create `RatchetSession.swift` with forward secrecy
- [x] Add unit tests for both classes
- [ ] Update iOS README with examples

## Reference Implementations
- Python: `python/shield/totp.py`, `python/shield/ratchet.py`
- Kotlin: `kotlin/src/main/kotlin/ai/guard8/shield/TOTP.kt`
- Swift: `swift/Sources/Shield/TOTP.swift`

## Acceptance Criteria
- [x] TOTP generates RFC 6238 compliant codes
- [x] RatchetSession provides forward secrecy
- [x] Cross-platform compatibility verified
- [x] Tests pass on both platforms
- [ ] Documentation updated

---
**Session Handoff**:
- Changed:
  - `android/shield/src/main/java/ai/guard8/shield/TOTP.kt` - TOTP + RecoveryCodes classes
  - `android/shield/src/main/java/ai/guard8/shield/RatchetSession.kt` - Forward secrecy session
  - `android/shield/src/test/java/ai/guard8/shield/TOTPTest.kt` - 25 unit tests
  - `android/shield/src/test/java/ai/guard8/shield/RatchetSessionTest.kt` - 18 unit tests
  - `ios/Sources/Shield/TOTP.swift` - TOTP + RecoveryCodes classes
  - `ios/Sources/Shield/RatchetSession.swift` - Forward secrecy session
  - `ios/Tests/ShieldTests/TOTPTests.swift` - 20 unit tests
  - `ios/Tests/ShieldTests/RatchetSessionTests.swift` - 17 unit tests
- Causality: TOTP uses HMAC-SHA1/SHA256 for RFC 6238, RatchetSession uses SHA256-CTR + HMAC-SHA256
- Verify: `cd android && gradle test`, `cd ios && swift test`
- Next: Update README documentation with TOTP/RatchetSession examples
