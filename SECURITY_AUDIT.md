# Security Audit Requirements

This document outlines the requirements for a third-party security audit of Shield.

## Known Non-Conformances (Pre-Audit)

### FIDO2 / WebAuthn — HIGH severity (backend-065)

The `shield-core/src/fido2/` module **does not implement the WebAuthn security
model**.  Identified by ARC security review r1b (2026-07-14), finding H7:

| Missing property | Impact |
|---|---|
| No origin binding (`clientDataJSON.origin` not checked) | Any origin can register/authenticate credentials for any relying party |
| No rpId binding (`authenticatorData.rpIdHash` not verified) | Credentials from one RP accepted by any other RP |
| No clientDataJSON binding (challenge not bound to origin + type) | Phishing and cross-origin attacks possible |
| No attestation | Cannot verify authenticator is genuine |

**Status (2026-08-03):** Interim fix applied (backend-065):
- `Fido2Manager` marked `#[deprecated(since = "4.0.0")]` with migration notice
- All module/type/function doc comments carry prominent `WARNING` headers
- Empty-challenge fail-closed guards added to `verify_registration` and
  `verify_authentication`
- `WebAuthnConfig` extended with `allowed_origins: Vec<String>`
- `validate_client_data()` stub added — enforces type, origin, and non-empty
  challenge; **not yet wired into** `verify_registration`/`verify_authentication`
  (full rewrite deferred to backend-065 proper)
- TODO comments at every missing validation point in `manager.rs`

**Recommendation:** Replace `fido2/` with [`webauthn-rs`](https://crates.io/crates/webauthn-rs) `0.5`
before any production use.  This module will be removed in Shield v5.0.

---

## Audit Scope

### In Scope

1. **Cryptographic Implementation**
   - PBKDF2-SHA256 key derivation (100,000 iterations)
   - SHA256-CTR stream cipher implementation
   - HMAC-SHA256 authentication
   - Nonce generation and handling
   - Key material handling and zeroization
   - Key separation (enc_key/mac_key via HMAC domain labels) — v2.1
   - HMAC-SHA256 in internal modules (replacing raw SHA256) — v2.1
   - Counter overflow protection — v2.1

2. **Core Components**
   - `Shield` class (password-based encryption)
   - `quickEncrypt`/`quickDecrypt` (pre-shared key)
   - `StreamCipher` (large file handling)
   - `RatchetSession` (forward secrecy)
   - `ShieldChannel` (secure transport)
   - `TOTP` (RFC 6238 compliance)

3. **Security Properties**
   - Constant-time comparisons
   - Memory safety (Rust implementation)
   - Side-channel resistance
   - Error handling (no information leakage)

4. **Cross-Language Consistency**
   - Verify byte-identical output across implementations
   - Check for language-specific vulnerabilities

### Out of Scope

- Application-level integration code
- Example applications
- Documentation website
- Build tooling and CI/CD

## Security Claims to Verify

| Claim | Requirement |
|-------|-------------|
| 256-bit security | Key space is 2^256, no shortcuts |
| Tamper detection | Any modification detected by HMAC |
| Forward secrecy | Past messages safe if key compromised |
| Constant-time | No timing side channels (`subtle::ConstantTimeEq`) |
| Memory safety | No buffer overflows or use-after-free |
| Key separation | Separate enc_key/mac_key via HMAC domain labels |
| Zeroize on Drop | All key-holding structs securely clear memory |
| Counter overflow | Hard failure at 2^32 blocks (137GB) |

## Audit Methodology

### Phase 1: Code Review (40%)
- Manual review of cryptographic code
- Focus on Rust core implementation
- Review Python/JavaScript for consistency

### Phase 2: Automated Analysis (20%)
- Static analysis tools (Clippy, Bandit, ESLint security)
- Fuzzing of encryption/decryption functions
- Memory safety analysis

### Phase 3: Penetration Testing (30%)
- Attempt to break encryption without key
- Side-channel attack attempts
- Malformed input handling
- Protocol-level attacks on ShieldChannel

### Phase 4: Documentation Review (10%)
- Verify security claims in documentation
- Check for misleading statements
- Review threat model accuracy

## Deliverables

1. **Executive Summary** - High-level findings for stakeholders
2. **Technical Report** - Detailed vulnerability analysis
3. **Remediation Guide** - Prioritized fix recommendations
4. **Verification Report** - Confirmation of fixes

## Severity Ratings

| Severity | Definition | Response Time |
|----------|------------|---------------|
| Critical | Key recovery, authentication bypass | 24 hours |
| High | Significant security degradation | 7 days |
| Medium | Limited impact vulnerabilities | 30 days |
| Low | Hardening recommendations | 90 days |
| Info | Best practice suggestions | Next release |

## Qualified Auditors

Preferred auditors with cryptography expertise:

- NCC Group
- Trail of Bits
- Cure53
- Quarkslab
- Include Security

## Budget Estimate

| Component | Estimated Cost |
|-----------|----------------|
| Rust core audit | $15,000 - $25,000 |
| Cross-language review | $10,000 - $15,000 |
| Protocol audit (ShieldChannel) | $8,000 - $12,000 |
| **Total** | **$33,000 - $52,000** |

## Timeline

1. **Week 1-2**: Auditor selection and kickoff
2. **Week 3-6**: Audit execution
3. **Week 7**: Draft report delivery
4. **Week 8-10**: Remediation
5. **Week 11**: Final report and publication

## Contact

For audit coordination:
- **Email**: admin@gibraltarcloud.dev
- **PGP Key**: Available at https://dikestra.ai/.well-known/pgp-key.txt

## Post-Audit

After successful audit:
1. Publish audit report (with auditor approval)
2. Update SECURITY.md with audit status
3. Add audit badge to README
4. Announce on security mailing lists
