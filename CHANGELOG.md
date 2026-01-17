# Changelog

All notable changes to Shield will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0] - 2026-01-17

### Added
- **Confidential Computing Support** - Hardware-based attestation for Trusted Execution Environments

  **Rust** (`shield-core` with `confidential` feature):
  - `AttestationProvider` trait: Common async interface for all TEE providers
  - `NitroAttestationProvider`: AWS Nitro Enclaves with COSE-signed PCR measurements
  - `SEVAttestationProvider`: GCP Confidential VMs (AMD SEV-SNP + vTPM)
  - `ConfidentialSpaceProvider`: GCP Confidential Space with workload identity
  - `MAAAttestationProvider`: Azure MAA (Microsoft Azure Attestation)
  - `AzureKeyVaultSKR`: Secure Key Release with attestation verification
  - `SGXAttestationProvider`: Intel SGX with DCAP quotes
  - `SealedStorage`: SGX-specific encrypted storage bound to enclave identity
  - `GramineManifestHelper`: Gramine manifest generation for SGX
  - `TEEKeyManager`: Attestation-gated key release with policy enforcement
  - `KeyReleasePolicy`: Configurable policies for measurement verification

  **Rust** (`shield-core` with `openapi` feature):
  - OpenAPI/Swagger schemas via `utoipa` for Confidential Computing APIs
  - Request/Response types: `AttestationRequest`, `AttestationResponse`, etc.
  - Auto-generated API documentation for attestation endpoints

  **Python** (`shield.integrations.confidential`):
  - `NitroAttestationProvider`: AWS Nitro with vsock support
  - `SEVAttestationProvider`: GCP Confidential VMs
  - `MAAAttestationProvider`: Azure MAA
  - `SGXAttestationProvider`: Intel SGX/DCAP
  - `AttestationMiddleware`: FastAPI middleware for client attestation
  - `@requires_attestation`: Decorator for attestation-protected endpoints
  - `TEEKeyManager`: Key derivation from attestation measurements
  - Cloud integrations: AWS KMS, GCP Secret Manager, Azure Key Vault

- **Confidential Computing Examples** (`examples/confidential-computing/`):
  - AWS Nitro Enclaves: FastAPI enclave + parent instance proxy
  - GCP Confidential VMs: SEV-SNP protected API server
  - Azure Confidential Containers: AKS with confcom
  - Intel SGX: Gramine-based enclave application
  - Deployment guides for all platforms

- **TaskGuard Tasks** for Confidential Computing:
  - `backend-022`: Base attestation types and traits
  - `backend-023`: AWS Nitro provider
  - `backend-024`: GCP SEV provider
  - `backend-025`: Azure MAA provider
  - `backend-026`: Intel SGX provider
  - `api-005`: OpenAPI/Swagger support
  - `integration-006` to `integration-010`: Python providers

### Changed
- Rust test count increased from 97 to 95 (with `confidential` feature)
- Added `ciborium` dependency for CBOR parsing (Nitro attestation)
- Added `async-trait` dependency for async trait support
- Added `reqwest` dependency for HTTP client (attestation services)
- Added `utoipa` dependency for OpenAPI schema generation

### Security
- TEE attestation verification before key release
- Hardware-rooted trust via PCR/MRENCLAVE measurements
- Attestation freshness verification (max age checks)
- Policy-based access control for confidential operations

## [1.0.2] - 2026-01-16

### Fixed
- Removed unused SALT_HEX test constant
- Added strict clippy lints from grapheme-nn
- Skip WASM build in release (ring doesn't support wasm32)
- Updated versions to 1.0.1 and fixed rust-toolchain action
- Fixed workflow permissions and stack trace exposure

## [1.0.1] - 2026-01-15

### Fixed
- Minor version bump with security fixes
- Workflow permissions hardening

## [1.0.0] - 2026-01-11

### Added
- **First stable release** - Production-ready encryption library
- Branding assets and logo
- Feature matrix documentation showing language support tiers
- **Android SDK** (`android/`) - Native Android library with:
  - `Shield` class with same API as other platforms
  - `SecureKeyStore` for Android Keystore + EncryptedSharedPreferences
  - Hardware-backed storage (TEE/StrongBox) support
  - Biometric authentication support
  - `TOTP` and `RatchetSession` for 2FA and forward secrecy
  - ProGuard rules included
- **iOS SDK** (`ios/`) - Native iOS/macOS library with:
  - `Shield` class with same API as other platforms
  - `SecureKeychain` for iOS Keychain with Face ID/Touch ID
  - `TOTP` and `RatchetSession` for 2FA and forward secrecy
  - CocoaPods and Swift Package Manager support
  - iOS 13+, macOS 10.15+, tvOS 13+, watchOS 6+ support
- CLI binaries for Linux (x86_64, ARM64), Windows, macOS (Intel, Apple Silicon)
- Complete CI/CD pipeline with automated releases
- Language-specific README documentation for all 12 implementations

### Changed
- All package versions aligned to 1.0.0
- Total test count: 400+ tests across all implementations
- Documented language tiers:
  - **Tier 1** (Full Features): Rust, Python, JavaScript, Go
  - **Tier 2** (Core Features): Java, C#, Swift, Kotlin, C
  - **Tier 3** (Platform-Optimized): Android, iOS, Browser, WASM

### Fixed
- Python type hints now properly use `Optional` for nullable parameters
- Fixed missing `Tuple` import in Python group module
- CI workflow now uses gradle/actions/setup-gradle for reliable Java/Android builds
- Fixed Android tests to use `Shield.create()` factory method instead of private constructor
- Browser SDK test suite with Vitest (27 tests)

### Security
- Secure memory zeroization for Rust key-holding structs:
  - `Shield` - encryption keys zeroized on drop
  - `RatchetSession` - chain keys zeroized on drop
  - `TOTP` - secret zeroized on drop
  - `SymmetricSignature` - signing and verification keys zeroized on drop
  - `LamportSignature` - private key material zeroized on drop
- Constant-time comparison in all cryptographic operations
- Cross-platform security: same guarantees across all 12 implementations

## [0.2.0] - 2026-01-11

### Added
- `ShieldChannel` - TLS-like secure transport using PAKE + RatchetSession
- `AsyncShieldChannel` - Tokio-based async version for high-performance networking
- `ChannelConfig` - Configuration for password, service, iterations, timeout
- `password` module - Password strength checker with entropy calculation
- Browser SDK (`@guard8/shield-browser`) - Auto-decrypt fetch() responses
- Python web integrations:
  - `ShieldMiddleware` for FastAPI
  - `ShieldFlask` extension
  - `RateLimiter` and `TokenBucket`
  - `EncryptedCookie` for secure sessions
  - `BrowserBridge` for client-side key exchange
  - `SecureCORS` for signed request validation

### Changed
- Rust core test count increased from 63 to 97 tests
- Total test count across all implementations: 400+

### Security
- Fixed PAKE protocol bug where different passwords could establish connection
- Added constant-time comparison for all cryptographic operations

## [0.1.0] - 2026-01-10

### Added
- Initial release of Shield encryption library
- Core encryption (`Shield` class) with PBKDF2-SHA256 + SHA256-CTR + HMAC-SHA256
- `quickEncrypt`/`quickDecrypt` for pre-shared key encryption
- `StreamCipher` for large file encryption with per-chunk authentication
- `RatchetSession` for forward secrecy with key ratcheting
- `TOTP` for RFC 6238 time-based one-time passwords
- `RecoveryCodes` for backup 2FA codes
- `SymmetricSignature` for HMAC-based signatures
- `LamportSignature` for quantum-safe one-time signatures
- `GroupEncryption` for multi-recipient encryption
- `KeyRotationManager` for zero-downtime key rotation
- `IdentityProvider` for token-based authentication/SSO
- CLI tool (`shield` command) for file encryption/decryption
- 10 language implementations:
  - Rust (shield-core)
  - Python (shield-crypto)
  - JavaScript (@guard8/shield)
  - Go (github.com/Guard8-ai/shield)
  - C (libshield)
  - Java (ai.guard8:shield)
  - C# (Guard8.Shield)
  - Swift (Shield package)
  - Kotlin (ai.guard8:shield)
  - WebAssembly (shield-wasm)
- Cross-language interoperability (byte-identical output)
- Comprehensive documentation (README, CHEATSHEET, MIGRATION, SECURITY)

### Security
- 256-bit symmetric keys (2^256 brute-force resistance)
- PBKDF2 with 100,000 iterations for key derivation
- HMAC-SHA256 for tamper detection
- Random 128-bit nonce per encryption
- EXPTIME security guarantees

[Unreleased]: https://github.com/Guard8-ai/Shield/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/Guard8-ai/Shield/compare/v1.0.2...v1.1.0
[1.0.2]: https://github.com/Guard8-ai/Shield/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/Guard8-ai/Shield/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/Guard8-ai/Shield/compare/v0.2.0...v1.0.0
[0.2.0]: https://github.com/Guard8-ai/Shield/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Guard8-ai/Shield/releases/tag/v0.1.0
