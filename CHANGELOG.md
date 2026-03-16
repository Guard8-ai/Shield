# Changelog

All notable changes to Shield will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.2.0] - 2026-03-15

### Added

- **Shield Proxy** (`shield-proxy/`): Transparent, protocol-agnostic proxy extension
  - Core TCP proxy with bidirectional forwarding and graceful shutdown
  - DNS forwarding with multi-upstream failover and health checks
  - Shield v2.1 encryption in the transport layer (length-prefixed framing)
  - Protocol detection: HTTP, TLS/HTTPS, WebSocket, raw TCP (non-destructive peek)
  - TOML configuration schema with validation and sensible defaults
  - Hot redundancy: active/standby pair with UDP heartbeat and automatic failover
  - Prometheus metrics endpoint (`/metrics`) and health endpoint (`/health`)
  - systemd unit file, Dockerfile (multi-stage distroless), docker-compose for HA pair
  - 33 tests covering all modules, zero clippy warnings

### Changed

- Version bumped to 2.2.0 across all 13 SDK package configs

## [2.1.0] - 2026-03-01

### Security

**Comprehensive Rust core security hardening** based on 189-finding fork security assessment. All Rust-applicable findings resolved.

#### Cryptographic Improvements
- **Key Separation**: Derived separate `enc_key` and `mac_key` from master key using HMAC-SHA256 domain separation (`shield-encrypt` / `shield-authenticate`). Prevents cross-protocol key reuse (CWE-323)
- **HMAC-SHA256 upgrade**: Replaced all internal `SHA256(key||data)` patterns with `HMAC-SHA256(key, data)` in 13 call sites across `group.rs`, `identity.rs`, `rotation.rs`, `exchange.rs`, `signatures.rs`, and `ratchet.rs`. Provides formal PRF security proof (Bellare 2006), length-extension resistance, and NIST SP 800-108 compliance
- **Core wire format preserved**: `shield.rs` and `stream.rs` keystream generation unchanged for cross-language interoperability
- **Counter overflow guard**: Added bounds assertion in all 8 keystream generators preventing silent `u32` wraparound at >137GB

#### Authentication & Memory Safety
- **Constant-time comparisons**: All MAC verifications use `subtle::ConstantTimeEq` (CWE-208)
- **Timing-safe authentication**: `IdentityProvider::authenticate()` runs PBKDF2 even for non-existent users to prevent user enumeration (CWE-203)
- **Zeroize on Drop**: Added `Drop` implementations for `IdentityProvider` and `SecureSession` that zeroize master keys, password hashes, and salts. Existing `Zeroize`/`ZeroizeOnDrop` derives on `Shield`, `RatchetSession`, `SymmetricSignature`, `TOTP`
- **Modulo bias elimination**: Padding length selection uses rejection sampling instead of modulo (CWE-330)
- **Padding validation**: Decryption rejects `pad_len` outside protocol bounds (32-128) before accessing plaintext

#### TOTP Hardening
- Digits clamped to 1-9 range (0 defaults to 6, >9 caps at 9)
- `window=0` now means exact-match verification (no silent override to 1)
- Recovery code entropy increased from 32 bits to 64 bits (8 random bytes, format `XXXX-XXXX-XXXX-XXXX`)

#### CLI Security
- Password and plaintext input via stdin to avoid process-list exposure
- `--force` flag required to overwrite existing output files
- Warnings when `-p` flag used (visible in `ps`)

#### Secure Transport
- **Sync channel timeout**: Added `connect_tcp()` / `accept_tcp()` methods on `ShieldChannel<TcpStream>` that enforce `handshake_timeout_ms` via socket read/write timeouts during handshake
- PAKE key derivation and session key computation use HMAC-SHA256 throughout

#### API Changes
- Removed `GroupEncryption::group_key()` and `BroadcastEncryption::master_key()` accessors (no callers existed, reduced attack surface)
- `Shield::master_key()` restricted to `pub(crate)` behind feature gates

### Changed
- Rust test count increased from 97 to 121 (106 unit + 7 interop + 8 doc-tests)
- Desktop fingerprinting implementation for JS/Go/Java/C (v2.1.0)
- **v2.1 hardening ported to all SDKs**: C#, Swift, Kotlin, Android, and iOS now include HMAC domain separation (`shield-encrypt` / `shield-authenticate` subkeys), v2 padding format with rejection sampling, timestamp-based replay protection, and v1/v2 auto-detection on decrypt
- **API breaking changes (5 SDKs)**:
  - **C#**: `Decrypt()` now throws `ShieldException` instead of returning `null`
  - **Swift**: `encrypt()` and `decrypt()` now `throw` instead of returning optionals
  - **Kotlin**: `decrypt()` now throws `ShieldException.AuthenticationFailed` instead of returning `null`
  - **Android**: `decrypt()` now throws `ShieldException.AuthenticationFailed` instead of returning `ByteArray?`
  - **iOS**: `encrypt()` and `decrypt()` now `throw ShieldError` instead of returning optionals
- All SDK versions aligned to 2.1.0 (Python, JavaScript, Java, C#, Swift, Kotlin, Android, iOS, Browser)

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
- Browser SDK (`@dikestra/shield-browser`) - Auto-decrypt fetch() responses
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
  - JavaScript (@dikestra/shield)
  - Go (github.com/Dikestra-ai/shield)
  - C (libshield)
  - Java (ai.dikestra:shield)
  - C# (Dikestra.Shield)
  - Swift (Shield package)
  - Kotlin (ai.dikestra:shield)
  - WebAssembly (shield-wasm)
- Cross-language interoperability (byte-identical output)
- Comprehensive documentation (README, CHEATSHEET, MIGRATION, SECURITY)

### Security
- 256-bit symmetric keys (2^256 brute-force resistance)
- PBKDF2 with 100,000 iterations for key derivation
- HMAC-SHA256 for tamper detection
- Random 128-bit nonce per encryption
- EXPTIME security guarantees

[Unreleased]: https://github.com/Dikestra-ai/Shield/compare/v2.1.0...HEAD
[2.1.0]: https://github.com/Dikestra-ai/Shield/compare/v1.1.0...v2.1.0
[1.1.0]: https://github.com/Dikestra-ai/Shield/compare/v1.0.2...v1.1.0
[1.0.2]: https://github.com/Dikestra-ai/Shield/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/Dikestra-ai/Shield/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/Dikestra-ai/Shield/compare/v0.2.0...v1.0.0
[0.2.0]: https://github.com/Dikestra-ai/Shield/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Dikestra-ai/Shield/releases/tag/v0.1.0
