//! Core Shield encryption implementation (wire format **v4**).
//!
//! v4 replaces the previous custom SHA-256 keystream + HMAC construction with a
//! **standard AEAD** (AES-256-GCM by default, ChaCha20-Poly1305 optional) taken
//! from the audited `ring` library. No cryptography is hand-rolled here: key
//! derivation uses `ring`'s PBKDF2 + HKDF, and encryption uses `ring`'s AEAD.
//!
//! Matches every other Shield binding byte-for-byte (see `tests/v4_test_vectors.json`).

use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::{hkdf, pbkdf2};
use std::num::NonZeroU32;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Result, ShieldError};

/// Current time in milliseconds since Unix epoch (platform-aware).
fn current_timestamp_ms() -> u64 {
    #[cfg(target_arch = "wasm32")]
    {
        // WASM: use Date.now() via extern binding (SystemTime unavailable)
        #[wasm_bindgen::prelude::wasm_bindgen]
        extern "C" {
            #[wasm_bindgen::prelude::wasm_bindgen(js_namespace = Date, js_name = now)]
            fn date_now() -> f64;
        }
        date_now() as u64
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }
}

/// PBKDF2 iteration count (OWASP 2023 floor for PBKDF2-HMAC-SHA256).
const PBKDF2_ITERATIONS: u32 = 600_000;

/// AEAD nonce size in bytes (96-bit, standard for AES-GCM and ChaCha20-Poly1305).
const NONCE_SIZE: usize = 12;

/// AEAD authentication tag size in bytes (128-bit).
const TAG_SIZE: usize = 16;

/// Random salt size in bytes (password mode).
const SALT_SIZE: usize = 16;

/// Authenticated version byte: password mode
/// (`version || suite || salt(16) || nonce(12) || ciphertext||tag`).
const VERSION_PASSWORD: u8 = 0x03;

/// Authenticated version byte: pre-shared-key mode
/// (`version || suite || nonce(12) || ciphertext||tag`).
const VERSION_KEY: u8 = 0x13;

/// Cipher-suite identifier: AES-256-GCM (default, FIPS-approved).
pub const SUITE_AES_256_GCM: u8 = 0x01;

/// Cipher-suite identifier: ChaCha20-Poly1305.
pub const SUITE_CHACHA20_POLY1305: u8 = 0x02;

/// Inner-plaintext header size: `timestamp_ms(8) + pad_len(1)`.
const INNER_HEADER_SIZE: usize = 9;

/// Minimum padding size (bytes).
const MIN_PADDING: usize = 32;

/// Maximum padding size (bytes).
const MAX_PADDING: usize = 128;

/// HKDF-Expand info string deriving the AEAD key from the master key.
const HKDF_AEAD_INFO: &[u8] = b"shield/aead/v4";

/// Fully-specified inputs to a deterministic AEAD seal (used for conformance
/// vectors and wrapped by the randomized `seal`).
struct SealInputs<'a> {
    nonce: [u8; NONCE_SIZE],
    timestamp_ms: u64,
    pad_len: u8,
    padding: &'a [u8],
    plaintext: &'a [u8],
}

/// Map a 1-byte cipher-suite identifier to a `ring` AEAD algorithm.
fn algorithm_for_suite(suite: u8) -> Result<&'static aead::Algorithm> {
    match suite {
        SUITE_AES_256_GCM => Ok(&aead::AES_256_GCM),
        SUITE_CHACHA20_POLY1305 => Ok(&aead::CHACHA20_POLY1305),
        _ => Err(ShieldError::InvalidFormat),
    }
}

/// Authenticated symmetric encryption using a standard AEAD.
///
/// Keys are derived from a password with PBKDF2-HMAC-SHA256 (random per-instance
/// salt, 600k iterations) or supplied directly as a 32-byte pre-shared key; the
/// AEAD key is then derived via HKDF-SHA256-Expand for domain separation. Data is
/// sealed with AES-256-GCM (default) or ChaCha20-Poly1305 — both standard,
/// hardware-accelerated, independently-audited AEADs.
///
/// **Length hiding:** each message carries 32–128 random padding bytes inside the
/// AEAD plaintext, so ciphertext length does not reveal exact message length.
///
/// **Freshness window (timestamp-based):** rejects messages older than the
/// configured window. This is NOT full replay protection — the base API does not
/// track seen nonces, so an identical ciphertext can be replayed within the
/// window. Use `RatchetSession` for per-message counters.
///
/// Key material is securely zeroized from memory when dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Shield {
    /// Master key: PBKDF2 output (password mode) or the pre-shared key (key mode).
    key: [u8; 32],
    /// AEAD key: `HKDF-SHA256-Expand(key, "shield/aead/v4", 32)`.
    aead_key: [u8; 32],
    /// Password bytes (password mode only; empty in pre-shared-key mode).
    /// Retained so the key can be re-derived from a sender's header salt.
    password: Vec<u8>,
    /// Per-instance random salt (password mode). `None` => pre-shared-key mode
    /// (`with_key`), which emits/consumes the `0x13` version with no salt.
    #[zeroize(skip)]
    salt: Option<[u8; SALT_SIZE]>,
    /// Service identifier bytes (domain separator, folded into the KDF salt).
    #[zeroize(skip)]
    service: Vec<u8>,
    /// PBKDF2 iteration count for this instance.
    #[zeroize(skip)]
    iterations: u32,
    /// Cipher suite used when encrypting (`SUITE_AES_256_GCM` by default).
    #[zeroize(skip)]
    suite: u8,
    /// Maximum message age in milliseconds (None = no freshness check).
    #[zeroize(skip)]
    max_age_ms: Option<u64>,
}

/// Derive the 32-byte master key as
/// `PBKDF2-HMAC-SHA256(password, salt || service, iterations, dklen=32)`.
fn derive_master_key(password: &[u8], salt: &[u8], service: &[u8], iterations: u32) -> [u8; 32] {
    let mut kdf_salt = Vec::with_capacity(salt.len() + service.len());
    kdf_salt.extend_from_slice(salt);
    kdf_salt.extend_from_slice(service);

    let mut key = [0u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        // iterations is always >= 1 in practice; fall back to 1 to stay total.
        NonZeroU32::new(iterations).unwrap_or(NonZeroU32::new(1).unwrap()),
        &kdf_salt,
        password,
        &mut key,
    );
    key
}

/// Derive the AEAD key from a master key via HKDF-SHA256-Expand
/// (`info = "shield/aead/v4"`, L = 32). HKDF-Expand only (the master key is the PRK).
fn derive_aead_key(master_key: &[u8; 32]) -> [u8; 32] {
    let prk = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, master_key);
    let okm = prk
        .expand(&[HKDF_AEAD_INFO], hkdf::HKDF_SHA256)
        .expect("HKDF-Expand with a SHA-256-length output never fails");
    let mut out = [0u8; 32];
    okm.fill(&mut out)
        .expect("HKDF fill of a 32-byte buffer never fails");
    out
}

impl Shield {
    /// Create a new Shield instance from password and service name.
    ///
    /// # Example
    /// ```
    /// use shield_core::Shield;
    /// let shield = Shield::new("my_password", "example.com");
    /// ```
    #[must_use]
    pub fn new(password: &str, service: &str) -> Self {
        // Cryptographically random 16-byte salt per instance.
        // (random_bytes only fails if the system RNG fails; fall back to a
        //  zero salt so the constructor stays infallible. A failing system RNG
        //  is effectively unrecoverable.)
        let salt: [u8; SALT_SIZE] = crate::random::random_bytes().unwrap_or([0u8; SALT_SIZE]);
        Self::from_password_with_salt(password, service, salt, PBKDF2_ITERATIONS)
    }

    /// Construct a password-mode Shield with an explicit salt and iteration
    /// count. Used internally for construction and for re-derivation on decrypt.
    fn from_password_with_salt(
        password: &str,
        service: &str,
        salt: [u8; SALT_SIZE],
        iterations: u32,
    ) -> Self {
        let password = password.as_bytes().to_vec();
        let service = service.as_bytes().to_vec();

        let key = derive_master_key(&password, &salt, &service, iterations);
        let aead_key = derive_aead_key(&key);
        Self {
            key,
            aead_key,
            password,
            salt: Some(salt),
            service,
            iterations,
            suite: SUITE_AES_256_GCM,
            max_age_ms: Some(60_000), // Default: 60 seconds
        }
    }

    /// Create Shield with a pre-shared key (no password derivation).
    ///
    /// Pre-shared-key mode: no password, no salt. Emits/consumes the `0x13`
    /// version byte.
    #[must_use]
    pub fn with_key(key: [u8; 32]) -> Self {
        let aead_key = derive_aead_key(&key);
        Self {
            key,
            aead_key,
            password: Vec::new(),
            salt: None,
            service: Vec::new(),
            iterations: PBKDF2_ITERATIONS,
            suite: SUITE_AES_256_GCM,
            max_age_ms: Some(60_000),
        }
    }

    /// Create Shield with hardware fingerprinting (device-bound encryption).
    ///
    /// Derives keys from password + hardware identifier, binding encryption to the
    /// physical device. Keys cannot be transferred to other hardware without the
    /// correct fingerprint.
    ///
    /// # Errors
    /// Returns error if hardware fingerprint cannot be collected.
    ///
    /// # Security
    /// - **Binding Strength**: MEDIUM (hardware IDs are stable but replaceable)
    /// - **Spoofability**: LOW-MEDIUM (requires hardware access or VM manipulation)
    /// - **Portability**: NONE (keys are device-bound by design)
    pub fn with_fingerprint(
        password: &str,
        service: &str,
        mode: crate::fingerprint::FingerprintMode,
    ) -> Result<Self> {
        // Collect hardware fingerprint
        let fingerprint = crate::fingerprint::collect_fingerprint(mode)?;

        // Combine password with fingerprint
        let combined_password = if fingerprint.is_empty() {
            password.to_string()
        } else {
            format!("{password}:{fingerprint}")
        };

        // Random per-instance salt, stored in the header on encrypt.
        let salt: [u8; SALT_SIZE] = crate::random::random_bytes()?;
        Ok(Self::from_password_with_salt(
            &combined_password,
            service,
            salt,
            PBKDF2_ITERATIONS,
        ))
    }

    /// Select the cipher suite used for encryption.
    ///
    /// Accepts `SUITE_AES_256_GCM` (default) or `SUITE_CHACHA20_POLY1305`. The
    /// suite is recorded in an authenticated byte of every ciphertext, so a
    /// recipient always decrypts with the suite the sender chose regardless of
    /// this setting.
    #[must_use]
    pub fn with_suite(mut self, suite: u8) -> Self {
        self.suite = suite;
        self
    }

    /// Set maximum message age for the freshness window.
    ///
    /// # Arguments
    /// * `max_age_ms` - Maximum age in milliseconds, or None to disable the check.
    #[must_use]
    pub fn with_max_age(mut self, max_age_ms: Option<u64>) -> Self {
        self.max_age_ms = max_age_ms;
        self
    }

    /// Encrypt data with a standard AEAD and length obfuscation.
    ///
    /// Output (password mode):
    ///   `0x03 || suite(1) || salt(16) || nonce(12) || ciphertext||tag`
    /// Output (pre-shared-key mode):
    ///   `0x13 || suite(1) || nonce(12) || ciphertext||tag`
    ///
    /// The AEAD plaintext (inner, authenticated + encrypted) is
    /// `timestamp_ms(8 LE) || pad_len(1) || random_padding(32-128) || message`.
    /// The AEAD additional data (authenticated, not encrypted) is every byte
    /// before the nonce: `version || suite || [salt]`.
    ///
    /// # Errors
    /// Returns error if random generation or AEAD sealing fails.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        Self::seal(&self.aead_key, self.suite, self.salt.as_ref(), plaintext)
    }

    /// Encrypt with a pre-shared key (pre-shared-key mode, `0x13`, AES-256-GCM).
    ///
    /// # Errors
    /// Returns error if random generation or AEAD sealing fails.
    pub fn encrypt_with_key(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
        let aead_key = derive_aead_key(key);
        Self::seal(&aead_key, SUITE_AES_256_GCM, None, plaintext)
    }

    /// Build the AEAD additional-authenticated-data prefix
    /// (`version || suite || [salt]`), which is also the wire prefix before the nonce.
    fn build_aad(suite: u8, salt: Option<&[u8; SALT_SIZE]>) -> Vec<u8> {
        let mut aad = Vec::with_capacity(2 + SALT_SIZE);
        match salt {
            Some(salt) => {
                aad.push(VERSION_PASSWORD);
                aad.push(suite);
                aad.extend_from_slice(salt);
            }
            None => {
                aad.push(VERSION_KEY);
                aad.push(suite);
            }
        }
        aad
    }

    /// Seal `plaintext` with a fresh random nonce, timestamp and padding.
    ///
    /// `salt` is `Some` for password mode (`0x03`) and `None` for pre-shared-key
    /// mode (`0x13`).
    fn seal(
        aead_key: &[u8; 32],
        suite: u8,
        salt: Option<&[u8; SALT_SIZE]>,
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        let nonce: [u8; NONCE_SIZE] = crate::random::random_bytes()?;

        // Random padding: 32-128 bytes (rejection sampling to avoid modulo bias).
        let pad_range = MAX_PADDING - MIN_PADDING + 1; // 97
        let pad_len = loop {
            let rand_byte: [u8; 1] = crate::random::random_bytes()?;
            let val = rand_byte[0] as usize;
            // 256 % 97 = 62, so reject values >= 97*2 to eliminate modulo bias.
            if val < pad_range * (256 / pad_range) {
                break (val % pad_range) + MIN_PADDING;
            }
        };
        let padding = crate::random::random_vec(pad_len)?;

        Self::seal_deterministic(
            aead_key,
            suite,
            salt,
            &SealInputs {
                nonce,
                timestamp_ms: current_timestamp_ms(),
                pad_len: pad_len as u8,
                padding: &padding,
                plaintext,
            },
        )
    }

    /// Deterministic AEAD seal over fully specified inputs.
    ///
    /// Separated from `seal` so conformance vectors (fixed nonce/timestamp/padding)
    /// reproduce byte-for-byte across every binding. `pad_len` must equal
    /// `padding.len()` and lie in `[MIN_PADDING, MAX_PADDING]`.
    fn seal_deterministic(
        aead_key: &[u8; 32],
        suite: u8,
        salt: Option<&[u8; SALT_SIZE]>,
        inputs: &SealInputs,
    ) -> Result<Vec<u8>> {
        let aad = Self::build_aad(suite, salt);

        // Inner plaintext: timestamp_ms(8 LE) || pad_len(1) || padding || message.
        let mut inner =
            Vec::with_capacity(INNER_HEADER_SIZE + inputs.padding.len() + inputs.plaintext.len());
        inner.extend_from_slice(&inputs.timestamp_ms.to_le_bytes());
        inner.push(inputs.pad_len);
        inner.extend_from_slice(inputs.padding);
        inner.extend_from_slice(inputs.plaintext);

        // Seal: ciphertext||tag = AEAD_Seal(aead_key, nonce, inner, aad).
        let algorithm = algorithm_for_suite(suite)?;
        let unbound = UnboundKey::new(algorithm, aead_key)
            .map_err(|_| ShieldError::KeyDerivationFailed("invalid AEAD key".into()))?;
        let key = LessSafeKey::new(unbound);
        let ring_nonce = Nonce::assume_unique_for_key(inputs.nonce);
        let mut in_out = inner;
        key.seal_in_place_append_tag(ring_nonce, Aad::from(&aad), &mut in_out)
            .map_err(|_| ShieldError::StreamError("AEAD seal failed".into()))?;

        // Assemble: aad(version||suite||[salt]) || nonce || ciphertext||tag.
        let mut result = Vec::with_capacity(aad.len() + NONCE_SIZE + in_out.len());
        result.extend_from_slice(&aad);
        result.extend_from_slice(&inputs.nonce);
        result.extend_from_slice(&in_out);
        Ok(result)
    }

    /// Decrypt and verify data. Dispatches on the leading authenticated
    /// version byte.
    ///
    /// - `0x03` (password mode): reads suite + 16-byte salt from the header and
    ///   re-derives the key from `header_salt || service`, then opens the AEAD.
    /// - `0x13` (pre-shared-key mode): uses this instance's pre-shared key.
    ///
    /// Unknown or legacy version bytes are rejected.
    ///
    /// # Errors
    /// Returns error if the version/suite is unknown, AEAD authentication fails,
    /// the ciphertext is malformed, or the message is outside the freshness window.
    pub fn decrypt(&self, encrypted: &[u8]) -> Result<Vec<u8>> {
        if encrypted.is_empty() {
            return Err(ShieldError::CiphertextTooShort {
                expected: 1,
                actual: 0,
            });
        }

        match encrypted[0] {
            VERSION_PASSWORD => {
                // version(1) || suite(1) || salt(16) || nonce(12) || ct||tag
                let aad_len = 2 + SALT_SIZE;
                let min_size = aad_len + NONCE_SIZE + TAG_SIZE;
                if encrypted.len() < min_size {
                    return Err(ShieldError::CiphertextTooShort {
                        expected: min_size,
                        actual: encrypted.len(),
                    });
                }
                // This instance must be in password mode to re-derive a key.
                if self.salt.is_none() {
                    return Err(ShieldError::InvalidFormat);
                }

                let suite = encrypted[1];
                let mut salt = [0u8; SALT_SIZE];
                salt.copy_from_slice(&encrypted[2..2 + SALT_SIZE]);

                // Re-derive the key from the sender's header salt + service.
                let key = derive_master_key(&self.password, &salt, &self.service, self.iterations);
                let aead_key = derive_aead_key(&key);

                Self::open(&aead_key, suite, encrypted, aad_len, self.max_age_ms)
            }
            VERSION_KEY => {
                // version(1) || suite(1) || nonce(12) || ct||tag
                let aad_len = 2;
                let suite = encrypted[1];
                Self::open(&self.aead_key, suite, encrypted, aad_len, self.max_age_ms)
            }
            _ => Err(ShieldError::InvalidFormat),
        }
    }

    /// Decrypt a pre-shared-key (`0x13`) ciphertext with an explicit key.
    ///
    /// # Errors
    /// Returns error if the version/suite is unknown, AEAD authentication fails,
    /// the ciphertext is malformed, or the message is outside the freshness window.
    pub fn decrypt_with_key(key: &[u8; 32], encrypted: &[u8]) -> Result<Vec<u8>> {
        if encrypted.is_empty() || encrypted[0] != VERSION_KEY {
            return Err(ShieldError::InvalidFormat);
        }
        if encrypted.len() < 2 + NONCE_SIZE + TAG_SIZE {
            return Err(ShieldError::CiphertextTooShort {
                expected: 2 + NONCE_SIZE + TAG_SIZE,
                actual: encrypted.len(),
            });
        }
        let aead_key = derive_aead_key(key);
        let suite = encrypted[1];
        Self::open(&aead_key, suite, encrypted, 2, Some(60_000))
    }

    /// Open an AEAD ciphertext: verify the tag over `aad`, decrypt, then parse and
    /// validate the inner `timestamp(8) || pad_len(1) || padding || message` layout
    /// and apply the freshness window.
    ///
    /// `aad_len` is the number of leading authenticated bytes (`version || suite
    /// || [salt]`), i.e. the offset of the nonce.
    fn open(
        aead_key: &[u8; 32],
        suite: u8,
        encrypted: &[u8],
        aad_len: usize,
        max_age_ms: Option<u64>,
    ) -> Result<Vec<u8>> {
        let algorithm = algorithm_for_suite(suite)?;

        if encrypted.len() < aad_len + NONCE_SIZE + TAG_SIZE {
            return Err(ShieldError::CiphertextTooShort {
                expected: aad_len + NONCE_SIZE + TAG_SIZE,
                actual: encrypted.len(),
            });
        }

        let aad = &encrypted[..aad_len];
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        nonce_bytes.copy_from_slice(&encrypted[aad_len..aad_len + NONCE_SIZE]);
        let ct_and_tag = &encrypted[aad_len + NONCE_SIZE..];

        let unbound = UnboundKey::new(algorithm, aead_key)
            .map_err(|_| ShieldError::KeyDerivationFailed("invalid AEAD key".into()))?;
        let key = LessSafeKey::new(unbound);
        let ring_nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let mut in_out = ct_and_tag.to_vec();
        let inner = key
            .open_in_place(ring_nonce, Aad::from(aad), &mut in_out)
            .map_err(|_| ShieldError::AuthenticationFailed)?;

        // Inner layout: timestamp_ms(8 LE) || pad_len(1) || padding || message.
        if inner.len() < INNER_HEADER_SIZE {
            return Err(ShieldError::InvalidFormat);
        }
        let mut ts_bytes = [0u8; 8];
        ts_bytes.copy_from_slice(&inner[..8]);
        let timestamp_ms = u64::from_le_bytes(ts_bytes);
        let pad_len = inner[8] as usize;

        // Validate padding length is within protocol bounds.
        if !(MIN_PADDING..=MAX_PADDING).contains(&pad_len) {
            return Err(ShieldError::AuthenticationFailed);
        }
        let data_start = INNER_HEADER_SIZE + pad_len;
        if data_start > inner.len() {
            return Err(ShieldError::InvalidFormat);
        }

        // Freshness window (NOT full replay protection).
        if let Some(max_age) = max_age_ms {
            let now_ms = current_timestamp_ms();
            let age = i64::try_from(now_ms).unwrap_or(i64::MAX)
                - i64::try_from(timestamp_ms).unwrap_or(0);
            // Reject future timestamps (clock skew > 5s).
            if age < -5000 {
                return Err(ShieldError::InvalidFormat);
            }
            // Reject expired messages.
            if age > i64::try_from(max_age).unwrap_or(i64::MAX) {
                return Err(ShieldError::InvalidFormat);
            }
        }

        Ok(inner[data_start..].to_vec())
    }

    /// Get the master key for internal use cases.
    ///
    /// Used by `TEEKeyManager` for attestation-bound key derivation and
    /// pgvector for HMAC-based vector operations.
    #[cfg(any(feature = "pgvector", feature = "confidential"))]
    #[must_use]
    pub(crate) fn master_key(&self) -> &[u8; 32] {
        &self.key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aead_key_deterministic() {
        let master = [7u8; 32];
        assert_eq!(derive_aead_key(&master), derive_aead_key(&master));
    }

    #[test]
    fn test_encrypt_format_v4_password() {
        let shield = Shield::new("password", "service");
        let encrypted = shield.encrypt(b"test").unwrap();

        // 0x03 || suite(1) || salt(16) || nonce(12) || inner(9+pad+pt) || tag(16)
        // pad in [32,128], pt = 4: min 1+1+16+12+(9+32+4)+16 = 91, max = +96 padding = 187
        assert_eq!(encrypted[0], VERSION_PASSWORD);
        assert_eq!(encrypted[1], SUITE_AES_256_GCM);
        assert!(
            encrypted.len() >= 91 && encrypted.len() <= 187,
            "len {}",
            encrypted.len()
        );
    }

    #[test]
    fn test_encrypt_format_v4_key() {
        let key = [3u8; 32];
        let encrypted = Shield::encrypt_with_key(&key, b"test").unwrap();
        assert_eq!(encrypted[0], VERSION_KEY);
        assert_eq!(encrypted[1], SUITE_AES_256_GCM);
    }

    #[test]
    fn test_v4_roundtrip_password() {
        let shield = Shield::new("password", "service");
        let plaintext = b"Hello, Shield v4!";
        let encrypted = shield.encrypt(plaintext).unwrap();
        let decrypted = shield.decrypt(&encrypted).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_v4_roundtrip_key() {
        let key = [9u8; 32];
        let encrypted = Shield::encrypt_with_key(&key, b"pre-shared").unwrap();
        let decrypted = Shield::decrypt_with_key(&key, &encrypted).unwrap();
        assert_eq!(b"pre-shared", decrypted.as_slice());
    }

    #[test]
    fn test_v4_roundtrip_key_instance() {
        let key = [9u8; 32];
        let shield = Shield::with_key(key);
        let encrypted = shield.encrypt(b"abc").unwrap();
        let decrypted = shield.decrypt(&encrypted).unwrap();
        assert_eq!(b"abc", decrypted.as_slice());
    }

    #[test]
    fn test_v4_empty_plaintext() {
        let shield = Shield::new("pw", "svc");
        let encrypted = shield.encrypt(b"").unwrap();
        let decrypted = shield.decrypt(&encrypted).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_v4_chacha_roundtrip() {
        let shield = Shield::new("password", "service").with_suite(SUITE_CHACHA20_POLY1305);
        let encrypted = shield.encrypt(b"chacha message").unwrap();
        assert_eq!(encrypted[1], SUITE_CHACHA20_POLY1305);
        // A fresh decryptor (default suite) must still decrypt: suite is read from the wire.
        let recipient = Shield::new("password", "service");
        let decrypted = recipient.decrypt(&encrypted).unwrap();
        assert_eq!(b"chacha message", decrypted.as_slice());
    }

    #[test]
    fn test_v4_replay_protection_disabled() {
        let shield = Shield::new("password", "service").with_max_age(None);
        let encrypted = shield.encrypt(b"no expiry").unwrap();
        let decrypted = shield.decrypt(&encrypted).unwrap();
        assert_eq!(b"no expiry", decrypted.as_slice());
    }

    #[test]
    fn test_v4_length_variation() {
        let shield = Shield::new("password", "service");
        let plaintext = b"same message";
        let mut lengths = std::collections::HashSet::new();
        for _ in 0..20 {
            lengths.insert(shield.encrypt(plaintext).unwrap().len());
        }
        assert!(
            lengths.len() > 1,
            "expected length variation from random padding"
        );
    }

    #[test]
    fn test_v4_tamper_detection() {
        let shield = Shield::new("password", "service");
        let mut encrypted = shield.encrypt(b"data").unwrap();
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0xFF; // flip a tag byte
        assert!(shield.decrypt(&encrypted).is_err());
    }

    #[test]
    fn test_v4_aad_tamper_detection() {
        let shield = Shield::new("password", "service");
        let mut encrypted = shield.encrypt(b"data").unwrap();
        encrypted[1] ^= 0x0F; // flip the authenticated suite byte
                              // suite becomes unknown OR auth fails — either way, rejected.
        assert!(shield.decrypt(&encrypted).is_err());
    }

    #[test]
    fn test_v4_wrong_password_fails() {
        let a = Shield::new("password-a", "service").with_max_age(None);
        let b = Shield::new("password-b", "service").with_max_age(None);
        let encrypted = a.encrypt(b"secret").unwrap();
        assert!(b.decrypt(&encrypted).is_err());
    }

    #[test]
    fn test_legacy_v3_format_is_hard_rejected() {
        // Clean break: a v3 password ciphertext began with 0x02; v4 expects 0x03.
        let shield = Shield::new("password", "service");
        let mut fake_v3 = vec![0x02u8];
        fake_v3.extend_from_slice(&[0u8; 16 + 16 + 32 + 16]);
        assert!(shield.decrypt(&fake_v3).is_err());
    }

    #[test]
    fn test_unknown_suite_rejected() {
        let key = [1u8; 32];
        let mut encrypted = Shield::encrypt_with_key(&key, b"x").unwrap();
        encrypted[1] = 0x7F; // unknown suite
        assert!(Shield::decrypt_with_key(&key, &encrypted).is_err());
    }

    /// Deterministic padding used by the conformance generator (byte i == i).
    fn det_padding(n: usize) -> Vec<u8> {
        (0..n).map(|i| i as u8).collect()
    }

    /// Build one deterministic conformance vector as a JSON object and verify it
    /// both reproduces and round-trips before emitting.
    #[allow(clippy::too_many_arguments)]
    fn make_vector(
        name: &str,
        suite: u8,
        password_service: Option<(&str, &str)>,
        key: [u8; 32],
        salt: Option<[u8; SALT_SIZE]>,
        nonce: [u8; NONCE_SIZE],
        timestamp_ms: u64,
        pad_len: u8,
        plaintext: &[u8],
    ) -> serde_json::Value {
        let (master, mode) = match password_service {
            Some((pw, svc)) => (
                derive_master_key(
                    pw.as_bytes(),
                    &salt.unwrap(),
                    svc.as_bytes(),
                    PBKDF2_ITERATIONS,
                ),
                "password",
            ),
            None => (key, "key"),
        };
        let aead_key = derive_aead_key(&master);
        let padding = det_padding(pad_len as usize);
        let output = Shield::seal_deterministic(
            &aead_key,
            suite,
            salt.as_ref(),
            &SealInputs {
                nonce,
                timestamp_ms,
                pad_len,
                padding: &padding,
                plaintext,
            },
        )
        .unwrap();

        // Self-check: the produced bytes must open back to the plaintext.
        let aad_len = if salt.is_some() { 2 + SALT_SIZE } else { 2 };
        let opened = Shield::open(&aead_key, suite, &output, aad_len, None).unwrap();
        assert_eq!(opened, plaintext, "vector {name} failed self round-trip");

        let mut obj = serde_json::Map::new();
        obj.insert("name".into(), name.into());
        obj.insert("mode".into(), mode.into());
        obj.insert("suite".into(), format!("0x{suite:02x}").into());
        if let Some((pw, svc)) = password_service {
            obj.insert("password".into(), pw.into());
            obj.insert("service".into(), svc.into());
            obj.insert("iterations".into(), PBKDF2_ITERATIONS.into());
            obj.insert("salt_hex".into(), hex::encode(salt.unwrap()).into());
        } else {
            obj.insert("key_hex".into(), hex::encode(key).into());
        }
        obj.insert("nonce_hex".into(), hex::encode(nonce).into());
        obj.insert("timestamp_ms".into(), timestamp_ms.into());
        obj.insert("pad_len".into(), u64::from(pad_len).into());
        obj.insert("padding_hex".into(), hex::encode(&padding).into());
        obj.insert("plaintext_hex".into(), hex::encode(plaintext).into());
        obj.insert("master_key_hex".into(), hex::encode(master).into());
        obj.insert("aead_key_hex".into(), hex::encode(aead_key).into());
        obj.insert("expected_output_hex".into(), hex::encode(&output).into());
        serde_json::Value::Object(obj)
    }

    /// Regenerate `tests/v4_test_vectors.json` from this Rust reference.
    /// Run with: `cargo test gen_v4_vectors -- --ignored --nocapture`
    #[test]
    #[ignore = "vector generator; run explicitly to regenerate tests/v4_test_vectors.json"]
    fn gen_v4_vectors() {
        const TS: u64 = 1_700_000_000_000;
        let test_key: [u8; 32] = {
            let mut k = [0u8; 32];
            hex::decode_to_slice(
                "0102030405060708091011121314151617181920212223242526272829303132",
                &mut k,
            )
            .unwrap();
            k
        };
        let salt_a: [u8; 16] = std::array::from_fn(|i| i as u8); // 00..0f
        let salt_b: [u8; 16] = std::array::from_fn(|i| 0x10 + i as u8); // 10..1f
        let nonce = |base: u8| -> [u8; 12] { std::array::from_fn(|i| base + i as u8) };

        let aes = SUITE_AES_256_GCM;
        let cha = SUITE_CHACHA20_POLY1305;

        let det = vec![
            make_vector(
                "password_basic",
                aes,
                Some(("test-password-123", "test.example.com")),
                [0; 32],
                Some(salt_a),
                nonce(0xa0),
                TS,
                32,
                b"Hello, Shield v4!",
            ),
            make_vector(
                "password_empty",
                aes,
                Some(("empty-test", "empty.example.com")),
                [0; 32],
                Some(salt_b),
                nonce(0xb0),
                TS,
                50,
                b"",
            ),
            make_vector(
                "password_unicode",
                aes,
                Some(("pw-unicode", "unicode.example.com")),
                [0; 32],
                Some(salt_a),
                nonce(0xc0),
                TS,
                128,
                "Grüsse, Shield! ✨".as_bytes(),
            ),
            make_vector(
                "key_basic",
                aes,
                None,
                test_key,
                None,
                nonce(0xd0),
                TS,
                32,
                b"Hello from Shield cross-language test!",
            ),
            make_vector(
                "key_empty",
                aes,
                None,
                test_key,
                None,
                nonce(0xe0),
                TS,
                64,
                b"",
            ),
            make_vector(
                "key_binary",
                aes,
                None,
                test_key,
                None,
                nonce(0xf0),
                TS,
                100,
                &det_padding(64),
            ),
        ];
        let det_chacha = vec![
            make_vector(
                "password_basic_chacha",
                cha,
                Some(("test-password-123", "test.example.com")),
                [0; 32],
                Some(salt_a),
                nonce(0xa0),
                TS,
                32,
                b"Hello, Shield v4!",
            ),
            make_vector(
                "key_basic_chacha",
                cha,
                None,
                test_key,
                None,
                nonce(0xd0),
                TS,
                32,
                b"Hello from Shield cross-language test!",
            ),
        ];

        let doc = serde_json::json!({
            "version": "4.0",
            "description": "Shield v4 conformance vectors generated from the Rust reference (shield-core/src/shield.rs). Standard AEAD: AES-256-GCM (suite 0x01) and ChaCha20-Poly1305 (suite 0x02). Each deterministic vector fixes salt/nonce/timestamp/padding so every binding reproduces 'expected_output_hex' BYTE-FOR-BYTE and also decrypts it (with the freshness window disabled).",
            "format": {
                "password_mode": "0x03 || suite(1) || salt(16) || nonce(12) || ciphertext||tag",
                "key_mode": "0x13 || suite(1) || nonce(12) || ciphertext||tag",
                "aad": "all bytes before the nonce: version || suite || [salt]",
                "inner_plaintext": "timestamp_ms(8 LE) || pad_len(1) || padding(pad_len, 32-128) || message",
                "kdf_password": "master = PBKDF2-HMAC-SHA256(password, salt||service, iterations=600000, dkLen=32)",
                "kdf_key": "master = provided 32-byte key",
                "aead_key": "HKDF-SHA256-Expand(master, info=\"shield/aead/v4\", L=32)"
            },
            "note_on_freshness": "Vectors carry a fixed timestamp far in the past; decrypt with the freshness window disabled (max_age_ms = None/nil).",
            "deterministic_vectors": det,
            "deterministic_vectors_chacha": det_chacha,
            "constants": {
                "VERSION_PASSWORD": "0x03",
                "VERSION_KEY": "0x13",
                "SUITE_AES_256_GCM": "0x01",
                "SUITE_CHACHA20_POLY1305": "0x02",
                "NONCE_SIZE": NONCE_SIZE,
                "TAG_SIZE": TAG_SIZE,
                "SALT_SIZE": SALT_SIZE,
                "INNER_HEADER_SIZE": INNER_HEADER_SIZE,
                "MIN_PADDING": MIN_PADDING,
                "MAX_PADDING": MAX_PADDING,
                "PBKDF2_ITERATIONS": PBKDF2_ITERATIONS,
                "HKDF_AEAD_INFO": "shield/aead/v4"
            }
        });

        let json = serde_json::to_string_pretty(&doc).unwrap();
        std::fs::write("../tests/v4_test_vectors.json", json + "\n").unwrap();
        eprintln!(
            "wrote ../tests/v4_test_vectors.json with {} AES + {} ChaCha vectors",
            6, 2
        );
    }
}
