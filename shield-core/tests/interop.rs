//! Cross-language interoperability tests (wire format v4, standard AEAD).
//!
//! Byte-for-byte cross-language equivalence is anchored by the deterministic
//! conformance vectors in `tests/v4_test_vectors.json` (generated from this Rust
//! reference and reproduced by every binding). These tests cover the
//! behavioural contract: round-trip, format, key/service isolation, and tamper
//! detection.

use shield_core::Shield;

#[test]
fn test_encrypt_decrypt_roundtrip() {
    let shield = Shield::new("password", "service");
    let plaintext = b"Hello, Shield world!";

    let encrypted = shield.encrypt(plaintext).unwrap();
    let decrypted = shield.decrypt(&encrypted).unwrap();

    assert_eq!(plaintext.as_slice(), decrypted.as_slice());
}

#[test]
fn test_ciphertext_format() {
    let shield = Shield::new("password", "service");
    let plaintext = b"test";
    let encrypted = shield.encrypt(plaintext).unwrap();

    // Password-mode v4 format:
    //   version(1) + suite(1) + salt(16) + nonce(12)
    //   + AEAD( timestamp(8) + pad_len(1) + padding(32-128) + plaintext ) + tag(16)
    // Fixed overhead = 1+1+16+12+16 = 46; inner header = 9; padding in [32,128].
    let pt = plaintext.len();
    let min = 46 + 9 + 32 + pt;
    let max = 46 + 9 + 128 + pt;
    assert!(
        encrypted.len() >= min && encrypted.len() <= max,
        "Ciphertext should be between {min} and {max} bytes, got {}",
        encrypted.len()
    );
    assert_eq!(encrypted[0], 0x03, "password-mode version byte");
    assert_eq!(encrypted[1], 0x01, "AES-256-GCM suite byte");
}

#[test]
fn test_different_passwords_isolation() {
    let shield1 = Shield::new("password1", "service");
    let shield2 = Shield::new("password2", "service");

    let plaintext = b"secret data";
    let encrypted = shield1.encrypt(plaintext).unwrap();

    // Should fail to decrypt with wrong password
    assert!(
        shield2.decrypt(&encrypted).is_err(),
        "Should not decrypt with wrong password"
    );
}

#[test]
fn test_different_services_isolation() {
    let shield1 = Shield::new("password", "service1");
    let shield2 = Shield::new("password", "service2");

    let plaintext = b"secret data";
    let encrypted = shield1.encrypt(plaintext).unwrap();

    // Should fail to decrypt with wrong service
    assert!(
        shield2.decrypt(&encrypted).is_err(),
        "Should not decrypt with wrong service"
    );
}

#[test]
fn test_tamper_detection() {
    let shield = Shield::new("password", "service");
    let mut encrypted = shield.encrypt(b"secret data").unwrap();

    // Tamper with a ciphertext byte (inside the AEAD body).
    encrypted[40] ^= 0xFF;

    assert!(
        shield.decrypt(&encrypted).is_err(),
        "Should detect tampering"
    );
}
