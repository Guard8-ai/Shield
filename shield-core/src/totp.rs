//! TOTP (Time-based One-Time Password) implementation.
//!
//! RFC 6238 compliant with recovery codes support.

use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{Result, ShieldError};

/// Default secret length in bytes.
const DEFAULT_SECRET_LEN: usize = 20;

/// TOTP generator and validator.
pub struct TOTP {
    secret: Vec<u8>,
    digits: usize,
    interval: u64,
}

impl TOTP {
    /// Create new TOTP with secret.
    pub fn new(secret: Vec<u8>, digits: usize, interval: u64) -> Self {
        Self {
            secret,
            digits: if digits == 0 { 6 } else { digits },
            interval: if interval == 0 { 30 } else { interval },
        }
    }

    /// Create with default settings (6 digits, 30 second interval).
    pub fn with_secret(secret: Vec<u8>) -> Self {
        Self::new(secret, 6, 30)
    }

    /// Generate a random secret.
    pub fn generate_secret() -> Result<Vec<u8>> {
        let rng = SystemRandom::new();
        let mut secret = vec![0u8; DEFAULT_SECRET_LEN];
        rng.fill(&mut secret).map_err(|_| ShieldError::RandomFailed)?;
        Ok(secret)
    }

    /// Generate TOTP code for given time.
    pub fn generate(&self, timestamp: Option<u64>) -> String {
        let time = timestamp.unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
        });

        let counter = time / self.interval;
        self.generate_hotp(counter)
    }

    /// Generate HOTP code for counter.
    fn generate_hotp(&self, counter: u64) -> String {
        let counter_bytes = counter.to_be_bytes();
        let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &self.secret);
        let tag = hmac::sign(&key, &counter_bytes);
        let hash = tag.as_ref();

        // Dynamic truncation (RFC 4226)
        let offset = (hash[19] & 0xf) as usize;
        let code = u32::from_be_bytes([
            hash[offset] & 0x7f,
            hash[offset + 1],
            hash[offset + 2],
            hash[offset + 3],
        ]);

        let modulo = 10u32.pow(self.digits as u32);
        format!("{:0width$}", code % modulo, width = self.digits)
    }

    /// Verify TOTP code with time window.
    pub fn verify(&self, code: &str, timestamp: Option<u64>, window: u32) -> bool {
        let time = timestamp.unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
        });

        let window = if window == 0 { 1 } else { window };

        for i in 0..=window {
            let t = time.saturating_sub((i as u64) * self.interval);
            if self.generate(Some(t)) == code {
                return true;
            }
            if i > 0 {
                let t = time + (i as u64) * self.interval;
                if self.generate(Some(t)) == code {
                    return true;
                }
            }
        }
        false
    }

    /// Convert secret to Base32.
    pub fn secret_to_base32(secret: &[u8]) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let mut result = String::new();
        let mut buffer = 0u64;
        let mut bits = 0;

        for &byte in secret {
            buffer = (buffer << 8) | (byte as u64);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                result.push(ALPHABET[((buffer >> bits) & 0x1f) as usize] as char);
            }
        }

        if bits > 0 {
            result.push(ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize] as char);
        }

        result
    }

    /// Decode Base32 secret.
    pub fn secret_from_base32(encoded: &str) -> Result<Vec<u8>> {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let mut result = Vec::new();
        let mut buffer = 0u64;
        let mut bits = 0;

        for c in encoded.chars() {
            let c = c.to_ascii_uppercase();
            if c == '=' {
                continue;
            }
            let val = ALPHABET
                .iter()
                .position(|&b| b == c as u8)
                .ok_or(ShieldError::InvalidFormat)?;

            buffer = (buffer << 5) | (val as u64);
            bits += 5;

            if bits >= 8 {
                bits -= 8;
                result.push((buffer >> bits) as u8);
            }
        }

        Ok(result)
    }

    /// Generate provisioning URI for QR codes.
    pub fn provisioning_uri(&self, account: &str, issuer: &str) -> String {
        let secret_b32 = Self::secret_to_base32(&self.secret);
        format!(
            "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits={}&period={}",
            issuer, account, secret_b32, issuer, self.digits, self.interval
        )
    }

    /// Get the secret.
    pub fn secret(&self) -> &[u8] {
        &self.secret
    }
}

/// Recovery codes for 2FA backup.
pub struct RecoveryCodes {
    codes: HashSet<String>,
    original_count: usize,
}

impl RecoveryCodes {
    /// Generate new recovery codes.
    pub fn new(count: usize) -> Result<Self> {
        let codes = Self::generate_codes(count)?;
        let original_count = codes.len();
        Ok(Self {
            codes: codes.into_iter().collect(),
            original_count,
        })
    }

    /// Generate codes list.
    pub fn generate_codes(count: usize) -> Result<Vec<String>> {
        let rng = SystemRandom::new();
        let mut codes = Vec::with_capacity(count);

        for _ in 0..count {
            let mut bytes = [0u8; 4];
            rng.fill(&mut bytes).map_err(|_| ShieldError::RandomFailed)?;
            let code = format!(
                "{:04X}-{:04X}",
                u16::from_be_bytes([bytes[0], bytes[1]]),
                u16::from_be_bytes([bytes[2], bytes[3]])
            );
            codes.push(code);
        }

        Ok(codes)
    }

    /// Verify and consume a recovery code.
    pub fn verify(&mut self, code: &str) -> bool {
        let normalized = code.to_uppercase().replace([' ', '-'], "");
        let formatted = if normalized.len() == 8 {
            format!("{}-{}", &normalized[0..4], &normalized[4..8])
        } else {
            code.to_uppercase()
        };

        self.codes.remove(&formatted)
    }

    /// Get remaining code count.
    pub fn remaining(&self) -> usize {
        self.codes.len()
    }

    /// Get all codes (for display to user).
    pub fn codes(&self) -> Vec<String> {
        self.codes.iter().cloned().collect()
    }

    /// Check if any codes remain.
    pub fn has_codes(&self) -> bool {
        !self.codes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_totp_generate_verify() {
        let secret = TOTP::generate_secret().unwrap();
        let totp = TOTP::with_secret(secret);
        let code = totp.generate(None);
        assert!(totp.verify(&code, None, 1));
    }

    #[test]
    fn test_totp_known_vector() {
        // RFC 6238 test vector
        let secret = b"12345678901234567890".to_vec();
        let totp = TOTP::new(secret, 8, 30);
        let code = totp.generate(Some(59));
        assert_eq!(code, "94287082");
    }

    #[test]
    fn test_base32_roundtrip() {
        let secret = TOTP::generate_secret().unwrap();
        let encoded = TOTP::secret_to_base32(&secret);
        let decoded = TOTP::secret_from_base32(&encoded).unwrap();
        assert_eq!(secret, decoded);
    }

    #[test]
    fn test_recovery_codes() {
        let mut rc = RecoveryCodes::new(10).unwrap();
        assert_eq!(rc.remaining(), 10);

        let codes = rc.codes();
        assert!(rc.verify(&codes[0]));
        assert_eq!(rc.remaining(), 9);

        // Can't reuse
        assert!(!rc.verify(&codes[0]));
    }

    #[test]
    fn test_provisioning_uri() {
        let totp = TOTP::with_secret(vec![1, 2, 3, 4, 5]);
        let uri = totp.provisioning_uri("user@example.com", "TestApp");
        assert!(uri.starts_with("otpauth://totp/"));
        assert!(uri.contains("TestApp"));
    }
}
