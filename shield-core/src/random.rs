//! Cross-platform secure random number generation.
//!
//! Uses `ring::rand::SystemRandom` on native targets and `getrandom` on WASM.

use crate::error::{Result, ShieldError};

/// Fill a buffer with cryptographically secure random bytes.
///
/// # Errors
/// Returns `ShieldError::RandomFailed` if the system RNG fails.
#[cfg(not(target_arch = "wasm32"))]
pub fn fill_random_bytes(buf: &mut [u8]) -> Result<()> {
    use ring::rand::{SecureRandom, SystemRandom};
    let rng = SystemRandom::new();
    rng.fill(buf).map_err(|_| ShieldError::RandomFailed)
}

/// Fill a buffer with cryptographically secure random bytes (WASM version).
///
/// # Errors
/// Returns `ShieldError::RandomFailed` if the system RNG fails.
#[cfg(target_arch = "wasm32")]
pub fn fill_random_bytes(buf: &mut [u8]) -> Result<()> {
    getrandom::getrandom(buf).map_err(|_| ShieldError::RandomFailed)
}

/// Generate a fixed-size random byte array.
///
/// # Errors
/// Returns `ShieldError::RandomFailed` if the system RNG fails.
pub fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut buf = [0u8; N];
    fill_random_bytes(&mut buf)?;
    Ok(buf)
}

/// Generate a random Vec of specified size.
///
/// # Errors
/// Returns `ShieldError::RandomFailed` if the system RNG fails.
pub fn random_vec(size: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; size];
    fill_random_bytes(&mut buf)?;
    Ok(buf)
}
