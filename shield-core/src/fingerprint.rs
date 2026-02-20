//! Hardware fingerprinting for device-bound encryption.
//!
//! Collects platform-specific hardware identifiers to create device-bound keys.
//! Adapted from SaaSClient-SideLicensingSystem with enhanced cross-platform support.

use crate::error::{Result, ShieldError};
use std::process::Command;

/// Fingerprint collection mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FingerprintMode {
    /// No hardware fingerprinting (backward compatible).
    None,
    /// Use motherboard serial number only.
    Motherboard,
    /// Use CPU identifier only.
    CPU,
    /// Use combined motherboard + CPU (recommended).
    Combined,
}

impl Default for FingerprintMode {
    fn default() -> Self {
        Self::None
    }
}

/// Collect hardware fingerprint based on mode.
///
/// # Errors
/// Returns error if hardware identifiers cannot be collected.
///
/// # Platform Support
/// - **Windows**: wmic commands (baseboard, CPU)
/// - **Linux**: /sys/class/dmi/id, dmidecode, /proc/cpuinfo
/// - **macOS**: system_profiler SPHardwareDataType
pub fn collect_fingerprint(mode: FingerprintMode) -> Result<String> {
    match mode {
        FingerprintMode::None => Ok(String::new()),
        FingerprintMode::Motherboard => get_motherboard_serial(),
        FingerprintMode::CPU => get_cpu_id(),
        FingerprintMode::Combined => {
            let mut components = Vec::new();

            if let Ok(mb) = get_motherboard_serial() {
                components.push(mb);
            }

            if let Ok(cpu) = get_cpu_id() {
                components.push(cpu);
            }

            if components.is_empty() {
                return Err(ShieldError::FingerprintUnavailable);
            }

            // Create hash of combined components (matches SaaSClient)
            let combined = components.join("-");
            Ok(format!("{:x}", md5::compute(combined.as_bytes())))
        }
    }
}

/// Get motherboard serial number (platform-specific).
#[cfg(target_os = "windows")]
fn get_motherboard_serial() -> Result<String> {
    let output = Command::new("wmic")
        .args(&["baseboard", "get", "serialnumber", "/value"])
        .output()
        .map_err(|_| ShieldError::FingerprintUnavailable)?;

    let output_str = String::from_utf8_lossy(&output.stdout);
    for line in output_str.lines() {
        if line.starts_with("SerialNumber=") {
            let serial = line.replace("SerialNumber=", "").trim().to_string();
            if !serial.is_empty() && serial != "To be filled by O.E.M." {
                return Ok(serial);
            }
        }
    }
    Err(ShieldError::FingerprintUnavailable)
}

#[cfg(target_os = "linux")]
fn get_motherboard_serial() -> Result<String> {
    // Try DMI sysfs first (no elevated privileges needed)
    if let Ok(content) = std::fs::read_to_string("/sys/class/dmi/id/board_serial") {
        let serial = content.trim();
        if !serial.is_empty() && serial != "To be filled by O.E.M." {
            return Ok(serial.to_string());
        }
    }

    // Fallback to dmidecode (may require sudo)
    let output = Command::new("dmidecode")
        .args(&["-s", "baseboard-serial-number"])
        .output()
        .map_err(|_| ShieldError::FingerprintUnavailable)?;

    let serial = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if !serial.is_empty() && serial != "To be filled by O.E.M." {
        Ok(serial)
    } else {
        Err(ShieldError::FingerprintUnavailable)
    }
}

#[cfg(target_os = "macos")]
fn get_motherboard_serial() -> Result<String> {
    let output = Command::new("system_profiler")
        .args(&["SPHardwareDataType"])
        .output()
        .map_err(|_| ShieldError::FingerprintUnavailable)?;

    let output_str = String::from_utf8_lossy(&output.stdout);
    for line in output_str.lines() {
        if line.contains("Serial Number") {
            if let Some(serial) = line.split(':').nth(1) {
                return Ok(serial.trim().to_string());
            }
        }
    }
    Err(ShieldError::FingerprintUnavailable)
}

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
fn get_motherboard_serial() -> Result<String> {
    Err(ShieldError::FingerprintUnavailable)
}

/// Get CPU identifier (platform-specific).
#[cfg(target_os = "windows")]
fn get_cpu_id() -> Result<String> {
    let output = Command::new("wmic")
        .args(&["cpu", "get", "ProcessorId", "/value"])
        .output()
        .map_err(|_| ShieldError::FingerprintUnavailable)?;

    let output_str = String::from_utf8_lossy(&output.stdout);
    for line in output_str.lines() {
        if line.starts_with("ProcessorId=") {
            let cpu_id = line.replace("ProcessorId=", "").trim().to_string();
            if !cpu_id.is_empty() {
                return Ok(cpu_id);
            }
        }
    }
    Err(ShieldError::FingerprintUnavailable)
}

#[cfg(target_os = "linux")]
fn get_cpu_id() -> Result<String> {
    if let Ok(content) = std::fs::read_to_string("/proc/cpuinfo") {
        // Use first processor line as identifier
        for line in content.lines() {
            if line.starts_with("processor") && line.contains("0") {
                return Ok(format!("{:x}", md5::compute(line.as_bytes())));
            }
        }
    }
    Err(ShieldError::FingerprintUnavailable)
}

#[cfg(target_os = "macos")]
fn get_cpu_id() -> Result<String> {
    let output = Command::new("sysctl")
        .args(&["-n", "machdep.cpu.brand_string"])
        .output()
        .map_err(|_| ShieldError::FingerprintUnavailable)?;

    let cpu_info = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if !cpu_info.is_empty() {
        Ok(format!("{:x}", md5::compute(cpu_info.as_bytes())))
    } else {
        Err(ShieldError::FingerprintUnavailable)
    }
}

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
fn get_cpu_id() -> Result<String> {
    Err(ShieldError::FingerprintUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_none_mode() {
        let fp = collect_fingerprint(FingerprintMode::None).unwrap();
        assert_eq!(fp, "");
    }

    #[test]
    fn test_combined_mode() {
        // This test may fail on systems without accessible hardware IDs
        // In CI/CD, consider mocking or skipping
        match collect_fingerprint(FingerprintMode::Combined) {
            Ok(fp) => {
                assert!(!fp.is_empty());
                assert_eq!(fp.len(), 32); // MD5 hex string
            }
            Err(ShieldError::FingerprintUnavailable) => {
                // Expected on VMs or restricted environments
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }
}
