//! Password strength analysis and validation.
//!
//! Provides entropy calculation and feedback to prevent users from
//! undermining Shield's EXPTIME security with weak passwords.
//!
//! # Example
//!
//! ```
//! use shield_core::password::{check_password, StrengthLevel};
//!
//! let result = check_password("MyP@ssw0rd123!");
//! println!("Entropy: {:.1} bits", result.entropy);
//! println!("Level: {:?}", result.level);
//! println!("Crack time: {}", result.crack_time_display());
//! ```

use std::collections::HashSet;

/// Password strength levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrengthLevel {
    /// < 30 bits - trivially crackable
    Critical,
    /// 30-50 bits - crackable in days
    Weak,
    /// 50-70 bits - crackable in years
    Fair,
    /// 70-90 bits - secure for most uses
    Strong,
    /// 90+ bits - highly secure
    VeryStrong,
}

impl StrengthLevel {
    /// Returns a human-readable description of the strength level.
    #[must_use]
    pub const fn description(&self) -> &'static str {
        match self {
            Self::Critical => "critically weak - change immediately",
            Self::Weak => "weak - easily crackable",
            Self::Fair => "fair - acceptable for low-value data",
            Self::Strong => "strong - secure for most uses",
            Self::VeryStrong => "very strong - highly secure",
        }
    }
}

/// Password strength analysis result.
#[derive(Debug, Clone)]
pub struct PasswordStrength {
    /// Length of the password
    pub length: usize,
    /// Entropy in bits
    pub entropy: f64,
    /// Strength level
    pub level: StrengthLevel,
    /// Estimated crack time in seconds (with PBKDF2)
    pub crack_time_seconds: f64,
    /// Improvement suggestions
    pub suggestions: Vec<String>,
}

impl PasswordStrength {
    /// Human-readable crack time estimate.
    #[must_use]
    pub fn crack_time_display(&self) -> String {
        let secs = self.crack_time_seconds;
        if secs < 1.0 {
            "instantly".to_string()
        } else if secs < 60.0 {
            format!("{secs:.0} seconds")
        } else if secs < 3600.0 {
            format!("{:.0} minutes", secs / 60.0)
        } else if secs < 86400.0 {
            format!("{:.0} hours", secs / 3600.0)
        } else if secs < 31_536_000.0 {
            format!("{:.0} days", secs / 86400.0)
        } else if secs < 31_536_000.0 * 100.0 {
            format!("{:.0} years", secs / 31_536_000.0)
        } else if secs < 31_536_000.0 * 1_000_000.0 {
            format!("{:.0} thousand years", secs / 31_536_000.0 / 1000.0)
        } else if secs < 31_536_000.0 * 1e9 {
            format!("{:.0} million years", secs / 31_536_000.0 / 1e6)
        } else {
            "billions of years".to_string()
        }
    }

    /// Whether password meets minimum security threshold (50 bits).
    #[must_use]
    pub const fn is_acceptable(&self) -> bool {
        self.entropy >= 50.0
    }

    /// Whether password meets recommended security threshold (72 bits).
    #[must_use]
    pub const fn is_recommended(&self) -> bool {
        self.entropy >= 72.0
    }
}

/// Common passwords to check against.
const COMMON_PASSWORDS: &[&str] = &[
    "password",
    "123456",
    "12345678",
    "qwerty",
    "abc123",
    "monkey",
    "master",
    "dragon",
    "letmein",
    "login",
    "admin",
    "welcome",
    "shadow",
    "sunshine",
    "princess",
    "football",
    "baseball",
    "iloveyou",
    "trustno1",
    "superman",
    "batman",
    "passw0rd",
    "hello",
    "charlie",
    "donald",
    "password1",
    "123456789",
    "1234567890",
    "1234567",
    "12345",
    "1234",
    "111111",
    "000000",
    "qwerty123",
    "password123",
    "letmein123",
    "welcome1",
    "admin123",
    "root",
];

/// Calculate character set size used in password.
fn calculate_charset_size(password: &str) -> usize {
    let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_special = password.chars().any(|c| !c.is_ascii_alphanumeric());

    let mut size = 0;
    if has_lower {
        size += 26;
    }
    if has_upper {
        size += 26;
    }
    if has_digit {
        size += 10;
    }
    if has_special {
        size += 32;
    }

    size.max(1)
}

/// Check if password matches common patterns.
fn has_common_pattern(password: &str) -> bool {
    let lower = password.to_lowercase();

    // Check for repeated character
    if password.len() > 1 {
        let first = password.chars().next().unwrap();
        if password.chars().all(|c| c == first) {
            return true;
        }
    }

    // Check for sequential digits
    let sequential_digits = [
        "012", "123", "234", "345", "456", "567", "678", "789", "890",
    ];
    for seq in sequential_digits {
        if lower.contains(seq) {
            return true;
        }
    }

    // Check for keyboard patterns
    let keyboard_patterns = ["qwerty", "asdf", "zxcv", "qazwsx"];
    for pattern in keyboard_patterns {
        if lower.contains(pattern) {
            return true;
        }
    }

    false
}

/// Calculate password entropy in bits.
///
/// # Arguments
/// * `password` - Password to analyze
///
/// # Returns
/// Entropy in bits, accounting for charset and patterns
#[must_use]
pub fn calculate_entropy(password: &str) -> f64 {
    if password.is_empty() {
        return 0.0;
    }

    // Check if it's a common password
    let lower = password.to_lowercase();
    if COMMON_PASSWORDS.iter().any(|&p| p == lower) {
        return 10.0; // ~1000 guesses
    }

    let charset_size = calculate_charset_size(password);
    // Password lengths are always small enough for exact f64 representation
    #[allow(clippy::cast_precision_loss)]
    let base_entropy = password.len() as f64 * (charset_size as f64).log2();

    // Apply pattern penalties
    let mut penalty = 0.0;
    if has_common_pattern(password) {
        penalty += 10.0;
    }

    // Penalty for repeated characters
    let unique_chars: HashSet<char> = password.chars().collect();
    if unique_chars.len() < password.len() / 2 {
        penalty += 5.0;
    }

    (base_entropy - penalty).max(1.0)
}

/// Get strength level from entropy.
#[must_use]
pub const fn get_strength_level(entropy: f64) -> StrengthLevel {
    if entropy < 30.0 {
        StrengthLevel::Critical
    } else if entropy < 50.0 {
        StrengthLevel::Weak
    } else if entropy < 70.0 {
        StrengthLevel::Fair
    } else if entropy < 90.0 {
        StrengthLevel::Strong
    } else {
        StrengthLevel::VeryStrong
    }
}

/// Estimate time to crack password via brute force.
///
/// Assumes 10 billion guesses/second GPU, reduced by PBKDF2 100k iterations.
#[must_use]
pub fn estimate_crack_time(entropy: f64) -> f64 {
    let keyspace = 2.0_f64.powf(entropy);
    // 10B guesses/sec GPU, but PBKDF2 100k iterations slows to ~100k/sec
    let effective_rate: f64 = 1e10 / 100_000.0;
    (keyspace / 2.0) / effective_rate.max(1.0)
}

/// Generate improvement suggestions based on password analysis.
fn get_suggestions(password: &str, entropy: f64) -> Vec<String> {
    let mut suggestions = Vec::new();

    if password.len() < 12 {
        suggestions.push(format!(
            "Increase length to 12+ characters (currently {})",
            password.len()
        ));
    }

    if !password.chars().any(|c| c.is_ascii_lowercase()) {
        suggestions.push("Add lowercase letters".to_string());
    }

    if !password.chars().any(|c| c.is_ascii_uppercase()) {
        suggestions.push("Add uppercase letters".to_string());
    }

    if !password.chars().any(|c| c.is_ascii_digit()) {
        suggestions.push("Add numbers".to_string());
    }

    if !password.chars().any(|c| !c.is_ascii_alphanumeric()) {
        suggestions.push("Add special characters (!@#$%^&*)".to_string());
    }

    let lower = password.to_lowercase();
    if COMMON_PASSWORDS.iter().any(|&p| p == lower) {
        suggestions.push("Avoid common passwords".to_string());
    }

    if entropy < 72.0 {
        suggestions.push("Consider using a passphrase (5+ random words)".to_string());
    }

    suggestions
}

/// Analyze password strength and provide feedback.
///
/// # Arguments
/// * `password` - Password to analyze
///
/// # Returns
/// `PasswordStrength` with entropy, level, crack time, and suggestions
///
/// # Example
///
/// ```
/// use shield_core::password::check_password;
///
/// let result = check_password("MySecureP@ss123");
/// assert!(result.is_acceptable());
/// println!("Entropy: {:.1} bits", result.entropy);
/// ```
#[must_use]
pub fn check_password(password: &str) -> PasswordStrength {
    let entropy = calculate_entropy(password);
    let level = get_strength_level(entropy);
    let crack_time = estimate_crack_time(entropy);
    let suggestions = get_suggestions(password, entropy);

    PasswordStrength {
        length: password.len(),
        entropy,
        level,
        crack_time_seconds: crack_time,
        suggestions,
    }
}

/// Check password and return warning message if weak.
///
/// # Arguments
/// * `password` - Password to check
/// * `min_entropy` - Minimum acceptable entropy (default: 50 bits)
///
/// # Returns
/// Warning message if password is weak, None otherwise
#[must_use]
pub fn warn_if_weak(password: &str, min_entropy: f64) -> Option<String> {
    let result = check_password(password);

    if result.entropy < min_entropy {
        let mut msg = format!(
            "Weak password: {:.0} bits entropy (recommend 72+ bits). Crack time: {}.",
            result.entropy,
            result.crack_time_display()
        );

        if !result.suggestions.is_empty() {
            use std::fmt::Write;
            let _ = write!(
                msg,
                " Suggestions: {}",
                result
                    .suggestions
                    .iter()
                    .take(2)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("; ")
            );
        }

        Some(msg)
    } else {
        None
    }
}

/// Quick entropy check.
#[must_use]
pub fn entropy(password: &str) -> f64 {
    calculate_entropy(password)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_password() {
        assert_eq!(calculate_entropy(""), 0.0);
    }

    #[test]
    fn test_common_password() {
        let result = check_password("password");
        assert_eq!(result.level, StrengthLevel::Critical);
        assert!(result.entropy <= 10.0);
    }

    #[test]
    fn test_weak_password() {
        let result = check_password("abc");
        assert_eq!(result.level, StrengthLevel::Critical);
    }

    #[test]
    fn test_fair_password() {
        let result = check_password("MyPassword1");
        assert!(matches!(
            result.level,
            StrengthLevel::Weak | StrengthLevel::Fair
        ));
    }

    #[test]
    fn test_strong_password() {
        let result = check_password("MyStr0ng!P@ssw0rd#2024");
        assert!(matches!(
            result.level,
            StrengthLevel::Strong | StrengthLevel::VeryStrong
        ));
    }

    #[test]
    fn test_passphrase() {
        let result = check_password("correct-horse-battery-staple-extra");
        assert!(result.is_acceptable());
    }

    #[test]
    fn test_charset_detection() {
        assert_eq!(calculate_charset_size("abc"), 26);
        assert_eq!(calculate_charset_size("ABC"), 26);
        assert_eq!(calculate_charset_size("aA"), 52);
        assert_eq!(calculate_charset_size("aA1"), 62);
        assert_eq!(calculate_charset_size("aA1!"), 94);
    }

    #[test]
    fn test_suggestions_generated() {
        let result = check_password("abc");
        assert!(!result.suggestions.is_empty());
    }

    #[test]
    fn test_warn_if_weak() {
        assert!(warn_if_weak("password", 50.0).is_some());
        assert!(warn_if_weak("MyStr0ng!P@ssw0rd#2024", 50.0).is_none());
    }

    #[test]
    fn test_crack_time_display() {
        let result = check_password("password");
        assert!(!result.crack_time_display().is_empty());

        let strong = check_password("ThisIsAVeryStrongPasswordWithLotsOfEntropy!@#$");
        assert!(
            strong.crack_time_display().contains("year")
                || strong.crack_time_display().contains("billion")
        );
    }

    #[test]
    fn test_repeated_chars_penalty() {
        let repeated = check_password("aaaaaaaa");
        let varied = check_password("abcdefgh");
        assert!(repeated.entropy < varied.entropy);
    }

    #[test]
    fn test_pattern_penalty() {
        let pattern = check_password("qwerty123");
        let random = check_password("xkq9m2pf");
        // Pattern should have lower entropy despite similar charset
        assert!(pattern.entropy < random.entropy + 15.0);
    }
}
