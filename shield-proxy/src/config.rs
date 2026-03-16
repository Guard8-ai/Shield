use std::path::Path;

use serde::Deserialize;

/// Top-level proxy configuration loaded from TOML.
#[derive(Debug, Clone, Deserialize)]
pub struct ProxyConfig {
    #[serde(default)]
    pub proxy: ProxySection,
    pub dns: Option<DnsSection>,
    #[serde(default)]
    pub upstream: Vec<UpstreamTarget>,
    #[serde(default)]
    pub shield: ShieldSection,
    pub redundancy: Option<RedundancySection>,
    #[serde(default)]
    pub metrics: MetricsSection,
    #[serde(default)]
    pub logging: LoggingSection,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProxySection {
    #[serde(default = "default_proxy_bind")]
    pub bind_address: String,
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    #[serde(default = "default_shutdown_timeout")]
    pub shutdown_timeout_secs: u64,
}

impl Default for ProxySection {
    fn default() -> Self {
        Self {
            bind_address: default_proxy_bind(),
            max_connections: default_max_connections(),
            shutdown_timeout_secs: default_shutdown_timeout(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct DnsSection {
    #[serde(default = "default_dns_bind")]
    pub bind_address: String,
    #[serde(default)]
    pub upstreams: Vec<DnsUpstream>,
    #[serde(default = "default_dns_timeout")]
    pub timeout_ms: u64,
    #[serde(default = "default_health_interval")]
    pub health_check_interval_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DnsUpstream {
    pub address: String,
    #[serde(default = "default_priority")]
    pub priority: u32,
    #[serde(default = "default_weight")]
    pub weight: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpstreamTarget {
    pub name: String,
    pub address: String,
    #[serde(default = "default_protocol")]
    pub protocol: String,
    #[serde(default)]
    pub shield_encrypt: bool,
    pub shield_key: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ShieldSection {
    #[serde(default = "default_shield_password")]
    pub password: String,
    #[serde(default = "default_shield_service")]
    pub service: String,
    #[serde(default = "default_replay_ttl")]
    pub replay_ttl_secs: u64,
}

impl Default for ShieldSection {
    fn default() -> Self {
        Self {
            password: default_shield_password(),
            service: default_shield_service(),
            replay_ttl_secs: default_replay_ttl(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RedundancySection {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_peer_address")]
    pub peer_address: String,
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval_ms: u64,
    #[serde(default = "default_failover_timeout")]
    pub failover_timeout_ms: u64,
    pub virtual_ip: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MetricsSection {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_metrics_bind")]
    pub bind_address: String,
    #[serde(default = "default_metrics_path")]
    pub path: String,
}

impl Default for MetricsSection {
    fn default() -> Self {
        Self {
            enabled: true,
            bind_address: default_metrics_bind(),
            path: default_metrics_path(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoggingSection {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_log_format")]
    pub format: String,
}

impl Default for LoggingSection {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
        }
    }
}

// Default value functions
fn default_proxy_bind() -> String { "0.0.0.0:8443".to_string() }
fn default_max_connections() -> usize { 10_000 }
fn default_shutdown_timeout() -> u64 { 30 }
fn default_dns_bind() -> String { "0.0.0.0:5353".to_string() }
fn default_dns_timeout() -> u64 { 2000 }
fn default_health_interval() -> u64 { 10 }
fn default_priority() -> u32 { 1 }
fn default_weight() -> u32 { 1 }
fn default_protocol() -> String { "tcp".to_string() }
fn default_shield_password() -> String { String::new() }
fn default_shield_service() -> String { "shield-proxy".to_string() }
fn default_replay_ttl() -> u64 { 60 }
fn default_peer_address() -> String { "127.0.0.1:8444".to_string() }
fn default_heartbeat_interval() -> u64 { 500 }
fn default_failover_timeout() -> u64 { 3000 }
fn default_true() -> bool { true }
fn default_metrics_bind() -> String { "0.0.0.0:9090".to_string() }
fn default_metrics_path() -> String { "/metrics".to_string() }
fn default_log_level() -> String { "info".to_string() }
fn default_log_format() -> String { "text".to_string() }

/// Configuration validation errors.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Failed to read config file: {0}")]
    Io(#[from] std::io::Error),
    #[error("Failed to parse TOML: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("Validation error: {0}")]
    Validation(String),
}

impl ProxyConfig {
    /// Load configuration from file or defaults.
    ///
    /// Checks `SHIELD_PROXY_CONFIG` env var, then `./shield-proxy.toml`,
    /// then falls back to defaults.
    pub fn load() -> Result<Self, ConfigError> {
        let path = std::env::var("SHIELD_PROXY_CONFIG")
            .unwrap_or_else(|_| "shield-proxy.toml".to_string());

        if Path::new(&path).exists() {
            let content = std::fs::read_to_string(&path)?;
            let config: Self = toml::from_str(&content)?;
            config.validate()?;
            Ok(config)
        } else {
            // Use defaults — valid for development/testing
            let config: Self = toml::from_str("")?;
            Ok(config)
        }
    }

    /// Load from a TOML string (used in tests).
    pub fn from_toml(content: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(content)?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.proxy.max_connections == 0 {
            return Err(ConfigError::Validation(
                "max_connections must be > 0".to_string(),
            ));
        }
        // Validate upstream targets have addresses
        for upstream in &self.upstream {
            if upstream.address.is_empty() {
                return Err(ConfigError::Validation(format!(
                    "upstream '{}' has empty address",
                    upstream.name
                )));
            }
            if upstream.shield_encrypt && upstream.shield_key.is_none() && self.shield.password.is_empty() {
                return Err(ConfigError::Validation(format!(
                    "upstream '{}' has shield_encrypt=true but no key or password configured",
                    upstream.name
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ProxyConfig::from_toml("").unwrap();
        assert_eq!(config.proxy.bind_address, "0.0.0.0:8443");
        assert_eq!(config.proxy.max_connections, 10_000);
        assert!(config.metrics.enabled);
        assert_eq!(config.metrics.bind_address, "0.0.0.0:9090");
    }

    #[test]
    fn test_full_config() {
        let toml = r#"
[proxy]
bind_address = "0.0.0.0:9443"
max_connections = 5000
shutdown_timeout_secs = 60

[dns]
bind_address = "0.0.0.0:5353"
timeout_ms = 3000
health_check_interval_secs = 15

[[dns.upstreams]]
address = "8.8.8.8:53"
priority = 1

[[dns.upstreams]]
address = "1.1.1.1:53"
priority = 2

[[upstream]]
name = "web"
address = "10.0.0.1:80"
protocol = "tcp"
shield_encrypt = false

[shield]
password = "test-password"
service = "my-proxy"
replay_ttl_secs = 120

[redundancy]
enabled = true
peer_address = "10.0.0.2:8444"
heartbeat_interval_ms = 250
failover_timeout_ms = 2000

[metrics]
enabled = true
bind_address = "0.0.0.0:9091"

[logging]
level = "debug"
format = "json"
"#;
        let config = ProxyConfig::from_toml(toml).unwrap();
        assert_eq!(config.proxy.bind_address, "0.0.0.0:9443");
        assert_eq!(config.proxy.max_connections, 5000);
        let dns = config.dns.unwrap();
        assert_eq!(dns.upstreams.len(), 2);
        assert_eq!(dns.upstreams[0].address, "8.8.8.8:53");
        assert_eq!(config.upstream.len(), 1);
        assert_eq!(config.upstream[0].name, "web");
        assert_eq!(config.shield.password, "test-password");
        let redundancy = config.redundancy.unwrap();
        assert!(redundancy.enabled);
        assert_eq!(redundancy.heartbeat_interval_ms, 250);
        assert_eq!(config.metrics.bind_address, "0.0.0.0:9091");
        assert_eq!(config.logging.level, "debug");
    }

    #[test]
    fn test_validation_zero_max_connections() {
        let toml = r#"
[proxy]
max_connections = 0
"#;
        let result = ProxyConfig::from_toml(toml);
        assert!(result.is_err());
    }

    #[test]
    fn test_validation_encrypt_without_key() {
        let toml = r#"
[[upstream]]
name = "secure"
address = "10.0.0.1:443"
shield_encrypt = true
"#;
        let result = ProxyConfig::from_toml(toml);
        assert!(result.is_err());
    }

    #[test]
    fn test_validation_encrypt_with_password() {
        let toml = r#"
[shield]
password = "my-secret"

[[upstream]]
name = "secure"
address = "10.0.0.1:443"
shield_encrypt = true
"#;
        let config = ProxyConfig::from_toml(toml).unwrap();
        assert!(config.upstream[0].shield_encrypt);
    }
}
