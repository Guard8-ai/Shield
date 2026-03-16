use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time;
use tracing::{debug, error, info, warn};

use crate::config::DnsSection;
use crate::metrics::MetricsCollector;

/// DNS forwarder with multi-upstream failover and health checking.
pub struct DnsForwarder {
    config: DnsSection,
    metrics: MetricsCollector,
}

/// Per-upstream resolver state.
struct ResolverState {
    address: String,
    priority: u32,
    healthy: Arc<AtomicBool>,
}

/// Maximum DNS UDP packet size.
const MAX_DNS_PACKET: usize = 4096;

/// DNS root query for health checks (minimal query for "." type A).
const HEALTH_CHECK_QUERY: &[u8] = &[
    0x00, 0x01, // Transaction ID
    0x01, 0x00, // Standard query
    0x00, 0x01, // Questions: 1
    0x00, 0x00, // Answers: 0
    0x00, 0x00, // Authority: 0
    0x00, 0x00, // Additional: 0
    0x00,       // Root domain
    0x00, 0x01, // Type: A
    0x00, 0x01, // Class: IN
];

impl DnsForwarder {
    pub fn new(config: DnsSection, metrics: MetricsCollector) -> Self {
        Self { config, metrics }
    }

    /// Run the DNS forwarder, listening for UDP queries and forwarding them.
    pub async fn run(&self) -> Result<(), std::io::Error> {
        let socket = Arc::new(UdpSocket::bind(&self.config.bind_address).await?);
        info!(bind = %self.config.bind_address, "DNS forwarder listening");

        // Build resolver list sorted by priority
        let mut resolvers: Vec<ResolverState> = self.config.upstreams.iter().map(|u| {
            ResolverState {
                address: u.address.clone(),
                priority: u.priority,
                healthy: Arc::new(AtomicBool::new(true)),
            }
        }).collect();
        resolvers.sort_by_key(|r| r.priority);

        // Spawn health checker for each resolver
        for resolver in &resolvers {
            let addr = resolver.address.clone();
            let healthy = Arc::clone(&resolver.healthy);
            let interval = self.config.health_check_interval_secs;
            let timeout_ms = self.config.timeout_ms;

            tokio::spawn(async move {
                health_check_loop(&addr, healthy, interval, timeout_ms).await;
            });
        }

        let mut buf = [0u8; MAX_DNS_PACKET];

        loop {
            let (len, client_addr) = socket.recv_from(&mut buf).await?;
            let query = buf[..len].to_vec();

            self.metrics.inc_dns_queries();

            let resolvers_snapshot: Vec<(String, bool)> = resolvers.iter().map(|r| {
                (r.address.clone(), r.healthy.load(Ordering::Relaxed))
            }).collect();

            let socket_clone = Arc::clone(&socket);
            let metrics = self.metrics.clone();
            let timeout_ms = self.config.timeout_ms;

            tokio::spawn(async move {
                match forward_query(&query, &resolvers_snapshot, timeout_ms).await {
                    Some(response) => {
                        if let Err(e) = socket_clone.send_to(&response, client_addr).await {
                            warn!(client = %client_addr, error = %e, "Failed to send DNS response");
                        }
                    }
                    None => {
                        metrics.inc_dns_failures();
                        warn!(client = %client_addr, "All DNS upstreams failed");
                    }
                }
            });
        }
    }
}

/// Forward a DNS query to the first healthy upstream, with failover.
async fn forward_query(
    query: &[u8],
    resolvers: &[(String, bool)],
    timeout_ms: u64,
) -> Option<Vec<u8>> {
    // Try healthy resolvers first (already sorted by priority)
    for (addr, healthy) in resolvers {
        if !healthy {
            continue;
        }
        if let Some(response) = try_resolver(query, addr, timeout_ms).await {
            return Some(response);
        }
    }

    // Fallback: try unhealthy resolvers as last resort
    for (addr, healthy) in resolvers {
        if *healthy {
            continue;
        }
        debug!(resolver = %addr, "Trying unhealthy resolver as fallback");
        if let Some(response) = try_resolver(query, addr, timeout_ms).await {
            return Some(response);
        }
    }

    None
}

/// Try forwarding a query to a single resolver with timeout.
async fn try_resolver(query: &[u8], addr: &str, timeout_ms: u64) -> Option<Vec<u8>> {
    let socket = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    socket.send_to(query, addr).await.ok()?;

    let mut buf = [0u8; MAX_DNS_PACKET];
    match time::timeout(Duration::from_millis(timeout_ms), socket.recv_from(&mut buf)).await {
        Ok(Ok((len, _))) => Some(buf[..len].to_vec()),
        _ => None,
    }
}

/// Periodically check resolver health by sending a DNS root query.
async fn health_check_loop(
    addr: &str,
    healthy: Arc<AtomicBool>,
    interval_secs: u64,
    timeout_ms: u64,
) {
    let mut interval = time::interval(Duration::from_secs(interval_secs));
    let mut consecutive_failures: u32 = 0;
    loop {
        interval.tick().await;

        let was_healthy = healthy.load(Ordering::Relaxed);
        let is_healthy = try_resolver(HEALTH_CHECK_QUERY, addr, timeout_ms).await.is_some();
        healthy.store(is_healthy, Ordering::Relaxed);

        if was_healthy && !is_healthy {
            consecutive_failures = 1;
            warn!(resolver = %addr, "DNS resolver went DOWN");
        } else if !is_healthy {
            consecutive_failures = consecutive_failures.saturating_add(1);
            if consecutive_failures.is_multiple_of(10) {
                error!(resolver = %addr, failures = consecutive_failures, "DNS resolver still DOWN");
            }
        } else if !was_healthy && is_healthy {
            consecutive_failures = 0;
            info!(resolver = %addr, "DNS resolver recovered");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_check_query_valid() {
        // Verify health check query is at least a minimal DNS packet
        assert!(HEALTH_CHECK_QUERY.len() >= 12, "DNS header must be at least 12 bytes");
        // Transaction ID
        assert_eq!(HEALTH_CHECK_QUERY[0], 0x00);
        assert_eq!(HEALTH_CHECK_QUERY[1], 0x01);
        // Flags: standard query
        assert_eq!(HEALTH_CHECK_QUERY[2], 0x01);
        // Questions count: 1
        assert_eq!(HEALTH_CHECK_QUERY[4], 0x00);
        assert_eq!(HEALTH_CHECK_QUERY[5], 0x01);
    }

    #[tokio::test]
    async fn test_forward_no_resolvers() {
        let result = forward_query(HEALTH_CHECK_QUERY, &[], 100).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_forward_all_unhealthy_fallback() {
        // All resolvers marked unhealthy, with unreachable addresses
        let resolvers = vec![
            ("127.0.0.1:19999".to_string(), false),
        ];
        // Should try the unhealthy resolver as fallback (will timeout)
        let result = forward_query(HEALTH_CHECK_QUERY, &resolvers, 50).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_dns_forwarder_creation() {
        let config = DnsSection {
            bind_address: "127.0.0.1:0".to_string(),
            upstreams: vec![],
            timeout_ms: 1000,
            health_check_interval_secs: 10,
        };
        let metrics = MetricsCollector::new();
        let forwarder = DnsForwarder::new(config, metrics);
        assert!(forwarder.config.upstreams.is_empty());
    }

    #[tokio::test]
    async fn test_try_resolver_timeout() {
        // Connect to a port that won't respond
        let result = try_resolver(HEALTH_CHECK_QUERY, "127.0.0.1:19998", 50).await;
        assert!(result.is_none());
    }
}
