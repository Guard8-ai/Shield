use std::sync::Arc;
use std::time::Instant;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use prometheus::{
    Encoder, IntCounter, IntGauge, Registry, TextEncoder,
};
use tracing::info;

use crate::config::MetricsSection;

/// Collects and exposes proxy metrics in Prometheus format.
#[derive(Clone)]
pub struct MetricsCollector {
    inner: Arc<MetricsInner>,
}

struct MetricsInner {
    registry: Registry,
    start_time: Instant,

    // Connection metrics
    connections_total: IntCounter,
    connections_active: IntGauge,
    bytes_forwarded: IntCounter,

    // DNS metrics
    dns_queries_total: IntCounter,
    dns_failures_total: IntCounter,

    // Shield metrics
    shield_encryptions_total: IntCounter,
    shield_decryptions_total: IntCounter,
    shield_errors_total: IntCounter,

    // Redundancy metrics
    redundancy_role: IntGauge,
    heartbeats_sent_total: IntCounter,
    failovers_total: IntCounter,
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsCollector {
    pub fn new() -> Self {
        let registry = Registry::new();

        let connections_total = IntCounter::new(
            "shield_proxy_connections_total",
            "Total number of connections accepted",
        ).unwrap();
        let connections_active = IntGauge::new(
            "shield_proxy_connections_active",
            "Number of currently active connections",
        ).unwrap();
        let bytes_forwarded = IntCounter::new(
            "shield_proxy_bytes_forwarded_total",
            "Total bytes forwarded",
        ).unwrap();
        let dns_queries_total = IntCounter::new(
            "shield_proxy_dns_queries_total",
            "Total DNS queries received",
        ).unwrap();
        let dns_failures_total = IntCounter::new(
            "shield_proxy_dns_failures_total",
            "Total DNS query failures",
        ).unwrap();
        let shield_encryptions_total = IntCounter::new(
            "shield_proxy_shield_encryptions_total",
            "Total Shield encryption operations",
        ).unwrap();
        let shield_decryptions_total = IntCounter::new(
            "shield_proxy_shield_decryptions_total",
            "Total Shield decryption operations",
        ).unwrap();
        let shield_errors_total = IntCounter::new(
            "shield_proxy_shield_errors_total",
            "Total Shield encryption/decryption errors",
        ).unwrap();
        let redundancy_role = IntGauge::new(
            "shield_proxy_redundancy_role",
            "Current redundancy role (1=active, 0=standby)",
        ).unwrap();
        let heartbeats_sent_total = IntCounter::new(
            "shield_proxy_heartbeats_sent_total",
            "Total heartbeat messages sent",
        ).unwrap();
        let failovers_total = IntCounter::new(
            "shield_proxy_failovers_total",
            "Total failover events",
        ).unwrap();

        registry.register(Box::new(connections_total.clone())).unwrap();
        registry.register(Box::new(connections_active.clone())).unwrap();
        registry.register(Box::new(bytes_forwarded.clone())).unwrap();
        registry.register(Box::new(dns_queries_total.clone())).unwrap();
        registry.register(Box::new(dns_failures_total.clone())).unwrap();
        registry.register(Box::new(shield_encryptions_total.clone())).unwrap();
        registry.register(Box::new(shield_decryptions_total.clone())).unwrap();
        registry.register(Box::new(shield_errors_total.clone())).unwrap();
        registry.register(Box::new(redundancy_role.clone())).unwrap();
        registry.register(Box::new(heartbeats_sent_total.clone())).unwrap();
        registry.register(Box::new(failovers_total.clone())).unwrap();

        Self {
            inner: Arc::new(MetricsInner {
                registry,
                start_time: Instant::now(),
                connections_total,
                connections_active,
                bytes_forwarded,
                dns_queries_total,
                dns_failures_total,
                shield_encryptions_total,
                shield_decryptions_total,
                shield_errors_total,
                redundancy_role,
                heartbeats_sent_total,
                failovers_total,
            }),
        }
    }

    // Connection metrics
    pub fn inc_connections_total(&self) { self.inner.connections_total.inc(); }
    pub fn set_connections_active(&self, v: u64) { self.inner.connections_active.set(v.cast_signed()); }
    pub fn add_bytes_forwarded(&self, v: u64) { self.inner.bytes_forwarded.inc_by(v); }

    // DNS metrics
    pub fn inc_dns_queries(&self) { self.inner.dns_queries_total.inc(); }
    pub fn inc_dns_failures(&self) { self.inner.dns_failures_total.inc(); }

    // Shield metrics
    pub fn inc_shield_encryptions(&self) { self.inner.shield_encryptions_total.inc(); }
    pub fn inc_shield_decryptions(&self) { self.inner.shield_decryptions_total.inc(); }
    pub fn inc_shield_errors(&self) { self.inner.shield_errors_total.inc(); }

    // Redundancy metrics
    pub fn set_redundancy_role(&self, v: i64) { self.inner.redundancy_role.set(v); }
    pub fn inc_heartbeats_sent(&self) { self.inner.heartbeats_sent_total.inc(); }
    pub fn inc_failovers(&self) { self.inner.failovers_total.inc(); }

    /// Uptime in seconds.
    pub fn uptime_secs(&self) -> u64 { self.inner.start_time.elapsed().as_secs() }

    /// Encode all metrics in Prometheus text format.
    pub fn encode_prometheus(&self) -> String {
        let encoder = TextEncoder::new();
        let metric_families = self.inner.registry.gather();
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer).unwrap();
        String::from_utf8(buffer).unwrap()
    }
}

/// HTTP server for metrics and health endpoints.
pub struct MetricsServer {
    config: MetricsSection,
    metrics: MetricsCollector,
}

impl MetricsServer {
    pub fn new(config: MetricsSection, metrics: MetricsCollector) -> Self {
        Self { config, metrics }
    }

    /// Run the metrics HTTP server.
    pub async fn run(self) -> Result<(), std::io::Error> {
        let app = Router::new()
            .route(&self.config.path, get(metrics_handler))
            .route("/health", get(health_handler))
            .with_state(self.metrics.clone());

        let listener = tokio::net::TcpListener::bind(&self.config.bind_address).await?;
        info!(bind = %self.config.bind_address, "Metrics server listening");

        axum::serve(listener, app).await?;
        Ok(())
    }
}

async fn metrics_handler(
    State(metrics): State<MetricsCollector>,
) -> impl IntoResponse {
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        metrics.encode_prometheus(),
    )
}

async fn health_handler(
    State(metrics): State<MetricsCollector>,
) -> impl IntoResponse {
    let health = serde_json::json!({
        "status": "healthy",
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_secs": metrics.uptime_secs(),
    });

    (
        StatusCode::OK,
        [("content-type", "application/json")],
        health.to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_collector_creation() {
        let metrics = MetricsCollector::new();
        assert!(metrics.uptime_secs() < 2);
    }

    #[test]
    fn test_metrics_increment() {
        let metrics = MetricsCollector::new();
        metrics.inc_connections_total();
        metrics.inc_connections_total();
        metrics.inc_dns_queries();
        metrics.inc_shield_encryptions();
        metrics.inc_shield_decryptions();
        metrics.inc_shield_errors();
        metrics.inc_heartbeats_sent();
        metrics.inc_failovers();
        metrics.set_connections_active(5);
        metrics.add_bytes_forwarded(1024);
        metrics.set_redundancy_role(1);

        let output = metrics.encode_prometheus();
        assert!(output.contains("shield_proxy_connections_total 2"));
        assert!(output.contains("shield_proxy_connections_active 5"));
        assert!(output.contains("shield_proxy_bytes_forwarded_total 1024"));
        assert!(output.contains("shield_proxy_dns_queries_total 1"));
        assert!(output.contains("shield_proxy_shield_encryptions_total 1"));
        assert!(output.contains("shield_proxy_shield_decryptions_total 1"));
        assert!(output.contains("shield_proxy_shield_errors_total 1"));
        assert!(output.contains("shield_proxy_redundancy_role 1"));
        assert!(output.contains("shield_proxy_heartbeats_sent_total 1"));
        assert!(output.contains("shield_proxy_failovers_total 1"));
    }

    #[test]
    fn test_prometheus_format() {
        let metrics = MetricsCollector::new();
        let output = metrics.encode_prometheus();
        // Should contain HELP and TYPE lines
        assert!(output.contains("# HELP shield_proxy_connections_total"));
        assert!(output.contains("# TYPE shield_proxy_connections_total counter"));
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        let metrics = MetricsCollector::new();

        let app = Router::new()
            .route("/health", get(health_handler))
            .with_state(metrics);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        // Give server a moment to start
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (mut read, mut write) = client.into_split();

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        write.write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = read.read(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);

        assert!(response.contains("200 OK"));
        assert!(response.contains("\"status\":\"healthy\""));
        assert!(response.contains("\"version\":\"2.2.0\""));
    }
}
