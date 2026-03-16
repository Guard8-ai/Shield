use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::io;
use tokio::net::TcpListener;
use tracing::{error, info, warn};

use crate::config::ProxyConfig;
use crate::metrics::MetricsCollector;
use crate::protocol::ProtocolDetector;
use crate::transport::ShieldTransport;

/// Core TCP proxy server.
pub struct ProxyServer {
    config: ProxyConfig,
    metrics: MetricsCollector,
    active_connections: Arc<AtomicUsize>,
}

/// Proxy server errors.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("No upstream configured")]
    NoUpstream,
}

impl ProxyServer {
    pub fn new(config: ProxyConfig, metrics: MetricsCollector) -> Self {
        Self {
            config,
            metrics,
            active_connections: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Run the proxy server until shutdown signal.
    pub async fn run(&self) -> Result<(), ProxyError> {
        let listener = TcpListener::bind(&self.config.proxy.bind_address).await?;
        info!(bind = %self.config.proxy.bind_address, "Proxy listening");

        let shutdown = tokio::signal::ctrl_c();
        tokio::pin!(shutdown);

        loop {
            tokio::select! {
                result = listener.accept() => {
                    let (client_stream, client_addr) = result?;
                    let current = self.active_connections.load(Ordering::Relaxed);

                    if current >= self.config.proxy.max_connections {
                        warn!(addr = %client_addr, max = self.config.proxy.max_connections, "Max connections reached, rejecting");
                        drop(client_stream);
                        continue;
                    }

                    self.active_connections.fetch_add(1, Ordering::Relaxed);
                    self.metrics.inc_connections_total();
                    self.metrics.set_connections_active(
                        self.active_connections.load(Ordering::Relaxed) as u64,
                    );

                    let active = Arc::clone(&self.active_connections);
                    let metrics = self.metrics.clone();
                    let config = self.config.clone();

                    tokio::spawn(async move {
                        // Detect protocol
                        let protocol = ProtocolDetector::detect(&client_stream).await;
                        info!(
                            addr = %client_addr,
                            protocol = %protocol,
                            "Connection accepted"
                        );

                        // Find upstream target (first configured, or protocol-based)
                        let upstream_addr = if let Some(target) = config.upstream.first() {
                            target.address.clone()
                        } else {
                            warn!(addr = %client_addr, "No upstream configured");
                            active.fetch_sub(1, Ordering::Relaxed);
                            metrics.set_connections_active(
                                active.load(Ordering::Relaxed) as u64,
                            );
                            return;
                        };

                        let should_encrypt = config.upstream.first()
                            .is_some_and(|t| t.shield_encrypt);

                        // Connect to upstream
                        match tokio::net::TcpStream::connect(&upstream_addr).await {
                            Ok(upstream_stream) => {
                                if should_encrypt {
                                    let key = config.upstream.first()
                                        .and_then(|t| t.shield_key.clone())
                                        .unwrap_or_default();
                                    let password = if key.is_empty() {
                                        &config.shield.password
                                    } else {
                                        &key
                                    };
                                    let forwarded = ShieldTransport::forward_encrypted(
                                        client_stream,
                                        upstream_stream,
                                        password,
                                        &config.shield.service,
                                        &metrics,
                                    ).await;

                                    if let Err(e) = forwarded {
                                        warn!(addr = %client_addr, error = %e, "Shield transport error");
                                    }
                                } else {
                                    let forwarded = forward_plain(
                                        client_stream,
                                        upstream_stream,
                                        &metrics,
                                    ).await;

                                    if let Err(e) = forwarded {
                                        if e.kind() != io::ErrorKind::UnexpectedEof
                                            && e.kind() != io::ErrorKind::ConnectionReset
                                        {
                                            warn!(addr = %client_addr, error = %e, "Forward error");
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                error!(
                                    addr = %client_addr,
                                    upstream = %upstream_addr,
                                    error = %e,
                                    "Failed to connect to upstream"
                                );
                            }
                        }

                        active.fetch_sub(1, Ordering::Relaxed);
                        metrics.set_connections_active(
                            active.load(Ordering::Relaxed) as u64,
                        );
                        info!(addr = %client_addr, "Connection closed");
                    });
                }
                _ = &mut shutdown => {
                    info!("Shutdown signal received, draining connections");
                    // Wait for active connections to finish
                    let timeout = std::time::Duration::from_secs(
                        self.config.proxy.shutdown_timeout_secs,
                    );
                    let start = std::time::Instant::now();
                    while self.active_connections.load(Ordering::Relaxed) > 0 {
                        if start.elapsed() > timeout {
                            warn!(
                                remaining = self.active_connections.load(Ordering::Relaxed),
                                "Shutdown timeout, forcing close"
                            );
                            break;
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                    return Ok(());
                }
            }
        }
    }
}

/// Plain bidirectional forwarding without encryption.
async fn forward_plain(
    mut client: tokio::net::TcpStream,
    mut upstream: tokio::net::TcpStream,
    metrics: &MetricsCollector,
) -> Result<(), io::Error> {
    let (bytes_up, bytes_down) = io::copy_bidirectional(&mut client, &mut upstream).await?;
    metrics.add_bytes_forwarded(bytes_up + bytes_down);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_plain_forwarding() {
        // Start a mock upstream server that echoes data
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut stream, _) = upstream_listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let n = stream.read(&mut buf).await.unwrap();
            stream.write_all(&buf[..n]).await.unwrap();
        });

        // Set up proxy config pointing to the upstream
        let mut config = ProxyConfig::from_toml("").unwrap();
        config.proxy.bind_address = "127.0.0.1:0".to_string();
        config.upstream.push(crate::config::UpstreamTarget {
            name: "test".to_string(),
            address: upstream_addr.to_string(),
            protocol: "tcp".to_string(),
            shield_encrypt: false,
            shield_key: None,
        });

        let metrics = MetricsCollector::new();

        // Test forward_plain with real TCP streams through the proxy relay
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();

        let metrics_clone = metrics.clone();
        let upstream_target = config.upstream[0].address.clone();
        tokio::spawn(async move {
            let (client_stream, _) = proxy_listener.accept().await.unwrap();
            let upstream_stream = tokio::net::TcpStream::connect(upstream_target).await.unwrap();
            forward_plain(client_stream, upstream_stream, &metrics_clone).await.unwrap();
        });

        // Client connects to proxy, sends data, reads echoed response
        let mut client = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        client.write_all(b"hello proxy").await.unwrap();
        client.shutdown().await.unwrap();

        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert_eq!(&response, b"hello proxy");
    }

    #[test]
    fn test_proxy_server_creation() {
        let config = ProxyConfig::from_toml("").unwrap();
        let metrics = MetricsCollector::new();
        let server = ProxyServer::new(config, metrics);
        assert_eq!(server.active_connections.load(Ordering::Relaxed), 0);
    }
}
