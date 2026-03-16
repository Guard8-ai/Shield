use std::process;

use shield_proxy::config::ProxyConfig;
use shield_proxy::dns::DnsForwarder;
use shield_proxy::metrics::MetricsServer;
use shield_proxy::proxy::ProxyServer;
use shield_proxy::redundancy::RedundancyManager;
use tracing::{error, info};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let config = match ProxyConfig::load() {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to load config: {e}");
            process::exit(1);
        }
    };

    info!(
        version = env!("CARGO_PKG_VERSION"),
        bind = %config.proxy.bind_address,
        "Shield Proxy starting"
    );

    let metrics = shield_proxy::metrics::MetricsCollector::new();

    // Spawn metrics server
    if config.metrics.enabled {
        let metrics_server = MetricsServer::new(config.metrics.clone(), metrics.clone());
        tokio::spawn(async move {
            if let Err(e) = metrics_server.run().await {
                error!("Metrics server error: {e}");
            }
        });
    }

    // Spawn DNS forwarder
    if let Some(ref dns_config) = config.dns {
        let dns = DnsForwarder::new(dns_config.clone(), metrics.clone());
        tokio::spawn(async move {
            if let Err(e) = dns.run().await {
                error!("DNS forwarder error: {e}");
            }
        });
    }

    // Spawn redundancy manager
    if let Some(ref redundancy_config) = config.redundancy {
        if redundancy_config.enabled {
            let mgr = RedundancyManager::new(redundancy_config.clone(), metrics.clone());
            tokio::spawn(async move {
                mgr.run().await;
            });
        }
    }

    // Run the proxy server (blocks until shutdown)
    let server = ProxyServer::new(config, metrics);
    if let Err(e) = server.run().await {
        error!("Proxy server error: {e}");
        process::exit(1);
    }

    info!("Shield Proxy stopped");
}
