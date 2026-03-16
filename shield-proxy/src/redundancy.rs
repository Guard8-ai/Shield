use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::net::UdpSocket;
use tokio::time;
use tracing::{error, info, warn};

use crate::config::RedundancySection;
use crate::metrics::MetricsCollector;

/// Node role in the active/standby pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Role {
    Standby = 0,
    Active = 1,
}

impl Role {
    fn from_u8(v: u8) -> Self {
        if v == 1 { Self::Active } else { Self::Standby }
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Standby => write!(f, "standby"),
            Self::Active => write!(f, "active"),
        }
    }
}

/// Heartbeat message format (binary, 17 bytes).
/// ```text
/// [role: 1 byte][sequence: 4 bytes BE][timestamp: 8 bytes BE][checksum: 4 bytes BE]
/// ```
const HEARTBEAT_SIZE: usize = 17;

/// Manages active/standby redundancy via UDP heartbeats.
pub struct RedundancyManager {
    config: RedundancySection,
    metrics: MetricsCollector,
    role: Arc<AtomicU8>,
}

impl RedundancyManager {
    pub fn new(config: RedundancySection, metrics: MetricsCollector) -> Self {
        // Start as standby; promote if no peer heartbeat received
        Self {
            config,
            metrics,
            role: Arc::new(AtomicU8::new(Role::Standby as u8)),
        }
    }

    /// Get the current role.
    pub fn role(&self) -> Role {
        Role::from_u8(self.role.load(Ordering::Relaxed))
    }

    /// Run the redundancy manager (heartbeat sender + receiver).
    pub async fn run(&self) {
        let role = Arc::clone(&self.role);
        let config = self.config.clone();
        let metrics = self.metrics.clone();

        // Bind a UDP socket for heartbeat communication
        let socket = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => Arc::new(s),
            Err(e) => {
                error!("Failed to bind heartbeat socket: {e}");
                return;
            }
        };

        // Spawn heartbeat sender (sends when active)
        let send_socket = Arc::clone(&socket);
        let send_role = Arc::clone(&role);
        let send_config = config.clone();
        let send_metrics = metrics.clone();
        tokio::spawn(async move {
            heartbeat_sender(send_socket, send_role, &send_config, &send_metrics).await;
        });

        // Run heartbeat receiver (monitors peer, manages role transitions)
        heartbeat_receiver(socket, role, &config, &metrics).await;
    }
}

/// Encode a heartbeat message.
fn encode_heartbeat(role: Role, sequence: u32) -> [u8; HEARTBEAT_SIZE] {
    let mut buf = [0u8; HEARTBEAT_SIZE];
    buf[0] = role as u8;
    buf[1..5].copy_from_slice(&sequence.to_be_bytes());

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    buf[5..13].copy_from_slice(&timestamp.to_be_bytes());

    // Simple checksum: sum of first 13 bytes
    let checksum: u32 = buf[..13].iter().map(|&b| u32::from(b)).sum();
    buf[13..17].copy_from_slice(&checksum.to_be_bytes());
    buf
}

/// Decode and validate a heartbeat message. Returns (role, sequence) or None.
fn decode_heartbeat(buf: &[u8]) -> Option<(Role, u32)> {
    if buf.len() < HEARTBEAT_SIZE {
        return None;
    }

    // Verify checksum
    let expected: u32 = buf[..13].iter().map(|&b| u32::from(b)).sum();
    let actual = u32::from_be_bytes([buf[13], buf[14], buf[15], buf[16]]);
    if expected != actual {
        return None;
    }

    let role = Role::from_u8(buf[0]);
    let sequence = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
    Some((role, sequence))
}

/// Send heartbeats to the peer at the configured interval.
async fn heartbeat_sender(
    socket: Arc<UdpSocket>,
    role: Arc<AtomicU8>,
    config: &RedundancySection,
    metrics: &MetricsCollector,
) {
    let mut interval = time::interval(Duration::from_millis(config.heartbeat_interval_ms));
    let mut sequence: u32 = 0;

    loop {
        interval.tick().await;

        let current_role = Role::from_u8(role.load(Ordering::Relaxed));
        if current_role != Role::Active {
            continue;
        }

        let heartbeat = encode_heartbeat(current_role, sequence);
        if let Err(e) = socket.send_to(&heartbeat, &config.peer_address).await {
            warn!(peer = %config.peer_address, error = %e, "Failed to send heartbeat");
        } else {
            metrics.inc_heartbeats_sent();
        }

        sequence = sequence.wrapping_add(1);
    }
}

/// Receive heartbeats from peer. Promote to active if peer goes silent.
async fn heartbeat_receiver(
    socket: Arc<UdpSocket>,
    role: Arc<AtomicU8>,
    config: &RedundancySection,
    metrics: &MetricsCollector,
) {
    let failover_timeout = Duration::from_millis(config.failover_timeout_ms);
    let mut buf = [0u8; HEARTBEAT_SIZE];

    // Initially, if no peer is detected within the failover timeout, promote to active
    loop {
        match time::timeout(failover_timeout, socket.recv_from(&mut buf)).await {
            Ok(Ok((len, _peer_addr))) => {
                if let Some((peer_role, _seq)) = decode_heartbeat(&buf[..len]) {
                    // Peer is active → we stay standby
                    if peer_role == Role::Active {
                        let was = Role::from_u8(role.load(Ordering::Relaxed));
                        if was == Role::Active {
                            info!("Peer reclaimed active role, stepping down to standby");
                            role.store(Role::Standby as u8, Ordering::Relaxed);
                            metrics.set_redundancy_role(0);
                        }
                    }
                }
            }
            Ok(Err(e)) => {
                warn!(error = %e, "Heartbeat receive error");
            }
            Err(_timeout) => {
                // No heartbeat received within timeout
                let was = Role::from_u8(role.load(Ordering::Relaxed));
                if was == Role::Standby {
                    info!("No peer heartbeat detected, promoting to ACTIVE");
                    role.store(Role::Active as u8, Ordering::Relaxed);
                    metrics.set_redundancy_role(1);
                    metrics.inc_failovers();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_heartbeat() {
        let heartbeat = encode_heartbeat(Role::Active, 42);
        let (role, seq) = decode_heartbeat(&heartbeat).unwrap();
        assert_eq!(role, Role::Active);
        assert_eq!(seq, 42);
    }

    #[test]
    fn test_decode_invalid_checksum() {
        let mut heartbeat = encode_heartbeat(Role::Standby, 1);
        heartbeat[16] ^= 0xFF; // Corrupt checksum
        assert!(decode_heartbeat(&heartbeat).is_none());
    }

    #[test]
    fn test_decode_too_short() {
        assert!(decode_heartbeat(&[0u8; 5]).is_none());
    }

    #[test]
    fn test_role_display() {
        assert_eq!(format!("{}", Role::Active), "active");
        assert_eq!(format!("{}", Role::Standby), "standby");
    }

    #[test]
    fn test_role_from_u8() {
        assert_eq!(Role::from_u8(0), Role::Standby);
        assert_eq!(Role::from_u8(1), Role::Active);
        assert_eq!(Role::from_u8(99), Role::Standby); // Unknown defaults to standby
    }

    #[test]
    fn test_redundancy_manager_creation() {
        let config = RedundancySection {
            enabled: true,
            peer_address: "127.0.0.1:8444".to_string(),
            heartbeat_interval_ms: 500,
            failover_timeout_ms: 3000,
            virtual_ip: None,
        };
        let metrics = MetricsCollector::new();
        let mgr = RedundancyManager::new(config, metrics);
        assert_eq!(mgr.role(), Role::Standby);
    }

    #[test]
    fn test_heartbeat_size() {
        let hb = encode_heartbeat(Role::Active, 0);
        assert_eq!(hb.len(), HEARTBEAT_SIZE);
    }
}
