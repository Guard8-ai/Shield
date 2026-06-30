use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ring::hmac;
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

/// Common heartbeat prefix: `[role: 1][sequence: 4 BE][timestamp_ms: 8 BE]`.
const HEARTBEAT_PREFIX: usize = 13;

/// Legacy (unauthenticated) heartbeat: prefix + 4-byte sum checksum = 17 bytes.
/// Used only when no pre-shared key is configured (and a warning is logged).
const LEGACY_HEARTBEAT_SIZE: usize = HEARTBEAT_PREFIX + 4;

/// Authenticated heartbeat: prefix + 32-byte HMAC-SHA256 tag = 45 bytes.
const AUTH_HEARTBEAT_SIZE: usize = HEARTBEAT_PREFIX + 32;

/// Largest heartbeat we will receive.
const MAX_HEARTBEAT_SIZE: usize = AUTH_HEARTBEAT_SIZE;

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

        // Derive the heartbeat authentication key from the configured PSK.
        let key = match config.psk.as_deref() {
            Some(psk) if !psk.is_empty() => {
                Some(Arc::new(hmac::Key::new(hmac::HMAC_SHA256, psk.as_bytes())))
            }
            _ => {
                warn!(
                    "redundancy.psk is not set: HA heartbeats are UNAUTHENTICATED. \
                     An attacker who can reach the heartbeat socket could forge role \
                     transitions (forced failover / split-brain). Set a high-entropy \
                     redundancy.psk on both nodes."
                );
                None
            }
        };

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
        let send_key = key.clone();
        tokio::spawn(async move {
            heartbeat_sender(send_socket, send_role, &send_config, &send_metrics, send_key.as_deref()).await;
        });

        // Run heartbeat receiver (monitors peer, manages role transitions)
        heartbeat_receiver(socket, role, &config, &metrics, key.as_deref()).await;
    }
}

/// Current wall-clock time in milliseconds since the Unix epoch.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Encode a heartbeat message.
///
/// With a key, the trailer is an HMAC-SHA256 tag over the 13-byte prefix
/// (45 bytes total). Without a key, the trailer is the legacy 4-byte sum
/// checksum (17 bytes total) — unauthenticated, used only when no PSK is set.
fn encode_heartbeat(role: Role, sequence: u32, key: Option<&hmac::Key>) -> Vec<u8> {
    let mut buf = Vec::with_capacity(AUTH_HEARTBEAT_SIZE);
    buf.push(role as u8);
    buf.extend_from_slice(&sequence.to_be_bytes());
    buf.extend_from_slice(&now_ms().to_be_bytes());

    if let Some(key) = key {
        let tag = hmac::sign(key, &buf[..HEARTBEAT_PREFIX]);
        buf.extend_from_slice(tag.as_ref());
    } else {
        // Legacy sum-of-bytes checksum (NOT authentication).
        let checksum: u32 = buf[..HEARTBEAT_PREFIX].iter().map(|&b| u32::from(b)).sum();
        buf.extend_from_slice(&checksum.to_be_bytes());
    }
    buf
}

/// Decode and authenticate a heartbeat message. Returns `(role, sequence,
/// timestamp_ms)` or `None` if the trailer does not verify.
///
/// With a key, the HMAC tag is verified in constant time; a forged or tampered
/// heartbeat is rejected. Without a key, only the legacy checksum is checked.
fn decode_heartbeat(buf: &[u8], key: Option<&hmac::Key>) -> Option<(Role, u32, u64)> {
    let expected_len = if key.is_some() {
        AUTH_HEARTBEAT_SIZE
    } else {
        LEGACY_HEARTBEAT_SIZE
    };
    if buf.len() < expected_len {
        return None;
    }

    let (prefix, trailer) = buf.split_at(HEARTBEAT_PREFIX);

    if let Some(key) = key {
        // Constant-time HMAC verification.
        hmac::verify(key, prefix, &trailer[..32]).ok()?;
    } else {
        let expected: u32 = prefix.iter().map(|&b| u32::from(b)).sum();
        let actual = u32::from_be_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);
        if expected != actual {
            return None;
        }
    }

    let role = Role::from_u8(prefix[0]);
    let sequence = u32::from_be_bytes([prefix[1], prefix[2], prefix[3], prefix[4]]);
    let timestamp = u64::from_be_bytes([
        prefix[5], prefix[6], prefix[7], prefix[8], prefix[9], prefix[10], prefix[11], prefix[12],
    ]);
    Some((role, sequence, timestamp))
}

/// Send heartbeats to the peer at the configured interval.
async fn heartbeat_sender(
    socket: Arc<UdpSocket>,
    role: Arc<AtomicU8>,
    config: &RedundancySection,
    metrics: &MetricsCollector,
    key: Option<&hmac::Key>,
) {
    let mut interval = time::interval(Duration::from_millis(config.heartbeat_interval_ms));
    let mut sequence: u32 = 0;

    loop {
        interval.tick().await;

        let current_role = Role::from_u8(role.load(Ordering::Relaxed));
        if current_role != Role::Active {
            continue;
        }

        let heartbeat = encode_heartbeat(current_role, sequence, key);
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
    key: Option<&hmac::Key>,
) {
    let failover_timeout = Duration::from_millis(config.failover_timeout_ms);
    let mut buf = [0u8; MAX_HEARTBEAT_SIZE];

    // Anti-replay: largest (sequence, timestamp) accepted so far. A heartbeat is
    // accepted only if it advances one of them, so a captured beat cannot be
    // replayed, while a peer restart (seq resets, timestamp advances) still works.
    let mut last_seq: u32 = 0;
    let mut last_ts: u64 = 0;
    let mut seen_any = false;
    // Reject heartbeats whose timestamp is too old (stale/replayed) or too far
    // in the future relative to our clock.
    let max_age_ms = config.failover_timeout_ms.saturating_mul(4).max(10_000);
    let max_skew_ms: u64 = 5_000;

    // Initially, if no peer is detected within the failover timeout, promote to active
    loop {
        match time::timeout(failover_timeout, socket.recv_from(&mut buf)).await {
            Ok(Ok((len, _peer_addr))) => {
                let Some((peer_role, seq, ts)) = decode_heartbeat(&buf[..len], key) else {
                    // Unauthenticated/forged/short heartbeat: ignore.
                    continue;
                };

                // Freshness: drop stale (possible replay) or future-dated beats.
                let now = now_ms();
                if ts.saturating_add(max_age_ms) < now || ts > now.saturating_add(max_skew_ms) {
                    warn!(seq, ts, now, "Dropping heartbeat outside freshness window");
                    continue;
                }

                // Anti-replay: must advance sequence or timestamp.
                if seen_any && seq <= last_seq && ts <= last_ts {
                    warn!(seq, last_seq, "Dropping replayed/stale heartbeat");
                    continue;
                }
                seen_any = true;
                last_seq = seq.max(last_seq);
                last_ts = ts.max(last_ts);

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

    fn test_key() -> hmac::Key {
        hmac::Key::new(hmac::HMAC_SHA256, b"a-high-entropy-shared-secret")
    }

    #[test]
    fn test_encode_decode_heartbeat_legacy() {
        let heartbeat = encode_heartbeat(Role::Active, 42, None);
        assert_eq!(heartbeat.len(), LEGACY_HEARTBEAT_SIZE);
        let (role, seq, _ts) = decode_heartbeat(&heartbeat, None).unwrap();
        assert_eq!(role, Role::Active);
        assert_eq!(seq, 42);
    }

    #[test]
    fn test_encode_decode_heartbeat_authenticated() {
        let key = test_key();
        let heartbeat = encode_heartbeat(Role::Active, 42, Some(&key));
        assert_eq!(heartbeat.len(), AUTH_HEARTBEAT_SIZE);
        let (role, seq, _ts) = decode_heartbeat(&heartbeat, Some(&key)).unwrap();
        assert_eq!(role, Role::Active);
        assert_eq!(seq, 42);
    }

    #[test]
    fn test_authenticated_heartbeat_rejects_wrong_key() {
        // RT2-6: a heartbeat signed with a different secret must be rejected.
        let attacker = hmac::Key::new(hmac::HMAC_SHA256, b"attacker-guessed-secret");
        let forged = encode_heartbeat(Role::Active, 1, Some(&attacker));
        assert!(decode_heartbeat(&forged, Some(&test_key())).is_none());
    }

    #[test]
    fn test_authenticated_heartbeat_rejects_tampered_role() {
        // Flipping the role byte of a validly-signed beat must fail the HMAC.
        let key = test_key();
        let mut heartbeat = encode_heartbeat(Role::Standby, 1, Some(&key));
        heartbeat[0] = Role::Active as u8; // tamper with the role
        assert!(decode_heartbeat(&heartbeat, Some(&key)).is_none());
    }

    #[test]
    fn test_authenticated_rejects_legacy_checksum_forgery() {
        // A legacy (checksum-only) heartbeat must NOT be accepted when a key is
        // configured — otherwise an attacker bypasses auth by omitting the tag.
        let legacy = encode_heartbeat(Role::Active, 1, None);
        assert!(decode_heartbeat(&legacy, Some(&test_key())).is_none());
    }

    #[test]
    fn test_decode_invalid_checksum() {
        let mut heartbeat = encode_heartbeat(Role::Standby, 1, None);
        heartbeat[16] ^= 0xFF; // Corrupt checksum
        assert!(decode_heartbeat(&heartbeat, None).is_none());
    }

    #[test]
    fn test_decode_too_short() {
        assert!(decode_heartbeat(&[0u8; 5], None).is_none());
        assert!(decode_heartbeat(&[0u8; 5], Some(&test_key())).is_none());
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
            psk: None,
        };
        let metrics = MetricsCollector::new();
        let mgr = RedundancyManager::new(config, metrics);
        assert_eq!(mgr.role(), Role::Standby);
    }

    #[test]
    fn test_heartbeat_size() {
        assert_eq!(encode_heartbeat(Role::Active, 0, None).len(), LEGACY_HEARTBEAT_SIZE);
        assert_eq!(
            encode_heartbeat(Role::Active, 0, Some(&test_key())).len(),
            AUTH_HEARTBEAT_SIZE
        );
    }
}
