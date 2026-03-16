use std::fmt;

use tokio::net::TcpStream;
use tracing::debug;

/// Detected protocol type from initial connection bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// HTTP (GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH)
    Http,
    /// TLS/HTTPS (0x16 0x03 handshake)
    Tls,
    /// WebSocket upgrade (detected after HTTP parsing)
    WebSocket,
    /// Raw TCP (unknown or binary protocol)
    Tcp,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http => write!(f, "HTTP"),
            Self::Tls => write!(f, "TLS"),
            Self::WebSocket => write!(f, "WebSocket"),
            Self::Tcp => write!(f, "TCP"),
        }
    }
}

/// Protocol detection using non-destructive peek.
pub struct ProtocolDetector;

/// HTTP method prefixes to match against.
const HTTP_METHODS: &[&[u8]] = &[
    b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ",
    b"OPTIONS ", b"PATCH ", b"CONNECT ",
];

/// WebSocket upgrade marker (case-insensitive check on the peeked buffer).
const WEBSOCKET_MARKER: &[u8] = b"upgrade: websocket";

impl ProtocolDetector {
    /// Peek at the first bytes of a TCP stream to detect the protocol.
    ///
    /// This is non-destructive: the bytes remain in the stream for normal reading.
    pub async fn detect(stream: &TcpStream) -> Protocol {
        let mut buf = [0u8; 512];
        match stream.peek(&mut buf).await {
            Ok(n) if n >= 2 => classify(&buf[..n]),
            _ => {
                debug!("Could not peek stream, defaulting to TCP");
                Protocol::Tcp
            }
        }
    }

    /// Classify a byte buffer (useful for testing without a real stream).
    pub fn classify_bytes(buf: &[u8]) -> Protocol {
        classify(buf)
    }
}

fn classify(buf: &[u8]) -> Protocol {
    // TLS: starts with ContentType.Handshake (0x16) and version (0x03 0x0X)
    if buf.len() >= 2 && buf[0] == 0x16 && buf[1] == 0x03 {
        return Protocol::Tls;
    }

    // HTTP method detection
    let is_http = HTTP_METHODS.iter().any(|method| {
        buf.len() >= method.len() && buf[..method.len()].eq_ignore_ascii_case(method)
    });

    if is_http {
        // Check for WebSocket upgrade in the peeked buffer
        if contains_case_insensitive(buf, WEBSOCKET_MARKER) {
            return Protocol::WebSocket;
        }
        return Protocol::Http;
    }

    Protocol::Tcp
}

/// Case-insensitive substring search in a byte buffer.
fn contains_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.len() > haystack.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_http_get() {
        assert_eq!(
            ProtocolDetector::classify_bytes(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
            Protocol::Http
        );
    }

    #[test]
    fn test_detect_http_post() {
        assert_eq!(
            ProtocolDetector::classify_bytes(b"POST /api HTTP/1.1\r\n"),
            Protocol::Http
        );
    }

    #[test]
    fn test_detect_tls() {
        // TLS 1.2 ClientHello
        let tls_hello = [0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00];
        assert_eq!(ProtocolDetector::classify_bytes(&tls_hello), Protocol::Tls);
    }

    #[test]
    fn test_detect_websocket() {
        let ws = b"GET /ws HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
        assert_eq!(ProtocolDetector::classify_bytes(ws), Protocol::WebSocket);
    }

    #[test]
    fn test_detect_raw_tcp() {
        assert_eq!(ProtocolDetector::classify_bytes(b"\x00\x01\x02\x03"), Protocol::Tcp);
    }

    #[test]
    fn test_detect_empty() {
        assert_eq!(ProtocolDetector::classify_bytes(b""), Protocol::Tcp);
    }

    #[test]
    fn test_detect_single_byte() {
        assert_eq!(ProtocolDetector::classify_bytes(b"\x16"), Protocol::Tcp);
    }

    #[test]
    fn test_protocol_display() {
        assert_eq!(format!("{}", Protocol::Http), "HTTP");
        assert_eq!(format!("{}", Protocol::Tls), "TLS");
        assert_eq!(format!("{}", Protocol::WebSocket), "WebSocket");
        assert_eq!(format!("{}", Protocol::Tcp), "TCP");
    }
}
