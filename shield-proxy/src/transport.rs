use std::time::Duration;

use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tracing::warn;

use crate::metrics::MetricsCollector;

/// Shield-encrypted transport layer.
///
/// Wraps TCP streams with Shield v2.1 encryption using length-prefixed framing:
/// `[4-byte big-endian length][encrypted payload]`
pub struct ShieldTransport;

/// Maximum frame size: 4 MB.
const MAX_FRAME_SIZE: u32 = 4 * 1024 * 1024;

/// Read buffer for plain-text chunked forwarding.
const READ_BUF_SIZE: usize = 32 * 1024;

pub const RELAY_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

const FRAME_HEADER_SIZE: usize = 9;
const FRAME_TYPE_DATA: u8 = 0;
const FRAME_TYPE_EOF: u8 = 1;

impl ShieldTransport {
    /// Forward traffic between client and upstream with Shield encryption.
    ///
    /// Client → (decrypt) → upstream (plain) → (encrypt) → client.
    /// The client side is Shield-encrypted; the upstream side is plain.
    pub async fn forward_encrypted(
        client: TcpStream,
        upstream: TcpStream,
        password: &str,
        service: &str,
        metrics: &MetricsCollector,
    ) -> Result<(), io::Error> {
        let (client_read, client_write) = client.into_split();
        let (upstream_read, upstream_write) = upstream.into_split();

        // Create separate Shield instances for each direction (Shield doesn't impl Clone)
        let password_enc = password.to_string();
        let service_enc = service.to_string();
        let metrics_enc = metrics.clone();
        let enc_handle = tokio::spawn(async move {
            let shield = shield_core::Shield::new(&password_enc, &service_enc);
            encrypt_pipe(upstream_read, client_write, &shield, &metrics_enc).await
        });

        let password_dec = password.to_string();
        let service_dec = service.to_string();
        let metrics_dec = metrics.clone();
        let dec_handle = tokio::spawn(async move {
            let shield = shield_core::Shield::new(&password_dec, &service_dec);
            decrypt_pipe(client_read, upstream_write, &shield, &metrics_dec).await
        });

        match join_pipes(enc_handle, dec_handle).await {
            Err(e) if !is_expected_close(&e) => Err(e),
            _ => Ok(()),
        }
    }
}

pub(crate) async fn join_pipes(
    mut first: JoinHandle<Result<(), io::Error>>,
    mut second: JoinHandle<Result<(), io::Error>>,
) -> Result<(), io::Error> {
    let first_result = tokio::select! {
        r = &mut first => flatten_join(r),
        r = &mut second => {
            std::mem::swap(&mut first, &mut second);
            flatten_join(r)
        }
    };
    if let Err(e) = first_result {
        second.abort();
        let _ = second.await;
        return Err(e);
    }
    flatten_join(second.await)
}

fn flatten_join(
    result: Result<Result<(), io::Error>, tokio::task::JoinError>,
) -> Result<(), io::Error> {
    match result {
        Ok(inner) => inner,
        Err(join_error) => Err(io::Error::other(join_error)),
    }
}

fn idle_timeout_err() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "relay idle timeout")
}

/// Read plain bytes from source, encrypt with Shield, write length-prefixed frames to dest.
async fn encrypt_pipe(
    mut source: tokio::net::tcp::OwnedReadHalf,
    mut dest: tokio::net::tcp::OwnedWriteHalf,
    shield: &shield_core::Shield,
    metrics: &MetricsCollector,
) -> Result<(), io::Error> {
    let mut buf = vec![0u8; READ_BUF_SIZE];
    let mut sequence: u64 = 0;
    loop {
        let n = timeout(RELAY_IDLE_TIMEOUT, source.read(&mut buf))
            .await
            .map_err(|_| idle_timeout_err())??;

        let frame_type = if n == 0 { FRAME_TYPE_EOF } else { FRAME_TYPE_DATA };

        // Build frame plaintext: [frame_type(1)] || [sequence(8 BE)] || [payload]
        let mut frame = Vec::with_capacity(FRAME_HEADER_SIZE + n);
        frame.push(frame_type);
        frame.extend_from_slice(&sequence.to_be_bytes());
        frame.extend_from_slice(&buf[..n]);

        let encrypted = shield.encrypt(&frame).map_err(|e| {
            metrics.inc_shield_errors();
            io::Error::other(format!("Shield encrypt error: {e}"))
        })?;
        metrics.inc_shield_encryptions();

        let len = u32::try_from(encrypted.len()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "encrypted frame too large")
        })?;
        dest.write_all(&len.to_be_bytes()).await?;
        dest.write_all(&encrypted).await?;
        dest.flush().await?;

        metrics.add_bytes_forwarded(u64::from(len) + 4);

        if frame_type == FRAME_TYPE_EOF {
            let _ = dest.shutdown().await;
            return Ok(());
        }

        sequence = sequence.wrapping_add(1);
    }
}

/// Read length-prefixed encrypted frames from source, decrypt with Shield, write plain to dest.
async fn decrypt_pipe(
    mut source: tokio::net::tcp::OwnedReadHalf,
    mut dest: tokio::net::tcp::OwnedWriteHalf,
    shield: &shield_core::Shield,
    metrics: &MetricsCollector,
) -> Result<(), io::Error> {
    let mut expected_sequence: u64 = 0;
    loop {
        // Read 4-byte length prefix
        let mut len_buf = [0u8; 4];
        match timeout(RELAY_IDLE_TIMEOUT, source.read_exact(&mut len_buf)).await {
            Err(_elapsed) => return Err(idle_timeout_err()),
            Ok(Ok(_)) => {}
            Ok(Err(e)) if e.kind() == io::ErrorKind::UnexpectedEof => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "stream closed without authenticated end-of-stream (possible truncation)",
                ));
            }
            Ok(Err(e)) => return Err(e),
        }

        let len = u32::from_be_bytes(len_buf);
        if len > MAX_FRAME_SIZE {
            warn!(frame_size = len, max = MAX_FRAME_SIZE, "Frame too large");
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "frame exceeds maximum size",
            ));
        }

        // Read encrypted payload
        let mut encrypted = vec![0u8; len as usize];
        timeout(RELAY_IDLE_TIMEOUT, source.read_exact(&mut encrypted))
            .await
            .map_err(|_| idle_timeout_err())??;

        // Decrypt
        let decrypted = shield.decrypt(&encrypted).map_err(|_| {
            metrics.inc_shield_errors();
            io::Error::new(io::ErrorKind::InvalidData, "Shield decryption failed")
        })?;

        metrics.inc_shield_decryptions();

        // Parse frame header: [frame_type(1)] || [sequence(8 BE)] || [payload]
        if decrypted.len() < FRAME_HEADER_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "decrypted frame too short for header",
            ));
        }
        let frame_type = decrypted[0];
        let sequence = u64::from_be_bytes(
            decrypted[1..9].try_into().expect("slice is 8 bytes"),
        );

        // Verify sequence number
        if sequence != expected_sequence {
            warn!(
                expected = expected_sequence,
                got = sequence,
                "Frame sequence mismatch — possible replay or reorder"
            );
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "frame sequence number mismatch",
            ));
        }
        expected_sequence = expected_sequence.wrapping_add(1);

        match frame_type {
            FRAME_TYPE_DATA => {
                dest.write_all(&decrypted[FRAME_HEADER_SIZE..]).await?;
                dest.flush().await?;
                metrics.add_bytes_forwarded(u64::from(len) + 4);
            }
            FRAME_TYPE_EOF => {
                let _ = dest.shutdown().await;
                return Ok(());
            }
            unknown => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unknown frame type: {unknown}"),
                ));
            }
        }
    }
}

pub(crate) fn is_expected_close(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::BrokenPipe
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a length-prefixed encrypted frame with the given `frame_type`, `sequence`, and payload.
    fn frame_plaintext(frame_type: u8, sequence: u64, payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(FRAME_HEADER_SIZE + payload.len());
        frame.push(frame_type);
        frame.extend_from_slice(&sequence.to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    /// Encrypt a frame plaintext and return [4-byte len prefix][encrypted bytes].
    fn make_encrypted_frame(shield: &shield_core::Shield, frame_type: u8, sequence: u64, payload: &[u8]) -> Vec<u8> {
        let plain = frame_plaintext(frame_type, sequence, payload);
        let encrypted = shield.encrypt(&plain).unwrap();
        let len = encrypted.len() as u32;
        let mut out = Vec::with_capacity(4 + encrypted.len());
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&encrypted);
        out
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_roundtrip() {
        // Create a TCP pair: sender writes encrypted frames, receiver decrypts
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let plaintext = b"Hello, Shield Transport!";

        // Send DATA frame (sequence 0) then EOF frame (sequence 1)
        let shield_send = shield_core::Shield::new("test-pass", "test-service");
        let send_task = tokio::spawn(async move {
            let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            let data_frame = make_encrypted_frame(&shield_send, FRAME_TYPE_DATA, 0, plaintext);
            stream.write_all(&data_frame).await.unwrap();
            let eof_frame = make_encrypted_frame(&shield_send, FRAME_TYPE_EOF, 1, b"");
            stream.write_all(&eof_frame).await.unwrap();
            stream.shutdown().await.unwrap();
        });

        let (source_stream, _) = listener.accept().await.unwrap();
        let (source_read, _source_write) = source_stream.into_split();

        // Create a destination pair to collect decrypted output
        let dest_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dest_addr = dest_listener.local_addr().unwrap();

        let collect_task = tokio::spawn(async move {
            let (mut stream, _) = dest_listener.accept().await.unwrap();
            let mut buf = Vec::new();
            stream.read_to_end(&mut buf).await.unwrap();
            buf
        });

        let dest_stream = tokio::net::TcpStream::connect(dest_addr).await.unwrap();
        let (_dest_read, dest_write) = dest_stream.into_split();

        // Decrypt pipe: reads encrypted frames from source, writes plaintext to dest
        let shield2 = shield_core::Shield::new("test-pass", "test-service");
        let metrics = MetricsCollector::new();
        decrypt_pipe(source_read, dest_write, &shield2, &metrics).await.unwrap();

        send_task.await.unwrap();
        let result = collect_task.await.unwrap();
        assert_eq!(result, plaintext);
    }

    #[tokio::test]
    async fn test_replayed_frame_rejected() {
        // Send the same sequence number twice — decrypt_pipe should return InvalidData
        let shield_send = shield_core::Shield::new("test-pass", "test-service");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let send_task = tokio::spawn(async move {
            let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            // Send sequence 0 twice (replay)
            let frame0 = make_encrypted_frame(&shield_send, FRAME_TYPE_DATA, 0, b"data");
            stream.write_all(&frame0).await.unwrap();
            stream.write_all(&frame0).await.unwrap();
            stream.shutdown().await.unwrap();
        });

        let (source_stream, _) = listener.accept().await.unwrap();
        let (source_read, _source_write) = source_stream.into_split();

        let dest_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dest_addr = dest_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = dest_listener.accept().await.unwrap();
            let mut buf = Vec::new();
            let _ = stream.read_to_end(&mut buf).await;
        });

        let dest_stream = tokio::net::TcpStream::connect(dest_addr).await.unwrap();
        let (_dest_read, dest_write) = dest_stream.into_split();

        let shield2 = shield_core::Shield::new("test-pass", "test-service");
        let metrics = MetricsCollector::new();
        let result = decrypt_pipe(source_read, dest_write, &shield2, &metrics).await;

        send_task.await.unwrap();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn test_truncated_stream_rejected() {
        // Send a data frame but no EOF — closing the stream should give InvalidData (truncation)
        let shield_send = shield_core::Shield::new("test-pass", "test-service");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let send_task = tokio::spawn(async move {
            let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            let frame0 = make_encrypted_frame(&shield_send, FRAME_TYPE_DATA, 0, b"data");
            stream.write_all(&frame0).await.unwrap();
            // Close without sending EOF frame
            stream.shutdown().await.unwrap();
        });

        let (source_stream, _) = listener.accept().await.unwrap();
        let (source_read, _source_write) = source_stream.into_split();

        let dest_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dest_addr = dest_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = dest_listener.accept().await.unwrap();
            let mut buf = Vec::new();
            let _ = stream.read_to_end(&mut buf).await;
        });

        let dest_stream = tokio::net::TcpStream::connect(dest_addr).await.unwrap();
        let (_dest_read, dest_write) = dest_stream.into_split();

        let shield2 = shield_core::Shield::new("test-pass", "test-service");
        let metrics = MetricsCollector::new();
        let result = decrypt_pipe(source_read, dest_write, &shield2, &metrics).await;

        send_task.await.unwrap();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_max_frame_size() {
        assert_eq!(MAX_FRAME_SIZE, 4 * 1024 * 1024);
    }
}
