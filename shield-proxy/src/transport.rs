use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
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

        // Wait for either direction to finish
        tokio::select! {
            r = enc_handle => {
                if let Ok(Err(e)) = r {
                    if is_expected_close(&e) { return Ok(()); }
                    return Err(e);
                }
            }
            r = dec_handle => {
                if let Ok(Err(e)) = r {
                    if is_expected_close(&e) { return Ok(()); }
                    return Err(e);
                }
            }
        }

        Ok(())
    }
}

/// Read plain bytes from source, encrypt with Shield, write length-prefixed frames to dest.
async fn encrypt_pipe(
    mut source: tokio::net::tcp::OwnedReadHalf,
    mut dest: tokio::net::tcp::OwnedWriteHalf,
    shield: &shield_core::Shield,
    metrics: &MetricsCollector,
) -> Result<(), io::Error> {
    let mut buf = vec![0u8; READ_BUF_SIZE];
    loop {
        let n = source.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }

        let encrypted = shield.encrypt(&buf[..n]).map_err(|e| {
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
    }
}

/// Read length-prefixed encrypted frames from source, decrypt with Shield, write plain to dest.
async fn decrypt_pipe(
    mut source: tokio::net::tcp::OwnedReadHalf,
    mut dest: tokio::net::tcp::OwnedWriteHalf,
    shield: &shield_core::Shield,
    metrics: &MetricsCollector,
) -> Result<(), io::Error> {
    loop {
        // Read 4-byte length prefix
        let mut len_buf = [0u8; 4];
        match source.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
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
        source.read_exact(&mut encrypted).await?;

        // Decrypt
        let decrypted = shield.decrypt(&encrypted).map_err(|_| {
            metrics.inc_shield_errors();
            io::Error::new(io::ErrorKind::InvalidData, "Shield decryption failed")
        })?;

        metrics.inc_shield_decryptions();
        dest.write_all(&decrypted).await?;
        dest.flush().await?;

        metrics.add_bytes_forwarded(u64::from(len) + 4);
    }
}

fn is_expected_close(e: &io::Error) -> bool {
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

    #[tokio::test]
    async fn test_encrypt_decrypt_roundtrip() {
        let shield = shield_core::Shield::new("test-pass", "test-service");

        // Create a TCP pair: sender writes encrypted frames, receiver decrypts
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let plaintext = b"Hello, Shield Transport!";
        let encrypted = shield.encrypt(plaintext).unwrap();
        let len = encrypted.len() as u32;

        // Sender: write a length-prefixed encrypted frame then close
        let send_task = tokio::spawn(async move {
            let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            stream.write_all(&len.to_be_bytes()).await.unwrap();
            stream.write_all(&encrypted).await.unwrap();
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

    #[test]
    fn test_max_frame_size() {
        assert_eq!(MAX_FRAME_SIZE, 4 * 1024 * 1024);
    }
}
