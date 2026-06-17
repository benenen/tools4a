//! Integration test for `SshDirectOrchestrator` over a single SOCKS5 layer
//! (`TunnelConfig::socks5(...)`).
//!
//! Spins up:
//!   1. A fake "target SSH" TCP listener that signals via oneshot on
//!      accept, then writes a non-SSH banner and closes. This proves the
//!      orchestrator reached the right target via the proxy without
//!      requiring a real SSH server.
//!   2. A scripted SOCKS5 proxy (no-auth) that parses the CONNECT body
//!      into `seen_target`, then bridges to the fake target listener.
//!   3. `SshDirectOrchestrator::execute(req, Some(socks5 tunnel))`.
//!
//! We assert:
//!   - The target listener was reached (proves end-to-end routing).
//!   - The proxy saw a CONNECT for `(req.host, req.port)` (proves the
//!     CONNECT body was constructed from the request via the connector
//!     chain, not a hardcoded constant).
//!   - The returned error names `req.host` (proves the host-key label
//!     was preserved through the connector-provided stream).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, oneshot};

use tools4a_core::{Service, TunnelConfig};
use tools4a_ssh::{SshDirectOrchestrator, SshExecRequest};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Spawn a fake "target SSH" listener that signals on accept, writes a
/// non-SSH banner, and closes. Returns its address and an oneshot rx
/// that fires when the accept happens.
async fn spawn_fake_ssh_target() -> (SocketAddr, oneshot::Receiver<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        if let Ok((mut sock, _)) = listener.accept().await {
            let _ = tx.send(());
            let _ = sock.write_all(b"NOT-SSH\r\n").await;
        }
    });
    (addr, rx)
}

/// Scripted SOCKS5 proxy: no-auth greeting, CONNECT, bridge to `upstream`.
/// Records the CONNECT target (decoded from the request body) into
/// `seen_target` so the test can assert what the client asked for.
async fn spawn_proxy(
    upstream: SocketAddr,
    seen_target: Arc<Mutex<Option<(String, u16)>>>,
) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut sock, _) = match listener.accept().await {
            Ok(p) => p,
            Err(_) => return,
        };

        // Greeting: VER NMETHODS METHODS — accept any, choose 0x00 (no auth).
        let mut head = [0u8; 2];
        if sock.read_exact(&mut head).await.is_err() {
            return;
        }
        let nmethods = head[1] as usize;
        let mut methods = vec![0u8; nmethods];
        if sock.read_exact(&mut methods).await.is_err() {
            return;
        }
        if sock.write_all(&[0x05, 0x00]).await.is_err() {
            return;
        }

        // CONNECT request: VER CMD RSV ATYP body...
        let mut req_head = [0u8; 5];
        if sock.read_exact(&mut req_head).await.is_err() {
            return;
        }
        let atyp = req_head[3];
        let (host, port) = match atyp {
            0x01 => {
                // 3 more IPv4 octets + 2 port bytes (first IPv4 octet already in req_head[4]).
                let mut rest = [0u8; 3 + 2];
                if sock.read_exact(&mut rest).await.is_err() {
                    return;
                }
                let host = format!("{}.{}.{}.{}", req_head[4], rest[0], rest[1], rest[2]);
                let port = u16::from_be_bytes([rest[3], rest[4]]);
                (host, port)
            }
            0x03 => {
                let dlen = req_head[4] as usize;
                let mut rest = vec![0u8; dlen + 2];
                if sock.read_exact(&mut rest).await.is_err() {
                    return;
                }
                let host = String::from_utf8_lossy(&rest[..dlen]).to_string();
                let port = u16::from_be_bytes([rest[dlen], rest[dlen + 1]]);
                (host, port)
            }
            _ => return,
        };
        *seen_target.lock().await = Some((host, port));

        // Reply success with BND=0.0.0.0:0.
        let reply = [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        if sock.write_all(&reply).await.is_err() {
            return;
        }

        // Bridge.
        let mut up = match tokio::net::TcpStream::connect(upstream).await {
            Ok(s) => s,
            Err(_) => return,
        };
        let _ = tokio::io::copy_bidirectional(&mut sock, &mut up).await;
    });
    addr
}

#[tokio::test]
async fn orchestrator_socks5_arm_reaches_target_via_proxy() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let (target_addr, target_rx) = spawn_fake_ssh_target().await;
        let seen_target = Arc::new(Mutex::new(None));
        let proxy_addr = spawn_proxy(target_addr, seen_target.clone()).await;

        let req = SshExecRequest {
            host: target_addr.ip().to_string(),
            port: target_addr.port(),
            user: "u".to_string(),
            password: Some("pw".to_string()),
            key_path: None,
            command: "true".to_string(),
            timeout_secs: None,
            max_timeout_secs: None,
        };
        let tunnel_config =
            TunnelConfig::socks5(proxy_addr.ip().to_string(), proxy_addr.port(), None, None);

        let result = SshDirectOrchestrator::execute(req, Some(tunnel_config)).await;

        // (1) Bytes reached the target through the proxy.
        tokio::time::timeout(Duration::from_secs(2), target_rx)
            .await
            .expect("target listener never received a connection")
            .expect("target listener task dropped tx without sending");

        // (2) The proxy saw the right CONNECT target (i.e. req.host:req.port,
        // not 127.0.0.1:<local-relay-port>).
        let seen = seen_target.lock().await.clone();
        assert_eq!(
            seen,
            Some((target_addr.ip().to_string(), target_addr.port())),
            "proxy should have received a CONNECT for the original target"
        );

        // (3) Error preserves req.host (proves host-key label survived
        // the override).
        let err = result.expect_err("non-SSH banner must fail the handshake");
        assert!(
            format!("{err}").contains(&target_addr.ip().to_string()),
            "error should reference req.host; got: {err}"
        );
    })
    .await
    .expect("test timed out");
}
