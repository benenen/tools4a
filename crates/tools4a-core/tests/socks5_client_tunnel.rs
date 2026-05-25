//! Integration tests for `Socks5ClientTunnel`.
//!
//! Each test spins up:
//!   1. A throwaway upstream TCP server (the "target") that just echoes
//!      bytes back. Used to verify end-to-end byte plumbing through the
//!      whole client tunnel.
//!   2. A scripted in-process SOCKS5 proxy that performs the handshake
//!      with our client and then bidirectionally bridges the inbound
//!      stream to the upstream "target" server.
//!   3. A `Socks5ClientTunnel` pointed at that scripted proxy, target
//!      pointed at the echo server.
//!
//! We then connect a TCP client to the tunnel's local endpoint, write
//! some bytes, and assert they come back — proving greeting + auth +
//! CONNECT + bidirectional copy all work.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

use tools4a_core::{Socks5ClientTunnel, Tunnel};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Spawn an echo TCP server on 127.0.0.1:0. Returns the address.
async fn spawn_echo_server() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

/// Scripted SOCKS5 proxy. Modes:
///   - `Ok { userpass }` — accept the connection, do greeting (auth method
///     0x00 or 0x02 depending on `userpass`), then auth success, then
///     reply Succeeded to CONNECT and bridge to `upstream`.
///   - `AuthFail` — reply 0x05/0x02 to greeting, then 0x01/0x01 (status=1)
///     to the userpass subneg. Drops the conn after.
///   - `HostUnreachable` — happy greeting, then reply REP=0x04 to CONNECT.
#[derive(Clone, Copy, Debug)]
enum ProxyMode {
    Ok { userpass: bool },
    AuthFail,
    HostUnreachable,
}

/// Spawn the scripted SOCKS5 proxy. Returns the proxy's local address.
async fn spawn_proxy(
    mode: ProxyMode,
    upstream: std::net::SocketAddr,
    seen_creds: Arc<Mutex<Option<(String, String)>>>,
) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut sock, _) = match listener.accept().await {
            Ok(p) => p,
            Err(_) => return,
        };

        // --- Greeting: read VER NMETHODS, then NMETHODS method bytes.
        let mut head = [0u8; 2];
        if sock.read_exact(&mut head).await.is_err() {
            return;
        }
        let nmethods = head[1] as usize;
        let mut methods = vec![0u8; nmethods];
        if sock.read_exact(&mut methods).await.is_err() {
            return;
        }

        let chosen: u8 = match mode {
            ProxyMode::Ok { userpass: false } => 0x00,
            ProxyMode::Ok { userpass: true } | ProxyMode::AuthFail => 0x02,
            ProxyMode::HostUnreachable => 0x00,
        };
        if sock.write_all(&[0x05, chosen]).await.is_err() {
            return;
        }

        if chosen == 0x02 {
            // userpass subneg: VER=0x01 ULEN UNAME PLEN PASSWD
            let mut h = [0u8; 2];
            if sock.read_exact(&mut h).await.is_err() {
                return;
            }
            let ulen = h[1] as usize;
            let mut uname = vec![0u8; ulen];
            if sock.read_exact(&mut uname).await.is_err() {
                return;
            }
            let mut plen_buf = [0u8; 1];
            if sock.read_exact(&mut plen_buf).await.is_err() {
                return;
            }
            let plen = plen_buf[0] as usize;
            let mut pass = vec![0u8; plen];
            if sock.read_exact(&mut pass).await.is_err() {
                return;
            }
            *seen_creds.lock().await = Some((
                String::from_utf8_lossy(&uname).to_string(),
                String::from_utf8_lossy(&pass).to_string(),
            ));

            let status = match mode {
                ProxyMode::AuthFail => 0x01,
                _ => 0x00,
            };
            if sock.write_all(&[0x01, status]).await.is_err() {
                return;
            }
            if matches!(mode, ProxyMode::AuthFail) {
                return;
            }
        }

        // --- CONNECT request: VER CMD RSV ATYP body...
        let mut req_head = [0u8; 5];
        if sock.read_exact(&mut req_head).await.is_err() {
            return;
        }
        let body_len = match req_head[3] {
            0x01 => 3 + 2, // 3 more IPv4 octets + port
            0x03 => req_head[4] as usize + 2,
            0x04 => 15 + 2,
            _ => return,
        };
        let mut body = vec![0u8; body_len];
        if sock.read_exact(&mut body).await.is_err() {
            return;
        }

        // Send CONNECT reply.
        let rep = match mode {
            ProxyMode::HostUnreachable => 0x04,
            _ => 0x00,
        };
        // Use ATYP=IPv4 0.0.0.0:0 BND echo to keep the wire bytes small.
        let reply = [0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        if sock.write_all(&reply).await.is_err() {
            return;
        }
        if rep != 0x00 {
            return;
        }

        // Bridge to upstream.
        let mut upstream = match tokio::net::TcpStream::connect(upstream).await {
            Ok(s) => s,
            Err(_) => return,
        };
        let _ = tokio::io::copy_bidirectional(&mut sock, &mut upstream).await;
    });
    addr
}

#[tokio::test]
async fn happy_path_no_auth() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let echo = spawn_echo_server().await;
        let seen = Arc::new(Mutex::new(None));
        let proxy = spawn_proxy(ProxyMode::Ok { userpass: false }, echo, seen.clone()).await;

        let mut tunnel = Socks5ClientTunnel::new(
            proxy.ip().to_string(),
            proxy.port(),
            None,
            None,
            echo.ip().to_string(),
            echo.port(),
        )
        .unwrap();
        let endpoint = tunnel.establish().await.unwrap();

        let mut client = tokio::net::TcpStream::connect((endpoint.host.as_str(), endpoint.port))
            .await
            .unwrap();
        client.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");

        drop(client);
        tunnel.close().await.unwrap();
        assert_eq!(*seen.lock().await, None, "no-auth path must not send creds");
    })
    .await
    .expect("test timed out");
}

#[tokio::test]
async fn happy_path_userpass() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let echo = spawn_echo_server().await;
        let seen = Arc::new(Mutex::new(None));
        let proxy = spawn_proxy(ProxyMode::Ok { userpass: true }, echo, seen.clone()).await;

        let mut tunnel = Socks5ClientTunnel::new(
            proxy.ip().to_string(),
            proxy.port(),
            Some("alice".into()),
            Some("s3cret".into()),
            echo.ip().to_string(),
            echo.port(),
        )
        .unwrap();
        let endpoint = tunnel.establish().await.unwrap();

        let mut client = tokio::net::TcpStream::connect((endpoint.host.as_str(), endpoint.port))
            .await
            .unwrap();
        client.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");

        drop(client);
        tunnel.close().await.unwrap();
        let creds = seen.lock().await.clone();
        assert_eq!(
            creds,
            Some(("alice".to_string(), "s3cret".to_string())),
            "proxy should have received the creds verbatim"
        );
    })
    .await
    .expect("test timed out");
}

#[tokio::test]
async fn auth_failure_closes_inbound_without_echo() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let echo = spawn_echo_server().await;
        let seen = Arc::new(Mutex::new(None));
        let proxy = spawn_proxy(ProxyMode::AuthFail, echo, seen.clone()).await;

        let mut tunnel = Socks5ClientTunnel::new(
            proxy.ip().to_string(),
            proxy.port(),
            Some("alice".into()),
            Some("wrongpw".into()),
            echo.ip().to_string(),
            echo.port(),
        )
        .unwrap();
        let endpoint = tunnel.establish().await.unwrap();

        // Connect to the tunnel; the inbound conn should be torn down
        // because the upstream handshake fails (forward_one returns Err,
        // dropping its end of the duplex).
        let mut client = tokio::net::TcpStream::connect((endpoint.host.as_str(), endpoint.port))
            .await
            .unwrap();
        // Write something; it's allowed to succeed (kernel buffers) but
        // the read should return 0 (clean EOF) reasonably quickly.
        let _ = client.write_all(b"hi").await;
        let mut buf = [0u8; 8];
        let n = client.read(&mut buf).await.unwrap_or(0);
        assert_eq!(n, 0, "inbound conn must EOF after upstream auth failure");

        tunnel.close().await.unwrap();
    })
    .await
    .expect("test timed out");
}

#[tokio::test]
async fn target_unreachable_closes_inbound() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let echo = spawn_echo_server().await;
        let seen = Arc::new(Mutex::new(None));
        let proxy = spawn_proxy(ProxyMode::HostUnreachable, echo, seen).await;

        let mut tunnel = Socks5ClientTunnel::new(
            proxy.ip().to_string(),
            proxy.port(),
            None,
            None,
            echo.ip().to_string(),
            echo.port(),
        )
        .unwrap();
        let endpoint = tunnel.establish().await.unwrap();

        let mut client = tokio::net::TcpStream::connect((endpoint.host.as_str(), endpoint.port))
            .await
            .unwrap();
        let _ = client.write_all(b"hi").await;
        let mut buf = [0u8; 8];
        let n = client.read(&mut buf).await.unwrap_or(0);
        assert_eq!(
            n, 0,
            "inbound conn must EOF when proxy returns host-unreachable"
        );

        tunnel.close().await.unwrap();
    })
    .await
    .expect("test timed out");
}
