//! Integration + multi-client concurrency tests for the Phase 21 tunnel
//! layer stack (Task 9).
//!
//! These tests stand up everything in-process — an echo TCP upstream, an
//! in-process `russh` server that accepts password auth and bridges
//! `direct-tcpip` channels, and a byte-accurate scripted SOCKS5 proxy — so
//! the composed chain can be exercised end-to-end without any external
//! daemon.
//!
//! Coverage:
//!   A. `[Socks5, SshHop]` end-to-end: a SOCKS5 proxy carries the SSH dial,
//!      the SSH server forwards `direct-tcpip` to an echo upstream, and the
//!      proxy is asserted to have observed a CONNECT to the SSH server's
//!      address (proves layer ORDER).
//!   B. Multi-client concurrency: 20 clients hit a single-SSH-layer tunnel
//!      concurrently; all succeed, and the russh server accepts exactly ONE
//!      inbound TCP connection (all 20 forwards multiplex as channels over
//!      the one SSH transport).
//!   C. SOCKS5 connector auth coverage: userpass success + auth-failure
//!      (the connector must Err, not hang). No russh server needed.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use russh::Channel;
use russh::server::{Auth, Handler as ServerHandler, Msg, Server as ServerTrait, Session};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

use tools4a_core::tunnel::{ForwardTarget, LayeredTunnel};
use tools4a_core::{JumpHop, Tunnel, TunnelConfig, TunnelLayer};

// ---------------------------------------------------------------------------
// Shared in-process fixtures
// ---------------------------------------------------------------------------

/// Spawn an echo TCP upstream. Each accepted connection is echoed byte-for-byte
/// until the peer closes. Loops forever, so it serves any number of dials.
/// Returns the bound port.
async fn spawn_echo_upstream() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => break,
            };
            tokio::spawn(async move {
                // Echo until EOF.
                let mut buf = [0u8; 1024];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    port
}

// ---------------------------------------------------------------------------
// In-process russh server
// ---------------------------------------------------------------------------

/// A russh server `Server` factory. Each accepted TCP connection produces one
/// `EchoSshHandler`. `accepts` counts inbound TCP accepts (incremented in
/// `new_client`) so a test can assert the SSH transport was established
/// exactly once across many forwarded connections.
struct EchoSshServer {
    upstream_port: u16,
    accepts: Arc<AtomicUsize>,
}

impl ServerTrait for EchoSshServer {
    type Handler = EchoSshHandler;

    fn new_client(&mut self, _peer: Option<std::net::SocketAddr>) -> EchoSshHandler {
        self.accepts.fetch_add(1, Ordering::SeqCst);
        EchoSshHandler {
            upstream_port: self.upstream_port,
        }
    }
}

struct EchoSshHandler {
    upstream_port: u16,
}

#[async_trait]
impl ServerHandler for EchoSshHandler {
    type Error = russh::Error;

    async fn auth_password(&mut self, _user: &str, _password: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    /// On a `direct-tcpip` request, dial the echo upstream and bridge bytes
    /// between the SSH channel and the upstream TCP socket. The requested
    /// `host_to_connect:port_to_connect` is ignored — every forward lands on
    /// the one echo upstream, which is all these tests need.
    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        _host_to_connect: &str,
        _port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let upstream_port = self.upstream_port;
        tokio::spawn(async move {
            let mut channel_stream = channel.into_stream();
            let mut upstream = match TcpStream::connect(("127.0.0.1", upstream_port)).await {
                Ok(s) => s,
                Err(_) => return,
            };
            let _ = tokio::io::copy_bidirectional(&mut channel_stream, &mut upstream).await;
        });
        Ok(true)
    }
}

/// Stand up the in-process russh server on `127.0.0.1:0`, forwarding every
/// `direct-tcpip` to `upstream_port`. Returns `(ssh_port, accepts_counter)`.
/// The accept counter is incremented once per inbound TCP connection.
async fn spawn_ssh_server(upstream_port: u16) -> (u16, Arc<AtomicUsize>) {
    let key = russh::keys::key::KeyPair::generate_ed25519();
    let mut config = russh::server::Config {
        keys: vec![key],
        ..Default::default()
    };
    // Keep the test snappy and deterministic — no long inactivity timers.
    config.inactivity_timeout = None;
    let config = Arc::new(config);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ssh_port = listener.local_addr().unwrap().port();
    let accepts = Arc::new(AtomicUsize::new(0));

    let mut server = EchoSshServer {
        upstream_port,
        accepts: accepts.clone(),
    };
    tokio::spawn(async move {
        // run_on_socket drives the accept loop, spawning a session task per conn.
        let _ = server.run_on_socket(config, &listener).await;
    });

    (ssh_port, accepts)
}

// ---------------------------------------------------------------------------
// Scripted SOCKS5 proxy
// ---------------------------------------------------------------------------

/// Outcome of one scripted SOCKS5 proxy session: what target the client asked
/// the proxy to CONNECT to (host:port, as the client encoded it).
#[derive(Debug, Clone, PartialEq, Eq)]
struct ObservedConnect {
    host: String,
    port: u16,
}

/// Read a SOCKS5 CONNECT request body off `stream` (the 4-byte head has
/// already been consumed) and return the decoded target. `atyp` is the ATYP
/// byte from the head.
async fn read_connect_target(stream: &mut TcpStream, atyp: u8) -> ObservedConnect {
    let host = match atyp {
        0x01 => {
            // IPv4: 4 bytes
            let mut a = [0u8; 4];
            stream.read_exact(&mut a).await.unwrap();
            format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3])
        }
        0x03 => {
            // Domain: 1 len byte + name
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await.unwrap();
            let mut name = vec![0u8; len[0] as usize];
            stream.read_exact(&mut name).await.unwrap();
            String::from_utf8(name).unwrap()
        }
        0x04 => {
            // IPv6: 16 bytes
            let mut a = [0u8; 16];
            stream.read_exact(&mut a).await.unwrap();
            // Render compactly; tests connect to 127.0.0.1 so this path is
            // unused in practice, but keep it correct.
            a.chunks(2)
                .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
                .collect::<Vec<_>>()
                .join(":")
        }
        other => panic!("unexpected ATYP 0x{other:02x}"),
    };
    let mut port_bytes = [0u8; 2];
    stream.read_exact(&mut port_bytes).await.unwrap();
    let port = u16::from_be_bytes(port_bytes);
    ObservedConnect { host, port }
}

/// Spawn a scripted no-auth SOCKS5 proxy that performs exactly ONE handshake:
/// greeting → choose NO_AUTH (0x00) → read CONNECT → reply success → then
/// `copy_bidirectional` to the real `(upstream_host, upstream_port)`. The
/// observed CONNECT target is sent over the returned oneshot once decoded.
/// Returns `(proxy_port, observed_rx)`.
async fn spawn_socks5_proxy_noauth(
    upstream_host: String,
    upstream_port: u16,
) -> (u16, oneshot::Receiver<ObservedConnect>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (observed_tx, observed_rx) = oneshot::channel();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        // --- Greeting: VER NMETHODS METHODS... ---
        let mut head = [0u8; 2];
        stream.read_exact(&mut head).await.unwrap();
        assert_eq!(head[0], 0x05, "SOCKS5 version");
        let mut methods = vec![0u8; head[1] as usize];
        stream.read_exact(&mut methods).await.unwrap();
        // Choose NO_AUTH.
        stream.write_all(&[0x05, 0x00]).await.unwrap();

        // --- CONNECT: VER CMD RSV ATYP ... ---
        let mut req = [0u8; 4];
        stream.read_exact(&mut req).await.unwrap();
        assert_eq!(req[0], 0x05);
        assert_eq!(req[1], 0x01, "CMD must be CONNECT");
        let observed = read_connect_target(&mut stream, req[3]).await;
        let _ = observed_tx.send(observed);

        // Reply: VER REP RSV ATYP=IPv4 BND.ADDR(0.0.0.0) BND.PORT(0).
        stream
            .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();

        // --- Bridge to the real upstream (the SSH server). ---
        let mut upstream = TcpStream::connect((upstream_host.as_str(), upstream_port))
            .await
            .unwrap();
        let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
    });

    (port, observed_rx)
}

// ---------------------------------------------------------------------------
// A. [Socks5, SshHop] end-to-end
// ---------------------------------------------------------------------------

/// The headline composed chain: client → local listener → SOCKS5 proxy →
/// (proxy CONNECTs to the SSH server) → SSH `direct-tcpip` → echo upstream.
/// Asserts the byte echoes back AND that the proxy saw a CONNECT to the SSH
/// server's address (proving the socks5 layer carries the ssh dial — layer
/// ORDER is correct).
#[tokio::test]
async fn socks5_then_ssh_end_to_end_echoes_and_proves_layer_order() {
    let echo_port = spawn_echo_upstream().await;
    let (ssh_port, _accepts) = spawn_ssh_server(echo_port).await;
    // The SOCKS5 proxy's job is to CONNECT to the SSH server's address.
    let (proxy_port, observed_rx) = spawn_socks5_proxy_noauth("127.0.0.1".into(), ssh_port).await;

    let cfg = TunnelConfig::layered(vec![
        TunnelLayer::Socks5 {
            host: "127.0.0.1".into(),
            port: proxy_port,
            user: None,
            password: None,
        },
        TunnelLayer::SshHop(JumpHop {
            host: "127.0.0.1".into(),
            user: "tester".into(),
            password: Some("hunter2".into()),
            key_path: None,
            port: ssh_port,
        }),
    ]);

    let mut tunnel = LayeredTunnel::new(
        &cfg,
        ForwardTarget::Tcp {
            host: "127.0.0.1".into(),
            port: echo_port,
        },
    )
    .with_listen_addr("127.0.0.1:0".parse().unwrap());

    let ep = tunnel.establish().await.expect("establish chain");

    // Drive a byte through the whole stack and assert the echo.
    let mut client = TcpStream::connect((ep.host.as_str(), ep.port))
        .await
        .unwrap();
    client.write_all(b"ping").await.unwrap();
    let mut got = [0u8; 4];
    client.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"ping", "byte must round-trip through socks5+ssh");

    // The proxy must have observed a CONNECT to the SSH server's port — this
    // proves the socks5 layer wrapped (and carried) the ssh dial, not the
    // other way around.
    let observed = observed_rx.await.expect("proxy observed a connect");
    assert_eq!(
        observed.port, ssh_port,
        "socks5 proxy must CONNECT to the ssh server's port (layer order)"
    );
    assert_eq!(observed.host, "127.0.0.1");

    tunnel.close().await.unwrap();
}

// ---------------------------------------------------------------------------
// B. Multi-client concurrency over a single SSH layer
// ---------------------------------------------------------------------------

/// The "多客户端同时连接不卡住" guarantee. 20 clients hit a single-SSH-layer
/// tunnel CONCURRENTLY; each writes a unique 4-byte tag and asserts the same
/// tag echoes back. Then asserts the SSH transport was established EXACTLY
/// ONCE (accepts == 1) — all 20 forwarded conns multiplexed as `direct-tcpip`
/// channels over the one SSH session.
#[tokio::test]
async fn multi_client_concurrency_multiplexes_one_ssh_session() {
    const N: usize = 20;

    let echo_port = spawn_echo_upstream().await;
    let (ssh_port, accepts) = spawn_ssh_server(echo_port).await;

    let cfg = TunnelConfig::ssh(vec![JumpHop {
        host: "127.0.0.1".into(),
        user: "tester".into(),
        password: Some("hunter2".into()),
        key_path: None,
        port: ssh_port,
    }]);

    let mut tunnel = LayeredTunnel::new(
        &cfg,
        ForwardTarget::Tcp {
            host: "127.0.0.1".into(),
            port: echo_port,
        },
    )
    .with_listen_addr("127.0.0.1:0".parse().unwrap());

    let ep = tunnel
        .establish()
        .await
        .expect("establish single-ssh tunnel");
    let host = Arc::new(ep.host);
    let port = ep.port;

    // Fan out N concurrent clients. Each gets a unique 4-byte tag.
    let mut set = tokio::task::JoinSet::new();
    for i in 0..N {
        let host = Arc::clone(&host);
        set.spawn(async move {
            let tag = (i as u32).to_be_bytes();
            let mut client = TcpStream::connect((host.as_str(), port)).await.unwrap();
            client.write_all(&tag).await.unwrap();
            let mut got = [0u8; 4];
            client.read_exact(&mut got).await.unwrap();
            assert_eq!(got, tag, "client {i} must get its own tag echoed back");
            i
        });
    }

    // (a) All 20 succeed.
    let mut done = std::collections::HashSet::new();
    while let Some(res) = set.join_next().await {
        let i = res.expect("client task must not panic");
        done.insert(i);
    }
    assert_eq!(done.len(), N, "all {N} concurrent clients must succeed");

    // (b) The SSH session was established exactly once: 20 forwards
    // multiplexed as channels over the one SSH transport.
    assert_eq!(
        accepts.load(Ordering::SeqCst),
        1,
        "the SSH transport must be established exactly once for all {N} clients"
    );

    tunnel.close().await.unwrap();
}

// ---------------------------------------------------------------------------
// C. SOCKS5 connector auth coverage (no russh server needed)
// ---------------------------------------------------------------------------

/// Scripted SOCKS5 proxy that REQUIRES userpass auth: selects METHOD_USERPASS
/// (0x02), validates the RFC 1929 sub-negotiation against the expected
/// credentials, replies 0x01 0x00 (success), reads the CONNECT, replies
/// success, then bridges to `(upstream_host, upstream_port)`.
/// Returns the proxy port.
async fn spawn_socks5_proxy_userpass(
    expect_user: String,
    expect_pass: String,
    upstream_host: String,
    upstream_port: u16,
) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        // --- Greeting: client must offer METHOD_USERPASS (0x02). ---
        let mut head = [0u8; 2];
        stream.read_exact(&mut head).await.unwrap();
        assert_eq!(head[0], 0x05);
        let mut methods = vec![0u8; head[1] as usize];
        stream.read_exact(&mut methods).await.unwrap();
        assert!(
            methods.contains(&0x02),
            "client must advertise userpass auth"
        );
        // Select USERPASS.
        stream.write_all(&[0x05, 0x02]).await.unwrap();

        // --- RFC 1929 sub-negotiation: VER ULEN UNAME PLEN PASSWD ---
        let mut ver = [0u8; 1];
        stream.read_exact(&mut ver).await.unwrap();
        assert_eq!(ver[0], 0x01, "userpass subneg version");
        let mut ulen = [0u8; 1];
        stream.read_exact(&mut ulen).await.unwrap();
        let mut uname = vec![0u8; ulen[0] as usize];
        stream.read_exact(&mut uname).await.unwrap();
        let mut plen = [0u8; 1];
        stream.read_exact(&mut plen).await.unwrap();
        let mut passwd = vec![0u8; plen[0] as usize];
        stream.read_exact(&mut passwd).await.unwrap();
        assert_eq!(uname, expect_user.as_bytes());
        assert_eq!(passwd, expect_pass.as_bytes());
        // Reply success.
        stream.write_all(&[0x01, 0x00]).await.unwrap();

        // --- CONNECT ---
        let mut req = [0u8; 4];
        stream.read_exact(&mut req).await.unwrap();
        assert_eq!(req[1], 0x01);
        let _ = read_connect_target(&mut stream, req[3]).await;
        stream
            .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();

        let mut upstream = TcpStream::connect((upstream_host.as_str(), upstream_port))
            .await
            .unwrap();
        let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
    });

    port
}

/// (C-i) SOCKS5 userpass auth SUCCESS: the connector negotiates RFC 1929,
/// authenticates, CONNECTs, and the byte round-trips to the echo upstream.
#[tokio::test]
async fn socks5_userpass_auth_success_round_trips() {
    let echo_port = spawn_echo_upstream().await;
    let proxy_port = spawn_socks5_proxy_userpass(
        "alice".into(),
        "s3cr3t".into(),
        "127.0.0.1".into(),
        echo_port,
    )
    .await;

    let cfg = TunnelConfig::socks5(
        "127.0.0.1".into(),
        proxy_port,
        Some("alice".into()),
        Some("s3cr3t".into()),
    );

    let mut tunnel = LayeredTunnel::new(
        &cfg,
        ForwardTarget::Tcp {
            host: "127.0.0.1".into(),
            port: echo_port,
        },
    )
    .with_listen_addr("127.0.0.1:0".parse().unwrap());

    let ep = tunnel.establish().await.expect("establish userpass socks5");
    let mut client = TcpStream::connect((ep.host.as_str(), ep.port))
        .await
        .unwrap();
    client.write_all(b"auth").await.unwrap();
    let mut got = [0u8; 4];
    client.read_exact(&mut got).await.unwrap();
    assert_eq!(
        &got, b"auth",
        "byte must round-trip through userpass socks5"
    );

    tunnel.close().await.unwrap();
}

/// Scripted SOCKS5 proxy that selects USERPASS then REJECTS the credentials
/// (replies 0x01 0x01). Returns the proxy port. After the reject it closes,
/// so the connector must surface an Err rather than hang.
async fn spawn_socks5_proxy_auth_failure() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        let mut head = [0u8; 2];
        stream.read_exact(&mut head).await.unwrap();
        let mut methods = vec![0u8; head[1] as usize];
        stream.read_exact(&mut methods).await.unwrap();
        // Select USERPASS.
        stream.write_all(&[0x05, 0x02]).await.unwrap();

        // Read (and discard) the RFC 1929 sub-negotiation.
        let mut ver = [0u8; 1];
        stream.read_exact(&mut ver).await.unwrap();
        let mut ulen = [0u8; 1];
        stream.read_exact(&mut ulen).await.unwrap();
        let mut uname = vec![0u8; ulen[0] as usize];
        stream.read_exact(&mut uname).await.unwrap();
        let mut plen = [0u8; 1];
        stream.read_exact(&mut plen).await.unwrap();
        let mut passwd = vec![0u8; plen[0] as usize];
        stream.read_exact(&mut passwd).await.unwrap();

        // Reject (STATUS != 0). Then drop the connection.
        let _ = stream.write_all(&[0x01, 0x01]).await;
    });

    port
}

/// (C-ii) SOCKS5 auth FAILURE: the proxy rejects credentials (0x01 0x01). The
/// connector must return an Err — NOT hang. We drive a client byte to force
/// the lazy CONNECT, and assert the byte does NOT round-trip (the forward
/// task errored on the rejected handshake before reaching the upstream).
#[tokio::test]
async fn socks5_auth_failure_errors_not_hangs() {
    // Directly exercise the connector so we can observe the Err synchronously,
    // rather than through the fire-and-forget LayeredTunnel forward task.
    use tools4a_core::tunnel::build_connector;

    let proxy_port = spawn_socks5_proxy_auth_failure().await;
    let connector = build_connector(&[TunnelLayer::Socks5 {
        host: "127.0.0.1".into(),
        port: proxy_port,
        user: Some("alice".into()),
        password: Some("wrong".into()),
    }]);

    // The CONNECT call must resolve to an Err (rejected auth), and must do so
    // promptly — wrap in a timeout so a hang fails the test deterministically.
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        connector.connect("127.0.0.1", 9),
    )
    .await
    .expect("connector must not hang on auth rejection");

    assert!(
        result.is_err(),
        "rejected SOCKS5 auth must surface as an Err, got Ok"
    );
}
