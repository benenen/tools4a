//! SOCKS5-client tunnel: routes outbound traffic through an already-running
//! external SOCKS5 proxy.
//!
//! Lifecycle mirrors `SshTunnel`:
//! - `new()` records the proxy + auth config (no IO).
//! - `establish()` binds `127.0.0.1:0`, spawns an accept loop, and returns
//!   the local TCP `TunnelEndpoint`. Each accepted inbound connection
//!   opens its OWN TCP to the SOCKS5 proxy, runs the SOCKS5 handshake +
//!   CONNECT to `(target_host, target_port)`, then bridges with
//!   `tokio::io::copy_bidirectional`.
//! - `close()` signals shutdown via the watch channel and awaits the
//!   accept task for bounded teardown. No pre-established sessions to drop.
//!
//! Auth: no-auth (RFC 1928 method 0x00) by default; RFC 1929 user/pass
//! (method 0x02) when both `proxy_user` and `proxy_pass` are provided.

use async_trait::async_trait;
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use crate::tunnel::socks::client::handshake_and_connect;
use crate::{Error, Result, Tunnel, TunnelEndpoint};

pub struct Socks5ClientTunnel {
    proxy_host: String,
    proxy_port: u16,
    proxy_user: Option<String>,
    proxy_pass: Option<String>,
    target_host: String,
    target_port: u16,
    /// Optional fixed listen address. `None` → bind 127.0.0.1:0 (random).
    listen_addr: Option<SocketAddr>,
    /// Set on `establish()`, cleared on `close()`.
    state: Option<Socks5ClientTunnelState>,
}

struct Socks5ClientTunnelState {
    shutdown: tokio::sync::watch::Sender<bool>,
    accept_task: JoinHandle<()>,
}

impl Socks5ClientTunnel {
    pub fn new(
        proxy_host: String,
        proxy_port: u16,
        proxy_user: Option<String>,
        proxy_pass: Option<String>,
        target_host: String,
        target_port: u16,
    ) -> Result<Self> {
        if proxy_host.is_empty() {
            return Err(Error::Config(
                "Socks5ClientTunnel requires a non-empty proxy_host".into(),
            ));
        }
        if proxy_user.is_some() != proxy_pass.is_some() {
            return Err(Error::Config(
                "Socks5ClientTunnel: proxy_user and proxy_pass must be set together".into(),
            ));
        }
        Ok(Self {
            proxy_host,
            proxy_port,
            proxy_user,
            proxy_pass,
            target_host,
            target_port,
            listen_addr: None,
            state: None,
        })
    }

    /// Override the default `127.0.0.1:0` listen binding. Reserved for
    /// future `tunnel-serve` daemon use; not wired into the CLI today.
    pub fn with_listen_addr(mut self, addr: SocketAddr) -> Self {
        self.listen_addr = Some(addr);
        self
    }
}

#[async_trait]
impl Tunnel for Socks5ClientTunnel {
    async fn establish(&mut self) -> Result<TunnelEndpoint> {
        if self.state.is_some() {
            return Err(Error::Connection(
                "Socks5ClientTunnel::establish called twice".into(),
            ));
        }

        let bind: SocketAddr = self
            .listen_addr
            .unwrap_or_else(|| "127.0.0.1:0".parse().expect("static addr"));
        let listener = TcpListener::bind(bind).await.map_err(Error::Io)?;
        let local = listener.local_addr().map_err(Error::Io)?;
        let local_port = local.port();
        let local_host = local.ip().to_string();

        let proxy_host = self.proxy_host.clone();
        let proxy_port = self.proxy_port;
        let proxy_user = self.proxy_user.clone();
        let proxy_pass = self.proxy_pass.clone();
        let target_host = self.target_host.clone();
        let target_port = self.target_port;

        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
        let accept_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
                    }
                    accepted = listener.accept() => {
                        match accepted {
                            Ok((inbound, _peer)) => {
                                let proxy_host = proxy_host.clone();
                                let proxy_user = proxy_user.clone();
                                let proxy_pass = proxy_pass.clone();
                                let target_host = target_host.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = forward_one(
                                        inbound,
                                        proxy_host,
                                        proxy_port,
                                        proxy_user,
                                        proxy_pass,
                                        target_host,
                                        target_port,
                                    ).await {
                                        eprintln!("socks5 client tunnel: forward failed: {e}");
                                    }
                                });
                            }
                            Err(e) => {
                                eprintln!("socks5 client tunnel: accept failed: {e}");
                                tokio::time::sleep(
                                    std::time::Duration::from_millis(50),
                                ).await;
                            }
                        }
                    }
                }
            }
        });

        self.state = Some(Socks5ClientTunnelState {
            shutdown: shutdown_tx,
            accept_task,
        });

        Ok(TunnelEndpoint {
            host: local_host,
            port: local_port,
        })
    }

    async fn close(&mut self) -> Result<()> {
        if let Some(state) = self.state.take() {
            let _ = state.shutdown.send(true);
            let _ = state.accept_task.await;
        }
        Ok(())
    }

    fn is_active(&self) -> bool {
        self.state.is_some()
    }
}

/// One inbound conn → one outbound to the SOCKS5 proxy → handshake → CONNECT
/// → bidirectional copy.
#[allow(clippy::too_many_arguments)]
async fn forward_one(
    mut inbound: TcpStream,
    proxy_host: String,
    proxy_port: u16,
    proxy_user: Option<String>,
    proxy_pass: Option<String>,
    target_host: String,
    target_port: u16,
) -> Result<()> {
    let mut outbound = TcpStream::connect((proxy_host.as_str(), proxy_port))
        .await
        .map_err(|e| {
            Error::Connection(format!(
                "connect to SOCKS5 proxy {proxy_host}:{proxy_port}: {e}"
            ))
        })?;

    handshake_and_connect(
        &mut outbound,
        proxy_user.as_deref(),
        proxy_pass.as_deref(),
        &target_host,
        target_port,
    )
    .await?;

    tokio::io::copy_bidirectional(&mut inbound, &mut outbound)
        .await
        .map_err(Error::Io)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_rejects_empty_proxy_host() {
        assert!(matches!(
            Socks5ClientTunnel::new("".into(), 1080, None, None, "target".into(), 3306),
            Err(Error::Config(ref m)) if m.contains("proxy_host")
        ));
    }

    #[test]
    fn new_rejects_password_without_user() {
        assert!(matches!(
            Socks5ClientTunnel::new(
                "p".into(),
                1080,
                None,
                Some("pw".into()),
                "target".into(),
                80
            ),
            Err(Error::Config(ref m)) if m.contains("set together")
        ));
    }

    #[test]
    fn new_rejects_user_without_password() {
        assert!(matches!(
            Socks5ClientTunnel::new(
                "p".into(),
                1080,
                Some("u".into()),
                None,
                "target".into(),
                80
            ),
            Err(Error::Config(ref m)) if m.contains("set together")
        ));
    }

    #[test]
    fn new_accepts_no_auth_inactive() {
        let t = Socks5ClientTunnel::new("p".into(), 1080, None, None, "target".into(), 80).unwrap();
        assert!(!t.is_active());
    }

    #[test]
    fn new_accepts_userpass_inactive() {
        let t = Socks5ClientTunnel::new(
            "p".into(),
            1080,
            Some("u".into()),
            Some("pw".into()),
            "target".into(),
            80,
        )
        .unwrap();
        assert!(!t.is_active());
    }

    #[tokio::test]
    async fn state_starts_inactive() {
        let t = Socks5ClientTunnel::new("p".into(), 1080, None, None, "target".into(), 80).unwrap();
        assert!(!t.is_active());
    }
}
