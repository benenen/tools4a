//! The one generic tunnel: bind a local listener, and per accepted
//! connection dial the target through the folded `Connector` chain.
//!
//! `build_tunnel` lowers every `TunnelConfig` to a `LayeredTunnel` whose
//! `connector` is `build_connector(&cfg.layers)` and whose `target` is a
//! plain TCP forward. `tunnel-serve` reuses the same engine with the
//! `Socks5Server` / `StreamLocal` targets.

use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

use super::chain::{build_connector, build_streamlocal_connector};
use super::socks::connector::Connector;
use super::socks::server::Socks5Server;
use crate::session::AcceptAnyHostKey;
use crate::{Error, Result, Tunnel, TunnelConfig, TunnelEndpoint, TunnelLayer};

/// What the local listener forwards each accepted connection to.
pub enum ForwardTarget {
    /// Forward every connection to a single fixed `(host, port)` over the
    /// chain. This is the `-L` port-forward shape used by `build_tunnel`.
    Tcp { host: String, port: u16 },
    /// Run a SOCKS5 server on the local port; each inbound SOCKS5 CONNECT
    /// is dialed through the chain. The `-D` dynamic-forward shape.
    Socks5Server,
    /// Forward to a remote unix-domain socket via the innermost SSH hop.
    StreamLocal { path: String },
}

/// Cheap `Clone`able description of a `ForwardTarget` so each spawned
/// per-connection task can own its own copy. `StreamLocal` is intentionally
/// absent: it never rides the generic `serve_conn` path (it needs a concrete
/// SSH handle, so `establish` runs a dedicated accept loop for it).
#[derive(Clone)]
enum TargetSpec {
    Tcp { host: String, port: u16 },
    Socks5Server,
}

impl ForwardTarget {
    /// Describe the non-streamlocal targets. Only called for `Tcp` /
    /// `Socks5Server` (streamlocal is dispatched separately in `establish`).
    fn describe(&self) -> TargetSpec {
        match self {
            ForwardTarget::Tcp { host, port } => TargetSpec::Tcp {
                host: host.clone(),
                port: *port,
            },
            ForwardTarget::Socks5Server => TargetSpec::Socks5Server,
            ForwardTarget::StreamLocal { .. } => {
                unreachable!("streamlocal targets are dispatched before describe()")
            }
        }
    }
}

pub struct LayeredTunnel {
    layers: Vec<TunnelLayer>,
    connector: Arc<dyn Connector>,
    target: ForwardTarget,
    listen_addr: Option<SocketAddr>,
    state: Option<LayeredState>,
    last_layer_is_ssh: bool,
}

struct LayeredState {
    shutdown: tokio::sync::watch::Sender<bool>,
    listener_task: tokio::task::JoinHandle<()>,
}

impl LayeredTunnel {
    pub fn new(cfg: &TunnelConfig, target: ForwardTarget) -> Self {
        Self {
            layers: cfg.layers.clone(),
            connector: build_connector(&cfg.layers),
            target,
            listen_addr: None,
            state: None,
            last_layer_is_ssh: cfg.last_layer_is_ssh(),
        }
    }

    /// Override the default `127.0.0.1:0` listen binding with a specific
    /// address. Used by the `tunnel-serve` CLI to bind a predictable port.
    pub fn with_listen_addr(mut self, addr: SocketAddr) -> Self {
        self.listen_addr = Some(addr);
        self
    }
}

#[async_trait]
impl Tunnel for LayeredTunnel {
    async fn establish(&mut self) -> Result<TunnelEndpoint> {
        if self.state.is_some() {
            return Err(Error::Connection(
                "LayeredTunnel::establish called twice".into(),
            ));
        }
        // Streamlocal needs a real SSH session at the innermost hop (the
        // TCP-shaped `Connector` API can't open a unix-socket channel), so
        // it folds a concrete `SshHopConnector` and runs its own forwarder.
        // The other two targets ride the generic `dyn Connector` chain.
        let streamlocal = match &self.target {
            ForwardTarget::StreamLocal { path } => {
                if !self.last_layer_is_ssh {
                    return Err(Error::Config(
                        "streamlocal target requires the innermost layer to be an SSH hop".into(),
                    ));
                }
                let conn = build_streamlocal_connector(&self.layers)?;
                conn.prewarm().await?;
                let handle = conn.handle().await?;
                Some((conn, handle, path.clone()))
            }
            _ => {
                // Fail fast: establish SSH sessions / validate the chain now
                // so bad credentials surface at establish() time.
                self.connector.prewarm().await?;
                None
            }
        };

        let bind = self
            .listen_addr
            .unwrap_or_else(|| "127.0.0.1:0".parse().expect("static addr"));
        let listener = tokio::net::TcpListener::bind(bind)
            .await
            .map_err(Error::Io)?;
        let local = listener.local_addr().map_err(Error::Io)?;
        let (host, port) = (local.ip().to_string(), local.port());

        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);

        let listener_task = if let Some((conn, handle, path)) = streamlocal {
            // Keep the concrete connector alive for the loop's lifetime so
            // its cached SSH session (and the channels on it) survive.
            tokio::spawn(async move {
                let _keepalive = conn;
                loop {
                    tokio::select! {
                        _ = shutdown_rx.changed() => {
                            if *shutdown_rx.borrow() { break; }
                        }
                        accepted = listener.accept() => {
                            let (inbound, _) = match accepted {
                                Ok(p) => p,
                                Err(e) => {
                                    eprintln!("layered tunnel: accept failed: {e}");
                                    break;
                                }
                            };
                            let handle = Arc::clone(&handle);
                            let path = path.clone();
                            tokio::spawn(async move {
                                if let Err(e) = forward_streamlocal(handle, path, inbound).await {
                                    eprintln!("layered tunnel: streamlocal forward failed: {e}");
                                }
                            });
                        }
                    }
                }
            })
        } else {
            let connector = Arc::clone(&self.connector);
            let target = self.target.describe();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = shutdown_rx.changed() => {
                            if *shutdown_rx.borrow() { break; }
                        }
                        accepted = listener.accept() => {
                            let (inbound, _) = match accepted {
                                Ok(p) => p,
                                Err(e) => {
                                    eprintln!("layered tunnel: accept failed: {e}");
                                    break;
                                }
                            };
                            let connector = Arc::clone(&connector);
                            let target = target.clone();
                            tokio::spawn(async move {
                                if let Err(e) = serve_conn(connector, target, inbound).await {
                                    eprintln!("layered tunnel: forward failed: {e}");
                                }
                            });
                        }
                    }
                }
            })
        };

        self.state = Some(LayeredState {
            shutdown: shutdown_tx,
            listener_task,
        });

        Ok(TunnelEndpoint { host, port })
    }

    async fn close(&mut self) -> Result<()> {
        if let Some(state) = self.state.take() {
            let _ = state.shutdown.send(true);
            let _ = state.listener_task.await;
        }
        Ok(())
    }

    fn is_active(&self) -> bool {
        self.state.is_some()
    }
}

async fn serve_conn(
    connector: Arc<dyn Connector>,
    target: TargetSpec,
    mut inbound: tokio::net::TcpStream,
) -> Result<()> {
    match target {
        TargetSpec::Tcp { host, port } => {
            let mut up = connector.connect(&host, port).await?;
            tokio::io::copy_bidirectional(&mut inbound, &mut up)
                .await
                .map_err(Error::Io)?;
        }
        TargetSpec::Socks5Server => {
            // The folded connector is exactly the `Connector` the SOCKS5
            // server drives its outbound CONNECTs through.
            Socks5Server::serve_one(inbound, connector).await?;
        }
    }
    Ok(())
}

/// Bridge an inbound TCP conn ⟷ a fresh `direct-streamlocal` channel on the
/// innermost SSH hop, to a remote unix-domain socket at `socket_path`.
async fn forward_streamlocal(
    session: Arc<Mutex<russh::client::Handle<AcceptAnyHostKey>>>,
    socket_path: String,
    mut inbound: tokio::net::TcpStream,
) -> Result<()> {
    let channel = session
        .lock()
        .await
        .channel_open_direct_streamlocal(socket_path.clone())
        .await
        .map_err(|e| {
            Error::Connection(format!(
                "open direct-streamlocal to {socket_path} failed: {e}"
            ))
        })?;
    // ChannelStream is not Unpin, so box-pin before copy_bidirectional.
    let mut channel_stream = Box::pin(channel.into_stream());
    tokio::io::copy_bidirectional(&mut inbound, &mut channel_stream)
        .await
        .map_err(Error::Io)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn layered_tcp_forward_carries_bytes_direct() {
        // upstream echo server
        let up = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up_addr = up.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = up.accept().await.unwrap();
            let mut b = [0u8; 4];
            s.read_exact(&mut b).await.unwrap();
            s.write_all(&b).await.unwrap();
        });

        let cfg = TunnelConfig::direct();
        let mut t = LayeredTunnel::new(
            &cfg,
            ForwardTarget::Tcp {
                host: "127.0.0.1".into(),
                port: up_addr.port(),
            },
        );
        let ep = t.establish().await.unwrap();
        let mut c = tokio::net::TcpStream::connect((ep.host.as_str(), ep.port))
            .await
            .unwrap();
        c.write_all(b"ping").await.unwrap();
        let mut got = [0u8; 4];
        c.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ping");
        t.close().await.unwrap();
    }

    #[tokio::test]
    async fn establish_twice_errors() {
        let cfg = TunnelConfig::direct();
        let mut t = LayeredTunnel::new(
            &cfg,
            ForwardTarget::Tcp {
                host: "127.0.0.1".into(),
                port: 9,
            },
        );
        t.establish().await.unwrap();
        assert!(t.is_active());
        assert!(matches!(t.establish().await, Err(Error::Connection(_))));
        t.close().await.unwrap();
        assert!(!t.is_active());
    }

    #[tokio::test]
    async fn streamlocal_without_ssh_tail_errors_at_establish() {
        let cfg = TunnelConfig::direct();
        let mut t = LayeredTunnel::new(
            &cfg,
            ForwardTarget::StreamLocal {
                path: "/var/run/docker.sock".into(),
            },
        );
        assert!(matches!(t.establish().await, Err(Error::Config(_))));
    }
}
