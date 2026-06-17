//! Connector chain engine: the base of every tunnel stack. Holds
//! `TcpConnector` (a raw local TCP dial), `Socks5Connector` (a SOCKS5
//! relay layer), and `SshHopConnector` (an SSH session layer with a
//! cached-once handle). `build_connector` folds a `TunnelLayer` slice
//! into the appropriate nested `Connector` chain.

use async_trait::async_trait;
use russh::client;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::{Mutex, OnceCell};

use super::socks::client::handshake_and_connect;
use super::socks::connector::{Connector, Stream};
use crate::session::{AcceptAnyHostKey, authenticate};
use crate::{Error, JumpHop, Result, TunnelLayer};

/// Base of every chain: a raw local TCP dial.
pub(crate) struct TcpConnector;

#[async_trait]
impl Connector for TcpConnector {
    async fn connect(&self, host: &str, port: u16) -> Result<Pin<Box<dyn Stream>>> {
        let s = TcpStream::connect((host, port))
            .await
            .map_err(|e| Error::Connection(format!("tcp connect to {host}:{port}: {e}")))?;
        Ok(Box::pin(s))
    }
}

/// A SOCKS5 layer: reach the proxy via `inner`, then SOCKS5 CONNECT to the next.
pub(crate) struct Socks5Connector {
    pub(crate) inner: Arc<dyn Connector>,
    pub(crate) proxy_host: String,
    pub(crate) proxy_port: u16,
    pub(crate) user: Option<String>,
    pub(crate) password: Option<String>,
}

#[async_trait]
impl Connector for Socks5Connector {
    async fn connect(&self, host: &str, port: u16) -> Result<Pin<Box<dyn Stream>>> {
        let mut stream = self
            .inner
            .connect(&self.proxy_host, self.proxy_port)
            .await?;
        handshake_and_connect(
            &mut stream,
            self.user.as_deref(),
            self.password.as_deref(),
            host,
            port,
        )
        .await?;
        Ok(stream)
    }

    async fn prewarm(&self) -> Result<()> {
        self.inner.prewarm().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn tcp_connector_reaches_a_local_listener() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            s.write_all(b"hi").await.unwrap();
        });
        let mut stream = TcpConnector
            .connect("127.0.0.1", addr.port())
            .await
            .unwrap();
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hi");
    }
}

type SshHandle = Arc<Mutex<client::Handle<AcceptAnyHostKey>>>;

/// An SSH layer: reach the SSH server via `inner`, establish and
/// authenticate ONCE (cached in `OnceCell`), then open one
/// `direct-tcpip` channel per `connect` call.
pub(crate) struct SshHopConnector {
    pub(crate) inner: Arc<dyn Connector>,
    pub(crate) hop: JumpHop,
    session: OnceCell<SshHandle>,
}

impl SshHopConnector {
    pub(crate) fn new(inner: Arc<dyn Connector>, hop: JumpHop) -> Self {
        Self {
            inner,
            hop,
            session: OnceCell::new(),
        }
    }

    /// Establish (or reuse) the SSH session on this hop and hand back the
    /// shared handle. Used by `StreamLocalTunnel`, which needs a real SSH
    /// session at the innermost hop to open `direct-streamlocal` channels.
    pub(crate) async fn handle(&self) -> Result<SshHandle> {
        self.ensure_session().await
    }

    async fn ensure_session(&self) -> Result<SshHandle> {
        let handle = self
            .session
            .get_or_try_init(|| async {
                let cfg = Arc::new(client::Config::default());
                let stream = self.inner.connect(&self.hop.host, self.hop.port).await?;
                let handler = AcceptAnyHostKey {
                    label: self.hop.host.clone(),
                };
                let mut session =
                    client::connect_stream(cfg, stream, handler)
                        .await
                        .map_err(|e| {
                            Error::Connection(format!(
                                "SSH connect to {} failed: {e}",
                                self.hop.host
                            ))
                        })?;
                authenticate(
                    &mut session,
                    &self.hop.user,
                    self.hop.password.as_deref(),
                    self.hop.key_path.as_deref().map(Path::new),
                )
                .await?;
                Ok::<_, Error>(Arc::new(Mutex::new(session)))
            })
            .await?;
        Ok(handle.clone())
    }
}

#[async_trait]
impl Connector for SshHopConnector {
    async fn connect(&self, host: &str, port: u16) -> Result<Pin<Box<dyn Stream>>> {
        let handle = self.ensure_session().await?;
        let channel = handle
            .lock()
            .await
            .channel_open_direct_tcpip(host.to_string(), port as u32, "127.0.0.1", 0u32)
            .await
            .map_err(|e| Error::Connection(format!("direct-tcpip to {host}:{port}: {e}")))?;
        Ok(Box::pin(channel.into_stream()))
    }

    async fn prewarm(&self) -> Result<()> {
        self.inner.prewarm().await?;
        self.ensure_session().await?;
        Ok(())
    }
}

/// Fold a layer list (local→target order) into the top `Connector`.
/// The bottom of the stack is always a raw `TcpConnector`; each layer
/// in `layers` wraps the accumulator in a new connector type.
pub fn build_connector(layers: &[TunnelLayer]) -> Arc<dyn Connector> {
    let mut acc: Arc<dyn Connector> = Arc::new(TcpConnector);
    for layer in layers {
        acc = fold_layer(acc, layer);
    }
    acc
}

fn fold_layer(acc: Arc<dyn Connector>, layer: &TunnelLayer) -> Arc<dyn Connector> {
    match layer {
        TunnelLayer::Socks5 {
            host,
            port,
            user,
            password,
        } => Arc::new(Socks5Connector {
            inner: acc,
            proxy_host: host.clone(),
            proxy_port: *port,
            user: user.clone(),
            password: password.clone(),
        }),
        TunnelLayer::SshHop(hop) => Arc::new(SshHopConnector::new(acc, hop.clone())),
    }
}

/// Fold a layer list whose innermost (last) layer MUST be an SSH hop,
/// returning the concrete `Arc<SshHopConnector>` for that final hop. The
/// `StreamLocalTunnel` needs this concrete type so it can grab the SSH
/// handle and open `direct-streamlocal` channels (which `Connector::connect`
/// — a TCP-shaped API — can't express). Errors if `layers` is empty or
/// doesn't end in an SSH hop.
pub(crate) fn build_streamlocal_connector(layers: &[TunnelLayer]) -> Result<Arc<SshHopConnector>> {
    let Some((last, init)) = layers.split_last() else {
        return Err(Error::Config(
            "streamlocal requires an SSH hop (empty layer stack)".into(),
        ));
    };
    let TunnelLayer::SshHop(hop) = last else {
        return Err(Error::Config(
            "streamlocal requires the innermost layer to be an SSH hop".into(),
        ));
    };
    let inner = build_connector(init);
    Ok(Arc::new(SshHopConnector::new(inner, hop.clone())))
}

#[cfg(test)]
mod build_connector_tests {
    use super::*;
    use crate::{JumpHop, TunnelLayer};

    #[derive(Default)]
    struct PrewarmProbe {
        count: std::sync::atomic::AtomicUsize,
    }

    #[async_trait]
    impl Connector for PrewarmProbe {
        async fn connect(&self, _h: &str, _p: u16) -> Result<Pin<Box<dyn Stream>>> {
            Err(Error::Connection("probe".into()))
        }

        async fn prewarm(&self) -> Result<()> {
            self.count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
    }

    use std::sync::atomic::Ordering::SeqCst;

    /// `build_connector` type-checks: a `[Socks5, SshHop]` list folds into an
    /// `Arc<dyn Connector>` (the concrete top is an `SshHopConnector` wrapping
    /// a `Socks5Connector` wrapping the base `TcpConnector`).
    #[tokio::test]
    async fn build_connector_folds_layers_into_a_connector() {
        let layers = vec![
            TunnelLayer::Socks5 {
                host: "p".into(),
                port: 1080,
                user: None,
                password: None,
            },
            TunnelLayer::SshHop(JumpHop {
                host: "gw".into(),
                user: "u".into(),
                password: Some("pw".into()),
                key_path: None,
                port: 22,
            }),
        ];
        let _top: Arc<dyn Connector> = build_connector(&layers);
    }

    /// `prewarm` walks the WHOLE chain bottom-first: an
    /// `SshHopConnector` over a `Socks5Connector` over a `PrewarmProbe`
    /// must reach the probe (count == 1) before the SSH session
    /// establishment fails on the probe's erroring `connect`.
    #[tokio::test]
    async fn prewarm_walks_the_full_chain_before_session_establish() {
        let probe = Arc::new(PrewarmProbe::default());
        let socks: Arc<dyn Connector> = Arc::new(Socks5Connector {
            inner: probe.clone(),
            proxy_host: "p".into(),
            proxy_port: 1080,
            user: None,
            password: None,
        });
        let ssh = SshHopConnector::new(
            socks,
            JumpHop {
                host: "gw".into(),
                user: "u".into(),
                password: Some("pw".into()),
                key_path: None,
                port: 22,
            },
        );

        // prewarm walks inner (ssh -> socks -> probe.prewarm) first, then tries
        // to establish the SSH session, which dials through the probe and fails.
        let err = ssh.prewarm().await;
        assert!(err.is_err(), "session establish must fail over the probe");
        assert_eq!(
            probe.count.load(SeqCst),
            1,
            "prewarm must reach the probe at the bottom of the chain"
        );
    }
}

#[cfg(test)]
mod socks_layer_tests {
    use super::*;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
    use tokio::sync::Mutex as TokioMutex;

    struct MockConnector {
        peer: TokioMutex<Option<DuplexStream>>,
        dialed: Arc<TokioMutex<Option<(String, u16)>>>,
    }
    #[async_trait]
    impl Connector for MockConnector {
        async fn connect(&self, host: &str, port: u16) -> Result<Pin<Box<dyn Stream>>> {
            *self.dialed.lock().await = Some((host.to_string(), port));
            let s = self.peer.lock().await.take().expect("connect called once");
            Ok(Box::pin(s))
        }
    }

    #[tokio::test]
    async fn socks5_connector_handshakes_through_inner_and_reaches_target() {
        let (client_end, mut proxy_end) = tokio::io::duplex(1024);
        let dialed = Arc::new(TokioMutex::new(None));
        let inner = Arc::new(MockConnector {
            peer: TokioMutex::new(Some(client_end)),
            dialed: dialed.clone(),
        });

        let proxy = tokio::spawn(async move {
            let mut greet = [0u8; 3];
            proxy_end.read_exact(&mut greet).await.unwrap(); // VER NMETHODS METHOD
            proxy_end.write_all(&[0x05, 0x00]).await.unwrap(); // choose NO_AUTH
            let mut head = [0u8; 4];
            proxy_end.read_exact(&mut head).await.unwrap(); // VER CMD RSV ATYP
            let mut len = [0u8; 1];
            proxy_end.read_exact(&mut len).await.unwrap();
            let mut rest = vec![0u8; len[0] as usize + 2];
            proxy_end.read_exact(&mut rest).await.unwrap();
            proxy_end
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            let mut b = [0u8; 1];
            proxy_end.read_exact(&mut b).await.unwrap();
            proxy_end.write_all(&b).await.unwrap();
        });

        let layer = Socks5Connector {
            inner,
            proxy_host: "proxy.invalid".into(),
            proxy_port: 1080,
            user: None,
            password: None,
        };
        let mut stream = layer.connect("target.invalid", 3306).await.unwrap();
        assert_eq!(
            dialed.lock().await.clone().unwrap(),
            ("proxy.invalid".into(), 1080)
        );
        stream.write_all(&[0x42]).await.unwrap();
        let mut got = [0u8; 1];
        stream.read_exact(&mut got).await.unwrap();
        assert_eq!(got[0], 0x42);
        proxy.await.unwrap();
    }
}
