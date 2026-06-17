//! `Connector` trait — abstracts "open a byte-stream to (host, port)"
//! so the SOCKS5 server and the layer-stack tunnels can be driven by any
//! transport (raw TCP, a SOCKS5 relay, an SSH `direct-tcpip` channel)
//! without the caller knowing which. The concrete impls live in
//! `tunnel::chain` (`TcpConnector` / `Socks5Connector` / `SshHopConnector`).

use async_trait::async_trait;
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::Result;

/// Async stream the SOCKS server bidirectionally copies bytes
/// between (inbound TCP socket <-> outbound `Stream`).
pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

#[async_trait]
pub trait Connector: Send + Sync {
    /// Open a stream to `host:port`. The implementor decides how to
    /// resolve, if at all — `SshHopConnector` forwards the literal name
    /// through SSH `direct-tcpip` so the bastion does the resolution.
    async fn connect(&self, host: &str, port: u16) -> Result<Pin<Box<dyn Stream>>>;

    /// Eagerly establish any cached state (e.g. an SSH session) so failures
    /// surface at tunnel `establish()` time, not on the first client byte.
    /// Default: nothing to warm.
    async fn prewarm(&self) -> Result<()> {
        Ok(())
    }
}
