//! Connector chain engine: the base of every tunnel stack. Currently holds
//! `TcpConnector` (a raw local TCP dial); later layers wrap an inner
//! `Connector` to compose SOCKS5/SSH transports.

use async_trait::async_trait;
use std::pin::Pin;
use std::sync::Arc;
use tokio::net::TcpStream;

use super::socks::client::handshake_and_connect;
use super::socks::connector::{Connector, Stream};
use crate::{Error, Result};

/// Base of every chain: a raw local TCP dial.
#[allow(dead_code)] // constructed by Task 3's build_connector
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
#[allow(dead_code)] // constructed by Task 3's build_connector
pub(crate) struct Socks5Connector {
    pub inner: Arc<dyn Connector>,
    pub proxy_host: String,
    pub proxy_port: u16,
    pub user: Option<String>,
    pub password: Option<String>,
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
