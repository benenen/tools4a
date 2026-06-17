//! Connector chain engine: the base of every tunnel stack. Currently holds
//! `TcpConnector` (a raw local TCP dial); later layers wrap an inner
//! `Connector` to compose SOCKS5/SSH transports.

use async_trait::async_trait;
use std::pin::Pin;
use tokio::net::TcpStream;

use super::socks::connector::{Connector, Stream};
use crate::{Error, Result};

/// Base of every chain: a raw local TCP dial.
#[allow(dead_code)] // used by Task 2 (Socks5Connector layer)
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
