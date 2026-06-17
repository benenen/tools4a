//! Tunnel runtime impls + a one-call helper that turns a `TunnelConfig`
//! into a ready-to-use `Box<dyn Tunnel>`. Each leaf service crate's
//! `<Svc>Orchestrator::execute` calls `build_tunnel` to produce the
//! right tunnel before dispatching to its lib's `execute`.

mod chain;
mod direct;
mod layered;
pub mod socks;
mod socks5_client_tunnel;
mod socks_tunnel;
mod ssh;
mod streamlocal;

use crate::{Result, Tunnel, TunnelConfig};

pub use chain::build_connector;
pub use direct::DirectTunnel;
pub use layered::{ForwardTarget, LayeredTunnel};
pub use socks::connector::Connector;
pub use socks_tunnel::SocksTunnel;
pub use socks5_client_tunnel::Socks5ClientTunnel;
pub use ssh::SshTunnel;
pub use streamlocal::StreamLocalTunnel;

/// Build the appropriate tunnel for a target `(host, port)` from a
/// `TunnelConfig`. `None` is treated as a direct connection. Lowers the
/// whole layer stack to a single `LayeredTunnel` whose folded connector
/// reaches the target through every layer, and which forwards the local
/// listen port to `(target_host, target_port)`.
pub fn build_tunnel(
    target_host: String,
    target_port: u16,
    tunnel_config: Option<TunnelConfig>,
) -> Result<Box<dyn Tunnel>> {
    let cfg = tunnel_config.unwrap_or_else(TunnelConfig::direct);
    Ok(Box::new(LayeredTunnel::new(
        &cfg,
        ForwardTarget::Tcp {
            host: target_host,
            port: target_port,
        },
    )))
}
