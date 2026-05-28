//! Tunnel runtime impls + a one-call helper that turns a `TunnelConfig`
//! into a ready-to-use `Box<dyn Tunnel>`. Each leaf service crate's
//! `<Svc>Orchestrator::execute` calls `build_tunnel` to produce the
//! right tunnel before dispatching to its lib's `execute`.

mod direct;
pub mod socks;
mod socks5_client_tunnel;
mod socks_tunnel;
mod ssh;
mod streamlocal;

use crate::{Result, Tunnel, TunnelConfig};

pub use direct::DirectTunnel;
pub use socks_tunnel::SocksTunnel;
pub use socks5_client_tunnel::Socks5ClientTunnel;
pub use ssh::SshTunnel;
pub use streamlocal::StreamLocalTunnel;

/// Build the appropriate tunnel for a target `(host, port)` from a
/// `TunnelConfig`. `None` is treated as `Direct`.
pub fn build_tunnel(
    target_host: String,
    target_port: u16,
    tunnel_config: Option<TunnelConfig>,
) -> Result<Box<dyn Tunnel>> {
    match tunnel_config {
        None | Some(TunnelConfig::Direct) => {
            Ok(Box::new(DirectTunnel::new(target_host, target_port)))
        }
        Some(TunnelConfig::Ssh { ssh_jumps }) => Ok(Box::new(SshTunnel::new(
            ssh_jumps,
            target_host,
            target_port,
        )?)),
        Some(TunnelConfig::Socks5 {
            socks5_host,
            socks5_port,
            socks5_user,
            socks5_password,
        }) => Ok(Box::new(Socks5ClientTunnel::new(
            socks5_host,
            socks5_port,
            socks5_user,
            socks5_password,
            target_host,
            target_port,
        )?)),
    }
}
