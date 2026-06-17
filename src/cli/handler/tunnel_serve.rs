//! `tools4a tunnel-serve ...` dispatch — long-running tunnel daemon.

use super::shared::parse_hop_url;
use crate::cli::TunnelServeType;
use std::net::SocketAddr;
use std::path::PathBuf;
use tools4a_core::tunnel::{ForwardTarget, LayeredTunnel};
use tools4a_core::{Error, JumpHop, Result, Tunnel, TunnelConfig, TunnelLayer};

#[allow(clippy::too_many_arguments)]
pub(super) async fn execute(
    kind: TunnelServeType,
    listen: SocketAddr,
    ssh_jump: Option<String>,
    ssh_user: Option<String>,
    ssh_password: Option<String>,
    ssh_key_path: Option<PathBuf>,
    ssh_port: u16,
    socks5_host: Option<String>,
    socks5_port: Option<u16>,
    socks5_user: Option<String>,
    socks5_password: Option<String>,
    hop: Vec<String>,
    target_host: Option<String>,
    target_port: Option<u16>,
    remote_socket: Option<String>,
) -> Result<()> {
    // Build the transport stack: prefer --hop; else lower --ssh-* + --socks5-*.
    let cfg = build_tunnel_config(
        &hop,
        ssh_jump,
        ssh_user,
        ssh_password,
        ssh_key_path,
        ssh_port,
        socks5_host,
        socks5_port,
        socks5_user,
        socks5_password,
    )?;

    // Validate per-type required + rejected fields.
    match kind {
        TunnelServeType::SshTcp => {
            if remote_socket.is_some() {
                return Err(Error::Config(
                    "--remote-socket is only valid with --type=ssh-streamlocal".to_string(),
                ));
            }
            if target_host.is_none() || target_port.is_none() {
                return Err(Error::Config(
                    "--type=ssh-tcp requires --target-host and --target-port".to_string(),
                ));
            }
        }
        TunnelServeType::SshStreamlocal => {
            if target_host.is_some() || target_port.is_some() {
                return Err(Error::Config(
                    "--target-host/--target-port are only valid with --type=ssh-tcp".to_string(),
                ));
            }
            if remote_socket.is_none() {
                return Err(Error::Config(
                    "--type=ssh-streamlocal requires --remote-socket".to_string(),
                ));
            }
            if !cfg.last_layer_is_ssh() {
                return Err(Error::Config(
                    "--type=ssh-streamlocal requires the stack to end in an SSH hop".to_string(),
                ));
            }
        }
        TunnelServeType::SshSocks => {
            if target_host.is_some() || target_port.is_some() || remote_socket.is_some() {
                return Err(Error::Config(
                    "--type=ssh-socks doesn't take --target-host/--target-port/--remote-socket"
                        .to_string(),
                ));
            }
        }
    }

    // Build the layer-engine target and establish (pre-warms → fails fast).
    let target = match kind {
        TunnelServeType::SshTcp => ForwardTarget::Tcp {
            host: target_host.expect("validated above"),
            port: target_port.expect("validated above"),
        },
        TunnelServeType::SshSocks => ForwardTarget::Socks5Server,
        TunnelServeType::SshStreamlocal => ForwardTarget::StreamLocal {
            path: remote_socket.expect("validated above"),
        },
    };
    let mut tunnel: Box<dyn Tunnel> =
        Box::new(LayeredTunnel::new(&cfg, target).with_listen_addr(listen));

    let ep = tunnel.establish().await?;
    let shape = match kind {
        TunnelServeType::SshTcp => "ssh-tcp",
        TunnelServeType::SshStreamlocal => "ssh-streamlocal",
        TunnelServeType::SshSocks => "ssh-socks",
    };
    eprintln!(
        "tunnel-serve [{shape}] listening on {host}:{port} (Ctrl-C to stop)",
        host = ep.host,
        port = ep.port,
    );

    wait_for_shutdown_signal().await;

    eprintln!("tunnel-serve: shutting down");
    let _ = tunnel.close().await;
    Ok(())
}

/// Build the `TunnelConfig` for `tunnel-serve`: `--hop` lowers directly to a
/// layer stack; otherwise `--ssh-*` (required) plus an optional `--socks5-*`
/// underlay are folded into `[Socks5?, SshHop...]`.
#[allow(clippy::too_many_arguments)]
fn build_tunnel_config(
    hop: &[String],
    ssh_jump: Option<String>,
    ssh_user: Option<String>,
    ssh_password: Option<String>,
    ssh_key_path: Option<PathBuf>,
    ssh_port: u16,
    socks5_host: Option<String>,
    socks5_port: Option<u16>,
    socks5_user: Option<String>,
    socks5_password: Option<String>,
) -> Result<TunnelConfig> {
    // --- Ordered --hop form ---------------------------------------------
    if !hop.is_empty() {
        if ssh_jump.is_some() || socks5_host.is_some() {
            return Err(Error::Config(
                "--hop cannot be combined with --ssh-jump/--socks5-host — pick one form"
                    .to_string(),
            ));
        }
        let layers = hop
            .iter()
            .map(|raw| parse_hop_url(raw))
            .collect::<Result<Vec<_>>>()?;
        return Ok(TunnelConfig::layered(layers));
    }

    // --- Legacy --ssh-* + optional --socks5-* underlay ------------------
    let ssh_jump = ssh_jump.ok_or_else(|| {
        Error::Config("--ssh-jump (or --hop) is required for tunnel-serve".to_string())
    })?;
    let ssh_user = ssh_user
        .ok_or_else(|| Error::Config("--ssh-user is required without --hop".to_string()))?;

    let host_jumps: Vec<String> = ssh_jump
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if host_jumps.is_empty() {
        return Err(Error::Config(
            "--ssh-jump must not be empty (single host or comma-separated chain)".to_string(),
        ));
    }
    let ssh_jumps: Vec<JumpHop> = host_jumps
        .into_iter()
        .map(|host| JumpHop {
            host,
            user: ssh_user.clone(),
            password: ssh_password.clone(),
            key_path: ssh_key_path
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned()),
            port: ssh_port,
        })
        .collect();

    let socks5_prefix = match socks5_host {
        Some(host) => {
            if host.is_empty() {
                return Err(Error::Config("--socks5-host must not be empty".to_string()));
            }
            if socks5_user.is_some() != socks5_password.is_some() {
                return Err(Error::Config(
                    "--socks5-user and --socks5-password must be set together".to_string(),
                ));
            }
            Some(TunnelLayer::Socks5 {
                host,
                port: socks5_port.unwrap_or(1080),
                user: socks5_user,
                password: socks5_password,
            })
        }
        None => {
            if socks5_port.is_some() || socks5_user.is_some() || socks5_password.is_some() {
                return Err(Error::Config(
                    "--socks5-host is required to add a socks5 underlay".to_string(),
                ));
            }
            None
        }
    };

    let mut layers = Vec::with_capacity(ssh_jumps.len() + 1);
    layers.extend(socks5_prefix);
    layers.extend(ssh_jumps.into_iter().map(TunnelLayer::SshHop));
    Ok(TunnelConfig::layered(layers))
}

/// Block until SIGINT or SIGTERM. On non-unix, falls back to ctrl-c only.
async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = sigterm.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hop_form_builds_layered() {
        let cfg = build_tunnel_config(
            &["socks5://p:1080".to_string(), "ssh://u@gw:22".to_string()],
            None,
            None,
            None,
            None,
            22,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(cfg.layers.len(), 2);
        assert!(cfg.last_layer_is_ssh());
        assert!(cfg.ssh_jumps().is_none());
    }

    #[test]
    fn legacy_ssh_only_builds_jump_chain() {
        let cfg = build_tunnel_config(
            &[],
            Some("gw".to_string()),
            Some("admin".to_string()),
            Some("pw".to_string()),
            None,
            22,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        let jumps = cfg.ssh_jumps().expect("all-ssh");
        assert_eq!(jumps.len(), 1);
        assert_eq!(jumps[0].user, "admin");
    }

    #[test]
    fn legacy_ssh_plus_socks5_combines() {
        let cfg = build_tunnel_config(
            &[],
            Some("gw".to_string()),
            Some("admin".to_string()),
            None,
            None,
            22,
            Some("192.0.2.10".to_string()),
            Some(2235),
            None,
            None,
        )
        .unwrap();
        assert_eq!(cfg.layers.len(), 2);
        assert!(cfg.ssh_jumps().is_none());
        assert!(cfg.last_layer_is_ssh());
        match &cfg.layers[0] {
            TunnelLayer::Socks5 { host, port, .. } => {
                assert_eq!(host, "192.0.2.10");
                assert_eq!(*port, 2235);
            }
            _ => panic!("expected socks5 underlay"),
        }
    }

    #[test]
    fn hop_combined_with_legacy_errors() {
        let err = build_tunnel_config(
            &["ssh://u@gw".to_string()],
            Some("gw".to_string()),
            Some("u".to_string()),
            None,
            None,
            22,
            None,
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(matches!(err, Error::Config(ref m) if m.contains("--hop cannot be combined")));
    }
}
