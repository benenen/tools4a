//! `DockerOrchestrator` — typed request → connection (mode picked from
//! `tunnel` + `unix_socket` fields) → dispatch through `run::run`. The
//! three connection modes:
//!
//! 1. **Local Unix socket** — `docker_host = unix:///var/run/docker.sock`,
//!    no tunnel. Pass through to `Docker::connect_with_unix`.
//! 2. **Local or remote TCP** — `docker_host = tcp://host:port` or
//!    `host:port`. If a tunnel stack ending in an SSH hop is provided,
//!    build a `LayeredTunnel` with `ForwardTarget::Tcp` and connect to
//!    its local TCP endpoint instead.
//! 3. **Remote Unix socket via SSH** — `unix_socket = Some("/var/run/...")`
//!    plus a tunnel stack ending in an SSH hop. Builds a `LayeredTunnel`
//!    with `ForwardTarget::StreamLocal` that exposes the remote socket as
//!    a local TCP port; bollard talks plain HTTP to it.
//!
//! Conflict guard: `unix_socket = Some(_)` requires a tunnel stack ending
//! in an SSH hop. A socks5-only stack is allowed as an underlay but
//! the outermost (target-side) layer must be `SshHop`.

use crate::actions::DockerAction;
use crate::connection::{ConnectTarget, connect_docker, parse_docker_host};
use crate::run::run as dispatch_action;
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::Mutex;
use tools4a_core::tunnel::{ForwardTarget, LayeredTunnel};
use tools4a_core::{Error, ExecutionResult, Result, Service, Tunnel, TunnelConfig};

pub const DEFAULT_TIMEOUT_SECS: u64 = 30;

#[derive(Debug, Clone)]
pub struct DockerRequest {
    pub action: DockerAction,
    /// Docker daemon endpoint. Accepts:
    /// - `unix:///path/to/docker.sock` (or bare `/path`)
    /// - `tcp://host:port` (or bare `host:port`)
    pub docker_host: String,
    /// If set, ignored unless `tunnel = ssh`. Forwards the remote unix
    /// socket at this path through a `LayeredTunnel` (StreamLocal target).
    /// Lets you reach `/var/run/docker.sock` on a remote host behind SSH.
    pub unix_socket: Option<String>,
    /// Write actions (run/restart) require this to be `true`. Read-only
    /// actions (ps/inspect/logs/stats/top) always run.
    pub allow_write: bool,
    pub timeout_secs: Option<u64>,
}

pub struct DockerOrchestrator;

/// One active tunnel handle held for the duration of a single call. We
/// box it under a trait so any `LayeredTunnel` variant (Tcp or
/// StreamLocal forward target) satisfies the same shape.
type ActiveTunnel = Arc<Mutex<Box<dyn Tunnel>>>;

#[async_trait]
impl Service for DockerOrchestrator {
    type Request = DockerRequest;

    async fn execute(
        req: DockerRequest,
        tunnel_config: Option<TunnelConfig>,
    ) -> Result<ExecutionResult> {
        if !req.action.is_readonly() && !req.allow_write {
            return Err(Error::Service(format!(
                "docker {}: write action requires --allow-write (CLI) / allow_write=true (MCP)",
                req.action.name()
            )));
        }

        // Resolve connection target + (optional) active tunnel.
        let (target, active_tunnel) = resolve_target(&req, tunnel_config).await?;

        let timeout = req.timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS);
        let docker = connect_docker(&target, timeout)?;
        let result = dispatch_action(&docker, req.action).await;

        // Tear down the tunnel before returning, regardless of outcome.
        if let Some(t) = active_tunnel {
            let mut guard = t.lock().await;
            let _ = guard.close().await;
        }
        result
    }
}

async fn resolve_target(
    req: &DockerRequest,
    tunnel_config: Option<TunnelConfig>,
) -> Result<(ConnectTarget, Option<ActiveTunnel>)> {
    let cfg = tunnel_config.unwrap_or_else(TunnelConfig::direct);

    // Direct (no tunnel): plain local socket / local-or-remote TCP.
    if cfg.is_direct() {
        if req.unix_socket.is_some() {
            return Err(Error::Config(
                "unix_socket only valid with an ssh tunnel (use docker_host=unix://path for the \
                 local socket)"
                    .to_string(),
            ));
        }
        return Ok((parse_docker_host(&req.docker_host)?, None));
    }

    // Any tunnel: the docker daemon is reached either over a remote unix
    // socket (direct-streamlocal) or a remote TCP port (direct-tcpip), both
    // of which ride an SSH session at the innermost hop. A SOCKS5 underlay
    // in front of the SSH chain is fine (it only carries the gateway dial),
    // but the stack MUST end in an SSH hop.
    if !cfg.last_layer_is_ssh() {
        return Err(Error::Config(
            "docker requires the tunnel stack to end in an SSH hop (a socks5-only proxy can't \
             reach the daemon socket; use ssh, optionally with a socks5:// underlay)"
                .to_string(),
        ));
    }

    let tunnel = match req.unix_socket.as_deref() {
        // Remote Unix socket via SSH (optionally behind a socks5 underlay).
        Some(socket_path) => LayeredTunnel::new(
            &cfg,
            ForwardTarget::StreamLocal {
                path: socket_path.to_string(),
            },
        ),
        // Remote TCP via SSH.
        None => {
            let target = parse_docker_host(&req.docker_host)?;
            let (host, port) = match target {
                ConnectTarget::Tcp(addr) => parse_host_port(&addr)?,
                ConnectTarget::UnixSocket(_) => {
                    return Err(Error::Config(
                        "an ssh tunnel with a unix:// docker_host requires \
                         unix_socket=<remote_path> (the remote daemon's socket); did you mean to \
                         set unix_socket?"
                            .to_string(),
                    ));
                }
            };
            LayeredTunnel::new(&cfg, ForwardTarget::Tcp { host, port })
        }
    };

    let mut tunnel = tunnel;
    let ep = tunnel.establish().await?;
    let addr = format!("{}:{}", ep.host, ep.port);
    let boxed: Box<dyn Tunnel> = Box::new(tunnel);
    Ok((ConnectTarget::Tcp(addr), Some(Arc::new(Mutex::new(boxed)))))
}

fn parse_host_port(addr: &str) -> Result<(String, u16)> {
    let (host, port_str) = addr.rsplit_once(':').ok_or_else(|| {
        Error::Config(format!(
            "docker_host '{addr}' must be host:port (e.g. tcp://1.2.3.4:2375)"
        ))
    })?;
    let port: u16 = port_str
        .parse()
        .map_err(|_| Error::Config(format!("invalid port in docker_host '{addr}'")))?;
    Ok((host.to_string(), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_req(action: DockerAction, allow_write: bool) -> DockerRequest {
        DockerRequest {
            action,
            docker_host: "unix:///var/run/docker.sock".into(),
            unix_socket: None,
            allow_write,
            timeout_secs: None,
        }
    }

    #[tokio::test]
    async fn write_action_rejected_without_allow_write() {
        let req = dummy_req(
            DockerAction::Restart {
                container: "x".into(),
                timeout_secs: None,
            },
            false,
        );
        let err = DockerOrchestrator::execute(req, None).await.unwrap_err();
        assert!(matches!(err, Error::Service(ref m) if m.contains("--allow-write")));
    }

    #[tokio::test]
    async fn unix_socket_without_ssh_rejected() {
        let req = DockerRequest {
            action: DockerAction::Ps {
                all: false,
                limit: None,
                filters: None,
            },
            docker_host: "tcp://127.0.0.1:2375".into(),
            unix_socket: Some("/var/run/docker.sock".into()),
            allow_write: false,
            timeout_secs: None,
        };
        let err = DockerOrchestrator::execute(req, None).await.unwrap_err();
        assert!(matches!(err, Error::Config(ref m) if m.contains("unix_socket")));
    }

    #[test]
    fn parse_host_port_ok() {
        assert_eq!(parse_host_port("h:2375").unwrap(), ("h".to_string(), 2375));
    }

    #[test]
    fn parse_host_port_missing_colon() {
        assert!(matches!(parse_host_port("no-port"), Err(Error::Config(_))));
    }
}
