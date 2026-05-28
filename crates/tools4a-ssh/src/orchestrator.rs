//! SSH-direct orchestrator: typed `SshExecRequest` → `tools4a_ssh::execute`
//! with optional jump-host chain built from the tunnel config.
//!
//! Like HTTP, SSH-direct doesn't have a `from_config` constructor —
//! Profile/YAML support was deferred. The bin builds `SshExecRequest`
//! directly from CLI flags / JSON params.

use crate::execute as ssh_execute;
use crate::request::SshExecRequest;
use async_trait::async_trait;
use tools4a_core::{
    Error, ExecutionResult, Result, Service, Socks5ClientTunnel, Tunnel, TunnelConfig,
    apply_with_timeout, resolve_effective_timeout,
};

/// Service default for the per-call execution timeout. Shell commands
/// over SSH can be long-running (builds, log tails) — keep this generous
/// and rely on the operator-set max for an absolute ceiling.
pub const DEFAULT_TIMEOUT_SECS: u64 = 300;

pub struct SshDirectOrchestrator;

#[async_trait]
impl Service for SshDirectOrchestrator {
    type Request = SshExecRequest;

    async fn execute(
        req: SshExecRequest,
        tunnel_config: Option<TunnelConfig>,
    ) -> Result<ExecutionResult> {
        if req.password.is_none() && req.key_path.is_none() {
            return Err(Error::Config(
                "SSH target requires --password or --key-path".to_string(),
            ));
        }

        let deadline =
            resolve_effective_timeout(req.timeout_secs, DEFAULT_TIMEOUT_SECS, req.max_timeout_secs);

        // Decide how to reach the target. Three shapes:
        //  - Direct / no tunnel: russh dials req.host directly.
        //  - SSH jump chain: russh runs over a direct-tcpip channel from
        //    the last jump (handled by ssh_execute when `jumps` is Some).
        //  - SOCKS5: stand up a local Socks5ClientTunnel, redirect the
        //    russh dial to its endpoint via `connect_addr_override`.
        let (jumps, mut socks_tunnel, connect_override) = match tunnel_config {
            None | Some(TunnelConfig::Direct) => (None, None, None),
            Some(TunnelConfig::Ssh { ssh_jumps }) => (Some(ssh_jumps), None, None),
            Some(TunnelConfig::Socks5 {
                socks5_host,
                socks5_port,
                socks5_user,
                socks5_password,
            }) => {
                let mut tunnel = Socks5ClientTunnel::new(
                    socks5_host,
                    socks5_port,
                    socks5_user,
                    socks5_password,
                    req.host.clone(),
                    req.port,
                )?;
                let endpoint = tunnel.establish().await?;
                let override_addr = (endpoint.host, endpoint.port);
                (None, Some(tunnel), Some(override_addr))
            }
        };

        let exec_result =
            apply_with_timeout(deadline, ssh_execute(req, jumps, connect_override)).await;

        // Always tear the tunnel down, regardless of success/failure.
        if let Some(t) = socks_tunnel.as_mut() {
            let _ = t.close().await;
        }

        let mut result = exec_result?;
        if let Some(w) = deadline.clamp_warning() {
            result.push_warning(w);
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_req() -> SshExecRequest {
        SshExecRequest {
            host: "h".to_string(),
            port: 22,
            user: "u".to_string(),
            password: None,
            key_path: None,
            command: "ls".to_string(),
            timeout_secs: None,
            max_timeout_secs: None,
        }
    }

    #[tokio::test]
    async fn execute_errors_without_password_or_key() {
        let err = SshDirectOrchestrator::execute(empty_req(), None)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Config(ref msg) if msg.contains("--password or --key-path")));
    }
}
