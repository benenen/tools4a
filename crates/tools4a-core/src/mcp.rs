//! MCP-tool abstraction. Each leaf service crate (tools4a-mysql,
//! tools4a-pgsql, …) defines a marker type implementing `McpTool`,
//! plus a JSON-schema-derived params struct. The bin's `src/mcp/server.rs`
//! dispatches uniformly via these impls — no per-service plumbing in
//! the bin.

use crate::{ExecutionResult, Result, TunnelConfig};
use async_trait::async_trait;
use schemars::JsonSchema;
use serde::Deserialize;

/// One MCP tool. The trait is intentionally minimal — leaf crates
/// expose `NAME`, `DESCRIPTION`, a `Params` type, and an async
/// `invoke` that returns the structured result. The bin wraps it in
/// rmcp's transport-specific machinery.
#[async_trait]
pub trait McpTool: Send + Sync + 'static {
    const NAME: &'static str;
    const DESCRIPTION: &'static str;
    type Params: for<'de> Deserialize<'de> + JsonSchema + Send + 'static;

    async fn invoke(params: Self::Params) -> Result<ExecutionResult>;
}

/// Tunnel kind as it appears in MCP JSON. Mirror of the CLI's
/// `--tunnel direct|ssh|socks5`.
#[derive(Debug, Clone, Deserialize, serde::Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum TunnelKind {
    Direct,
    Ssh,
    Socks5,
}

/// MCP `ssh_jump` field accepts either a single host string,
/// a comma-separated string, or a JSON array of strings.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum SshJumpInput {
    Single(String),
    Multiple(Vec<String>),
}

impl SshJumpInput {
    pub fn into_jumps(self) -> Vec<String> {
        match self {
            SshJumpInput::Single(s) => s
                .split(',')
                .map(|p| p.trim().to_string())
                .filter(|p| !p.is_empty())
                .collect(),
            SshJumpInput::Multiple(v) => v.into_iter().filter(|s| !s.is_empty()).collect(),
        }
    }
}

/// Build a `TunnelConfig` from the shared MCP tunnel-related fields.
/// Returns `None` when `kind` is `None`. Validates per-kind required
/// fields and rejects mixing `ssh_*` and `socks5_*` family fields with
/// the wrong tunnel kind.
#[allow(clippy::too_many_arguments)]
pub fn build_tunnel_config(
    kind: Option<TunnelKind>,
    ssh_jump: Option<SshJumpInput>,
    ssh_user: Option<String>,
    ssh_password: Option<String>,
    ssh_key_path: Option<String>,
    ssh_port: Option<u16>,
    socks5_host: Option<String>,
    socks5_port: Option<u16>,
    socks5_user: Option<String>,
    socks5_password: Option<String>,
) -> Result<Option<TunnelConfig>> {
    let Some(kind) = kind else {
        return Ok(None);
    };
    let stray_ssh = ssh_jump.is_some()
        || ssh_user.is_some()
        || ssh_password.is_some()
        || ssh_key_path.is_some()
        || ssh_port.is_some();
    let stray_socks5 = socks5_host.is_some()
        || socks5_port.is_some()
        || socks5_user.is_some()
        || socks5_password.is_some();
    match kind {
        TunnelKind::Direct => {
            if stray_ssh {
                return Err(crate::Error::Config(
                    "ssh_* fields are only valid with tunnel = \"ssh\"".to_string(),
                ));
            }
            if stray_socks5 {
                return Err(crate::Error::Config(
                    "socks5_* fields are only valid with tunnel = \"socks5\"".to_string(),
                ));
            }
            Ok(Some(TunnelConfig::Direct))
        }
        TunnelKind::Ssh => {
            if stray_socks5 {
                return Err(crate::Error::Config(
                    "socks5_* fields are only valid with tunnel = \"socks5\"".to_string(),
                ));
            }
            let jumps = ssh_jump.map(SshJumpInput::into_jumps).ok_or_else(|| {
                crate::Error::Config("ssh_jump is required when tunnel = \"ssh\"".to_string())
            })?;
            if jumps.is_empty() {
                return Err(crate::Error::Config(
                    "ssh_jump must not be empty".to_string(),
                ));
            }
            let ssh_user = ssh_user.ok_or_else(|| {
                crate::Error::Config("ssh_user is required when tunnel = \"ssh\"".to_string())
            })?;
            Ok(Some(TunnelConfig::Ssh {
                ssh_jumps: jumps,
                ssh_user,
                ssh_password,
                ssh_key_path,
                ssh_port: ssh_port.unwrap_or(22),
            }))
        }
        TunnelKind::Socks5 => {
            if stray_ssh {
                return Err(crate::Error::Config(
                    "ssh_* fields are only valid with tunnel = \"ssh\"".to_string(),
                ));
            }
            let host = socks5_host.ok_or_else(|| {
                crate::Error::Config("socks5_host is required when tunnel = \"socks5\"".to_string())
            })?;
            if host.is_empty() {
                return Err(crate::Error::Config(
                    "socks5_host must not be empty".to_string(),
                ));
            }
            if socks5_user.is_some() != socks5_password.is_some() {
                return Err(crate::Error::Config(
                    "socks5_user and socks5_password must be set together".to_string(),
                ));
            }
            Ok(Some(TunnelConfig::Socks5 {
                socks5_host: host,
                socks5_port: socks5_port.unwrap_or(1080),
                socks5_user,
                socks5_password,
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_jump_single_string_is_split_on_commas() {
        let j = SshJumpInput::Single("a,b,c".to_string()).into_jumps();
        assert_eq!(j, vec!["a", "b", "c"]);
    }

    #[test]
    fn ssh_jump_array_is_passed_through() {
        let j = SshJumpInput::Multiple(vec!["a".into(), "b".into()]).into_jumps();
        assert_eq!(j, vec!["a", "b"]);
    }

    #[test]
    fn direct_with_stray_ssh_field_errors() {
        let err = build_tunnel_config(
            Some(TunnelKind::Direct),
            Some(SshJumpInput::Single("h".into())),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(matches!(err, crate::Error::Config(ref msg) if msg.contains("ssh_*")));
    }

    #[test]
    fn ssh_without_jump_errors() {
        let err = build_tunnel_config(
            Some(TunnelKind::Ssh),
            None,
            Some("u".into()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(matches!(err, crate::Error::Config(ref msg) if msg.contains("ssh_jump")));
    }

    #[test]
    fn socks5_minimal_ok() {
        let cfg = build_tunnel_config(
            Some(TunnelKind::Socks5),
            None,
            None,
            None,
            None,
            None,
            Some("192.0.2.10".into()),
            None,
            None,
            None,
        )
        .unwrap()
        .unwrap();
        match cfg {
            TunnelConfig::Socks5 {
                socks5_host,
                socks5_port,
                socks5_user,
                socks5_password,
            } => {
                assert_eq!(socks5_host, "192.0.2.10");
                assert_eq!(socks5_port, 1080);
                assert!(socks5_user.is_none());
                assert!(socks5_password.is_none());
            }
            _ => panic!("expected Socks5"),
        }
    }

    #[test]
    fn socks5_full_ok() {
        let cfg = build_tunnel_config(
            Some(TunnelKind::Socks5),
            None,
            None,
            None,
            None,
            None,
            Some("proxy.internal".into()),
            Some(2235),
            Some("alice".into()),
            Some("s3cret".into()),
        )
        .unwrap()
        .unwrap();
        match cfg {
            TunnelConfig::Socks5 {
                socks5_port,
                socks5_user,
                socks5_password,
                ..
            } => {
                assert_eq!(socks5_port, 2235);
                assert_eq!(socks5_user.as_deref(), Some("alice"));
                assert_eq!(socks5_password.as_deref(), Some("s3cret"));
            }
            _ => panic!("expected Socks5"),
        }
    }

    #[test]
    fn socks5_missing_host_errors() {
        let err = build_tunnel_config(
            Some(TunnelKind::Socks5),
            None,
            None,
            None,
            None,
            None,
            None,
            Some(2235),
            None,
            None,
        )
        .unwrap_err();
        assert!(matches!(err, crate::Error::Config(ref msg) if msg.contains("socks5_host")));
    }

    #[test]
    fn socks5_with_stray_ssh_field_errors() {
        let err = build_tunnel_config(
            Some(TunnelKind::Socks5),
            Some(SshJumpInput::Single("j".into())),
            None,
            None,
            None,
            None,
            Some("p".into()),
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(matches!(err, crate::Error::Config(ref msg) if msg.contains("ssh_*")));
    }

    #[test]
    fn ssh_with_stray_socks5_field_errors() {
        let err = build_tunnel_config(
            Some(TunnelKind::Ssh),
            Some(SshJumpInput::Single("j".into())),
            Some("u".into()),
            None,
            None,
            None,
            Some("p".into()),
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(matches!(err, crate::Error::Config(ref msg) if msg.contains("socks5_*")));
    }

    #[test]
    fn direct_with_stray_socks5_field_errors() {
        let err = build_tunnel_config(
            Some(TunnelKind::Direct),
            None,
            None,
            None,
            None,
            None,
            Some("p".into()),
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(matches!(err, crate::Error::Config(ref msg) if msg.contains("socks5_*")));
    }

    #[test]
    fn socks5_user_without_pass_errors() {
        let err = build_tunnel_config(
            Some(TunnelKind::Socks5),
            None,
            None,
            None,
            None,
            None,
            Some("p".into()),
            None,
            Some("alice".into()),
            None,
        )
        .unwrap_err();
        assert!(matches!(err, crate::Error::Config(ref msg) if msg.contains("set together")));
    }
}
