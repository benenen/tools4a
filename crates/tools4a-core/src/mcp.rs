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
    Detailed(Vec<SshJumpHopInput>),
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
            SshJumpInput::Detailed(v) => v.into_iter().map(|h| h.host).collect(),
        }
    }
}

/// One pre-merge jump hop in the MCP `ssh_jump` object form. Fields
/// that are `None` fall back to the call's top-level `ssh_user` /
/// `ssh_password` / `ssh_key_path` / `ssh_port` defaults.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct SshJumpHopInput {
    pub host: String,
    pub user: Option<String>,
    pub password: Option<String>,
    pub key_path: Option<String>,
    pub port: Option<u16>,
}

/// Merge a pre-merge `SshJumpHopInput` against top-level defaults into a
/// fully-resolved `JumpHop`. Used by both the MCP `build_tunnel_config`
/// and the CLI `cli_to_tunnel_config`. `hop_index` is 0-based internally
/// but rendered as 1-based ("ssh hop 1", "ssh hop 2", ...) in the
/// validation error messages so users can locate the offending hop using
/// the same counting convention they'd use in conversation.
pub fn merge_hop(
    hop_index: usize,
    hop: SshJumpHopInput,
    default_user: Option<&str>,
    default_password: Option<&str>,
    default_key_path: Option<&str>,
    default_port: u16,
) -> crate::Result<crate::JumpHop> {
    if hop.host.is_empty() {
        return Err(crate::Error::Config(format!(
            "ssh hop {}: host must not be empty",
            hop_index + 1
        )));
    }
    let user = hop
        .user
        .or_else(|| default_user.map(str::to_string))
        .ok_or_else(|| {
            crate::Error::Config(format!(
                "ssh hop {} ({}): missing user — set hop.user or top-level ssh_user",
                hop_index + 1,
                hop.host
            ))
        })?;
    Ok(crate::JumpHop {
        host: hop.host,
        user,
        password: hop
            .password
            .or_else(|| default_password.map(str::to_string)),
        key_path: hop
            .key_path
            .or_else(|| default_key_path.map(str::to_string)),
        port: hop.port.unwrap_or(default_port),
    })
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
            let raw = ssh_jump.ok_or_else(|| {
                crate::Error::Config("ssh_jump is required when tunnel = \"ssh\"".to_string())
            })?;
            let default_port = ssh_port.unwrap_or(22);
            let hop_inputs: Vec<SshJumpHopInput> = match raw {
                SshJumpInput::Single(_) | SshJumpInput::Multiple(_) => raw
                    .into_jumps()
                    .into_iter()
                    .map(|host| SshJumpHopInput {
                        host,
                        user: None,
                        password: None,
                        key_path: None,
                        port: None,
                    })
                    .collect(),
                SshJumpInput::Detailed(v) => v,
            };
            if hop_inputs.is_empty() {
                return Err(crate::Error::Config(
                    "ssh_jump must not be empty".to_string(),
                ));
            }
            let ssh_jumps: Vec<crate::JumpHop> = hop_inputs
                .into_iter()
                .enumerate()
                .map(|(i, hop)| {
                    merge_hop(
                        i,
                        hop,
                        ssh_user.as_deref(),
                        ssh_password.as_deref(),
                        ssh_key_path.as_deref(),
                        default_port,
                    )
                })
                .collect::<crate::Result<_>>()?;
            Ok(Some(TunnelConfig::Ssh { ssh_jumps }))
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

    #[test]
    fn merge_hop_overrides_top_level_when_hop_specifies() {
        let hop = SshJumpHopInput {
            host: "h".into(),
            user: Some("hop-u".into()),
            password: Some("hop-pw".into()),
            key_path: None,
            port: Some(2222),
        };
        let merged = merge_hop(0, hop, Some("default-u"), Some("default-pw"), None, 22).unwrap();
        assert_eq!(merged.host, "h");
        assert_eq!(merged.user, "hop-u");
        assert_eq!(merged.password.as_deref(), Some("hop-pw"));
        assert_eq!(merged.port, 2222);
    }

    #[test]
    fn ssh_jump_detailed_form_parses_via_serde() {
        let raw = r#"[
            {"host":"gw","user":"admin","password":"pw1"},
            {"host":"54","user":"xxjs","password":"pw2","port":2222}
        ]"#;
        let parsed: SshJumpInput = serde_json::from_str(raw).expect("detailed array should parse");
        match parsed {
            SshJumpInput::Detailed(v) => {
                assert_eq!(v.len(), 2);
                assert_eq!(v[0].host, "gw");
                assert_eq!(v[1].port, Some(2222));
            }
            other => panic!("expected Detailed, got {other:?}"),
        }
    }

    #[test]
    fn ssh_detailed_with_per_hop_creds_builds_two_distinct_jumphops() {
        let cfg = build_tunnel_config(
            Some(TunnelKind::Ssh),
            Some(SshJumpInput::Detailed(vec![
                SshJumpHopInput {
                    host: "gw".into(),
                    user: Some("admin".into()),
                    password: Some("pw1".into()),
                    key_path: None,
                    port: None,
                },
                SshJumpHopInput {
                    host: "54".into(),
                    user: Some("xxjs".into()),
                    password: Some("pw2".into()),
                    key_path: None,
                    port: Some(2222),
                },
            ])),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap()
        .unwrap();
        match cfg {
            TunnelConfig::Ssh { ssh_jumps } => {
                assert_eq!(ssh_jumps.len(), 2);
                assert_eq!(ssh_jumps[0].user, "admin");
                assert_eq!(ssh_jumps[0].password.as_deref(), Some("pw1"));
                assert_eq!(ssh_jumps[0].port, 22); // default
                assert_eq!(ssh_jumps[1].user, "xxjs");
                assert_eq!(ssh_jumps[1].password.as_deref(), Some("pw2"));
                assert_eq!(ssh_jumps[1].port, 2222);
            }
            _ => panic!("expected Ssh"),
        }
    }

    #[test]
    fn ssh_detailed_falls_back_to_top_level_per_field() {
        // hop[0] has user but no password → password comes from top-level
        // hop[1] has password but no user → user comes from top-level
        let cfg = build_tunnel_config(
            Some(TunnelKind::Ssh),
            Some(SshJumpInput::Detailed(vec![
                SshJumpHopInput {
                    host: "a".into(),
                    user: Some("hop-u".into()),
                    password: None,
                    key_path: None,
                    port: None,
                },
                SshJumpHopInput {
                    host: "b".into(),
                    user: None,
                    password: Some("hop-pw".into()),
                    key_path: None,
                    port: None,
                },
            ])),
            Some("top-u".into()),
            Some("top-pw".into()),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap()
        .unwrap();
        let TunnelConfig::Ssh { ssh_jumps } = cfg else {
            panic!("expected Ssh")
        };
        assert_eq!(ssh_jumps[0].user, "hop-u");
        assert_eq!(ssh_jumps[0].password.as_deref(), Some("top-pw"));
        assert_eq!(ssh_jumps[1].user, "top-u");
        assert_eq!(ssh_jumps[1].password.as_deref(), Some("hop-pw"));
    }

    #[test]
    fn ssh_detailed_hop_with_no_user_and_no_default_errors() {
        let err = build_tunnel_config(
            Some(TunnelKind::Ssh),
            Some(SshJumpInput::Detailed(vec![SshJumpHopInput {
                host: "lonely".into(),
                user: None,
                password: Some("p".into()),
                key_path: None,
                port: None,
            }])),
            None, // no top-level ssh_user
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(matches!(err, crate::Error::Config(ref m)
            if m.contains("ssh hop 1") && m.contains("missing user")));
    }

    #[test]
    fn ssh_detailed_hop_with_empty_host_errors() {
        let err = build_tunnel_config(
            Some(TunnelKind::Ssh),
            Some(SshJumpInput::Detailed(vec![SshJumpHopInput {
                host: "".into(),
                user: Some("u".into()),
                password: None,
                key_path: None,
                port: None,
            }])),
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
        assert!(matches!(err, crate::Error::Config(ref m)
            if m.contains("host must not be empty")));
    }

    #[test]
    fn ssh_detailed_empty_array_errors() {
        let err = build_tunnel_config(
            Some(TunnelKind::Ssh),
            Some(SshJumpInput::Detailed(vec![])),
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
        assert!(matches!(err, crate::Error::Config(ref m) if m.contains("must not be empty")));
    }
}
