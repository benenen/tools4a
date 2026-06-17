//! MCP-tool abstraction. Each leaf service crate (tools4a-mysql,
//! tools4a-pgsql, …) defines a marker type implementing `McpTool`,
//! plus a JSON-schema-derived params struct. The bin's `src/mcp/server.rs`
//! dispatches uniformly via these impls — no per-service plumbing in
//! the bin.

use crate::{ExecutionResult, Result, TunnelConfig, TunnelLayer};
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

/// One layer in the ordered `tunnel_layers` MCP input. Tagged by `type`:
/// `{"type":"socks5", ...}` or `{"type":"ssh", ...}`. The list is
/// local→target order — first element nearest the client, last nearest
/// the target. Mutually exclusive with the legacy `tunnel`/`ssh_*`/
/// `socks5_*` fields.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum TunnelLayerInput {
    /// Route through an external SOCKS5 proxy. `port` defaults to 1080.
    Socks5 {
        host: String,
        port: Option<u16>,
        user: Option<String>,
        password: Option<String>,
    },
    /// Establish an SSH session and route subsequent hops through it.
    /// `port` defaults to 22. `user` is required.
    Ssh {
        host: String,
        port: Option<u16>,
        user: Option<String>,
        password: Option<String>,
        key_path: Option<String>,
    },
}

/// Lower an ordered `TunnelLayerInput` list into a `TunnelConfig`,
/// validating each layer (non-empty host; SSH layers require a user).
/// Error messages render layer positions 1-based to match how users
/// count hops in conversation.
pub fn layer_inputs_to_config(inputs: Vec<TunnelLayerInput>) -> Result<TunnelConfig> {
    let mut layers = Vec::with_capacity(inputs.len());
    for (i, inp) in inputs.into_iter().enumerate() {
        layers.push(match inp {
            TunnelLayerInput::Socks5 {
                host,
                port,
                user,
                password,
            } => {
                if host.is_empty() {
                    return Err(crate::Error::Config(format!(
                        "tunnel_layers[{}] (socks5): host must not be empty",
                        i + 1
                    )));
                }
                if user.is_some() != password.is_some() {
                    return Err(crate::Error::Config(format!(
                        "tunnel_layers[{}] (socks5): user and password must be set together",
                        i + 1
                    )));
                }
                TunnelLayer::Socks5 {
                    host,
                    port: port.unwrap_or(1080),
                    user,
                    password,
                }
            }
            TunnelLayerInput::Ssh {
                host,
                port,
                user,
                password,
                key_path,
            } => {
                if host.is_empty() {
                    return Err(crate::Error::Config(format!(
                        "tunnel_layers[{}] (ssh): host must not be empty",
                        i + 1
                    )));
                }
                let user = user.ok_or_else(|| {
                    crate::Error::Config(format!("tunnel_layers[{}] (ssh): missing user", i + 1))
                })?;
                TunnelLayer::SshHop(crate::JumpHop {
                    host,
                    user,
                    password,
                    key_path,
                    port: port.unwrap_or(22),
                })
            }
        });
    }
    Ok(TunnelConfig { layers })
}

/// Build a `TunnelConfig` from the shared MCP tunnel-related fields.
/// Returns `None` when neither `kind` nor `tunnel_layers` is given.
///
/// Two mutually-exclusive forms:
/// - `tunnel_layers`: an ordered layer stack (preferred, fully general).
///   Combining it with ANY legacy field (`tunnel`/`ssh_*`/`socks5_*`) is
///   an error.
/// - Legacy `tunnel` + `ssh_*`/`socks5_*`: lowered to a layer stack.
///   `tunnel="ssh"` with `socks5_host` set now LOWERS to a `[Socks5,
///   SshHop…]` stack instead of erroring (the underlay-then-jump shape).
#[allow(clippy::too_many_arguments)]
pub fn build_tunnel_config(
    tunnel_layers: Option<Vec<TunnelLayerInput>>,
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
    let stray_ssh = ssh_jump.is_some()
        || ssh_user.is_some()
        || ssh_password.is_some()
        || ssh_key_path.is_some()
        || ssh_port.is_some();
    let stray_socks5 = socks5_host.is_some()
        || socks5_port.is_some()
        || socks5_user.is_some()
        || socks5_password.is_some();

    // --- Ordered layer-stack form ---------------------------------------
    // `tunnel_layers` is the general form; it cannot be combined with any
    // of the legacy single-form fields.
    if let Some(layers) = tunnel_layers {
        if kind.is_some() || stray_ssh || stray_socks5 {
            return Err(crate::Error::Config(
                "tunnel_layers cannot be combined with tunnel/ssh_*/socks5_* — pick one form"
                    .to_string(),
            ));
        }
        return Ok(Some(layer_inputs_to_config(layers)?));
    }

    let Some(kind) = kind else {
        return Ok(None);
    };

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
            Ok(Some(TunnelConfig::direct()))
        }
        TunnelKind::Ssh => {
            // `socks5_*` with `tunnel="ssh"` is no longer an error: it
            // lowers to a SOCKS5 underlay in front of the SSH jump chain.
            let socks5_prefix = if let Some(host) = socks5_host {
                if socks5_user.is_some() != socks5_password.is_some() {
                    return Err(crate::Error::Config(
                        "socks5_user and socks5_password must be set together".to_string(),
                    ));
                }
                if host.is_empty() {
                    return Err(crate::Error::Config(
                        "socks5_host must not be empty".to_string(),
                    ));
                }
                Some(TunnelLayer::Socks5 {
                    host,
                    port: socks5_port.unwrap_or(1080),
                    user: socks5_user,
                    password: socks5_password,
                })
            } else {
                // No socks5_host, but stray socks5_port/user/password alone
                // is still nonsensical.
                if socks5_port.is_some() || socks5_user.is_some() || socks5_password.is_some() {
                    return Err(crate::Error::Config(
                        "socks5_host is required to add a socks5 underlay".to_string(),
                    ));
                }
                None
            };
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
            let mut layers = Vec::with_capacity(ssh_jumps.len() + 1);
            layers.extend(socks5_prefix);
            layers.extend(ssh_jumps.into_iter().map(TunnelLayer::SshHop));
            Ok(Some(TunnelConfig { layers }))
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
            Ok(Some(TunnelConfig::socks5(
                host,
                socks5_port.unwrap_or(1080),
                socks5_user,
                socks5_password,
            )))
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
    fn no_kind_no_layers_is_none() {
        let cfg = build_tunnel_config(
            None, None, None, None, None, None, None, None, None, None, None,
        )
        .unwrap();
        assert!(cfg.is_none());
    }

    #[test]
    fn direct_with_stray_ssh_field_errors() {
        let err = build_tunnel_config(
            None,
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
            None,
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
            None,
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
        assert_eq!(cfg.layers.len(), 1);
        match &cfg.layers[0] {
            TunnelLayer::Socks5 {
                host,
                port,
                user,
                password,
            } => {
                assert_eq!(host, "192.0.2.10");
                assert_eq!(*port, 1080);
                assert!(user.is_none());
                assert!(password.is_none());
            }
            _ => panic!("expected Socks5"),
        }
    }

    #[test]
    fn socks5_full_ok() {
        let cfg = build_tunnel_config(
            None,
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
        match &cfg.layers[0] {
            TunnelLayer::Socks5 {
                port,
                user,
                password,
                ..
            } => {
                assert_eq!(*port, 2235);
                assert_eq!(user.as_deref(), Some("alice"));
                assert_eq!(password.as_deref(), Some("s3cret"));
            }
            _ => panic!("expected Socks5"),
        }
    }

    #[test]
    fn socks5_missing_host_errors() {
        let err = build_tunnel_config(
            None,
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
            None,
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
    fn legacy_ssh_plus_socks5_now_lowers_instead_of_erroring() {
        // tunnel="ssh" + socks5_host set => [Socks5, SshHop...]
        let cfg = build_tunnel_config(
            None,
            Some(TunnelKind::Ssh),
            Some(SshJumpInput::Single("127.0.0.1".into())),
            Some("admin".into()),
            Some("pw".into()),
            None,
            Some(3203),
            Some("192.0.2.10".into()),
            Some(2235),
            None,
            None,
        )
        .unwrap()
        .unwrap();
        assert_eq!(cfg.layers.len(), 2);
        assert!(matches!(
            cfg.layers.first(),
            Some(TunnelLayer::Socks5 { .. })
        ));
        assert!(matches!(cfg.layers.last(), Some(TunnelLayer::SshHop(_))));
        assert!(cfg.ssh_jumps().is_none());
        assert!(cfg.last_layer_is_ssh());
        match &cfg.layers[0] {
            TunnelLayer::Socks5 { host, port, .. } => {
                assert_eq!(host, "192.0.2.10");
                assert_eq!(*port, 2235);
            }
            _ => panic!("expected socks5 prefix"),
        }
    }

    #[test]
    fn direct_with_stray_socks5_field_errors() {
        let err = build_tunnel_config(
            None,
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
            None,
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
    fn tunnel_layers_lowers_socks5_then_ssh() {
        let layers = vec![
            TunnelLayerInput::Socks5 {
                host: "192.0.2.10".into(),
                port: Some(2235),
                user: None,
                password: None,
            },
            TunnelLayerInput::Ssh {
                host: "127.0.0.1".into(),
                port: Some(3203),
                user: Some("admin".into()),
                password: Some("pw".into()),
                key_path: None,
            },
        ];
        let cfg = build_tunnel_config(
            Some(layers),
            None,
            None,
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
        assert_eq!(cfg.layers.len(), 2);
        assert!(cfg.ssh_jumps().is_none());
        assert!(cfg.last_layer_is_ssh());
    }

    #[test]
    fn tunnel_layers_ssh_without_user_errors() {
        let err = layer_inputs_to_config(vec![TunnelLayerInput::Ssh {
            host: "h".into(),
            port: None,
            user: None,
            password: Some("p".into()),
            key_path: None,
        }])
        .unwrap_err();
        assert!(matches!(err, crate::Error::Config(ref m)
            if m.contains("tunnel_layers[1]") && m.contains("missing user")));
    }

    #[test]
    fn layers_and_legacy_tunnel_together_is_error() {
        let err = build_tunnel_config(
            Some(vec![TunnelLayerInput::Socks5 {
                host: "p".into(),
                port: None,
                user: None,
                password: None,
            }]),
            Some(TunnelKind::Ssh),
            Some(SshJumpInput::Single("j".into())),
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
        assert!(matches!(err, crate::Error::Config(ref m) if m.contains("tunnel_layers")));
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
            None,
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
        let ssh_jumps = cfg.ssh_jumps().expect("all-ssh");
        assert_eq!(ssh_jumps.len(), 2);
        assert_eq!(ssh_jumps[0].user, "admin");
        assert_eq!(ssh_jumps[0].password.as_deref(), Some("pw1"));
        assert_eq!(ssh_jumps[0].port, 22); // default
        assert_eq!(ssh_jumps[1].user, "xxjs");
        assert_eq!(ssh_jumps[1].password.as_deref(), Some("pw2"));
        assert_eq!(ssh_jumps[1].port, 2222);
    }

    #[test]
    fn ssh_detailed_falls_back_to_top_level_per_field() {
        // hop[0] has user but no password → password comes from top-level
        // hop[1] has password but no user → user comes from top-level
        let cfg = build_tunnel_config(
            None,
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
        let ssh_jumps = cfg.ssh_jumps().expect("all-ssh");
        assert_eq!(ssh_jumps[0].user, "hop-u");
        assert_eq!(ssh_jumps[0].password.as_deref(), Some("top-pw"));
        assert_eq!(ssh_jumps[1].user, "top-u");
        assert_eq!(ssh_jumps[1].password.as_deref(), Some("hop-pw"));
    }

    #[test]
    fn ssh_detailed_hop_with_no_user_and_no_default_errors() {
        let err = build_tunnel_config(
            None,
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
            None,
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
            None,
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
