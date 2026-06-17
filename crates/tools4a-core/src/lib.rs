//! Core traits and shared types for the tools4a workspace.
//!
//! Holds the trait floor (`Tunnel`, `Connection`, `Service`, `McpTool`),
//! shared error/result types, the `TunnelConfig` enum, the
//! Profile/YAML/CLI 3-layer Config types, the concrete `DirectTunnel`
//! and `SshTunnel` runtime impls, and the SSH `session` helpers shared
//! between `SshTunnel` and `tools4a-ssh`'s `SshExec`. Per-service
//! orchestrator + MCP impls live in their leaf crate (`tools4a-mysql`,
//! `tools4a-pgsql`, …).

pub mod config;
pub mod mcp;
pub mod readonly;
pub mod result_compression;
pub mod session;
pub mod timeout;
pub mod toon;
pub mod tunnel;

pub use mcp::{McpTool, SshJumpInput, TunnelKind, build_tunnel_config};
pub use result_compression::{
    ColumnInfo, ColumnStats, CompressedResult, CompressionInfo, CompressionStrategy,
};
pub use timeout::{
    DEFAULT_MAX_TIMEOUT_SECS, EffectiveTimeout, apply_with_timeout, resolve_effective_timeout,
};
pub use toon::{compressed_to_toon, to_toon};
pub use tunnel::{
    Connector, DirectTunnel, Socks5ClientTunnel, SocksTunnel, SshTunnel, StreamLocalTunnel,
    build_connector, build_tunnel,
};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::fmt;

// -- Error --------------------------------------------------------------

#[derive(Debug)]
pub enum Error {
    Config(String),
    Connection(String),
    Execution(String),
    Io(std::io::Error),
    /// Errors from a specific service (MySQL, SSH library, YAML parser, …).
    /// Higher crates wrap their library errors into this variant via
    /// `Error::Service(format!("{e}"))` to keep core dep-free.
    Service(String),
    /// The underlying protocol call exceeded the resolved timeout.
    /// Carries the full `EffectiveTimeout` so the error message can
    /// distinguish "you asked for 60s and got 60s" from "you asked for
    /// 60s but the operator-side cap shrank it to 3s".
    Timeout(timeout::EffectiveTimeout),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Config(msg) => write!(f, "Configuration error: {msg}"),
            Error::Connection(msg) => write!(f, "Connection error: {msg}"),
            Error::Execution(msg) => write!(f, "Execution error: {msg}"),
            Error::Io(e) => write!(f, "IO error: {e}"),
            Error::Service(msg) => write!(f, "Service error: {msg}"),
            Error::Timeout(t) => {
                if t.clamped {
                    write!(
                        f,
                        "Timeout: operation exceeded {}s (requested {}s was capped to the {}s ceiling)",
                        t.effective_secs, t.requested_secs, t.max_secs
                    )
                } else {
                    write!(f, "Timeout: operation exceeded {}s", t.effective_secs)
                }
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            Error::Config(_)
            | Error::Connection(_)
            | Error::Execution(_)
            | Error::Service(_)
            | Error::Timeout(_) => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

// -- Tunnel -------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct TunnelEndpoint {
    pub host: String,
    pub port: u16,
}

#[async_trait]
pub trait Tunnel: Send + Sync {
    async fn establish(&mut self) -> Result<TunnelEndpoint>;
    async fn close(&mut self) -> Result<()>;
    fn is_active(&self) -> bool;
}

// -- Connection ---------------------------------------------------------

#[async_trait]
pub trait Connection: Send + Sync {
    async fn connect(&mut self) -> Result<()>;
    async fn disconnect(&mut self) -> Result<()>;
    fn is_connected(&self) -> bool;
}

// -- ExecutionResult ----------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<String>>,
    pub affected_rows: u64,
    /// Non-fatal advisories surfaced by the orchestrator (e.g. a clamp
    /// notice when the requested timeout exceeded the configured maximum).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

impl ExecutionResult {
    pub fn new(columns: Vec<String>, rows: Vec<Vec<String>>, affected_rows: u64) -> Self {
        Self {
            columns,
            rows,
            affected_rows,
            warnings: Vec::new(),
        }
    }

    pub fn with_warning(mut self, warning: impl Into<String>) -> Self {
        self.warnings.push(warning.into());
        self
    }

    pub fn push_warning(&mut self, warning: impl Into<String>) {
        self.warnings.push(warning.into());
    }

    /// Create a truncated version of this result for token-saving.
    /// Returns a new `ExecutionResult` with only the first `max_rows` rows,
    /// plus a warning indicating truncation. The full result should be
    /// preserved in the UI resource.
    pub fn truncated(&self, max_rows: usize) -> Self {
        if self.rows.len() <= max_rows {
            return self.clone();
        }

        let mut truncated = Self {
            columns: self.columns.clone(),
            rows: self.rows.iter().take(max_rows).cloned().collect(),
            affected_rows: self.affected_rows,
            warnings: self.warnings.clone(),
        };

        truncated.push_warning(format!(
            "Result truncated: showing first {} of {} rows. Full data available in UI.",
            max_rows,
            self.rows.len()
        ));

        truncated
    }
}

// -- TunnelConfig -------------------------------------------------------

/// One resolved hop in an SSH jump chain. Post-merge: `user` is required,
/// `port` is concrete (defaulted to 22 if absent), `password`/`key_path`
/// stay optional because either may carry auth.
#[derive(Clone, Serialize, Deserialize)]
pub struct JumpHop {
    pub host: String,
    pub user: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_path: Option<String>,
    #[serde(default = "default_ssh_port")]
    pub port: u16,
}

impl std::fmt::Debug for JumpHop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JumpHop")
            .field("host", &self.host)
            .field("user", &self.user)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("key_path", &self.key_path)
            .field("port", &self.port)
            .finish()
    }
}

/// Tunnel selection plus its parameters. Shared shape across all services.
/// Runtime impls (`DirectTunnel`, `SshTunnel`, `Socks5ClientTunnel`) live
/// in this crate's `tunnel` module.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum TunnelConfig {
    Direct,
    Ssh {
        /// Resolved jump-hop list in client→target order. Each hop carries
        /// its own credentials. The MCP and CLI builders fold pre-merge
        /// top-level `ssh_user`/`ssh_password`/etc. into each hop before
        /// constructing this; consumers see a fully-resolved per-hop view.
        ssh_jumps: Vec<JumpHop>,
    },
    /// Route through an already-running external SOCKS5 proxy. Phase 19.
    Socks5 {
        socks5_host: String,
        #[serde(default = "default_socks5_port")]
        socks5_port: u16,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        socks5_user: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        socks5_password: Option<String>,
    },
}

fn default_ssh_port() -> u16 {
    22
}

pub(crate) fn default_socks5_port() -> u16 {
    1080
}

/// One composable layer in a tunnel stack, used by the Phase 21 layer engine.
/// The list is ordered local→target: the first element is nearest the client,
/// the last is nearest the target service. `build_connector` folds the slice
/// into a nested `Connector` chain starting from a raw `TcpConnector`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TunnelLayer {
    /// Route through an external SOCKS5 proxy.
    Socks5 {
        host: String,
        #[serde(default = "default_socks5_port")]
        port: u16,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        user: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<String>,
    },
    /// Establish an SSH session (credentials + port from `JumpHop`), then
    /// route subsequent connections through direct-tcpip channels on that
    /// session.
    SshHop(JumpHop),
}

// -- Service trait ------------------------------------------------------

/// A service orchestrator: takes a typed request + an optional tunnel
/// config, returns a structured result. Each leaf service crate
/// (`tools4a-mysql`, `tools4a-pgsql`, …) implements this for its own
/// `<Svc>Orchestrator` type. CLI/MCP layers build the typed request
/// (resolving Profile/YAML/CLI args before this point) and dispatch.
#[async_trait]
pub trait Service {
    /// Service-specific request shape. CLI handler / MCP tool builds
    /// this from user input.
    type Request;

    async fn execute(req: Self::Request, tunnel: Option<TunnelConfig>) -> Result<ExecutionResult>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tunnel_config_ssh_round_trips_via_yaml() {
        // TunnelConfig::Ssh now holds Vec<JumpHop>; we construct and
        // serialize/deserialize rather than parsing legacy YAML.
        let hop = JumpHop {
            host: "bastion.com".to_string(),
            user: "admin".to_string(),
            password: Some("pw".to_string()),
            key_path: None,
            port: 22,
        };
        let cfg = TunnelConfig::Ssh {
            ssh_jumps: vec![hop],
        };
        let yaml = serde_yml::to_string(&cfg).unwrap();
        let back: TunnelConfig = serde_yml::from_str(&yaml).unwrap();
        match back {
            TunnelConfig::Ssh { ssh_jumps } => {
                assert_eq!(ssh_jumps.len(), 1);
                assert_eq!(ssh_jumps[0].host, "bastion.com");
                assert_eq!(ssh_jumps[0].user, "admin");
            }
            _ => panic!("expected Ssh"),
        }
    }

    #[test]
    fn test_tunnel_config_socks5_minimal_yaml() {
        let yaml = r#"
type: socks5
socks5_host: 192.0.2.10
"#;
        let cfg: TunnelConfig = serde_yml::from_str(yaml).unwrap();
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
    fn test_tunnel_config_socks5_full_yaml() {
        let yaml = r#"
type: socks5
socks5_host: proxy.internal
socks5_port: 2235
socks5_user: alice
socks5_password: s3cret
"#;
        let cfg: TunnelConfig = serde_yml::from_str(yaml).unwrap();
        match cfg {
            TunnelConfig::Socks5 {
                socks5_host,
                socks5_port,
                socks5_user,
                socks5_password,
            } => {
                assert_eq!(socks5_host, "proxy.internal");
                assert_eq!(socks5_port, 2235);
                assert_eq!(socks5_user.as_deref(), Some("alice"));
                assert_eq!(socks5_password.as_deref(), Some("s3cret"));
            }
            _ => panic!("expected Socks5"),
        }
    }

    #[test]
    fn test_tunnel_config_socks5_serialize_skips_none_auth() {
        let cfg = TunnelConfig::Socks5 {
            socks5_host: "p".into(),
            socks5_port: 1080,
            socks5_user: None,
            socks5_password: None,
        };
        let yaml = serde_yml::to_string(&cfg).unwrap();
        assert!(!yaml.contains("socks5_user"), "{yaml}");
        assert!(!yaml.contains("socks5_password"), "{yaml}");
        // And round-trips cleanly.
        let back: TunnelConfig = serde_yml::from_str(&yaml).unwrap();
        match back {
            TunnelConfig::Socks5 {
                socks5_host,
                socks5_user,
                socks5_password,
                ..
            } => {
                assert_eq!(socks5_host, "p");
                assert!(socks5_user.is_none());
                assert!(socks5_password.is_none());
            }
            _ => panic!("expected Socks5"),
        }
    }

    #[test]
    fn test_jump_hop_debug_masks_password() {
        let hop = JumpHop {
            host: "bastion.example.com".to_string(),
            user: "admin".to_string(),
            password: Some("secret".to_string()),
            key_path: Some("/home/admin/.ssh/id_rsa".to_string()),
            port: 22,
        };
        let debug_output = format!("{:?}", hop);
        assert!(
            debug_output.contains("<redacted>"),
            "expected '<redacted>' in debug output, got: {debug_output}"
        );
        assert!(
            !debug_output.contains("secret"),
            "password 'secret' must not appear in debug output, got: {debug_output}"
        );
        // key_path stays visible
        assert!(
            debug_output.contains("/home/admin/.ssh/id_rsa"),
            "key_path should be visible in debug output, got: {debug_output}"
        );
        // None password also works without leaking anything unexpected
        let hop_no_pw = JumpHop {
            host: "b".to_string(),
            user: "u".to_string(),
            password: None,
            key_path: None,
            port: 22,
        };
        let debug_none = format!("{:?}", hop_no_pw);
        assert!(
            !debug_none.contains("secret"),
            "no password should be present, got: {debug_none}"
        );
    }

    #[test]
    fn test_tunnel_config_socks5_toml_round_trip() {
        // Verifies the variant works under TOML (Profile uses TOML), since
        // serde_yml and toml have slightly different defaults around enums.
        let cfg = TunnelConfig::Socks5 {
            socks5_host: "p".into(),
            socks5_port: 2235,
            socks5_user: Some("u".into()),
            socks5_password: Some("pw".into()),
        };
        let toml_str = toml::to_string(&cfg).unwrap();
        let back: TunnelConfig = toml::from_str(&toml_str).unwrap();
        match back {
            TunnelConfig::Socks5 {
                socks5_port,
                socks5_user,
                ..
            } => {
                assert_eq!(socks5_port, 2235);
                assert_eq!(socks5_user.as_deref(), Some("u"));
            }
            _ => panic!("expected Socks5"),
        }
    }
}
