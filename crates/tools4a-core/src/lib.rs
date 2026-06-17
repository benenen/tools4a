//! Core traits and shared types for the tools4a workspace.
//!
//! Holds the trait floor (`Tunnel`, `Connection`, `Service`, `McpTool`),
//! shared error/result types, the `TunnelConfig` ordered-layer struct,
//! the Profile/YAML/CLI 3-layer Config types, the `LayeredTunnel`
//! runtime impl + connector-chain engine, and the SSH `session` helpers
//! shared between the tunnel impls and `tools4a-ssh`'s `SshExec`.
//! Per-service orchestrator + MCP impls live in their leaf crate
//! (`tools4a-mysql`, `tools4a-pgsql`, …).

pub mod config;
pub mod mcp;
pub mod readonly;
pub mod result_compression;
pub mod session;
pub mod timeout;
pub mod toon;
pub mod tunnel;

pub use mcp::{
    McpTool, SshJumpInput, TunnelKind, TunnelLayerInput, build_tunnel_config,
    layer_inputs_to_config,
};
pub use result_compression::{
    ColumnInfo, ColumnStats, CompressedResult, CompressionInfo, CompressionStrategy,
};
pub use timeout::{
    DEFAULT_MAX_TIMEOUT_SECS, EffectiveTimeout, apply_with_timeout, resolve_effective_timeout,
};
pub use toon::{compressed_to_toon, to_toon};
pub use tunnel::{
    Connector, DirectTunnel, ForwardTarget, LayeredTunnel, Socks5ClientTunnel, SocksTunnel,
    SshTunnel, StreamLocalTunnel, build_connector, build_tunnel,
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

/// Tunnel selection plus its parameters: an ordered transport stack,
/// local→target. An empty layer list is a direct connection. Runtime
/// impls fold the layers into a `Connector` chain (`build_connector`)
/// driven by a `LayeredTunnel`. Constructor helpers (`direct`/`ssh`/
/// `socks5`/`layered`) and accessors (`is_direct`/`ssh_jumps`/
/// `last_layer_is_ssh`) preserve most call-site ergonomics from the old
/// 3-variant enum.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelConfig {
    #[serde(default)]
    pub layers: Vec<TunnelLayer>,
}

impl TunnelConfig {
    /// A direct (no-hop) connection.
    pub fn direct() -> Self {
        Self { layers: vec![] }
    }

    /// An all-SSH jump chain, in client→target order.
    pub fn ssh(jumps: Vec<JumpHop>) -> Self {
        Self {
            layers: jumps.into_iter().map(TunnelLayer::SshHop).collect(),
        }
    }

    /// A single external SOCKS5 proxy hop.
    pub fn socks5(host: String, port: u16, user: Option<String>, password: Option<String>) -> Self {
        Self {
            layers: vec![TunnelLayer::Socks5 {
                host,
                port,
                user,
                password,
            }],
        }
    }

    /// An arbitrary ordered layer stack.
    pub fn layered(layers: Vec<TunnelLayer>) -> Self {
        Self { layers }
    }

    /// True when there are no transport layers (a direct connection).
    pub fn is_direct(&self) -> bool {
        self.layers.is_empty()
    }

    /// `Some(jumps)` iff EVERY layer is an SSH hop (no socks5 underlay) —
    /// lets callers that still think in "jump chain" terms keep working.
    /// `None` if any layer is a SOCKS5 hop.
    pub fn ssh_jumps(&self) -> Option<Vec<JumpHop>> {
        let mut out = Vec::with_capacity(self.layers.len());
        for l in &self.layers {
            match l {
                TunnelLayer::SshHop(h) => out.push(h.clone()),
                TunnelLayer::Socks5 { .. } => return None,
            }
        }
        Some(out)
    }

    /// True iff the innermost (closest-to-target) layer is an SSH hop.
    /// Required by SocksTunnel / streamlocal / ssh-exec, which need a real
    /// SSH session at the end of the chain.
    pub fn last_layer_is_ssh(&self) -> bool {
        matches!(self.layers.last(), Some(TunnelLayer::SshHop(_)))
    }
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
    fn ssh_config_builds_from_jumps() {
        let hop = JumpHop {
            host: "bastion.com".into(),
            user: "admin".into(),
            password: Some("pw".into()),
            key_path: None,
            port: 22,
        };
        let cfg = TunnelConfig::ssh(vec![hop]);
        let jumps = cfg.ssh_jumps().expect("all-ssh");
        assert_eq!(jumps.len(), 1);
        assert_eq!(jumps[0].host, "bastion.com");
        assert_eq!(jumps[0].user, "admin");
        assert!(!cfg.is_direct());
        assert!(cfg.last_layer_is_ssh());
    }

    #[test]
    fn direct_has_no_layers() {
        let cfg = TunnelConfig::direct();
        assert!(cfg.is_direct());
        assert!(!cfg.last_layer_is_ssh());
        // No layers → an empty (but Some) jump chain.
        assert_eq!(cfg.ssh_jumps().map(|j| j.len()), Some(0));
    }

    #[test]
    fn socks5_is_single_layer_and_not_a_jump_chain() {
        let cfg = TunnelConfig::socks5("p".into(), 2235, Some("u".into()), Some("pw".into()));
        assert_eq!(cfg.layers.len(), 1);
        assert!(!cfg.is_direct());
        assert!(cfg.ssh_jumps().is_none()); // a socks5 layer is not a jump
        assert!(!cfg.last_layer_is_ssh());
        match &cfg.layers[0] {
            TunnelLayer::Socks5 {
                host,
                port,
                user,
                password,
            } => {
                assert_eq!(host, "p");
                assert_eq!(*port, 2235);
                assert_eq!(user.as_deref(), Some("u"));
                assert_eq!(password.as_deref(), Some("pw"));
            }
            _ => panic!("expected Socks5 layer"),
        }
    }

    #[test]
    fn socks5_then_ssh_is_not_pure_jump_chain() {
        let cfg = TunnelConfig::layered(vec![
            TunnelLayer::Socks5 {
                host: "p".into(),
                port: 2235,
                user: None,
                password: None,
            },
            TunnelLayer::SshHop(JumpHop {
                host: "127.0.0.1".into(),
                user: "admin".into(),
                password: Some("x".into()),
                key_path: None,
                port: 3203,
            }),
        ]);
        assert!(cfg.ssh_jumps().is_none()); // has a socks5 layer
        assert!(cfg.last_layer_is_ssh()); // ends on SSH → can host a target
        assert!(!cfg.is_direct());
    }

    #[test]
    fn tunnel_config_round_trips_via_yaml() {
        let cfg = TunnelConfig::layered(vec![
            TunnelLayer::Socks5 {
                host: "proxy.internal".into(),
                port: 1080,
                user: None,
                password: None,
            },
            TunnelLayer::SshHop(JumpHop {
                host: "bastion.com".into(),
                user: "admin".into(),
                password: Some("pw".into()),
                key_path: None,
                port: 22,
            }),
        ]);
        let yaml = serde_yml::to_string(&cfg).unwrap();
        let back: TunnelConfig = serde_yml::from_str(&yaml).unwrap();
        assert_eq!(back.layers.len(), 2);
        assert!(back.ssh_jumps().is_none());
        assert!(back.last_layer_is_ssh());
    }

    #[test]
    fn tunnel_config_round_trips_via_toml() {
        // Profile uses TOML; verify the struct survives a TOML round-trip.
        let cfg = TunnelConfig::socks5("p".into(), 2235, Some("u".into()), Some("pw".into()));
        let toml_str = toml::to_string(&cfg).unwrap();
        let back: TunnelConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(back.layers.len(), 1);
        match &back.layers[0] {
            TunnelLayer::Socks5 { port, user, .. } => {
                assert_eq!(*port, 2235);
                assert_eq!(user.as_deref(), Some("u"));
            }
            _ => panic!("expected Socks5"),
        }
    }

    #[test]
    fn empty_layers_yaml_deserializes_to_direct() {
        let cfg: TunnelConfig = serde_yml::from_str("layers: []").unwrap();
        assert!(cfg.is_direct());
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
}
