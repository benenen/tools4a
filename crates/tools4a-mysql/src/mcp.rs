//! `mysql_exec` MCP tool — params + `McpTool` impl. Mirrors the CLI's
//! `tools4a mysql ...` behavior: 3-layer config merge (TOML profile →
//! YAML → MCP fields), then dispatch through `MysqlOrchestrator`.

use crate::orchestrator::{MysqlOrchestrator, MysqlRequest};
use async_trait::async_trait;
use schemars::JsonSchema;
use serde::Deserialize;
use std::path::PathBuf;
use tools4a_core::config::{Config, ConfigLoader, ConfigMerger, Profile, ServiceType, TomlConfig};
use tools4a_core::{
    Error, ExecutionResult, McpTool, Result, Service, SshJumpInput, TunnelKind, build_tunnel_config,
};

fn default_format() -> String {
    "toon".to_string()
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct MysqlExecParams {
    pub query: String,

    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_write: bool,

    /// Include HTML UI resource in the response. Disabled by default to
    /// save tokens (~1700 tokens per call). When enabled, returns an
    /// interactive HTML table alongside the JSON data.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub include_ui: bool,

    /// Output format for the result. Options: "toon" (default), "json".
    /// TOON format saves 30-60% tokens by using indentation-based format
    /// instead of JSON. Set to "json" for traditional JSON output.
    #[serde(default = "default_format")]
    pub format: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
    /// Saved MySQL connection profile name or alias from
    /// `~/.config/tools4a/config.toml`. Call `profiles_list` first when
    /// the user names an environment but its canonical profile is unknown.
    /// Do not also pass host/password/tunnel fields when the profile is enough.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<PathBuf>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tunnel: Option<TunnelKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_jump: Option<SshJumpInput>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_key_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_port: Option<u16>,

    /// SOCKS5 proxy host (used when tunnel = "socks5"). Phase 19.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socks5_host: Option<String>,
    /// SOCKS5 proxy port (default 1080).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socks5_port: Option<u16>,
    /// SOCKS5 username (RFC 1929 user/pass auth — requires socks5_password).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socks5_user: Option<String>,
    /// SOCKS5 password (RFC 1929 user/pass auth — requires socks5_user).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socks5_password: Option<String>,

    /// Ordered transport hop stack (local->target), the general form.
    /// Each element is `{"type":"socks5",...}` or `{"type":"ssh",...}`.
    /// Mutually exclusive with the legacy `tunnel`/`ssh_*`/`socks5_*`
    /// fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tunnel_layers: Option<Vec<tools4a_core::mcp::TunnelLayerInput>>,

    /// Per-call execution timeout in seconds. Capped by the operator's
    /// `TOOLS4A_MAX_TIMEOUT_SECS` env var or TOML `[defaults]`. When
    /// unset, the service default applies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,
}

pub struct MysqlMcp;

#[async_trait]
impl McpTool for MysqlMcp {
    const NAME: &'static str = "mysql_exec";
    const DESCRIPTION: &'static str = "Execute MySQL SQL for schema inspection, data queries, \
         diagnostics, and approved writes. Use this tool instead of ssh_exec or docker_exec \
         whenever the target is MySQL. Prefer a saved profile name or alias; call profiles_list \
         first when the environment mapping is unknown. Direct connections and configured \
         tunnels are supported. Reads are allowed by default; writes require allow_write=true.";
    type Params = MysqlExecParams;

    async fn invoke(params: MysqlExecParams) -> Result<ExecutionResult> {
        let allow_write = params.allow_write;
        let query = params.query.clone();
        let toml = ConfigLoader::load_default_toml()?;
        let max_timeout_secs = toml.as_ref().and_then(toml_max_timeout);
        let config = params_to_config(&params, toml)?;
        let tunnel = config.tunnel.clone();
        let mut req = MysqlRequest::from_config(config, query)?;
        if let Some(ts) = params.timeout_secs {
            req.timeout_secs = Some(ts);
        }
        req.max_timeout_secs = max_timeout_secs;
        req.allow_write = allow_write;
        MysqlOrchestrator::execute(req, tunnel).await
    }
}

fn toml_max_timeout(toml: &TomlConfig) -> Option<u64> {
    toml.defaults.max_timeout_secs
}

fn params_to_config(p: &MysqlExecParams, toml: Option<TomlConfig>) -> Result<Config> {
    let mut configs: Vec<Config> = Vec::new();

    if let Some(profile_name) = &p.profile {
        let toml_config = toml.ok_or_else(|| {
            Error::Config(format!(
                "profile '{profile_name}' requested but no ~/.config/tools4a/config.toml found"
            ))
        })?;
        let (_, profile_cfg) =
            toml_config.resolve_profile(profile_name, Some(ServiceType::Mysql))?;
        configs.push(profile_to_config(profile_cfg));
    }

    if let Some(path) = p.config.as_deref() {
        configs.push(ConfigLoader::load_yaml_file(path)?);
    }

    let tunnel_config = build_tunnel_config(
        p.tunnel_layers.clone(),
        p.tunnel.clone(),
        p.ssh_jump.clone(),
        p.ssh_user.clone(),
        p.ssh_password.clone(),
        p.ssh_key_path.clone(),
        p.ssh_port,
        p.socks5_host.clone(),
        p.socks5_port,
        p.socks5_user.clone(),
        p.socks5_password.clone(),
    )?;

    configs.push(Config {
        service_type: Some(ServiceType::Mysql),
        host: p.host.clone(),
        port: p.port,
        user: p.user.clone(),
        password: p.password.clone(),
        database: p.database.clone(),
        db: None,
        key_path: None,
        tunnel: tunnel_config,
        timeout_secs: p.timeout_secs,
    });

    Ok(ConfigMerger::merge_multiple(configs))
}

fn profile_to_config(profile: &Profile) -> Config {
    Config {
        service_type: Some(profile.service_type.clone()),
        host: profile.host.clone(),
        port: profile.port,
        user: profile.user.clone(),
        password: profile.password.clone(),
        database: profile.database.clone(),
        db: profile.db,
        key_path: profile.key_path.clone(),
        tunnel: profile.tunnel.clone(),
        timeout_secs: profile.timeout_secs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_params() -> MysqlExecParams {
        MysqlExecParams {
            query: "SELECT 1".to_string(),
            allow_write: false,
            host: None,
            port: None,
            user: None,
            password: None,
            database: None,
            profile: None,
            config: None,
            tunnel: None,
            ssh_jump: None,
            ssh_user: None,
            ssh_password: None,
            ssh_key_path: None,
            ssh_port: None,
            socks5_host: None,
            socks5_port: None,
            socks5_user: None,
            socks5_password: None,
            tunnel_layers: None,
            timeout_secs: None,
            include_ui: false,
            format: "toon".to_string(),
        }
    }

    #[test]
    fn explicit_fields_become_config() {
        let p = MysqlExecParams {
            host: Some("db.example.com".into()),
            port: Some(3307),
            user: Some("alice".into()),
            ..empty_params()
        };
        let cfg = params_to_config(&p, None).unwrap();
        assert_eq!(cfg.host.as_deref(), Some("db.example.com"));
        assert_eq!(cfg.port, Some(3307));
        assert_eq!(cfg.user.as_deref(), Some("alice"));
    }

    #[test]
    fn timeout_secs_flows_into_config() {
        let p = MysqlExecParams {
            host: Some("h".into()),
            user: Some("u".into()),
            timeout_secs: Some(7),
            ..empty_params()
        };
        let cfg = params_to_config(&p, None).unwrap();
        assert_eq!(cfg.timeout_secs, Some(7));
    }

    #[test]
    fn profile_alias_selects_saved_mysql_connection() {
        let params = MysqlExecParams {
            profile: Some("114".into()),
            ..empty_params()
        };
        let toml: TomlConfig = serde_json::from_value(serde_json::json!({
            "profiles": {
                "mysql114": {
                    "type": "mysql",
                    "host": "db.example.invalid",
                    "user": "reader",
                    "aliases": ["114", "114 mysql"]
                }
            }
        }))
        .unwrap();

        let cfg = params_to_config(&params, Some(toml)).unwrap();
        assert_eq!(cfg.host.as_deref(), Some("db.example.invalid"));
        assert_eq!(cfg.user.as_deref(), Some("reader"));
    }

    #[test]
    fn allow_write_defaults_to_false() {
        let p: MysqlExecParams =
            serde_json::from_value(serde_json::json!({"query": "SELECT 1"})).unwrap();
        assert!(!p.allow_write);
    }
}
