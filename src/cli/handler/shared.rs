//! Helpers shared across the per-service handler submodules:
//! - 3-layer Config merge (TOML profile -> YAML file -> CLI args)
//! - `cli_to_tunnel_config` + Profile->Config converter
//! - operator-side `max_timeout_secs` lookup
//! - stderr warnings sink

use crate::cli::{Cli, TunnelKind};
use tools4a_core::config::{Config, ConfigLoader, ConfigMerger, Profile, ServiceType, TomlConfig};
use tools4a_core::{Error, ExecutionResult, Result, TunnelConfig};

/// 3-layer config build for typed-DB services (mysql/pgsql/clickhouse/mongo).
#[allow(clippy::too_many_arguments)]
pub(super) fn build_config(
    cli: &Cli,
    service_type: ServiceType,
    host: Option<String>,
    port: Option<u16>,
    user: Option<String>,
    password: Option<String>,
    database: Option<String>,
    key_path: Option<String>,
    profile: Option<String>,
) -> Result<Config> {
    let mut configs: Vec<Config> = Vec::new();

    // 1. Default TOML profile (if --profile=NAME and ~/.config/tools4a/config.toml exists)
    if let Some(profile_name) = &profile {
        if let Some(toml_config) = ConfigLoader::load_default_toml()? {
            let profile_cfg = toml_config.profiles.get(profile_name).ok_or_else(|| {
                Error::Config(format!("profile '{profile_name}' not found in config.toml"))
            })?;
            configs.push(profile_to_config(profile_cfg));
        } else {
            return Err(Error::Config(format!(
                "profile '{profile_name}' requested but no ~/.config/tools4a/config.toml found"
            )));
        }
    }

    // 2. YAML config file
    if let Some(config_path) = cli.config.as_deref() {
        configs.push(ConfigLoader::load_yaml_file(config_path)?);
    }

    // 3. CLI arguments (highest priority)
    let tunnel_config = cli_to_tunnel_config(cli)?;
    configs.push(Config {
        service_type: Some(service_type),
        host,
        port,
        user,
        password,
        database,
        db: None,
        key_path,
        tunnel: tunnel_config,
        timeout_secs: cli.timeout,
    });

    Ok(ConfigMerger::merge_multiple(configs))
}

/// Redis-flavored Config build (different field set: `db` instead of `database`,
/// no `user`).
pub(super) fn build_config_redis(
    cli: &Cli,
    host: Option<String>,
    port: Option<u16>,
    password: Option<String>,
    db: Option<u32>,
    profile: Option<String>,
) -> Result<Config> {
    let mut configs: Vec<Config> = Vec::new();

    if let Some(profile_name) = &profile {
        if let Some(toml_config) = ConfigLoader::load_default_toml()? {
            let profile_cfg = toml_config.profiles.get(profile_name).ok_or_else(|| {
                Error::Config(format!("profile '{profile_name}' not found in config.toml"))
            })?;
            configs.push(profile_to_config(profile_cfg));
        } else {
            return Err(Error::Config(format!(
                "profile '{profile_name}' requested but no ~/.config/tools4a/config.toml found"
            )));
        }
    }

    if let Some(config_path) = cli.config.as_deref() {
        configs.push(ConfigLoader::load_yaml_file(config_path)?);
    }

    let tunnel_config = cli_to_tunnel_config(cli)?;
    configs.push(Config {
        service_type: Some(ServiceType::Redis),
        host,
        port,
        user: None,
        password,
        database: None,
        db,
        key_path: None,
        tunnel: tunnel_config,
        timeout_secs: cli.timeout,
    });

    Ok(ConfigMerger::merge_multiple(configs))
}

/// Read TOML `[defaults].max_timeout_secs` once per CLI invocation. Env var
/// `TOOLS4A_MAX_TIMEOUT_SECS` still takes precedence at the orchestrator layer.
pub(super) fn load_max_timeout_secs() -> Result<Option<u64>> {
    Ok(ConfigLoader::load_default_toml()?.and_then(|t: TomlConfig| t.defaults.max_timeout_secs))
}

/// Emit non-fatal advisories (e.g. timeout-clamp notices) to stderr so they
/// don't get tangled up with the result table on stdout.
pub(super) fn print_warnings(result: &ExecutionResult) {
    for w in &result.warnings {
        eprintln!("warning: {w}");
    }
}

/// Convert top-level CLI `--tunnel` + `--ssh-*` + `--socks5-*` flags into a
/// `TunnelConfig`. Cross-validates that flags from the wrong family aren't
/// mixed with the chosen `--tunnel` kind.
pub(super) fn cli_to_tunnel_config(cli: &Cli) -> Result<Option<TunnelConfig>> {
    let Some(kind) = cli.tunnel else {
        return Ok(None);
    };
    let ssh = &cli.ssh;
    let socks5 = &cli.socks5;
    let stray_ssh = ssh.ssh_jump.is_some()
        || ssh.ssh_user.is_some()
        || ssh.ssh_password.is_some()
        || ssh.ssh_key_path.is_some()
        || ssh.ssh_port.is_some();
    let stray_socks5 = socks5.socks5_host.is_some()
        || socks5.socks5_port.is_some()
        || socks5.socks5_user.is_some()
        || socks5.socks5_password.is_some();
    match kind {
        TunnelKind::Direct => {
            if stray_ssh {
                return Err(Error::Config(
                    "SSH options (--ssh-*) are only valid with --tunnel=ssh".to_string(),
                ));
            }
            if stray_socks5 {
                return Err(Error::Config(
                    "SOCKS5 options (--socks5-*) are only valid with --tunnel=socks5".to_string(),
                ));
            }
            Ok(Some(TunnelConfig::Direct))
        }
        TunnelKind::Ssh => {
            if stray_socks5 {
                return Err(Error::Config(
                    "SOCKS5 options (--socks5-*) are only valid with --tunnel=socks5".to_string(),
                ));
            }
            let raw_jump = ssh.ssh_jump.clone().ok_or_else(|| {
                Error::Config("--ssh-jump is required when --tunnel=ssh".to_string())
            })?;
            let host_jumps: Vec<String> = raw_jump
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if host_jumps.is_empty() {
                return Err(Error::Config("--ssh-jump must not be empty".to_string()));
            }
            let ssh_user = ssh.ssh_user.clone().ok_or_else(|| {
                Error::Config("--ssh-user is required when --tunnel=ssh".to_string())
            })?;
            let port = ssh.ssh_port.unwrap_or(22);
            let ssh_jumps: Vec<tools4a_core::JumpHop> = host_jumps
                .into_iter()
                .map(|host| tools4a_core::JumpHop {
                    host,
                    user: ssh_user.clone(),
                    password: ssh.ssh_password.clone(),
                    key_path: ssh.ssh_key_path.clone(),
                    port,
                })
                .collect();
            Ok(Some(TunnelConfig::Ssh { ssh_jumps }))
        }
        TunnelKind::Socks5 => {
            if stray_ssh {
                return Err(Error::Config(
                    "SSH options (--ssh-*) are only valid with --tunnel=ssh".to_string(),
                ));
            }
            let host = socks5.socks5_host.clone().ok_or_else(|| {
                Error::Config("--socks5-host is required when --tunnel=socks5".to_string())
            })?;
            if host.is_empty() {
                return Err(Error::Config("--socks5-host must not be empty".to_string()));
            }
            if socks5.socks5_user.is_some() != socks5.socks5_password.is_some() {
                return Err(Error::Config(
                    "--socks5-user and --socks5-password must be set together".to_string(),
                ));
            }
            Ok(Some(TunnelConfig::Socks5 {
                socks5_host: host,
                socks5_port: socks5.socks5_port.unwrap_or(1080),
                socks5_user: socks5.socks5_user.clone(),
                socks5_password: socks5.socks5_password.clone(),
            }))
        }
    }
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
    use clap::Parser;

    fn parse(extra: &[&str]) -> Cli {
        let mut args = vec!["tools4a"];
        args.extend_from_slice(extra);
        args.extend_from_slice(&["mysql", "SELECT 1"]);
        Cli::try_parse_from(args).expect("CLI parse")
    }

    #[test]
    fn socks5_minimal_builds_socks5_variant() {
        let cli = parse(&["--tunnel=socks5", "--socks5-host=192.0.2.10"]);
        match cli_to_tunnel_config(&cli).unwrap() {
            Some(TunnelConfig::Socks5 {
                socks5_host,
                socks5_port,
                socks5_user,
                socks5_password,
            }) => {
                assert_eq!(socks5_host, "192.0.2.10");
                assert_eq!(socks5_port, 1080);
                assert!(socks5_user.is_none());
                assert!(socks5_password.is_none());
            }
            other => panic!("expected Socks5, got {other:?}"),
        }
    }

    #[test]
    fn socks5_with_auth_builds_full_variant() {
        let cli = parse(&[
            "--tunnel=socks5",
            "--socks5-host=p",
            "--socks5-port=2235",
            "--socks5-user=alice",
            "--socks5-password=s3cret",
        ]);
        match cli_to_tunnel_config(&cli).unwrap() {
            Some(TunnelConfig::Socks5 {
                socks5_port,
                socks5_user,
                socks5_password,
                ..
            }) => {
                assert_eq!(socks5_port, 2235);
                assert_eq!(socks5_user.as_deref(), Some("alice"));
                assert_eq!(socks5_password.as_deref(), Some("s3cret"));
            }
            other => panic!("expected Socks5, got {other:?}"),
        }
    }

    #[test]
    fn socks5_missing_host_errors() {
        let cli = parse(&["--tunnel=socks5"]);
        let err = cli_to_tunnel_config(&cli).unwrap_err();
        assert!(matches!(err, Error::Config(ref m) if m.contains("--socks5-host")));
    }

    #[test]
    fn socks5_user_without_password_errors() {
        let cli = parse(&["--tunnel=socks5", "--socks5-host=p", "--socks5-user=alice"]);
        let err = cli_to_tunnel_config(&cli).unwrap_err();
        assert!(matches!(err, Error::Config(ref m) if m.contains("set together")));
    }

    #[test]
    fn direct_rejects_stray_socks5() {
        let cli = parse(&["--tunnel=direct", "--socks5-host=p"]);
        let err = cli_to_tunnel_config(&cli).unwrap_err();
        assert!(matches!(err, Error::Config(ref m) if m.contains("--socks5-*")));
    }

    #[test]
    fn ssh_rejects_stray_socks5() {
        let cli = parse(&[
            "--tunnel=ssh",
            "--ssh-jump=bastion.com",
            "--ssh-user=u",
            "--socks5-host=p",
        ]);
        let err = cli_to_tunnel_config(&cli).unwrap_err();
        assert!(matches!(err, Error::Config(ref m) if m.contains("--socks5-*")));
    }

    #[test]
    fn socks5_rejects_stray_ssh() {
        let cli = parse(&[
            "--tunnel=socks5",
            "--socks5-host=p",
            "--ssh-jump=bastion.com",
        ]);
        let err = cli_to_tunnel_config(&cli).unwrap_err();
        assert!(matches!(err, Error::Config(ref m) if m.contains("--ssh-*")));
    }
}
