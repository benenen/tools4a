//! Helpers shared across the per-service handler submodules:
//! - 3-layer Config merge (TOML profile -> YAML file -> CLI args)
//! - `cli_to_tunnel_config` + Profile->Config converter
//! - operator-side `max_timeout_secs` lookup
//! - stderr warnings sink

use crate::cli::{Cli, TunnelKind};
use tools4a_core::config::{Config, ConfigLoader, ConfigMerger, Profile, ServiceType, TomlConfig};
use tools4a_core::{
    Error, ExecutionResult, JumpHop, Result, TunnelConfig, TunnelLayer,
    mcp::{SshJumpHopInput, merge_hop},
};

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
            let (_, profile_cfg) =
                toml_config.resolve_profile(profile_name, Some(service_type.clone()))?;
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
            let (_, profile_cfg) =
                toml_config.resolve_profile(profile_name, Some(ServiceType::Redis))?;
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

/// Percent-decode RFC 3986 userinfo / query values.
fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16)
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse one `--hop` URL into a `TunnelLayer`. URL forms:
///   socks5://[user[:pass]@]host[:port]
///   ssh://user[:pass]@host[:port][?key=/abs/path]
pub(crate) fn parse_hop_url(raw: &str) -> Result<TunnelLayer> {
    let (scheme, rest) = raw
        .split_once("://")
        .ok_or_else(|| Error::Config(format!("--hop '{raw}': expected scheme://...")))?;
    // split optional ?query
    let (authority, query) = match rest.split_once('?') {
        Some((a, q)) => (a, Some(q)),
        None => (rest, None),
    };
    let (userinfo, hostport) = match authority.rsplit_once('@') {
        Some((u, h)) => (Some(u), h),
        None => (None, authority),
    };
    let (host, port_opt) = match hostport.rsplit_once(':') {
        Some((h, p)) => (
            h.to_string(),
            Some(
                p.parse::<u16>()
                    .map_err(|_| Error::Config(format!("--hop '{raw}': bad port")))?,
            ),
        ),
        None => (hostport.to_string(), None),
    };
    if host.is_empty() {
        return Err(Error::Config(format!("--hop '{raw}': empty host")));
    }
    let (user, password) = match userinfo {
        None => (None, None),
        Some(ui) => match ui.split_once(':') {
            Some((u, p)) => (Some(pct_decode(u)), Some(pct_decode(p))),
            None => (Some(pct_decode(ui)), None),
        },
    };
    match scheme {
        "socks5" => Ok(TunnelLayer::Socks5 {
            host,
            port: port_opt.unwrap_or(1080),
            user,
            password,
        }),
        "ssh" => {
            let user =
                user.ok_or_else(|| Error::Config(format!("--hop '{raw}': ssh needs a user")))?;
            let key_path = query.and_then(|q| {
                q.split('&')
                    .find_map(|kv| kv.strip_prefix("key="))
                    .map(pct_decode)
            });
            Ok(TunnelLayer::SshHop(JumpHop {
                host,
                user,
                password,
                key_path,
                port: port_opt.unwrap_or(22),
            }))
        }
        other => Err(Error::Config(format!(
            "--hop '{raw}': unknown scheme '{other}'"
        ))),
    }
}

/// Convert top-level CLI `--hop` (preferred) or `--tunnel` + `--ssh-*` +
/// `--socks5-*` flags into a `TunnelConfig`. `--hop` lowers directly to an
/// ordered layer stack; the legacy flags lower to the same stack, with
/// `--socks5-*` becoming a SOCKS5 underlay in front of the SSH jump chain.
pub(super) fn cli_to_tunnel_config(cli: &Cli) -> Result<Option<TunnelConfig>> {
    // --- Ordered --hop form (preferred) ---------------------------------
    if !cli.hop.is_empty() {
        let layers = cli
            .hop
            .iter()
            .map(|raw| parse_hop_url(raw))
            .collect::<Result<Vec<_>>>()?;
        return Ok(Some(TunnelConfig::layered(layers)));
    }

    let Some(kind) = cli.tunnel else {
        return Ok(None);
    };
    let ssh = &cli.ssh;
    let socks5 = &cli.socks5;
    let stray_ssh = ssh.ssh_jump.is_some()
        || !ssh.ssh_hop.is_empty()
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
            Ok(Some(TunnelConfig::direct()))
        }
        TunnelKind::Ssh => {
            // `--socks5-*` with `--tunnel=ssh` is no longer an error: it
            // lowers to a SOCKS5 underlay in front of the SSH jump chain.
            let socks5_prefix = socks5_underlay_layer(socks5)?;
            let default_port = ssh.ssh_port.unwrap_or(22);
            let hop_inputs: Vec<SshJumpHopInput> =
                match (ssh.ssh_jump.as_deref(), ssh.ssh_hop.is_empty()) {
                    (Some(_), false) => {
                        return Err(Error::Config(
                            "--ssh-jump and --ssh-hop are mutually exclusive — pick one"
                                .to_string(),
                        ));
                    }
                    (None, true) => {
                        return Err(Error::Config(
                            "--ssh-jump or --ssh-hop is required when --tunnel=ssh".to_string(),
                        ));
                    }
                    (Some(raw), true) => raw
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .map(|host| SshJumpHopInput {
                            host,
                            user: None,
                            password: None,
                            key_path: None,
                            port: None,
                        })
                        .collect(),
                    (None, false) => ssh
                        .ssh_hop
                        .iter()
                        .enumerate()
                        .map(|(i, raw)| {
                            serde_json::from_str::<SshJumpHopInput>(raw).map_err(|e| {
                                Error::Config(format!("--ssh-hop #{} parse failed: {e}", i + 1))
                            })
                        })
                        .collect::<Result<Vec<_>>>()?,
                };
            if hop_inputs.is_empty() {
                return Err(Error::Config(
                    "--ssh-jump / --ssh-hop must not be empty".to_string(),
                ));
            }
            let ssh_jumps: Vec<JumpHop> = hop_inputs
                .into_iter()
                .enumerate()
                .map(|(i, hop)| {
                    merge_hop(
                        i,
                        hop,
                        ssh.ssh_user.as_deref(),
                        ssh.ssh_password.as_deref(),
                        ssh.ssh_key_path.as_deref(),
                        default_port,
                    )
                })
                .collect::<Result<_>>()?;
            let mut layers = Vec::with_capacity(ssh_jumps.len() + 1);
            layers.extend(socks5_prefix);
            layers.extend(ssh_jumps.into_iter().map(TunnelLayer::SshHop));
            Ok(Some(TunnelConfig::layered(layers)))
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
            Ok(Some(TunnelConfig::socks5(
                host,
                socks5.socks5_port.unwrap_or(1080),
                socks5.socks5_user.clone(),
                socks5.socks5_password.clone(),
            )))
        }
    }
}

/// Lower `--socks5-*` flags (under `--tunnel=ssh`) into an optional SOCKS5
/// underlay layer. `--socks5-host` is required for any underlay; stray
/// `--socks5-port/-user/-password` without a host is an error.
fn socks5_underlay_layer(socks5: &crate::cli::Socks5TunnelArgs) -> Result<Option<TunnelLayer>> {
    let Some(host) = socks5.socks5_host.clone() else {
        if socks5.socks5_port.is_some()
            || socks5.socks5_user.is_some()
            || socks5.socks5_password.is_some()
        {
            return Err(Error::Config(
                "--socks5-host is required to add a socks5 underlay".to_string(),
            ));
        }
        return Ok(None);
    };
    if host.is_empty() {
        return Err(Error::Config("--socks5-host must not be empty".to_string()));
    }
    if socks5.socks5_user.is_some() != socks5.socks5_password.is_some() {
        return Err(Error::Config(
            "--socks5-user and --socks5-password must be set together".to_string(),
        ));
    }
    Ok(Some(TunnelLayer::Socks5 {
        host,
        port: socks5.socks5_port.unwrap_or(1080),
        user: socks5.socks5_user.clone(),
        password: socks5.socks5_password.clone(),
    }))
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
        let cfg = cli_to_tunnel_config(&cli).unwrap().unwrap();
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
            other => panic!("expected Socks5, got {other:?}"),
        }
    }

    #[test]
    fn socks5_with_auth_builds_full_variant() {
        let cli = parse(&[
            "--tunnel=socks5",
            "--socks5-host=p",
            "--socks5-port=1080",
            "--socks5-user=alice",
            "--socks5-password=s3cret",
        ]);
        let cfg = cli_to_tunnel_config(&cli).unwrap().unwrap();
        match &cfg.layers[0] {
            TunnelLayer::Socks5 {
                port,
                user,
                password,
                ..
            } => {
                assert_eq!(*port, 1080);
                assert_eq!(user.as_deref(), Some("alice"));
                assert_eq!(password.as_deref(), Some("s3cret"));
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
    fn ssh_plus_socks5_combines_into_underlay_then_jump() {
        // tunnel=ssh + --socks5-host now LOWERS to [Socks5, SshHop...].
        let cli = parse(&[
            "--tunnel=ssh",
            "--ssh-jump=bastion.com",
            "--ssh-user=u",
            "--socks5-host=192.0.2.10",
            "--socks5-port=1080",
        ]);
        let cfg = cli_to_tunnel_config(&cli).unwrap().unwrap();
        assert_eq!(cfg.layers.len(), 2);
        assert!(cfg.ssh_jumps().is_none());
        assert!(cfg.last_layer_is_ssh());
        match &cfg.layers[0] {
            TunnelLayer::Socks5 { host, port, .. } => {
                assert_eq!(host, "192.0.2.10");
                assert_eq!(*port, 1080);
            }
            other => panic!("expected socks5 underlay, got {other:?}"),
        }
        match &cfg.layers[1] {
            TunnelLayer::SshHop(h) => assert_eq!(h.host, "bastion.com"),
            other => panic!("expected ssh hop, got {other:?}"),
        }
    }

    #[test]
    fn ssh_plus_socks5_port_without_host_errors() {
        // The reviewer-flagged untested branch: socks5 underlay fields
        // (port/user) without --socks5-host is nonsensical.
        let cli = parse(&[
            "--tunnel=ssh",
            "--ssh-jump=bastion.com",
            "--ssh-user=u",
            "--socks5-port=1080",
        ]);
        let err = cli_to_tunnel_config(&cli).unwrap_err();
        assert!(matches!(err, Error::Config(ref m) if m.contains("--socks5-host")));
    }

    #[test]
    fn hop_socks5_then_ssh_builds_layered() {
        let cli = parse(&[
            "--hop",
            "socks5://192.0.2.10:1080",
            "--hop",
            "ssh://admin:not-a-real-password@192.0.2.20:22",
        ]);
        let cfg = cli_to_tunnel_config(&cli).unwrap().unwrap();
        assert_eq!(cfg.layers.len(), 2);
        assert!(cfg.ssh_jumps().is_none());
        assert!(cfg.last_layer_is_ssh());
        match &cfg.layers[0] {
            TunnelLayer::Socks5 { host, port, .. } => {
                assert_eq!(host, "192.0.2.10");
                assert_eq!(*port, 1080);
            }
            other => panic!("expected socks5, got {other:?}"),
        }
        match &cfg.layers[1] {
            TunnelLayer::SshHop(h) => {
                assert_eq!(h.host, "192.0.2.20");
                assert_eq!(h.port, 22);
                assert_eq!(h.user, "admin");
                assert_eq!(h.password.as_deref(), Some("not-a-real-password"));
            }
            other => panic!("expected ssh hop, got {other:?}"),
        }
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

    #[test]
    fn ssh_hop_single_builds_jump_with_per_hop_creds() {
        let cli = parse(&[
            "--tunnel=ssh",
            "--ssh-hop",
            r#"{"host":"gw","user":"admin","password":"not-a-real-password","port":2222}"#,
        ]);
        let cfg = cli_to_tunnel_config(&cli).unwrap().unwrap();
        let ssh_jumps = cfg.ssh_jumps().expect("all-ssh");
        assert_eq!(ssh_jumps.len(), 1);
        assert_eq!(ssh_jumps[0].host, "gw");
        assert_eq!(ssh_jumps[0].user, "admin");
        assert_eq!(
            ssh_jumps[0].password.as_deref(),
            Some("not-a-real-password")
        );
        assert_eq!(ssh_jumps[0].port, 2222);
    }

    #[test]
    fn ssh_hop_repeated_accumulates_two_hops() {
        let cli = parse(&[
            "--tunnel=ssh",
            "--ssh-hop",
            r#"{"host":"gw","user":"admin","password":"pw1"}"#,
            "--ssh-hop",
            r#"{"host":"54","user":"target-user","password":"pw2"}"#,
        ]);
        let cfg = cli_to_tunnel_config(&cli).unwrap().unwrap();
        let ssh_jumps = cfg.ssh_jumps().expect("all-ssh");
        assert_eq!(ssh_jumps.len(), 2);
        assert_eq!(ssh_jumps[0].user, "admin");
        assert_eq!(ssh_jumps[1].user, "target-user");
    }

    #[test]
    fn ssh_jump_and_ssh_hop_together_errors() {
        let cli = parse(&[
            "--tunnel=ssh",
            "--ssh-jump=gw",
            "--ssh-hop",
            r#"{"host":"54","user":"target-user"}"#,
        ]);
        let err = cli_to_tunnel_config(&cli).unwrap_err();
        assert!(matches!(err, Error::Config(ref m) if m.contains("mutually exclusive")));
    }

    #[test]
    fn ssh_hop_invalid_json_errors() {
        let cli = parse(&["--tunnel=ssh", "--ssh-hop", "not-json{"]);
        let err = cli_to_tunnel_config(&cli).unwrap_err();
        assert!(
            matches!(err, Error::Config(ref m) if m.contains("--ssh-hop") && m.contains("parse failed"))
        );
    }
}

#[cfg(test)]
mod hop_tests {
    use super::*;
    use tools4a_core::TunnelLayer;

    #[test]
    fn parse_socks5_hop_no_auth() {
        let l = parse_hop_url("socks5://192.0.2.10:1080").unwrap();
        match l {
            TunnelLayer::Socks5 {
                host,
                port,
                user,
                password,
            } => {
                assert_eq!(host, "192.0.2.10");
                assert_eq!(port, 1080);
                assert!(user.is_none() && password.is_none());
            }
            _ => panic!(),
        }
    }

    #[test]
    fn parse_socks5_hop_default_port() {
        let l = parse_hop_url("socks5://proxy.internal").unwrap();
        match l {
            TunnelLayer::Socks5 { host, port, .. } => {
                assert_eq!(host, "proxy.internal");
                assert_eq!(port, 1080);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn parse_ssh_hop_with_percent_encoded_password() {
        // not-a-real%21password -> not-a-real!password
        let l = parse_hop_url("ssh://admin:not-a-real%21password@192.0.2.20:22").unwrap();
        match l {
            TunnelLayer::SshHop(h) => {
                assert_eq!(h.host, "192.0.2.20");
                assert_eq!(h.port, 22);
                assert_eq!(h.user, "admin");
                assert_eq!(h.password.as_deref(), Some("not-a-real!password"));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn parse_ssh_hop_key_via_query() {
        let l = parse_hop_url("ssh://ubuntu@192.0.2.30?key=/home/me/.ssh/id_ed25519").unwrap();
        match l {
            TunnelLayer::SshHop(h) => {
                assert_eq!(h.port, 22);
                assert_eq!(h.user, "ubuntu");
                assert_eq!(h.key_path.as_deref(), Some("/home/me/.ssh/id_ed25519"));
                assert!(h.password.is_none());
            }
            _ => panic!(),
        }
    }

    #[test]
    fn parse_hop_rejects_missing_scheme() {
        assert!(parse_hop_url("192.0.2.10:1080").is_err());
    }

    #[test]
    fn parse_hop_rejects_unknown_scheme() {
        let err = parse_hop_url("http://x:80").unwrap_err();
        assert!(matches!(err, Error::Config(ref m) if m.contains("unknown scheme")));
    }

    #[test]
    fn parse_ssh_hop_without_user_errors() {
        let err = parse_hop_url("ssh://192.0.2.30:22").unwrap_err();
        assert!(matches!(err, Error::Config(ref m) if m.contains("ssh needs a user")));
    }
}
