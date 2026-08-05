use crate::{Error, Result as CoreResult, TunnelConfig};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ServiceType {
    Mysql,
    Pgsql,
    Clickhouse,
    Redis,
    Mongo,
    Ssh,
    Http,
}

impl FromStr for ServiceType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "mysql" => Ok(ServiceType::Mysql),
            "pgsql" | "postgres" | "postgresql" => Ok(ServiceType::Pgsql),
            "clickhouse" | "ch" => Ok(ServiceType::Clickhouse),
            "redis" => Ok(ServiceType::Redis),
            "mongo" | "mongodb" => Ok(ServiceType::Mongo),
            "ssh" => Ok(ServiceType::Ssh),
            "http" => Ok(ServiceType::Http),
            _ => Err(format!("Invalid service type: {}", s)),
        }
    }
}

impl ServiceType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ServiceType::Mysql => "mysql",
            ServiceType::Pgsql => "pgsql",
            ServiceType::Clickhouse => "clickhouse",
            ServiceType::Redis => "redis",
            ServiceType::Mongo => "mongo",
            ServiceType::Ssh => "ssh",
            ServiceType::Http => "http",
        }
    }

    pub fn supports_profiles(&self) -> bool {
        matches!(
            self,
            ServiceType::Mysql
                | ServiceType::Pgsql
                | ServiceType::Clickhouse
                | ServiceType::Redis
                | ServiceType::Mongo
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    #[serde(rename = "type")]
    pub service_type: ServiceType,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub user: Option<String>,
    pub password: Option<String>,
    pub database: Option<String>,
    /// Redis database number. Ignored by non-Redis services.
    pub db: Option<u32>,
    pub key_path: Option<String>,
    pub tunnel: Option<TunnelConfig>,
    /// Human-facing names that may be used anywhere a canonical profile
    /// name is accepted. Kept out of `Config` because aliases select a
    /// profile; they are not connection settings themselves.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
    /// Per-profile default for the caller-facing execution timeout
    /// (seconds). Lower precedence than CLI `--timeout` / MCP
    /// `timeout_secs`; subject to the global `max_timeout_secs` ceiling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,
}

/// Top-level `[defaults]` block in `~/.config/tools4a/config.toml`.
/// Operator-side knobs that apply globally (not per profile).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DefaultsConfig {
    /// Hard ceiling for per-call execution timeouts (seconds). The
    /// `TOOLS4A_MAX_TIMEOUT_SECS` env var takes precedence over this.
    /// When unset in both, the built-in `DEFAULT_MAX_TIMEOUT_SECS`
    /// (1 hour) applies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_timeout_secs: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TomlConfig {
    #[serde(default)]
    pub profiles: std::collections::HashMap<String, Profile>,
    #[serde(default)]
    pub defaults: DefaultsConfig,
}

impl TomlConfig {
    /// Resolve an exact profile name or a human-facing alias. Exact names
    /// win for backwards compatibility. Alias matching is trimmed and
    /// ASCII-case-insensitive, and is scoped by service type when supplied.
    pub fn resolve_profile(
        &self,
        name_or_alias: &str,
        service_type: Option<ServiceType>,
    ) -> CoreResult<(&str, &Profile)> {
        const MAX_ROUTING_NAME_CHARS: usize = 128;
        let requested = name_or_alias.trim();
        if requested.is_empty() {
            return Err(Error::Config(
                "requested profile name or alias is empty".to_string(),
            ));
        }
        validate_routing_name(
            "requested profile name or alias",
            requested,
            MAX_ROUTING_NAME_CHARS,
        )?;
        self.validate_aliases(service_type.as_ref())?;
        if let Some((name, profile)) = self.profiles.get_key_value(requested) {
            if let Some(expected) = service_type.as_ref()
                && profile.service_type != *expected
            {
                return Err(Error::Config(format!(
                    "profile '{name}' has type '{}', but '{}' was requested",
                    profile.service_type.as_str(),
                    expected.as_str()
                )));
            }
            return Ok((name.as_str(), profile));
        }

        let matches = self
            .profiles
            .iter()
            .filter(|(_, profile)| {
                service_type
                    .as_ref()
                    .is_none_or(|expected| profile.service_type == *expected)
            })
            .filter(|(_, profile)| {
                profile
                    .aliases
                    .iter()
                    .any(|alias| alias.trim().eq_ignore_ascii_case(requested))
            })
            .collect::<Vec<_>>();

        match matches.as_slice() {
            [(name, profile)] => Ok((name.as_str(), *profile)),
            [] => Err(Error::Config(format!(
                "profile or alias '{requested}' not found in config.toml"
            ))),
            _ => {
                let mut names = matches
                    .iter()
                    .map(|(name, _)| name.as_str())
                    .collect::<Vec<_>>();
                names.sort_unstable();
                Err(Error::Config(format!(
                    "profile alias '{requested}' is ambiguous: {}",
                    names.join(", ")
                )))
            }
        }
    }

    /// Validate aliases without serializing or logging profile contents.
    pub fn validate_aliases(&self, service_type: Option<&ServiceType>) -> CoreResult<()> {
        const MAX_ALIASES_PER_PROFILE: usize = 32;
        const MAX_ROUTING_NAME_CHARS: usize = 128;

        let mut canonical_names: HashMap<(ServiceType, String), &str> = HashMap::new();
        let mut owners: HashMap<(ServiceType, String), &str> = HashMap::new();
        let mut profiles = self.profiles.iter().collect::<Vec<_>>();
        profiles.sort_unstable_by_key(|(name, _)| name.as_str());

        for (name, profile) in &profiles {
            if service_type.is_some_and(|expected| profile.service_type != *expected) {
                continue;
            }
            validate_routing_name("profile name", name, MAX_ROUTING_NAME_CHARS)?;
            let key = (profile.service_type.clone(), name.to_ascii_lowercase());
            if let Some(owner) = canonical_names.insert(key, name.as_str()) {
                return Err(Error::Config(format!(
                    "profile names '{owner}' and '{name}' differ only by ASCII case"
                )));
            }
        }

        for (name, profile) in profiles {
            if service_type.is_some_and(|expected| profile.service_type != *expected) {
                continue;
            }
            if profile.aliases.len() > MAX_ALIASES_PER_PROFILE {
                return Err(Error::Config(format!(
                    "profile '{name}' has too many aliases (max {MAX_ALIASES_PER_PROFILE})"
                )));
            }
            for alias in &profile.aliases {
                let normalized = alias.trim();
                if normalized.is_empty() {
                    return Err(Error::Config(format!(
                        "profile '{name}' contains an empty alias"
                    )));
                }
                validate_routing_name("profile alias", alias, MAX_ROUTING_NAME_CHARS)?;
                if normalized != alias {
                    return Err(Error::Config(format!(
                        "profile '{name}' contains an alias with leading or trailing whitespace"
                    )));
                }
                let key = (
                    profile.service_type.clone(),
                    normalized.to_ascii_lowercase(),
                );
                if let Some(canonical) = canonical_names.get(&key) {
                    return Err(Error::Config(format!(
                        "profile alias '{normalized}' for '{name}' conflicts with canonical profile '{canonical}'"
                    )));
                }
                if let Some(owner) = owners.insert(key, name.as_str()) {
                    return Err(Error::Config(format!(
                        "duplicate alias '{normalized}' for profiles '{owner}' and '{name}'"
                    )));
                }
            }
        }
        Ok(())
    }
}

fn validate_routing_name(kind: &str, value: &str, max_chars: usize) -> CoreResult<()> {
    if value.chars().count() > max_chars {
        return Err(Error::Config(format!(
            "{kind} exceeds {max_chars} characters"
        )));
    }
    if value
        .chars()
        .any(|ch| ch.is_control() || is_bidi_control(ch))
    {
        return Err(Error::Config(format!(
            "{kind} contains control or bidirectional formatting characters"
        )));
    }
    Ok(())
}

fn is_bidi_control(ch: char) -> bool {
    matches!(
        ch,
        '\u{061c}'
            | '\u{200e}'
            | '\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}'
    )
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Config {
    #[serde(rename = "type")]
    pub service_type: Option<ServiceType>,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub user: Option<String>,
    pub password: Option<String>,
    pub database: Option<String>,
    /// Redis database number. Ignored by non-Redis services.
    pub db: Option<u32>,
    pub key_path: Option<String>,
    pub tunnel: Option<TunnelConfig>,
    /// Per-call execution timeout (seconds), as merged from
    /// profile/YAML/CLI. `None` means "use the service default".
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_type_from_str() {
        assert_eq!("mysql".parse::<ServiceType>().unwrap(), ServiceType::Mysql);
        assert_eq!("pgsql".parse::<ServiceType>().unwrap(), ServiceType::Pgsql);
        assert_eq!(
            "postgres".parse::<ServiceType>().unwrap(),
            ServiceType::Pgsql
        );
        assert_eq!(
            "postgresql".parse::<ServiceType>().unwrap(),
            ServiceType::Pgsql
        );
        assert_eq!("redis".parse::<ServiceType>().unwrap(), ServiceType::Redis);
        assert_eq!("mongo".parse::<ServiceType>().unwrap(), ServiceType::Mongo);
        assert_eq!(
            "mongodb".parse::<ServiceType>().unwrap(),
            ServiceType::Mongo
        );
        assert_eq!(
            "clickhouse".parse::<ServiceType>().unwrap(),
            ServiceType::Clickhouse
        );
        assert_eq!(
            "ch".parse::<ServiceType>().unwrap(),
            ServiceType::Clickhouse
        );
        assert_eq!("ssh".parse::<ServiceType>().unwrap(), ServiceType::Ssh);
        assert!("invalid".parse::<ServiceType>().is_err());
    }
}
