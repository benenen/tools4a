use super::{ConfigLoader, ServiceType};
use crate::{Error, ExecutionResult, McpTool, Result};
use async_trait::async_trait;
use schemars::JsonSchema;
use serde::Deserialize;

/// `profiles_list` has no connection parameters: it reads only the default
/// local tools4a profile registry and returns an allowlisted metadata view.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
pub struct ProfilesListParams {}

pub struct ProfilesListMcp;

#[async_trait]
impl McpTool for ProfilesListMcp {
    const NAME: &'static str = "profiles_list";
    const DESCRIPTION: &'static str = "List saved tools4a connection profile names, service types, and aliases. \
         Use this before a service tool when the user names an environment but \
         the canonical profile is unknown. Returns no hosts, users, passwords, \
         keys, databases, tunnel details, or configuration paths. Read-only.";
    type Params = ProfilesListParams;

    async fn invoke(_params: ProfilesListParams) -> Result<ExecutionResult> {
        let Some(config) = ConfigLoader::load_default_toml().map_err(|_| {
            Error::Config(
                "profile registry is invalid or unreadable; inspect the local tools4a configuration"
                    .to_string(),
            )
        })?
        else {
            return Ok(ExecutionResult::new(
                vec!["name".into(), "type".into(), "aliases".into()],
                Vec::new(),
                0,
            ));
        };

        for service_type in [
            ServiceType::Mysql,
            ServiceType::Pgsql,
            ServiceType::Clickhouse,
            ServiceType::Redis,
            ServiceType::Mongo,
        ] {
            config.validate_aliases(Some(&service_type))?;
        }
        let mut profiles = config.profiles.iter().collect::<Vec<_>>();
        profiles.retain(|(_, profile)| profile.service_type.supports_profiles());
        profiles.sort_unstable_by_key(|(name, _)| name.as_str());
        let rows = profiles
            .into_iter()
            .map(|(name, profile)| {
                let mut aliases = profile.aliases.clone();
                aliases.sort_unstable_by_key(|alias| alias.to_ascii_lowercase());
                vec![
                    name.clone(),
                    profile.service_type.as_str().to_string(),
                    serde_json::to_string(&aliases)
                        .expect("serializing string aliases cannot fail"),
                ]
            })
            .collect::<Vec<_>>();
        let affected_rows = rows.len() as u64;

        Ok(ExecutionResult::new(
            vec!["name".into(), "type".into(), "aliases".into()],
            rows,
            affected_rows,
        ))
    }
}
