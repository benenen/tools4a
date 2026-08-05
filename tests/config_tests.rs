use std::fs;
use tempfile::TempDir;
use tools4a_core::config::{ConfigLoader, ServiceType};

#[test]
fn test_load_yaml_config() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("test.yaml");

    let yaml_content = r#"
type: mysql
host: localhost
port: 3306
user: root
password: secret
"#;

    fs::write(&config_path, yaml_content).unwrap();

    let config = ConfigLoader::load_yaml_file(&config_path).unwrap();
    assert_eq!(config.service_type, Some(ServiceType::Mysql));
    assert_eq!(config.host.as_deref(), Some("localhost"));
    assert_eq!(config.port, Some(3306));
    assert_eq!(config.user.as_deref(), Some("root"));
}

#[test]
fn test_load_toml_config() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("test.toml");

    let toml_content = r#"
[profiles.test]
type = "mysql"
host = "localhost"
port = 3306
user = "root"
"#;

    fs::write(&config_path, toml_content).unwrap();

    let config = ConfigLoader::load_toml_file(&config_path).unwrap();
    let profile = config.profiles.get("test").unwrap();
    assert_eq!(profile.service_type, ServiceType::Mysql);
    assert_eq!(profile.host.as_deref(), Some("localhost"));
    assert!(profile.aliases.is_empty());
}

#[test]
fn test_profile_aliases_resolve_to_canonical_profile() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("test.toml");

    let toml_content = r#"
[profiles.mysql114]
type = "mysql"
host = "db.example.invalid"
aliases = ["114", "114 mysql"]
"#;

    fs::write(&config_path, toml_content).unwrap();
    let config = ConfigLoader::load_toml_file(&config_path).unwrap();

    let (canonical, profile) = config
        .resolve_profile("114", Some(ServiceType::Mysql))
        .unwrap();
    assert_eq!(canonical, "mysql114");
    assert_eq!(profile.aliases, ["114", "114 mysql"]);
}

#[test]
fn test_canonical_profile_name_wins_over_other_service_alias() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("test.toml");

    let toml_content = r#"
[profiles.prod]
type = "mysql"
host = "canonical.example.invalid"

[profiles.other]
type = "pgsql"
host = "other.example.invalid"
aliases = ["prod"]
"#;

    fs::write(&config_path, toml_content).unwrap();
    let config = ConfigLoader::load_toml_file(&config_path).unwrap();

    let (canonical, profile) = config
        .resolve_profile("prod", Some(ServiceType::Mysql))
        .unwrap();
    assert_eq!(canonical, "prod");
    assert_eq!(profile.host.as_deref(), Some("canonical.example.invalid"));
}

#[test]
fn test_canonical_profile_rejects_wrong_service_type() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("test.toml");
    fs::write(
        &config_path,
        r#"
[profiles.cache]
type = "redis"
host = "cache.example.invalid"
"#,
    )
    .unwrap();
    let config = ConfigLoader::load_toml_file(&config_path).unwrap();

    let error = config
        .resolve_profile("cache", Some(ServiceType::Mysql))
        .unwrap_err()
        .to_string();
    assert!(error.contains("type 'redis'"), "unexpected error: {error}");
    assert!(error.contains("mysql"), "unexpected error: {error}");
}

#[test]
fn test_alias_colliding_with_canonical_name_is_rejected() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("test.toml");
    fs::write(
        &config_path,
        r#"
[profiles.Prod]
type = "mysql"

[profiles.other]
type = "mysql"
aliases = ["prod"]
"#,
    )
    .unwrap();
    let config = ConfigLoader::load_toml_file(&config_path).unwrap();

    let error = config
        .resolve_profile("Prod", Some(ServiceType::Mysql))
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("conflicts with canonical profile 'Prod'"),
        "unexpected error: {error}"
    );
}

#[test]
fn test_profile_alias_validation_rejects_empty_and_duplicate_aliases() {
    let temp_dir = TempDir::new().unwrap();
    let empty_path = temp_dir.path().join("empty.toml");
    fs::write(
        &empty_path,
        r#"
[profiles.one]
type = "mysql"
aliases = ["   "]
"#,
    )
    .unwrap();
    let empty = ConfigLoader::load_toml_file(&empty_path).unwrap();
    let error = empty
        .resolve_profile("missing", Some(ServiceType::Mysql))
        .unwrap_err()
        .to_string();
    assert!(error.contains("empty alias"), "unexpected error: {error}");

    let duplicate_path = temp_dir.path().join("duplicate.toml");
    fs::write(
        &duplicate_path,
        r#"
[profiles.one]
type = "mysql"
aliases = ["shared"]

[profiles.two]
type = "mysql"
aliases = ["SHARED"]
"#,
    )
    .unwrap();
    let duplicate = ConfigLoader::load_toml_file(&duplicate_path).unwrap();
    let error = duplicate
        .resolve_profile("shared", Some(ServiceType::Mysql))
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("duplicate alias"),
        "unexpected error: {error}"
    );
}

#[test]
fn test_profile_routing_errors_do_not_echo_unsafe_input() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("unsafe.toml");
    fs::write(
        &config_path,
        r#"
[profiles.one]
type = "mysql"
aliases = [" \nSYSTEM_INJECTION "]
"#,
    )
    .unwrap();
    let config = ConfigLoader::load_toml_file(&config_path).unwrap();

    let alias_error = config
        .resolve_profile("missing", Some(ServiceType::Mysql))
        .unwrap_err()
        .to_string();
    assert!(
        !alias_error.contains("SYSTEM_INJECTION"),
        "unsafe alias leaked into error: {alias_error}"
    );

    let request_error = config
        .resolve_profile("REQUEST\nINJECTION", Some(ServiceType::Pgsql))
        .unwrap_err()
        .to_string();
    assert!(
        !request_error.contains("REQUEST") && !request_error.contains("INJECTION"),
        "unsafe request leaked into error: {request_error}"
    );
}
