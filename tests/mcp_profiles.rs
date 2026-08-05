use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::TempDir;

fn binary_path() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_tools4a"))
}

fn call_profiles_list(config: &str) -> String {
    let config_home = TempDir::new().unwrap();
    let tools4a_dir = config_home.path().join("tools4a");
    std::fs::create_dir(&tools4a_dir).unwrap();
    std::fs::write(tools4a_dir.join("config.toml"), config).unwrap();

    let mut child = Command::new(binary_path())
        .env("XDG_CONFIG_HOME", config_home.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn tools4a");

    let mut stdin = child.stdin.take().expect("no stdin");
    let stdout = child.stdout.take().expect("no stdout");
    let mut reader = BufReader::new(stdout);

    let initialize = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"profiles-test","version":"0.0.1"}}}"#;
    writeln!(stdin, "{initialize}").unwrap();
    let initialized = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
    writeln!(stdin, "{initialized}").unwrap();
    let call = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"profiles_list","arguments":{}}}"#;
    writeln!(stdin, "{call}").unwrap();
    stdin.flush().unwrap();

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut response = String::new();
    while Instant::now() < deadline {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap() == 0 {
            break;
        }
        if line.contains("\"id\":2") {
            response = line;
            break;
        }
    }

    drop(stdin);
    let _ = child.kill();
    let _ = child.wait();
    response
}

#[test]
fn profiles_list_returns_only_safe_profile_metadata() {
    let response = call_profiles_list(
        r#"
[profiles.orders]
type = "mysql"
aliases = ["prod", "orders-ro"]
host = "HOST_SENTINEL"
user = "USER_SENTINEL"
password = "PASSWORD_SENTINEL"
database = "DATABASE_SENTINEL"
key_path = "/KEY_SENTINEL"

[profiles.unsupported]
type = "ssh"
aliases = ["host-shell"]
"#,
    );

    assert!(
        response.contains("orders"),
        "missing profile name: {response}"
    );
    assert!(
        response.contains("mysql"),
        "missing service type: {response}"
    );
    assert!(response.contains("prod"), "missing aliases: {response}");
    assert!(
        !response.contains("unsupported") && !response.contains("host-shell"),
        "profiles_list exposed a service without profile support: {response}"
    );
    for sentinel in [
        "HOST_SENTINEL",
        "USER_SENTINEL",
        "PASSWORD_SENTINEL",
        "DATABASE_SENTINEL",
        "/KEY_SENTINEL",
    ] {
        assert!(
            !response.contains(sentinel),
            "profiles_list leaked {sentinel}: {response}"
        );
    }
}

#[test]
fn profiles_list_redacts_malformed_config_errors() {
    let response = call_profiles_list(
        r#"
[profiles.orders]
type = "mysql"
password = "PASSWORD_SENTINEL
"#,
    );

    assert!(
        response.contains("profile registry is invalid or unreadable"),
        "missing safe error: {response}"
    );
    for forbidden in ["PASSWORD_SENTINEL", "config.toml", "/tmp/"] {
        assert!(
            !response.contains(forbidden),
            "profiles_list leaked malformed config detail '{forbidden}': {response}"
        );
    }
}
