//! End-to-end smoke test that runs the binary with no subcommand
//! (which boots the MCP server) and exchanges a minimal JSON-RPC
//! handshake over its stdio. Verifies that `mysql_exec` shows up in
//! `tools/list`.
//!
//! Transport framing: newline-delimited JSON (one JSON object per line),
//! confirmed from rmcp 1.6 `src/transport/async_rw.rs` which uses a
//! newline-scanning codec — NOT Content-Length framing.

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::time::Duration;

fn binary_path() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_tools4a"))
}

#[test]
fn test_mcp_lists_mysql_exec_tool() {
    let mut child = Command::new(binary_path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn tools4a");

    let mut stdin = child.stdin.take().expect("no stdin");
    let stdout = child.stdout.take().expect("no stdout");
    let stderr = child.stderr.take().expect("no stderr");
    let mut reader = BufReader::new(stdout);

    // Framing: newline-delimited JSON (rmcp 1.6 stdio transport).
    // Protocol version "2024-11-05" is explicitly accepted per rmcp model.rs.
    let initialize = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke-test","version":"0.0.1"}}}"#;
    writeln!(stdin, "{initialize}").unwrap();

    let initialized = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
    writeln!(stdin, "{initialized}").unwrap();

    let list_tools = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#;
    writeln!(stdin, "{list_tools}").unwrap();
    stdin.flush().unwrap();

    let mut list_response = String::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        let mut line = String::new();
        let n = reader.read_line(&mut line).unwrap();
        if n == 0 {
            break;
        }
        if line.contains("\"id\":2") {
            list_response = line;
            break;
        }
    }

    drop(stdin);
    let _ = child.wait_timeout(Duration::from_secs(5));
    let _ = child.kill();

    if list_response.is_empty() {
        // Capture stderr for diagnosis.
        let mut err_buf = String::new();
        std::io::Read::read_to_string(&mut BufReader::new(stderr), &mut err_buf).ok();
        eprintln!("---child stderr---\n{err_buf}\n---end---");
    }

    let response: serde_json::Value =
        serde_json::from_str(&list_response).expect("tools/list returned invalid JSON");
    let tools = response["result"]["tools"]
        .as_array()
        .expect("tools/list result missing tools array");
    let names = tools
        .iter()
        .map(|tool| tool["name"].as_str().unwrap().to_string())
        .collect::<BTreeSet<_>>();
    let expected = [
        "profiles_list",
        "mysql_exec",
        "pgsql_exec",
        "clickhouse_exec",
        "redis_exec",
        "mongo_exec",
        "http_exec",
        "ssh_exec",
        "browser_exec",
        "docker_ps",
        "docker_inspect",
        "docker_logs",
        "docker_stats",
        "docker_top",
        "docker_exec",
        "docker_restart",
        "milvus_list_databases",
        "milvus_list_collections",
        "milvus_describe_collection",
        "milvus_collection_stats",
        "milvus_list_partitions",
        "milvus_query",
        "milvus_search",
        "milvus_drop_collection",
        "milvus_load_collection",
        "milvus_release_collection",
        "rabbitmq_list_queues",
        "rabbitmq_queue_info",
        "rabbitmq_get_messages",
        "rabbitmq_list_bindings",
        "rabbitmq_overview",
    ]
    .into_iter()
    .map(str::to_string)
    .collect::<BTreeSet<_>>();
    assert_eq!(tools.len(), 31, "unexpected duplicate or missing MCP tool");
    assert_eq!(names, expected);

    let mysql = tools
        .iter()
        .find(|tool| tool["name"] == "mysql_exec")
        .expect("tools/list missing mysql_exec");
    let description = mysql["description"].as_str().unwrap();
    for phrase in [
        "profiles_list",
        "profile name or alias",
        "ssh_exec",
        "docker_exec",
    ] {
        assert!(
            description.contains(phrase),
            "mysql_exec description missing '{phrase}': {description}"
        );
    }
    let profile_description = mysql["inputSchema"]["properties"]["profile"]["description"]
        .as_str()
        .expect("mysql_exec profile schema is missing a description");
    for phrase in ["name or alias", "profiles_list"] {
        assert!(
            profile_description.contains(phrase),
            "profile schema description missing '{phrase}': {profile_description}"
        );
    }
}

trait WaitTimeoutExt {
    fn wait_timeout(&mut self, dur: Duration) -> Option<std::process::ExitStatus>;
}

impl WaitTimeoutExt for std::process::Child {
    fn wait_timeout(&mut self, dur: Duration) -> Option<std::process::ExitStatus> {
        let deadline = std::time::Instant::now() + dur;
        while std::time::Instant::now() < deadline {
            match self.try_wait() {
                Ok(Some(status)) => return Some(status),
                Ok(None) => std::thread::sleep(Duration::from_millis(50)),
                Err(_) => return None,
            }
        }
        None
    }
}
