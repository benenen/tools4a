//! Top-level entry: build (optional) SSH jump chain, open final SSH
//! session to the target with target credentials, exec the command,
//! map the output to an ExecutionResult.

use russh::client;
use std::sync::Arc;
use tokio::sync::Mutex;
use tools4a_core::{Error, ExecutionResult, Result};

use crate::exec::{SshExec, output_to_result};
use crate::request::{SshExecRequest, SshJumpsConfig};
use tools4a_core::session::{AcceptAnyHostKey, authenticate, build_session_chain};

/// Run a single shell command on the SSH target described by `req`,
/// optionally going through `jumps`. Always tears down the chain via Drop
/// before returning.
///
/// `connect_addr_override` (used by the Phase 19-follow-up SOCKS5 path) redirects the
/// final TCP dial — when `Some((host, port))` AND `jumps` is empty, russh
/// connects to `(host, port)` instead of `(req.host, req.port)`. The
/// host-key warning label still uses `req.host`, so users see the real
/// target name (not `127.0.0.1`).
pub async fn execute(
    req: SshExecRequest,
    jumps: Option<SshJumpsConfig>,
    connect_addr_override: Option<(String, u16)>,
) -> Result<ExecutionResult> {
    let cfg = std::sync::Arc::new(client::Config::default());

    // Build the jump chain (if any). Returns the last jump's session.
    let mut jump_sessions = match &jumps {
        Some(j) if !j.jumps.is_empty() => {
            build_session_chain(
                &j.jumps,
                &j.user,
                j.password.as_deref(),
                j.key_path.as_deref(),
                j.port,
            )
            .await?
        }
        _ => Vec::new(),
    };

    // Open the FINAL SSH session to the target. If we have a jump chain,
    // open a direct-tcpip channel from the last jump and run SSH over it
    // (with TARGET's credentials, not the jump credentials). Otherwise
    // TCP-connect — to the override addr if one was supplied (SOCKS5
    // path), else directly to the target. The host-key label always uses
    // req.host so the stderr fingerprint warning names the real target.
    let target_handler = AcceptAnyHostKey {
        label: req.host.clone(),
    };
    let mut target_session = if let Some(last_jump) = jump_sessions.last() {
        let channel = last_jump
            .lock()
            .await
            .channel_open_direct_tcpip(req.host.clone(), req.port as u32, "127.0.0.1", 0u32)
            .await
            .map_err(|e| {
                Error::Connection(format!(
                    "open direct-tcpip to {}:{} via last jump failed: {e}",
                    req.host, req.port
                ))
            })?;
        let stream = Box::pin(channel.into_stream());
        client::connect_stream(cfg, stream, target_handler)
            .await
            .map_err(|e| {
                Error::Connection(format!("SSH connect to {} (chained) failed: {e}", req.host))
            })?
    } else {
        let (dial_host, dial_port) = match &connect_addr_override {
            Some((h, p)) => (h.as_str(), *p),
            None => (req.host.as_str(), req.port),
        };
        client::connect(cfg, (dial_host, dial_port), target_handler)
            .await
            .map_err(|e| Error::Connection(format!("SSH connect to {} failed: {e}", req.host)))?
    };

    // Authenticate with TARGET's creds (not the jump creds).
    authenticate(
        &mut target_session,
        &req.user,
        req.password.as_deref(),
        req.key_path.as_deref(),
    )
    .await?;

    let target_session = Arc::new(Mutex::new(target_session));

    // Exec the command.
    let result = SshExec::run(target_session.clone(), &req.command).await;

    // Drop the target session and the jump chain (Drop closes the
    // underlying channels/connections).
    drop(target_session);
    jump_sessions.clear();

    Ok(output_to_result(result?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::SshExecRequest;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    /// `connect_addr_override` must:
    ///  1. Cause the TCP dial to land on the override address.
    ///  2. Keep `req.host` in error messages (host-key label preserved).
    #[tokio::test]
    async fn connect_addr_override_redirects_dial_but_keeps_host_label() {
        // Fake listener that signals on accept then closes the connection
        // with a non-SSH banner so russh's handshake fails fast.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fake_addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let _ = tx.send(());
                let _ = sock.write_all(b"NOT-SSH\r\n").await;
            }
        });

        let req = SshExecRequest {
            host: "fake-target-host.invalid".to_string(),
            port: 12345,
            user: "u".to_string(),
            password: Some("pw".to_string()),
            key_path: None,
            command: "true".to_string(),
            timeout_secs: None,
            max_timeout_secs: None,
        };

        let result = execute(
            req,
            None,
            Some((fake_addr.ip().to_string(), fake_addr.port())),
        )
        .await;

        // (1) Dial reached the override listener.
        tokio::time::timeout(Duration::from_secs(2), rx)
            .await
            .expect("override dial never reached the listener")
            .expect("listener task dropped tx without sending");

        // (2) Error preserves the original host name and does NOT leak the
        // override addr.
        let err = result.expect_err("non-SSH banner must fail the handshake");
        let msg = format!("{err}");
        assert!(
            msg.contains("fake-target-host.invalid"),
            "error should reference req.host; got: {msg}"
        );
        assert!(
            !msg.contains(&fake_addr.ip().to_string()),
            "error must not leak override host; got: {msg}"
        );
    }
}
