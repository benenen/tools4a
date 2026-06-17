//! Top-level entry: open the final SSH session to the target over a
//! pre-connected transport stream (the connector chain handles all jump /
//! socks5 layers), authenticate with target credentials, exec the command,
//! map the output to an ExecutionResult.

use russh::client;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::Mutex;
use tools4a_core::tunnel::Stream;
use tools4a_core::{Error, ExecutionResult, Result};

use crate::exec::{SshExec, output_to_result};
use crate::request::SshExecRequest;
use tools4a_core::session::{AcceptAnyHostKey, authenticate};

/// Run a single shell command on the SSH target described by `req`, over the
/// already-connected transport `stream`. The caller (orchestrator) builds the
/// transport via the connector chain (`build_connector(&cfg.layers).connect(
/// &req.host, req.port)`), which transparently folds in any SOCKS5 / SSH-jump
/// layers; here we just run the final SSH session on top of it.
///
/// The host-key warning label uses `req.host`, so users see the real target
/// name even when the stream rode through a chain.
pub async fn execute(req: SshExecRequest, stream: Pin<Box<dyn Stream>>) -> Result<ExecutionResult> {
    let cfg = std::sync::Arc::new(client::Config::default());

    let target_handler = AcceptAnyHostKey {
        label: req.host.clone(),
    };
    let mut target_session = client::connect_stream(cfg, stream, target_handler)
        .await
        .map_err(|e| Error::Connection(format!("SSH connect to {} failed: {e}", req.host)))?;

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

    // Drop the target session (Drop closes the underlying channels).
    drop(target_session);

    Ok(output_to_result(result?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::SshExecRequest;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;
    use tools4a_core::tunnel::build_connector;

    /// Running the session over a stream produced by the connector chain
    /// must keep `req.host` in error messages (host-key label preserved),
    /// even when the underlying dial landed on a different address.
    #[tokio::test]
    async fn session_over_connector_stream_keeps_host_label() {
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

        // A direct (empty-layer) connector dialing the fake listener stands
        // in for "the connector reached the target on some address".
        let connector = build_connector(&[]);
        let stream = connector
            .connect(&fake_addr.ip().to_string(), fake_addr.port())
            .await
            .expect("dial fake listener");

        let result = execute(req, stream).await;

        // (1) Dial reached the listener.
        tokio::time::timeout(Duration::from_secs(2), rx)
            .await
            .expect("dial never reached the listener")
            .expect("listener task dropped tx without sending");

        // (2) Error preserves the original host name (host-key label).
        let err = result.expect_err("non-SSH banner must fail the handshake");
        let msg = format!("{err}");
        assert!(
            msg.contains("fake-target-host.invalid"),
            "error should reference req.host; got: {msg}"
        );
    }
}
