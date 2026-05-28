//! BrowserOrchestrator — `Service` impl for the browser tool.
//!
//! Tunnel behavior:
//!   - None / Direct: spawn agent-browser as-is.
//!   - Ssh: build a SocksTunnel (server-side SOCKS5 over the SSH chain),
//!     inject `--proxy socks5://<local-endpoint>` into the request, then
//!     run; tear the tunnel down on exit.
//!   - Socks5: skip the local hop entirely. agent-browser already speaks
//!     SOCKS5 natively, so we just format `socks5://[user:pass@]host:port`
//!     directly into the request. No tunnel object to manage.

use async_trait::async_trait;
use tools4a_core::{Error, ExecutionResult, Result, Service, SocksTunnel, Tunnel, TunnelConfig};

use crate::execute::execute;
use crate::request::BrowserRequest;

pub struct BrowserOrchestrator;

/// Percent-encode userinfo for use inside a `socks5://user:pass@host:port` URL.
/// Only the characters that would break URL parsing in this position (`:` `@`
/// `/` `?` `#` `%` + space + control chars) are escaped. ASCII alnum and the
/// RFC 3986 "unreserved" set pass through untouched.
fn percent_encode_userinfo(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        let pass = matches!(b,
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'
            | b'-' | b'.' | b'_' | b'~'
        );
        if pass {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Build the `socks5://[user:pass@]host:port` URL that agent-browser
/// consumes via its `--proxy` flag. Userinfo is percent-encoded so creds
/// containing `:` `@` `/` etc. don't break URL parsing on the receiving end.
pub(crate) fn format_socks5_url(
    host: &str,
    port: u16,
    user: Option<&str>,
    pass: Option<&str>,
) -> String {
    match (user, pass) {
        (Some(u), Some(p)) => format!(
            "socks5://{}:{}@{}:{}",
            percent_encode_userinfo(u),
            percent_encode_userinfo(p),
            host,
            port
        ),
        _ => format!("socks5://{host}:{port}"),
    }
}

#[async_trait]
impl Service for BrowserOrchestrator {
    type Request = BrowserRequest;

    async fn execute(
        mut req: Self::Request,
        tunnel: Option<TunnelConfig>,
    ) -> Result<ExecutionResult> {
        match tunnel {
            None | Some(TunnelConfig::Direct) => execute(req).await,
            Some(TunnelConfig::Ssh { ssh_jumps }) => {
                if req.proxy.is_some() {
                    return Err(Error::Config(
                        "tunnel=ssh and an explicit `proxy` field conflict: \
                         tools4a injects `--proxy socks5://...` when ssh is set. \
                         Pick one — drop `proxy` and let tools4a do it, or use \
                         tunnel=direct + your own proxy."
                            .into(),
                    ));
                }

                let mut t = SocksTunnel::new(ssh_jumps)?;
                let endpoint = t.establish().await?;
                req.proxy = Some(format!("socks5://{}:{}", endpoint.host, endpoint.port));

                let result = execute(req).await;

                // Tear down regardless of outcome. Errors here don't
                // override the execute() result; the call already
                // happened, so the user-facing outcome is whatever
                // execute returned.
                if let Err(e) = t.close().await {
                    eprintln!("BrowserOrchestrator: SocksTunnel close: {e}");
                }
                result
            }
            Some(TunnelConfig::Socks5 {
                socks5_host,
                socks5_port,
                socks5_user,
                socks5_password,
            }) => {
                if req.proxy.is_some() {
                    return Err(Error::Config(
                        "tunnel=socks5 and an explicit `proxy` field conflict: \
                         tools4a injects `--proxy socks5://...` when socks5 tunnel \
                         is set. Pick one — drop `proxy` and let tools4a do it, or \
                         use tunnel=direct + your own proxy."
                            .into(),
                    ));
                }
                req.proxy = Some(format_socks5_url(
                    &socks5_host,
                    socks5_port,
                    socks5_user.as_deref(),
                    socks5_password.as_deref(),
                ));
                execute(req).await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req() -> BrowserRequest {
        BrowserRequest {
            subcommand: "snapshot".into(),
            args: Vec::new(),
            session: None,
            proxy: None,
            proxy_bypass: None,
            browser_args: None,
            bin: Some(std::path::PathBuf::from("/nonexistent/ab")),
        }
    }

    #[tokio::test]
    async fn errors_when_user_proxy_conflicts_with_ssh_tunnel() {
        use tools4a_core::JumpHop;
        let mut r = req();
        r.proxy = Some("socks5://example.com:1080".into());
        let err = BrowserOrchestrator::execute(
            r,
            Some(TunnelConfig::Ssh {
                ssh_jumps: vec![JumpHop {
                    host: "bastion.example.com".to_string(),
                    user: "admin".to_string(),
                    password: None,
                    key_path: None,
                    port: 22,
                }],
            }),
        )
        .await
        .unwrap_err();
        match err {
            Error::Config(m) => {
                assert!(m.contains("conflict"), "got: {m}");
                assert!(m.contains("socks5"), "got: {m}");
            }
            other => panic!("got {other:?}"),
        }
    }

    #[tokio::test]
    async fn accepts_none_tunnel() {
        // Delegates to execute, which delegates to BrowserExec; the
        // missing binary surfaces as Error::Config "not found",
        // confirming the guard didn't short-circuit.
        let err = BrowserOrchestrator::execute(req(), None).await.unwrap_err();
        match err {
            Error::Config(m) => assert!(m.contains("not found"), "got: {m}"),
            other => panic!("expected Config, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn errors_when_user_proxy_conflicts_with_socks5_tunnel() {
        let mut r = req();
        r.proxy = Some("socks5://example.com:1080".into());
        let err = BrowserOrchestrator::execute(
            r,
            Some(TunnelConfig::Socks5 {
                socks5_host: "p".into(),
                socks5_port: 1080,
                socks5_user: None,
                socks5_password: None,
            }),
        )
        .await
        .unwrap_err();
        match err {
            Error::Config(m) => {
                assert!(m.contains("conflict"), "got: {m}");
                assert!(m.contains("socks5"), "got: {m}");
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn socks5_url_no_auth() {
        assert_eq!(
            format_socks5_url("192.0.2.10", 2235, None, None),
            "socks5://192.0.2.10:2235"
        );
    }

    #[test]
    fn socks5_url_with_simple_auth() {
        assert_eq!(
            format_socks5_url("p", 1080, Some("alice"), Some("s3cret")),
            "socks5://alice:s3cret@p:1080"
        );
    }

    #[test]
    fn socks5_url_percent_encodes_special_chars_in_userinfo() {
        // ':' '@' '/' '%' and space all need escaping in userinfo. Letters
        // and digits pass through; '-' '.' '_' '~' are RFC 3986 unreserved.
        assert_eq!(
            format_socks5_url("p", 1080, Some("us:er"), Some("p@/w%d")),
            "socks5://us%3Aer:p%40%2Fw%25d@p:1080"
        );
    }

    #[test]
    fn socks5_url_user_without_pass_emits_no_userinfo() {
        // Defensive: at the orchestrator-input level the validation layer
        // should have rejected this; format_socks5_url falls back to the
        // no-auth shape rather than emitting "socks5://alice@p:1080" with
        // a half-formed userinfo.
        assert_eq!(
            format_socks5_url("p", 1080, Some("alice"), None),
            "socks5://p:1080"
        );
    }
}
