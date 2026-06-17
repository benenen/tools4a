//! Shared SOCKS5 *client* handshake — greeting → optional userpass auth →
//! CONNECT — over any AsyncRead+AsyncWrite stream. Used by the
//! layer-stack `Socks5Connector` (in `chain.rs`).

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::codec::{
    METHOD_NO_AUTH, METHOD_USERPASS, connect_reply_body_len, parse_connect_reply,
    parse_greeting_reply, parse_userpass_reply, write_client_greeting, write_connect_request,
    write_userpass_auth,
};
use crate::{Error, Result};

/// SOCKS5 client handshake. On return, `outbound` is ready for application bytes.
pub(crate) async fn handshake_and_connect<S>(
    outbound: &mut S,
    user: Option<&str>,
    pass: Option<&str>,
    target_host: &str,
    target_port: u16,
) -> Result<()>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let userpass = user.is_some() && pass.is_some();

    // --- Greeting ---
    outbound
        .write_all(&write_client_greeting(userpass))
        .await
        .map_err(Error::Io)?;
    let mut greet_reply = [0u8; 2];
    outbound
        .read_exact(&mut greet_reply)
        .await
        .map_err(Error::Io)?;
    let method = parse_greeting_reply(&greet_reply)?;

    // --- Optional auth subnegotiation ---
    match method {
        METHOD_NO_AUTH => {}
        METHOD_USERPASS => {
            let (u, p) = match (user, pass) {
                (Some(u), Some(p)) => (u, p),
                _ => {
                    return Err(Error::Service(
                        "SOCKS5 proxy chose user/pass auth but no credentials were provided".into(),
                    ));
                }
            };
            outbound
                .write_all(&write_userpass_auth(u, p)?)
                .await
                .map_err(Error::Io)?;
            let mut auth_reply = [0u8; 2];
            outbound
                .read_exact(&mut auth_reply)
                .await
                .map_err(Error::Io)?;
            parse_userpass_reply(&auth_reply)?;
        }
        other => {
            return Err(Error::Service(format!(
                "SOCKS5 proxy chose unsupported auth method 0x{other:02x}"
            )));
        }
    }

    // --- CONNECT ---
    outbound
        .write_all(&write_connect_request(target_host, target_port)?)
        .await
        .map_err(Error::Io)?;
    // Read VER REP RSV ATYP (4 bytes), then ATYP-dependent BND length + 2 port bytes.
    let mut head = [0u8; 5];
    outbound.read_exact(&mut head).await.map_err(Error::Io)?;
    let atyp = head[3];
    let first_addr_byte = head[4];
    let body_len = connect_reply_body_len(atyp, first_addr_byte).ok_or_else(|| {
        Error::Service(format!(
            "SOCKS5 connect reply: unsupported ATYP 0x{atyp:02x}"
        ))
    })?;
    let mut full = Vec::with_capacity(5 + body_len);
    full.extend_from_slice(&head);
    full.resize(5 + body_len, 0);
    outbound
        .read_exact(&mut full[5..])
        .await
        .map_err(Error::Io)?;
    parse_connect_reply(&full)?;
    Ok(())
}
