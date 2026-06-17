//! SOCKS5 building blocks shared across the layer stack. The `codec`
//! sub-module is pure (bytes in → bytes out, no IO). The `client`
//! module holds the shared SOCKS5 client handshake used by
//! `Socks5Connector`. The `connector` and `server` modules provide
//! the `Connector` trait and `Socks5Server::serve_one` used by
//! `LayeredTunnel` when the forward target is `ForwardTarget::Socks5Server`.

pub(crate) mod client;
pub mod codec;
pub mod connector;
pub mod server;

pub use codec::{
    ReplyCode, Request, parse_greeting, parse_request, write_greeting_reply, write_request_reply,
};
pub use connector::{Connector, SshConnector, Stream};
pub use server::Socks5Server;
