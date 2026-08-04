//! ClickHouse stack: HTTP-based connection + executor primitives, the
//! `ClickhouseOrchestrator` `Service` impl, and the `ClickhouseMcp`
//! `McpTool` impl.
//!
//! Talks to ClickHouse's HTTP interface (default port 8123). HTTPS is
//! out of scope for v1.

pub mod connection;
pub mod execute;
pub mod executor;
pub mod mcp;
pub mod orchestrator;

pub use connection::ClickhouseConnection;
pub use execute::{ClickhouseParams, execute};
pub use executor::ClickhouseExecutor;
pub use mcp::{ClickhouseExecParams, ClickhouseMcp};
pub use orchestrator::{ClickhouseOrchestrator, ClickhouseRequest};
