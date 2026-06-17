//! Top-level entry: run one agent-browser invocation and return the
//! structured result. No tunnel handling here — `BrowserOrchestrator`
//! resolves the tunnel layer stack and injects `--proxy socks5://...`
//! into the request before calling this.

use tools4a_core::{ExecutionResult, Result};

use crate::exec::{BrowserExec, output_to_result};
use crate::request::BrowserRequest;

pub async fn execute(req: BrowserRequest) -> Result<ExecutionResult> {
    let out = BrowserExec::run(req).await?;
    Ok(output_to_result(out))
}
