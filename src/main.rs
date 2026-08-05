use clap::Parser;
use tokio::runtime::{Builder, Runtime};
use tools4a::cli::{Cli, CliHandler};
use tools4a::mcp;

const DEFAULT_WORKER_THREADS: usize = 8;

fn build_runtime() -> std::io::Result<Runtime> {
    Builder::new_multi_thread()
        .worker_threads(DEFAULT_WORKER_THREADS)
        .enable_all()
        .build()
}

fn main() {
    let runtime = match build_runtime() {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("Error: failed to build Tokio runtime: {e}");
            std::process::exit(1);
        }
    };

    runtime.block_on(run());
}

async fn run() {
    let cli = Cli::parse();

    let result = if cli.command.is_none() {
        // No subcommand -> run MCP server over stdio.
        mcp::serve_stdio().await
    } else {
        CliHandler::handle(cli).await
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_runtime_uses_eight_worker_threads() {
        let runtime = build_runtime().expect("runtime should build");

        assert_eq!(runtime.metrics().num_workers(), 8);
    }
}
