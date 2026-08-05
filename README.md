# tools4a

Unified CLI + MCP (Model Context Protocol) tool for MySQL, PostgreSQL, ClickHouse, Redis, MongoDB, HTTP, SSH, and Browser — with composable SSH + SOCKS5 tunnels.

## Features

- **CLI Mode**: Execute commands directly from the command line
- **MCP Mode**: Run as an MCP server for AI assistant integration
- **Configuration**: Support for TOML profiles and YAML config files
- **SSH Jump Host**: Access internal services through bastion hosts

## Status

This is the Phase 21 release. Currently implemented:

- All eight service orchestrators (`MysqlOrchestrator`, `PgsqlOrchestrator`, `ClickhouseOrchestrator`, `RedisOrchestrator`, `MongoOrchestrator`, `HttpOrchestrator`, `SshDirectOrchestrator`, `BrowserOrchestrator`) impl the `tools4a_core::Service` trait, defined as `async fn execute(Self::Request, Option<TunnelConfig>) -> Result<ExecutionResult>`. Each lives in its own leaf crate (`tools4a-mysql`, `tools4a-pgsql`, …) alongside the corresponding `<Svc>Mcp` impl of `tools4a_core::McpTool`.
- MySQL CLI mode (`tools4a mysql "..."`) and `mysql_exec` MCP tool.
- PostgreSQL CLI mode (`tools4a pgsql "..."`) and `pgsql_exec` MCP tool.
- **ClickHouse CLI mode** (`tools4a clickhouse "..."`) and `clickhouse_exec` MCP tool — SQL over the HTTP interface (default port 8123).
- Redis CLI mode (`tools4a redis "..."`) and `redis_exec` MCP tool.
- MongoDB CLI mode (`tools4a mongo '{"find":"coll","filter":{}}'`) and `mongo_exec` MCP tool — JSON document passed to `Database::run_command`.
- HTTP CLI mode (`tools4a http GET https://...`) and `http_exec` MCP tool.
- SSH-direct CLI mode (`tools4a ssh "..."`) and `ssh_exec` MCP tool —
  run a shell command on a target SSH server, optionally through SSH jump hosts.
- **Browser CLI mode** (`tools4a browser <SUBCOMMAND> [ARGS]...`) and `browser_exec` MCP tool — thin wrapper around the externally-installed [`agent-browser`](https://github.com/vercel-labs/agent-browser) binary (operator installs it separately). Any SSH-containing layer stack stands up a `LayeredTunnel` with `ForwardTarget::Socks5Server` and injects `--proxy socks5://127.0.0.1:<rand>` automatically; a pure-SOCKS5 stack short-circuits to `--proxy socks5://…` directly without a local relay.
- Configuration via YAML file (`--config=PATH`) or TOML profile (`--profile=NAME`)
  for MySQL, PostgreSQL, ClickHouse, Redis, and MongoDB. (HTTP, SSH-direct, and Browser profile/YAML not yet supported.)
- **Composable tunnel layer stack (Phase 21)** — `TunnelConfig` is now `struct { layers: Vec<TunnelLayer> }` (ordered local→target); `TunnelLayer` is either `Socks5 { host, port, user?, password? }` or `SshHop(JumpHop)`. Empty `layers` = direct. One generic `LayeredTunnel` (`impl Tunnel`) driven by `build_connector(&[TunnelLayer])` folds the layers (`TcpConnector` base → each layer wraps the inner connector); SSH layers cache their session in a `OnceCell` (one `direct-tcpip` channel per client connection → multi-client without head-of-line blocking). The old per-shape impls (`DirectTunnel`, `SshTunnel`, `Socks5ClientTunnel`, `SocksTunnel`, `StreamLocalTunnel`) have been removed.
- Direct connection (no `--hop`/`--tunnel`, or `--tunnel=direct`).
- SSH tunnel (`--tunnel=ssh`) with single- or multi-hop jump (`--ssh-jump=h1[,h2,...]`),
  password or key auth. Host keys accepted with a fingerprint warning.
  Works for all eight services through the unified `LayeredTunnel`/`build_connector` layer model.
- External SOCKS5 proxy (`--tunnel=socks5 --socks5-host=H --socks5-port=P [--socks5-user=U --socks5-password=W]`, default port 1080, RFC 1929 user/pass auth). All services route through the `LayeredTunnel` connector chain. Browser short-circuits a pure-SOCKS5 stack by passing `socks5://[user:pass@]host:port` directly to agent-browser's `--proxy`. `ssh` no longer errors on `--tunnel=socks5` (it routes through the layer chain). `docker` errors only when a non-empty stack does not end in an SSH hop (a `[Socks5, SshHop]` underlay is valid; socks5-only still errors for docker since streamlocal needs an SSH tail).
- **Composable `--hop` flag (Phase 21)** — repeatable, ordered, URL-form. Mutually exclusive with legacy `--tunnel`/`--ssh-*`/`--socks5-*`; legacy flags still work and are lowered to layers. `--tunnel=ssh` + `--socks5-*` now composes (SOCKS5 underlay + SSH hop) instead of being an error.
- **`tunnel_layers` MCP field (Phase 21)** — ordered JSON array of `{type:"socks5"|"ssh", host, port, user?, password?, key_path?}`. Conflicts with legacy `tunnel`/`ssh_jump`/`ssh_*`/`socks5_*` fields.
- MCP server mode (`tools4a` with no subcommand) over stdio. SQL tools (mysql/pgsql/clickhouse) and HTTP tool return a second `Content::resource` (MCP App UI, MIME `text/html`) alongside the JSON text — clients without MCP Apps support ignore it.

Not yet implemented:
- SSH key passphrases, strict known_hosts verification
- SSH PTY allocation (interactive commands like `top` won't work)
- HTTP / SSH-direct / Browser profile/YAML config
- HTTP/SSE MCP transport (the SERVER's transport)
- Redis cluster routing, pub/sub, transactions, scripting (EVAL)
- Per-Value typed mapping for RESP3 `Map` / `Set` / `Push`
- SCP/SFTP file transfer

## Installation

Build a release binary and install it on `PATH`:

```bash
cargo install --path .
# or, for an unpublished build:
cargo build --release && cp target/release/tools4a ~/.local/bin/
```

`cargo install --path .` puts the binary at
`~/.cargo/bin/tools4a`, which is on `PATH` by default after a normal
Rust toolchain install.

This repo is a Cargo workspace. The `tools4a` binary crate lives at
the repo root (presentation layer only). The lib crates under `crates/`
are: `tools4a-core` (everything shared — trait floor + `LayeredTunnel`
+ `build_connector` + `ForwardTarget` + `build_tunnel` + Config/Profile
/Loader/Merger + SSH `session` chain helpers + `McpTool` trait), and
the eight leaf service crates `tools4a-mysql` / `tools4a-pgsql` /
`tools4a-clickhouse` / `tools4a-redis` / `tools4a-mongo` /
`tools4a-http` / `tools4a-ssh` / `tools4a-browser`.
Each leaf crate owns its full vertical slice: protocol primitives,
the `<Svc>Orchestrator: impl Service`, and the `<Svc>Mcp: impl
McpTool`. Every leaf depends only on `tools4a-core`. `cargo build`
/ `cargo test` from the root build and test all of them.

## Usage

### Read-only by default (mysql, pgsql, mongo)

The `mysql`, `pgsql`, and `mongo` subcommands (and their MCP equivalents)
**reject write operations by default**. Use `--allow-write`
(`allow_write: true` in MCP) to opt in.

| Service | Reads (always allowed)                    | Writes (need `--allow-write`)                                 |
| ------- | ----------------------------------------- | ------------------------------------------------------------- |
| mysql   | `SELECT`, `SHOW`, `EXPLAIN`, `DESCRIBE`, `WITH`, `VALUES`, `TABLE` | `INSERT`, `UPDATE`, `DELETE`, `REPLACE`, `CREATE`, `DROP`, `ALTER`, `TRUNCATE`, `GRANT`, `CALL`, `SET`, … |
| pgsql   | same as mysql                             | same as mysql, plus `COPY`, `VACUUM`, `ANALYZE`, etc.         |
| mongo   | `find`, `aggregate` (no `$out`/`$merge`), `count`, `distinct`, `listCollections`, `listDatabases`, `listIndexes`, `dbStats`, `collStats`, `serverStatus`, `ping`, `hello`, `buildInfo`, `getParameter`, … | `insert`, `update`, `delete`, `findAndModify`, `drop`, `create`, `createIndexes`, `aggregate` with `$out` / `$merge`, … |

For mysql + pgsql, when `--allow-write` is **not** set, the session is
also forced into a DB-level read-only mode (`SET SESSION TRANSACTION
READ ONLY` / `SET default_transaction_read_only = on`) as a second line
of defense — so a misclassified write will still be rejected by the
database itself. Mongo has no per-session read-only mode, so the
orchestrator-level command whitelist is the only guard.

Redis, HTTP, and SSH are **not** restricted — they accept any command
without `--allow-write`.

### MySQL

```bash
# Direct connection (read-only by default)
tools4a mysql "SELECT * FROM users" --host=localhost --user=root --password=not-a-real-password

# Write — requires --allow-write
tools4a mysql "INSERT INTO users (name) VALUES ('alice')" \
  --host=localhost --user=root --password=not-a-real-password --allow-write

# Using YAML config
tools4a --config=mysql.yaml mysql "SELECT * FROM users"

# Using TOML profile
tools4a mysql "SELECT * FROM users" --profile=prod

# Through a single SSH jump
tools4a --tunnel=ssh --ssh-jump=bastion.example.invalid --ssh-user=admin --ssh-password=not-a-real-jump-password \
  mysql --host=mysql.example.invalid --user=root --password=not-a-real-db-password "SELECT 1"

# Through two SSH jumps (comma-separated; all share --ssh-user/--ssh-password)
tools4a --tunnel=ssh --ssh-jump=bastion1.example.invalid,bastion2.example.invalid --ssh-user=admin \
  --ssh-key-path=/path/to/not-a-real-jump-key \
  mysql --host=mysql.example.invalid --user=root --password=not-a-real-db-password "SELECT 1"

# Through an external SOCKS5 proxy
tools4a --tunnel=socks5 --socks5-host=192.0.2.10 --socks5-port=2235 \
  mysql --host=mysql.example.invalid --user=root --password=not-a-real-db-password "SELECT 1"

# Through an external SOCKS5 proxy with RFC 1929 user/pass auth
tools4a --tunnel=socks5 --socks5-host=proxy.example.invalid --socks5-user=alice \
  --socks5-password=not-a-real-proxy-password \
  mysql --host=mysql.example.invalid --user=root --password=not-a-real-db-password "SELECT 1"

# Composable --hop (Phase 21): SOCKS5 underlay → SSH → target (the canonical chain)
tools4a --hop 'socks5://192.0.2.10:2235' \
        --hop 'ssh://admin:not-a-real-password@gateway.example.invalid:22' \
  mysql --host=mysql.example.invalid --user=root --password=not-a-real-db-password "SELECT 1"

# Composable --hop: SSH multi-hop with per-hop credentials
tools4a --hop 'ssh://admin:not-a-real-password@bastion1.example.invalid' \
        --hop 'ssh://dbuser:not-a-real-password@bastion2.example.invalid' \
  mysql --host=mysql.example.invalid --user=root --password=not-a-real-db-password "SELECT 1"

# tunnel-serve: local TCP port-forward through SOCKS5 → SSH (Phase 21)
tools4a tunnel-serve --type tcp --listen 127.0.0.1:13306 \
  --target-host mysql.example.invalid --target-port 3306 \
  --hop 'socks5://192.0.2.10:2235' \
  --hop 'ssh://admin:not-a-real-password@gateway.example.invalid:22'
```

### PostgreSQL

```bash
# Direct connection (read-only)
tools4a pgsql "SELECT * FROM users LIMIT 5" --host=localhost --user=postgres --password=not-a-real-password --database=myapp

# Write — requires --allow-write
tools4a pgsql "DELETE FROM events WHERE created_at < now() - interval '30 days'" \
  --host=localhost --user=postgres --password=not-a-real-password --database=myapp --allow-write

# Through an SSH jump
tools4a --tunnel=ssh --ssh-jump=bastion.example.invalid --ssh-user=admin --ssh-key-path=/path/to/not-a-real-key \
  pgsql --host=pgsql.example.invalid --user=app --password=not-a-real-password --database=myapp "SELECT NOW()"

# Using a TOML profile
tools4a pgsql "SELECT count(*) FROM events" --profile=prod-postgres
```

### MongoDB

Mongo commands are JSON documents passed to `Database::run_command`:

```bash
# find (read — works without --allow-write)
tools4a mongo '{"find":"users","filter":{"active":true},"limit":5}' \
  --host=localhost --database=myapp

# insert (write — requires --allow-write)
tools4a mongo '{"insert":"events","documents":[{"type":"signup","ts":1}]}' \
  --host=mongo.example.invalid --user=app --password=not-a-real-password --database=analytics \
  --allow-write

# Through an SSH jump
tools4a --tunnel=ssh --ssh-jump=bastion.example.invalid --ssh-user=admin --ssh-password=not-a-real-jump-password \
  mongo '{"listCollections":1}' --host=mongo.example.invalid --database=admin
```

### Redis

```bash
# Direct connection
tools4a redis "GET mykey" --host=localhost --port=6379

# With password + db
tools4a redis "HGETALL myhash" --host=localhost --password=not-a-real-password --db=2

# Through an SSH jump
tools4a --tunnel=ssh --ssh-jump=bastion.example.invalid --ssh-user=admin --ssh-password=not-a-real-jump-password \
  redis "INFO replication" --host=redis.example.invalid --password=not-a-real-cache-password

# Using a TOML profile
tools4a redis "KEYS *" --profile=prod-cache
```

### HTTP

```bash
# Simple GET
tools4a http GET https://api.example.com/users

# POST with JSON body
tools4a http POST https://api.example.com/users \
  --json --data '{"name":"alice"}' \
  --bearer "$API_TOKEN"

# Through an SSH jump to an internal HTTPS service
tools4a --tunnel=ssh --ssh-jump=bastion.example.invalid --ssh-user=admin --ssh-password=not-a-real-jump-password \
  http GET https://internal-api.example.invalid/health

# Self-signed cert internal service (show full status + headers + body)
tools4a http GET https://192.0.2.5/api --insecure -i
```

### SSH (remote command execution)

```bash
# Direct connection
tools4a ssh "uname -a" --host=server.example.invalid --user=admin --key-path=/path/to/not-a-real-key

# With password
tools4a ssh "df -h" --host=192.0.2.5 --user=root --password=not-a-real-password

# Through an SSH jump (jump creds are SEPARATE from target creds)
tools4a --tunnel=ssh --ssh-jump=bastion.example.invalid --ssh-user=jumper --ssh-password=not-a-real-jump-password \
  ssh "systemctl status nginx" --host=server.example.invalid --user=admin --key-path=/path/to/not-a-real-target-key

# Show structured output (exit_code/stdout/stderr table)
tools4a ssh "false" --host=server.example.invalid --user=user --key-path=/path/to/not-a-real-key -i
```

By default `tools4a`'s exit code mirrors the remote command's exit code,
so shell-script usage works (e.g. `if tools4a ssh "test -f /etc/passwd" ...`).

### Browser (agent-browser passthrough)

Pre-requisite: install [`agent-browser`](https://github.com/vercel-labs/agent-browser)
separately (`npm i -g agent-browser` or the upstream Rust build). tools4a
shells out to it; it does not bundle a browser.

```bash
# Open a URL in a named session, then snapshot
tools4a browser open https://example.com --session work
tools4a browser snapshot --session work

# Pass agent-browser flags directly — they sit AFTER the subcommand
tools4a browser open https://example.com --wait
# tools4a-side flags (--session, --proxy, --bin) go BEFORE the subcommand
tools4a browser --session work open https://example.com

# Show structured output (exit_code/stdout/stderr table)
tools4a browser snapshot --session work -i

# Through an SSH bastion (tools4a binds a per-call SOCKS5 listener via LayeredTunnel Socks5Server)
tools4a --tunnel=ssh --ssh-jump=bastion.example.invalid --ssh-user=admin \
  browser open https://internal.example.invalid --session work

# Composable --hop for browser: SOCKS5 underlay → SSH bastion → browser
tools4a --hop 'socks5://192.0.2.10:2235' \
        --hop 'ssh://admin:not-a-real-password@bastion.example.invalid' \
  browser open https://internal.example.invalid --session work
```

`tools4a`'s exit code mirrors `agent-browser`'s, like the `ssh`
subcommand. Any SSH-containing layer stack (e.g. `--tunnel=ssh` or
`--hop 'ssh://...'`) stands up a `LayeredTunnel` with
`ForwardTarget::Socks5Server` (no external `ssh -D` needed) — tools4a
binds `127.0.0.1:<random>` and injects `--proxy socks5://...` into the
agent-browser invocation; the listener is torn down when the call
returns. A pure-SOCKS5 stack (`--tunnel=socks5` or a single
`--hop 'socks5://...'`) short-circuits by passing `--proxy socks5://…`
directly to agent-browser without a local relay. If you set BOTH
`--tunnel=ssh` AND `--proxy ...`, that's an `Error::Config` conflict —
pick one.

### MCP Server

Run `tools4a` with no subcommand to start an MCP server over stdio:

```bash
tools4a
```

It exposes 31 tools: one safe profile-discovery tool (`profiles_list`),
eight service tools (`mysql_exec`, `pgsql_exec`, `clickhouse_exec`,
`redis_exec`, `mongo_exec`, `http_exec`, `ssh_exec`, `browser_exec`),
seven Docker tools, ten Milvus tools, and five RabbitMQ tools. The 30
service/action tools accept their service parameters plus shared tunnel
fields; `profiles_list` returns only profile names, types, and aliases. The
preferred form (Phase 21) is `tunnel_layers` (an ordered JSON array of
`{type:"socks5"|"ssh", host, port, user?, password?, key_path?}`);
legacy flat fields (`tunnel`, `ssh_jump`, `ssh_user`, `ssh_password`,
`ssh_key_path`, `ssh_port`, `socks5_host`, `socks5_port`, etc.) still
work and are lowered to layers automatically.
`browser_exec` additionally requires the [`agent-browser`](https://github.com/vercel-labs/agent-browser)
binary to be installed on `$PATH` (or via `$AGENT_BROWSER_BIN`) — tools4a
shells out to it and captures stdout/stderr/exit_code. AI clients
(Claude Desktop, Cursor, etc.) can call these tools to query databases,
run shell commands through SSH jump hosts, and automate a real browser.

Example MCP configuration entry (e.g. for Claude Desktop):

```json
{
  "mcpServers": {
    "tools4a": {
      "command": "/usr/local/bin/tools4a"
    }
  }
}
```

### Install in Claude Code

This repo ships a Claude Code plugin (`.claude-plugin/plugin.json` +
`.claude-plugin/marketplace.json` + `.mcp.json` + `skills/`). Once
installed, Claude gets all 31 MCP tools plus the
project-specific skills — all wired up automatically.

Pick **one** of the two paths below.

#### Path A: Install as a plugin (recommended)

Gives you the MCP tools **and** the bundled skills (`tools4a-using`,
`mysql-debugging`, `ssh-bastion-checklist`).

```bash
# 1. Build & install the binary onto $PATH
cargo install --path .                              # produces ~/.cargo/bin/tools4a

# 2. In a Claude Code session, register this repo as a marketplace
/plugin marketplace add /absolute/path/to/tools4a   # one-time

# 3. Install the plugin from that marketplace
/plugin install tools4a@tools4a                     # enable plugin

# 4. Verify
/mcp                                                # should list `tools4a`
```

To upgrade after pulling new commits, rebuild the binary
(`cargo install --path . --force`) and re-run `/plugin marketplace update tools4a`.

#### Path B: Install as a plain MCP server (lighter)

Gives you the 31 MCP tools only (no skills). Useful if you don't want
plugin-level integration.

```bash
# 1. Build & install the binary
cargo install --path .

# 2. Register the MCP server with Claude Code
claude mcp add tools4a tools4a                      # name=tools4a, command=tools4a

# 3. Verify
claude mcp list                                     # should show `tools4a`
```

The `tools4a` binary speaks MCP over stdio when invoked with no
subcommand, so no extra flags are needed.

#### What the plugin provides

- **MCP tools** auto-registered via `.mcp.json`:
  - `profiles_list` — discover canonical profile names and aliases without exposing connection details or credentials.
  - `mysql_exec` — run a MySQL query.
  - `pgsql_exec` — run a PostgreSQL query.
  - `clickhouse_exec` — run a ClickHouse SQL query (HTTP interface).
  - `redis_exec` — run a Redis command.
  - `mongo_exec` — run a MongoDB command (JSON document to `runCommand`).
  - `http_exec` — send an HTTP request.
  - `ssh_exec` — run a shell command on a remote SSH server.
  - `browser_exec` — run an `agent-browser` subcommand (browser automation; requires the external `agent-browser` binary).
  - Seven `docker_*`, ten `milvus_*`, and five `rabbitmq_*` tools for their respective services.
- **Skills** that guide the assistant (Path A only):
  - `tools4a-using` — routing and safety guide for all 31 tools, including profile aliases, parameter shapes, config priority, tunnels, output mapping, and destructive-command confirmation.
  - `mysql-debugging` — diagnostic queries for common MySQL errors, locks, slow queries.
  - `ssh-bastion-checklist` — narrows down SSH-tunnel failures.
  - `browser-using` — agent-browser daemon model, session reuse, Phase 1 SOCKS workaround for SSH-routed browsing.

### Configuration

**YAML Config** (`mysql.yaml`):
```yaml
type: mysql
host: localhost
port: 3306
user: root
password: not-a-real-password
database: mydb
```

**TOML Config** (`~/.config/tools4a/config.toml`):
```toml
[profiles.prod]
type = "mysql"
aliases = ["production", "orders"]
host = "prod.example.invalid"
port = 3306
user = "app_user"
password = "not-a-real-password"
```

Profile names and aliases are routing metadata: each is limited to 128
characters and may not contain control or bidirectional-formatting characters.
A profile accepts at most 32 aliases. Within one service type, aliases and
canonical profile names must be unique under ASCII case-folding.

## Development

Run tests:
```bash
cargo test
```

Build:
```bash
cargo build
```

## License

MIT
