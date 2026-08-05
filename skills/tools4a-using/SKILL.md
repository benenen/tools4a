---
name: tools4a-using
description: "Route user requests for saved profiles, MySQL/PostgreSQL/ClickHouse/Redis/MongoDB, HTTP/SSH/Browser, Docker, Milvus, or RabbitMQ to the 31 tools4a MCP tools. Covers aliases, parameters, tunnels, outputs, write gates, and destructive-action confirmation."
---

# Using the tools4a MCP tools

`tools4a` exposes 31 MCP tools. Internally every tool produces a `{columns, rows, affected_rows}` `ExecutionResult`. On the MCP wire, `mysql_exec`, `pgsql_exec`, and `clickhouse_exec` default to TOON and accept `format="json"`; Redis, MongoDB, HTTP, SSH, and Browser return JSON text; `profiles_list` plus all 22 `docker_*`, `milvus_*`, and `rabbitmq_*` tools return TOON text. Parse the returned text according to that family rather than assuming every tool returns a JSON object. MySQL, PostgreSQL, ClickHouse, Redis, and MongoDB additionally accept `profile` / `config` for 3-layer config merge; the other service tools take connection fields directly. Browser requires the external `agent-browser` binary on the tools4a host.

| Family | Count | Tools | Required connection/action input |
| --- | ---: | --- | --- |
| Profile discovery | 1 | `profiles_list` | no input; returns only canonical name, service type, and aliases |
| SQL / data services | 5 | `mysql_exec`, `pgsql_exec`, `clickhouse_exec`, `redis_exec`, `mongo_exec` | service action plus host/auth, or a configured profile |
| HTTP / SSH / Browser | 3 | `http_exec`, `ssh_exec`, `browser_exec` | `method` + `url`; `command` + SSH target/auth; or browser `subcommand` |
| Docker | 7 | `docker_ps`, `docker_inspect`, `docker_logs`, `docker_stats`, `docker_top`, `docker_exec`, `docker_restart` | local Docker socket by default; action-specific container/command fields |
| Milvus | 10 | `milvus_list_databases`, `milvus_list_collections`, `milvus_describe_collection`, `milvus_collection_stats`, `milvus_list_partitions`, `milvus_query`, `milvus_search`, `milvus_drop_collection`, `milvus_load_collection`, `milvus_release_collection` | `host` plus action-specific database/collection/query/vector fields |
| RabbitMQ | 5 | `rabbitmq_list_queues`, `rabbitmq_queue_info`, `rabbitmq_get_messages`, `rabbitmq_list_bindings`, `rabbitmq_overview` | Management API `host` plus action-specific vhost/queue/filter fields |

Direct connection defaults: Docker uses `docker_host=unix:///var/run/docker.sock`; `docker_host` selects a direct local Unix endpoint or a direct/SSH-tunneled TCP endpoint, while `unix_socket` specifically names a remote Unix socket and is valid only with a tunnel stack ending in SSH (when set, it determines the remote target and `docker_host` is ignored). Milvus requires `host`, defaults to `scheme=http` / `port=19530`, and accepts optional `user` / `password`; RabbitMQ requires `host`, defaults to `scheme=http` / `port=15672` (`15671` for HTTPS), and accepts HTTP basic-auth `user` / `password`. Do not rely on RabbitMQ's `guest` / `guest` library defaults outside a local development broker.

## Tool input shapes

```json
// profiles_list — call first when an environment name is known but its canonical profile is not
{}

// mysql_exec
{ "query": "SELECT 1", "profile": "prod", "database": "myapp" }
{ "query": "SELECT 1", "host": "db.example.invalid", "user": "alice", "password": "not-a-real-password" }

// pgsql_exec — same shape as mysql_exec, default port 5432, no `db` field (use `database`)
{ "query": "SELECT 1", "profile": "prod-pg", "database": "myapp" }
{ "query": "SELECT 1", "host": "pg.example.invalid", "user": "app", "password": "not-a-real-password", "database": "myapp" }

// redis_exec — `command` parsed via shlex; quoted args supported
{ "command": "GET foo", "host": "redis.example.invalid", "password": "not-a-real-password", "db": 0 }
{ "command": "EVAL \"return 1\" 0", "profile": "prod-cache" }

// mongo_exec — `command` is a JSON OBJECT string (parsed → BSON → run_command)
{ "command": "{\"find\":\"users\",\"filter\":{\"x\":1}}", "profile": "prod-mongo" }
{ "command": "{\"insert\":\"events\",\"documents\":[{\"a\":1}]}", "host": "mongo", "database": "analytics" }

// http_exec — no profile/YAML
{ "method": "GET", "url": "https://api.example.com/x" }
{ "method": "POST", "url": "...", "data": "{...}", "json": true, "bearer": "..." }
{ "method": "GET", "url": "...", "headers": ["X-Trace: abc"], "insecure": true }

// ssh_exec — TARGET creds (user/password/key_path) separate from JUMP creds (ssh_*)
{ "command": "uptime", "host": "server", "user": "admin", "key_path": "/home/me/.ssh/id_rsa" }

// clickhouse_exec — SQL over HTTP, default port 8123, default user "default"
{ "query": "SELECT 1", "host": "ch", "user": "default" }
{ "query": "SELECT count() FROM events", "profile": "prod-ch" }

// browser_exec — shells out to agent-browser; sessions persist across calls
{ "subcommand": "open", "args": ["https://example.com"], "session": "work" }
{ "subcommand": "snapshot", "session": "work" }
// tunnel="ssh" works: tools4a binds a per-call SOCKS5 listener over the
// SSH chain and injects --proxy socks5://127.0.0.1:<rand> into agent-browser.
// If you set BOTH tunnel=ssh AND an explicit proxy, that's Error::Config (conflict).

// Docker — local socket is the default; inspect/list/logs/stats/top are read-only
{ "container": "app", "tail": "100" } // docker_logs
{ "all": false, "filters": {"status": ["running"]} } // docker_ps; true also includes stopped containers
{ "container": "app", "cmd": ["sh", "-c", "id"], "allow_write": true } // docker_exec

// Milvus — host is required; query/search elide vector cells by default
{ "host": "milvus.example.invalid" } // milvus_list_collections
{ "host": "milvus.example.invalid", "user": "reader", "password": "not-a-real-password", "collection": "docs", "expr": "id > 100", "output_fields": ["id", "title"], "limit": 20, "include_vectors": false } // milvus_query
{ "host": "milvus.example.invalid", "collection": "docs", "vectors": [[0.1, 0.2]], "limit": 10 } // milvus_search

// RabbitMQ — uses the HTTP Management API (default http://host:15672)
{ "host": "rabbitmq.example.invalid", "user": "monitor", "password": "not-a-real-password", "vhost": "/", "limit": 100 } // rabbitmq_list_queues
{ "host": "rabbitmq.example.invalid", "user": "monitor", "password": "not-a-real-password", "vhost": "/", "queue": "jobs", "count": 1, "truncate_bytes": 4096 } // rabbitmq_get_messages
```

The 30 service/action tools accept the shared tunnel fields; `profiles_list` does not. The recommended form uses `tunnel_layers` (ordered, composable):
```json
"tunnel_layers": [
  {"type": "socks5", "host": "192.0.2.10", "port": 1080},
  {"type": "ssh",    "host": "192.0.2.20", "port": 22, "user": "admin", "password": "not-a-real-password"}
]
```
Legacy flat fields still work and are lowered to layers automatically:
```
"tunnel": "ssh",                  // "direct" (default) | "ssh" | "socks5"
"ssh_jump": "gateway.example.invalid", // string OR comma-separated OR JSON array
"ssh_user": "jumper",
"ssh_password": "not-a-real-password", // OR ssh_key_path
"ssh_port": 22
```
`tunnel_layers` conflicts with any legacy `tunnel`/`ssh_*`/`socks5_*` fields — use one form or the other.

Since Phase 21, `tunnel="ssh"` + `socks5_*` fields (previously an error) now compose: the socks5 leg is prepended as an underlay and the SSH hop goes on top.

Docker defaults to `unix:///var/run/docker.sock`. For a remote Unix socket, set `unix_socket=/var/run/docker.sock` and use a tunnel stack that ends in an SSH hop; a bare SOCKS5 layer cannot forward a Unix socket. Milvus and RabbitMQ use the same fixed-target TCP tunnel behavior as the database and HTTP tools.

## Three-layer config priority (mysql / pgsql / clickhouse / redis / mongo)

Low → high: TOML profile (`~/.config/tools4a/config.toml [profiles.<NAME>]`) → YAML file (`config: /path.yaml`) → explicit fields. Each layer fills `Option<...>` fields; later layers overwrite. A profile may define `aliases = ["prod", "orders"]`; canonical names win, and aliases are scoped by service type. Call `profiles_list` when the user names an environment but the canonical profile is unknown. It returns only `name`, `type`, and `aliases`, never connection details or credentials. Use a profile to avoid pasting credentials repeatedly; override per call only what differs (e.g. `database`, `query`).

HTTP, SSH-direct, Browser, Docker, Milvus, and RabbitMQ have no profile/YAML — pass all fields explicitly.

## Tunnel layer syntax (Phase 21+)

The preferred form for any tunnel chain — whether a single hop, multi-hop, SOCKS5 underlay + SSH, or just SSH — is `tunnel_layers` (an ordered list of layers, local→target):

```json
// SOCKS5 proxy only (e.g. reach a service behind 192.0.2.10:1080)
{"tunnel_layers": [{"type": "socks5", "host": "192.0.2.10", "port": 1080}]}

// SSH hop only
{"tunnel_layers": [{"type": "ssh", "host": "gateway.example.invalid", "user": "admin", "password": "not-a-real-password"}]}

// SOCKS5 underlay + SSH (the 浙工业 / zgy pattern):
// local → SOCKS5 proxy → SSH gateway → target service
{"tunnel_layers": [
  {"type": "socks5", "host": "192.0.2.10", "port": 1080},
  {"type": "ssh",    "host": "192.0.2.20", "port": 22, "user": "admin", "password": "not-a-real-password"}
]}

// SSH multi-hop (Client → Bastion1 → Bastion2 → Target)
{"tunnel_layers": [
  {"type": "ssh", "host": "bastion1.example.invalid", "user": "admin", "password": "not-a-real-password"},
  {"type": "ssh", "host": "bastion2.example.invalid", "user": "admin", "key_path": "/path/to/not-a-real-key"}
]}
```

Each SSH layer in `tunnel_layers` accepts: `host`, `port` (default 22), `user`, `password`, `key_path`.
Each SOCKS5 layer accepts: `host`, `port` (default 1080), `user` (optional), `password` (optional).

## SSH tunnel syntax (legacy, still works)

```json
// Single hop
{"tunnel": "ssh", "ssh_jump": "gateway.example.invalid", "ssh_user": "admin", "ssh_password": "not-a-real-password"}

// Multi-hop (Client → Bastion1 → Bastion2 → Target)
{"tunnel": "ssh", "ssh_jump": "bastion1.example.invalid,bastion2.example.invalid", "ssh_user": "admin", "ssh_key_path": "/path/to/not-a-real-key"}
{"tunnel": "ssh", "ssh_jump": ["bastion1.example.invalid", "bastion2.example.invalid"], "ssh_user": "admin", "ssh_key_path": "/path/to/not-a-real-key"}
```

All hops share the same `ssh_user` / `ssh_password` / `ssh_key_path` / `ssh_port` when using the string forms above. For chains where each hop needs different credentials, use the object form (MCP) or `--hop` (CLI).

Since Phase 21, `tunnel="ssh"` + `socks5_*` fields now compose (SOCKS5 underlay + SSH) instead of being rejected.

### Per-hop credentials (MCP)

When hops in the chain need different credentials, pass `ssh_jump` as an
array of objects. Each object's `user`/`password`/`key_path`/`port` is
optional and falls back to the top-level `ssh_user`/etc.

```json
{
  "tunnel": "ssh",
  "ssh_jump": [
    {"host": "gateway.example.invalid", "user": "admin", "password": "not-a-real-password"},
    {"host": "target.example.invalid",    "user": "target-user",  "password": "not-a-real-target-password", "port": 2222}
  ]
}
```

### Per-hop CLI (Phase 21+)

Use `--hop` (repeatable, URL form) for the ordered layer stack. Mutually exclusive with legacy `--tunnel`/`--ssh-*`/`--socks5-*`:

```bash
# SOCKS5 underlay + SSH (the 浙工业 / zgy pattern)
tools4a --hop 'socks5://192.0.2.10:1080' \
        --hop 'ssh://admin:not-a-real-password@192.0.2.20:22' \
        mysql "SELECT 1" --host=db.example.invalid --user=root --password=not-a-real-password

# SSH multi-hop with different per-hop keys
tools4a --hop 'ssh://admin:not-a-real-password@gateway.example.invalid' \
        --hop 'ssh://target-user:not-a-real-password@target.example.invalid:2222' \
        mysql "SELECT 1" --host=db.example.invalid --user=app --password=not-a-real-password

# tunnel-serve: local TCP forward through SOCKS5 → SSH
tools4a tunnel-serve --type tcp --listen 127.0.0.1:13306 \
  --target-host db.example.invalid --target-port 3306 \
  --hop 'socks5://192.0.2.10:1080' \
  --hop 'ssh://admin:not-a-real-password@192.0.2.20:22'
```

Note: special characters in URL userinfo must be percent-encoded (e.g. `@` → `%40`, `:` → `%3A`).
Prefer profiles or key paths for real environments. Never paste production passwords into committed examples or shared shell history; the inline credentials above are explicitly non-real placeholders.

For **`ssh_exec`** specifically: the TARGET creds (`user`, `password` / `key_path`, `port`) and the JUMP creds (`ssh_*`) are independent. The tool never infers one from the other — supply both even when they happen to be the same.

For **`http_exec`** through SSH: TLS SNI / Host header / cert verification all use the URL's original hostname; the tunnel only redirects DNS to a local listener. HTTPS-via-tunnel works without TLS surgery.

For **`ssh_exec` through SOCKS5**: use `tunnel_layers` with a `socks5` entry (or legacy `tunnel="socks5"` + `socks5_*` fields). tools4a routes the russh TCP dial through the SOCKS5 proxy via the connector chain. The host-key warning still names the real target host (not `127.0.0.1`), and target credentials authenticate the SSH session as usual — the proxy only carries TCP.

## Output mapping

For `mysql_exec`, `pgsql_exec`, and `clickhouse_exec`, distinguish serialization compression from row-level compression:

- Default `format="toon"`, `include_ui=false`: return every row in TOON, typically using 30–60% fewer tokens than JSON; do not truncate or summarize rows.
- `format="json"`, `include_ui=false`: return every row as pretty JSON; do not compress rows.
- `include_ui=true`: keep the full result in the HTML UI resource, but compress the text sent to the LLM by row count: up to 20 rows stay complete; 21–100 return the first 20; 101–1000 return 10 evenly distributed samples plus statistics; more than 1000 return schema and statistics only.
- `include_ui` defaults to `false`, so ordinary SQL calls use TOON format compression without row-level data loss.

**mysql_exec** — standard `{columns, rows, affected_rows}`. DML returns empty rows + non-zero affected_rows.

**pgsql_exec** — standard `{columns, rows, affected_rows}` like mysql. Type mapping covers bool / int / float / text / date / time / timestamp / timestamptz; uncommon types (json, jsonb, uuid, arrays) render as `<typename>` placeholders.

**mongo_exec** — single `result` row containing the JSON-serialized result Document. For find-style commands the Document has shape `{"cursor": {"firstBatch": [...]}}`. For write commands it has `{"n": ..., "ok": 1}`. Caller parses the JSON string in the row to navigate the response.

**redis_exec** — single `result` column; rows depend on the Redis Value:

| Redis Value | rows |
| --- | --- |
| Nil | empty |
| Int / BulkString / SimpleString / Okay | 1 row |
| Array | one row per element (HGETALL flattens to alternating field/value rows) |
| Map / Set / Push / RESP3-only | 1 row, Debug-formatted (known limitation) |

**http_exec** — flat `field`/`value` rows: `status_code`, `status`, `header.<name>` (one per response header), `body`. Body is UTF-8 if possible, else `<N bytes (non-UTF-8 body)>`. When showing to the user: default to printing just the `body` row; print the whole table only if the user asked for headers or for debugging.

**ssh_exec** — three rows: `exit_code` (`0` = success; `<unknown>` if channel closed without exit status, treat as failure), `stdout`, `stderr`.

**clickhouse_exec** — standard `{columns, rows, affected_rows}` like mysql/pgsql. Result comes from ClickHouse's HTTP interface; an empty DDL/DML response returns empty rows with `affected_rows=0`.

**browser_exec** — three rows: `exit_code` (`0` = success), `stdout` (agent-browser's stdout, often JSON for structured subcommands like `snapshot`), `stderr` (diagnostic if any). Parse `stdout` as JSON when the subcommand documents JSON output; otherwise treat as plain text.

**docker_*** — MCP responses use TOON. `docker_ps` / `docker_top` contain tabular rows; `docker_inspect` / `docker_stats` contain one JSON cell; `docker_logs` contains one combined text cell; `docker_exec` contains `field` / `value` rows for `exit_code`, `stdout`, and `stderr`; restart returns one result cell. Use `docker_logs` rather than `docker_exec` when logs are sufficient.

**milvus_*** — MCP responses use TOON. List/stats actions return compact tables, describe returns one JSON cell, and query/search return requested scalar fields plus identifiers/scores. Vector cells render as `<vec dim=N>` unless `include_vectors=true`, which can produce very large responses.

**rabbitmq_*** — MCP responses use TOON. `rabbitmq_list_queues`, `rabbitmq_list_bindings`, `rabbitmq_get_messages`, and `rabbitmq_overview` contain compact tables; `rabbitmq_queue_info` contains one JSON cell. Message peek immediately requeues each fetched message (`ackmode=ack_requeue_true`) rather than permanently consuming it, but the peek can still affect redelivery metrics or ordering and may expose sensitive payloads. Keep `count` small and set `truncate_bytes` to a task-appropriate bound (for example, `4096`).

## Write gating (`allow_write`)

The gated tools are **read-only by default**. SQL/Mongo writes are rejected
with `Error::Service("write operation not allowed without --allow-write (CLI) /
allow_write=true (MCP)")`; Docker and Milvus return an action-specific
write-gating error. Pass `allow_write: true` only after confirming the action.

- **mysql_exec / pgsql_exec**: read-only first-keyword whitelist is
  `SELECT`, `SHOW`, `EXPLAIN`, `DESCRIBE` / `DESC`, `WITH`, `VALUES`,
  `TABLE`, `USE`. Anything else (INSERT/UPDATE/DELETE/DDL/etc.) needs
  `allow_write: true`. As a second line of defense, when
  `allow_write=false` the SQL session is forced into DB-level read-only
  (`SET SESSION TRANSACTION READ ONLY` for MySQL, `SET
  default_transaction_read_only = on` for Postgres).
- **mongo_exec**: read-only commands are `find`, `aggregate` (without
  `$out`/`$merge` stages), `count`, `distinct`, `listCollections`,
  `listDatabases`, `listIndexes`, `dbStats`, `collStats`,
  `serverStatus`, `ping`, `hello`, `buildInfo`, `getParameter`, etc.
  Writes (`insert`, `update`, `delete`, `findAndModify`, `drop`,
  `create`, `createIndexes`, aggregate-with-`$out`/`$merge`) need
  `allow_write: true`. Mongo has no per-session read-only mode, so the
  command whitelist is the only guard.
- **clickhouse_exec**: same SQL-keyword whitelist as mysql/pgsql plus
  ClickHouse-specific reads (`DESCRIBE TABLE`, `SHOW DATABASES`, etc.).
  When `allow_write=false` the HTTP call also sets `readonly=1` on the
  server side as a second line of defense.
- **docker_exec / docker_restart**: always require `allow_write=true`.
  `docker_ps`, `docker_inspect`, `docker_logs`, `docker_stats`, and
  `docker_top` are read-only and do not expose the flag.
- **milvus_drop_collection / milvus_load_collection / milvus_release_collection**:
  require `allow_write=true`. The remaining seven Milvus tools are read-only.
- **redis_exec / http_exec / ssh_exec / browser_exec**: NOT gated. They
  accept any command/method without `allow_write` — Redis is
  shell-shaped, HTTP/SSH encode write semantics in their method/command,
  and browser actions are external-side-effect rather than tools4a-side.
- **rabbitmq_***: none of the five current tools requires `allow_write`.
  List/info/binding/overview are pure reads; message peek is non-destructive
  because it requeues rather than permanently consuming messages, but it is
  not zero-impact and may affect ordering or redelivery metrics.

## Destructive commands — confirm with the user FIRST

When `allow_write: true` is being passed (or for non-gated services),
still confirm before running anything destructive:

- **mysql_exec**: any `DROP`, `TRUNCATE`, `DELETE`, `UPDATE` without a `WHERE`, `ALTER`, `GRANT`, `REVOKE`. Treat as a privileged shell.
- **pgsql_exec**: `DROP`, `TRUNCATE`, `DELETE without WHERE`, `UPDATE without WHERE`, `GRANT`, `REVOKE`, `ALTER`. Same caution as mysql.
- **redis_exec**: `FLUSHDB`, `FLUSHALL`, `DEL` / `UNLINK` against more than a single named key, `DEBUG FLUSHALL`, `CONFIG SET`, `CLUSTER FORGET` / `MEET`, `RENAME` / `RENAMENX` (silently overwrites). `KEYS *` on prod can block — prefer `SCAN`.
- **mongo_exec**: `drop` (collection drop), `dropDatabase`, `delete` with broad filter, `update` with `"multi": true` + broad filter, `findAndModify` with `"remove": true`, admin commands `createUser` / `dropUser` / `grantRolesToUser`.
- **http_exec**: `POST` / `PUT` / `DELETE` / `PATCH`. Watch for missing `data` — user may have typed POST when they meant GET.
- **ssh_exec**: `rm` / `find ... -delete`, `mv` overwrite, `dd`, `mkfs.*`, `systemctl restart` / `reboot` / `shutdown`, `apt install` / `apt remove`, `kill -9` / `pkill`, anything starting with `sudo`.
- **clickhouse_exec**: `DROP`, `TRUNCATE`, `DELETE FROM`, `ALTER ... DROP`, `OPTIMIZE FINAL` (rewrites parts), `DETACH PARTITION`. ClickHouse-specific: avoid running `SELECT * FROM huge_table` without `LIMIT` on prod — the query streams the whole table over HTTP.
- **browser_exec**: `fill` / `type` on prod forms (PII), `click` on irreversible buttons (Submit, Delete, Pay), `eval` (arbitrary JS — always confirm), `network route` / `unroute` (rewrites traffic), `cookies` / `storage` writes. Prefer `snapshot` first to confirm page state before any state-changing subcommand. For per-service details see `browser-using`.
- **docker_exec**: any mutating shell command, privileged exec, package installation, process termination, or command targeting host-mounted paths. Treat `privileged=true` as high risk.
- **docker_restart**: always confirm the exact container and expected service impact.
- **milvus_drop_collection**: always destructive; confirm the exact collection and backup/recovery plan.
- **milvus_load_collection / milvus_release_collection**: change cluster memory state and can affect latency/availability; confirm on production clusters.

Read-only operations (`SELECT`, `GET` / `EXISTS` / `INFO`, `GET` / `HEAD`, `ls` / `cat` / `df` / `ps` / `systemctl status` / `journalctl`, Docker list/inspect/logs/stats/top, Milvus list/describe/stats/query/search, and RabbitMQ list/info/overview) are safe to run without a confirmation prompt. Keep RabbitMQ message peeks bounded because payloads can be sensitive and requeueing may affect delivery metrics.

## Common error shapes

- `Error::Config("MySQL host is required")` / `("Pgsql host is required")` / `("Pgsql user is required")` / `("Redis host is required")` / `("Mongo host is required")` / `("Mongo database is required")` / `("SSH target requires --password or --key-path")` — final merged config missing a required field. Profile wrong, YAML wrong, or fill it in explicitly.
- `Error::Config("invalid URL ...")` / `("URL ... uses an unsupported scheme ...")` — http_exec URL parse failure or non-http/https scheme (ftp:// / file://).
- `Error::Service("MySQL: ...")` / `("Pgsql: ...")` / `("Pgsql query: ...")` / `("Redis: NOAUTH" / "WRONGTYPE" / "MOVED ...")` / `("Mongo: ...")` / `("Mongo run_command: ...")` / `("HTTP: ...")` / `("SSH session open failed")` — service-side error. Read the message for the cause.
- `Error::Connection("SSH connect ... failed")` / `("SSH publickey/password auth failed")` — wrong creds or unreachable host. For `ssh_exec`: jump creds vs target creds are separate.
- `Error::Execution("failed to parse Redis command (unbalanced quotes?)")` — shlex parsing failed.
- `Error::Execution("failed to parse Mongo command as JSON: ...")` / `("failed to convert command JSON to BSON: ...")` / `("Mongo command must be a JSON object")` — mongo_exec command string is not valid JSON, not a JSON object, or cannot be converted to BSON.
- `Error::Config("agent-browser binary not found ...")` — operator must install agent-browser separately (`npm i -g agent-browser` or upstream Rust build). Don't auto-install.
- `Error::Config("tunnel=ssh and an explicit `proxy` field conflict ...")` — user set BOTH `tunnel=ssh` AND `proxy=...` on `browser_exec`. tools4a injects its own `--proxy socks5://...` from the SOCKS tunnel endpoint when ssh is set; pick one or the other.
- Docker connection errors → verify `docker_host`, local socket permissions, or for a remote socket set `unix_socket` and ensure the tunnel stack ends in SSH. A bare SOCKS5 tunnel cannot carry a Unix socket.
- Milvus config/connection errors → verify required `host`, default port `19530`, scheme/auth, collection load state, vector dimension, and `anns_field` when multiple vector fields exist.
- RabbitMQ Management API errors → verify required `host`, HTTP/HTTPS port (`15672`/`15671`), basic auth, vhost URL encoding, and that the management plugin is enabled.
- `docker_exec`, `docker_restart`, `milvus_drop_collection`, `milvus_load_collection`, or `milvus_release_collection` rejected as a write action → pass `allow_write=true` only after confirmation.
- Any `SSH tunnel ... failed` / multi-hop drop → escalate to `ssh-bastion-checklist`.
- MySQL-specific (1045 / 1146 / 1062 / deadlock / slow query / processlist) → escalate to `mysql-debugging`.
- Browser-specific (agent-browser daemon issues, selector mismatches, page-load failures) → escalate to `browser-using`.

## PTY / TTY limitation (ssh_exec)

`ssh_exec` does NOT allocate a PTY. Commands needing a TTY (`top`, `htop`, `vim`, `passwd`, anything calling `isatty(stdin)`) will fail or behave unexpectedly. Use non-interactive variants (`top -bn1`, etc.) or wrap in `bash -c '...'`.

## What this skill is NOT

- Not a tutorial on each service — assume the user knows the SQL, Redis, shell, Docker, Milvus, or RabbitMQ operation they want.
- Not for streaming / WebSocket / SSE / SCP/SFTP / Redis cluster routing / pub-sub / streaming Docker logs / RabbitMQ publishing or consuming / scripting orchestration.
- Not a debugging skill — see `mysql-debugging` for MySQL diagnostics, `ssh-bastion-checklist` for SSH tunnel troubleshooting.
