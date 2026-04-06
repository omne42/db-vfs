# Storage Backends

## Backend configuration matrix

| Backend | Key config | Default / behavior |
| --- | --- | --- |
| SQLite | `limits.max_io_ms`, `limits.max_walk_ms` | each checked-out connection resets `busy_timeout` to the active request budget |
| SQLite | `limits.max_db_connections` | r2d2 pool size |
| Postgres | `limits.max_io_ms`, `limits.max_walk_ms` | `statement_timeout` follows the active request budget |
| Postgres | `limits.max_db_connections` | r2d2 pool size |

## Timeout behavior

| Backend | Timeout mechanism | On timeout |
| --- | --- | --- |
| SQLite | per-request `busy_timeout` + service wall-clock + interrupt handle | returns `timeout`; interrupted work may finish shortly in background |
| Postgres | per-request `statement_timeout` + service wall-clock | query canceled and surfaced as `timeout` |

Retry decision still depends on operation semantics (`conflict`, idempotency, etc).

## Migration contract

- migrations run at service startup;
- migration failure aborts startup;
- migrations are expected to be idempotent for existing environments;
- startup order: validate service policy/auth/audit wiring -> open connection -> run migrations ->
  serve traffic.

Version storage keeps a per-path generation row so CAS versions remain monotonic across
delete/recreate. This prevents stale `expected_version` values from accidentally matching a new
file lifetime after the same path is recreated.

The built-in SQLite/Postgres stores normalize their public `(workspace_id, path, path_prefix)`
inputs with the same workspace/path rules as the VFS boundary, so direct store callers cannot
persist keys that the VFS would later fail to address consistently.

If an external `Store` implementation relies on the trait's compatibility fallbacks for
`get_content_chunk` or `list_metas_by_prefix_page`, `db-vfs` now emits one-time warnings instead
of silently degrading ranged-read or large-prefix scan semantics.

## Quick verification

SQLite:

```bash
cargo run -p db-vfs-service -- --sqlite ./db.sqlite --policy ./policy.local.toml
```

Postgres:

```bash
cargo run -p db-vfs-service --features postgres -- \
  --postgres 'postgres://user:pass@localhost:5432/db_vfs' \
  --policy ./policy.local.toml
```

After startup, run one `write` and one `read` request and verify 2xx responses.
