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
- startup order: open connection -> run migrations -> serve traffic.

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
