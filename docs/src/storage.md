# Storage Backends

## Backend configuration matrix

| Backend | Key config | Default / behavior |
| --- | --- | --- |
| SQLite | `limits.max_io_ms` | used for busy timeout (capped) |
| SQLite | `limits.max_db_connections` | r2d2 pool size |
| Postgres | `limits.max_io_ms` | sets statement timeout |
| Postgres | `limits.max_db_connections` | r2d2 pool size |

## Timeout behavior

| Backend | Timeout mechanism | On timeout |
| --- | --- | --- |
| SQLite | service wall-clock + interrupt handle | best-effort interrupt, may finish shortly in background |
| Postgres | service wall-clock + statement timeout | query canceled by DB timeout rules |

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
