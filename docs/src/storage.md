# Storage Backends

## Backend configuration matrix

| Backend | Key config | Default / behavior |
| --- | --- | --- |
| SQLite | `limits.max_io_ms` | used for pool wait and per-request busy timeout |
| SQLite | `limits.max_db_connections` | r2d2 pool size; forced to `1` for `:memory:` |
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

For `--sqlite :memory:`, the service intentionally uses a single pooled connection so migrations,
schema, and request traffic all see the same in-memory database. Treat this mode as local/dev/test
only.

Postgres:

```bash
cargo run -p db-vfs-service --features postgres -- \
  --postgres 'postgres://user:pass@localhost:5432/db_vfs' \
  --policy ./policy.local.toml
```

After startup, run one `write` and one `read` request and verify 2xx responses.
