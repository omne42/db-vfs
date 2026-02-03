# Storage backends

## SQLite

- Intended for dev/test and single-node deployments.
- Uses `r2d2_sqlite` for connection pooling.
- The service attempts to interrupt in-flight SQLite queries on timeout (best-effort).

## Postgres

- Intended for production deployments (build with `--features postgres`).
- Uses `r2d2_postgres` for connection pooling.
- The service configures Postgres `statement_timeout` based on policy `limits.max_io_ms`.

## Migrations

Migrations live under `migrations/` and are applied on startup:

- `migrations/sqlite/`
- `migrations/postgres/`
