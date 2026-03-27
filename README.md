# db-vfs

DB-backed virtual filesystem (DB-VFS) for service workloads.

## What it provides

- Safety-first policy model: **Permissions + Limits + Secrets + Traversal + Auth**.
- Tool-like operations: `read`, `write`, `patch`, `delete`, `glob`, `grep`.
- Backends: SQLite (default/dev) and Postgres (`--features postgres`).

## Quickstart (5 min)

1. Create a local policy and token:

```bash
cp policy.example.toml policy.local.toml
export DB_VFS_TOKEN='dev-token-change-me'
```

2. Enable local writes in `policy.local.toml`:

```toml
[permissions]
write = true
```

3. Start SQLite service:

```bash
cargo run -p db-vfs-service -- \
  --sqlite ./db-vfs.sqlite \
  --policy ./policy.local.toml \
  --listen 127.0.0.1:8080
```

4. Verify write/read:

```bash
curl -sS http://127.0.0.1:8080/v1/write \
  -H 'content-type: application/json' \
  -H "authorization: Bearer ${DB_VFS_TOKEN}" \
  -d '{"workspace_id":"w1","path":"docs/a.txt","content":"hello","expected_version":null}'

curl -sS http://127.0.0.1:8080/v1/read \
  -H 'content-type: application/json' \
  -H "authorization: Bearer ${DB_VFS_TOKEN}" \
  -d '{"workspace_id":"w1","path":"docs/a.txt","start_line":null,"end_line":null}'
```

## API field reference (minimal)

All endpoints are JSON `POST` and require:

- `content-type: application/json`
- `authorization: Bearer <token>` (unless `--unsafe-no-auth`)

| Endpoint | Request fields | Key response fields | Typical errors |
| --- | --- | --- | --- |
| `/v1/read` | `workspace_id`, `path`, `start_line?`, `end_line?` | `requested_path`, `path`, `content`, `bytes_read`, `version` | `unauthorized`, `invalid_path`, `not_found` |
| `/v1/write` | `workspace_id`, `path`, `content`, `expected_version?` | `requested_path`, `path`, `bytes_written`, `created`, `version` | `conflict`, `file_too_large` |
| `/v1/patch` | `workspace_id`, `path`, `patch`, `expected_version` | `requested_path`, `path`, `bytes_written`, `version` | `patch`, `conflict`, `not_found` |
| `/v1/delete` | `workspace_id`, `path`, `expected_version?`, `ignore_missing?` | `requested_path`, `path`, `deleted` | `conflict`, `not_found` |
| `/v1/glob` | `workspace_id`, `pattern`, `path_prefix?` | `matches`, `truncated`, public scan counters | `not_permitted`, `timeout` |
| `/v1/grep` | `workspace_id`, `query`, `regex`, `glob?`, `path_prefix?` | `matches[]`, `truncated`, public scan counters | `invalid_regex`, `not_permitted`, `timeout` |

Error body:

```json
{"code":"<stable_code>","message":"<human message>"}
```

`ignore_missing = true` makes `/v1/delete` idempotent for absent targets by returning
`200 {"deleted":false,...}`.

Line-range `read` enforces `max_read_bytes` on the returned slice, not on the whole backing file.

`expected_version` is monotonic per `(workspace_id, path)` even across delete/recreate. Recreating
a deleted file does not reset its version back to `1`, so stale CAS tokens cannot hit a new file
lifetime by accident.

## Security Baseline

- Keep auth enabled; avoid `--unsafe-no-auth` outside local isolated dev.
- Prefer `sha256:<64 hex>` tokens or env-backed runtime tokens.
- Scope tokens with `allowed_workspaces` (avoid broad `*` in production).
- Use TLS/HTTPS end-to-end for bearer token transport.
- Enable audit log with `audit.required = true`.

## Performance Limits

Tune policy `limits` for your workload:

- request bytes: `max_read_bytes`, `max_write_bytes`, `max_patch_bytes`
- scan bounds: `max_results`, `max_walk_files`, `max_walk_entries`, `max_walk_ms`, `max_line_bytes`
- concurrency: `max_concurrency_io`, `max_concurrency_scan`, `max_db_connections`
- timeout/rate: `max_io_ms`, `max_requests_per_ip_per_sec`, `max_requests_burst_per_ip`

Budget semantics:

- `max_io_ms` bounds non-scan requests (`read`/`write`/`patch`/`delete`) and DB pool wait/connect time.
- `max_walk_ms` bounds scan execution (`glob`/`grep`); `max_walk_ms = None` keeps scan runtime unbounded.
- SQLite `busy_timeout` and Postgres `statement_timeout` follow the active request budget; scan requests with `max_walk_ms = None` do not inherit `max_io_ms` as an implicit backend wait cap.

## Observability / Audit

- `x-request-id` is accepted/echoed; invalid/missing IDs are replaced by service-generated IDs.
- Optional JSONL audit via `audit.jsonl_path`.
- With `audit.required = true`, audit runs fail-closed after startup: requests block on audit backpressure, and worker loss aborts the process instead of silently dropping events.
- Early rejects (unauthorized/invalid JSON/rate-limited) are audited with `workspace_id="<unknown>"`.
- Service logs use `tracing`; configure via `RUST_LOG`.

## Troubleshooting matrix

| HTTP | Common causes | First checks |
| --- | --- | --- |
| `401` | missing/invalid token | `Authorization`, token hash/env var |
| `403` | workspace/policy denied | `allowed_workspaces`, `permissions.*`, `secrets.deny_globs` |
| `409` | stale CAS version | re-read latest version before retry |
| `408` | timeout budget exceeded (operation status may be unknown) | `limits.max_io_ms`, `limits.max_walk_ms`, DB latency, pool/lock wait |
| `503` | concurrency saturation | `max_concurrency_*`, `max_db_connections` |

## More docs

- Docs entrypoints: `docs/README.md` and `docs/docs-system-map.md`
- Human docs (`mdBook`): `docs/` (`./scripts/docs.sh`)
- LLM bundle: `llms.txt` and `docs/llms.txt` (`./scripts/llms.sh`)
