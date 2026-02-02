# db-vfs

DB-backed “virtual filesystem” (DB-VFS) intended for server / high-concurrency workloads.

Goals:

- Preserve the explicit safety model shape: **Policy + Secrets + Limits**.
- Provide tool-like operations: `read`, `glob`, `grep`, `write`, `patch`, `delete`.
- Support SQLite (dev/test) and Postgres (production).

This is intentionally *not* part of `safe-fs-tools` to keep that crate focused on local OS
filesystem semantics and a small dependency graph.

## Semantics

- `workspace_id` is the namespace boundary (like a “workspace root”).
- All `path`/`path_prefix` values are **root-relative**:
  - Must not start with `/`
  - Must not contain `..`
  - `path_prefix` may be empty (`""`) to mean “the whole workspace” **only if**
    `policy.permissions.allow_full_scan = true`
- Scope control (`path_prefix`):
  - `grep` requires an explicit `path_prefix` unless a safe literal prefix can be derived from
    `glob` (e.g. `"docs/**/*.md"` → `"docs/"`).
  - `glob` similarly requires `path_prefix` for broad patterns without a safe literal prefix (e.g.
    `"**/*.md"`).
- Concurrency control (`expected_version` / CAS):
  - `read` returns a `version`.
  - `patch` requires `expected_version`.
  - `write(expected_version = None)` is **create-only**; updates require `expected_version`.
  - `delete(expected_version = Some(v))` enforces CAS; `delete(expected_version = None)` is
    unconditional.

## HTTP service

By default the service requires an auth token configured in the policy file (`[auth]`), and each
token can be restricted to a workspace allowlist. For local development only, you can run with
`--unsafe-no-auth`.

Notes:

- Token values can be plaintext or a SHA-256 hash: `sha256:<64 hex chars>` (recommended for stored policies).
- Request tracing uses `x-request-id`:
  - If the client sets it, the service echoes it back.
  - Otherwise the service generates one and returns it in the response headers.
- Concurrency and pooling are controlled by policy `limits`:
  - `max_concurrency_io` (read/write/patch/delete)
  - `max_concurrency_scan` (glob/grep)
  - `max_db_connections` (SQLite/Postgres pool size)

### SQLite

Run:

```bash
cd db-vfs
cargo run -p db-vfs-service -- \
  --sqlite ./db-vfs.sqlite \
  --policy ./policy.example.toml \
  --listen 127.0.0.1:8080
```

### Postgres

Run (requires building with `postgres` enabled):

```bash
cd db-vfs
cargo run -p db-vfs-service --features postgres -- \
  --postgres "postgres://user:pass@localhost:5432/db_vfs" \
  --policy ./policy.example.toml \
  --listen 127.0.0.1:8080
```

Endpoints (JSON POST):

- `/v1/read`
- `/v1/write`
- `/v1/patch`
- `/v1/delete`
- `/v1/glob`
- `/v1/grep`

Minimal example:

```bash
curl -sS http://127.0.0.1:8080/v1/write \
  -H 'content-type: application/json' \
  -H 'authorization: Bearer CHANGE_ME' \
  -d '{"workspace_id":"w1","path":"docs/a.txt","content":"hello","expected_version":null}'

curl -sS http://127.0.0.1:8080/v1/grep \
  -H 'content-type: application/json' \
  -H 'authorization: Bearer CHANGE_ME' \
  -d '{"workspace_id":"w1","query":"hello","regex":false,"glob":"docs/**/*.txt","path_prefix":null}'
```
