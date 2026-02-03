# Policy

The service loads a policy file (`.toml` or `.json`) into `db_vfs_core::policy::VfsPolicy`.

Start from `policy.example.toml` (also linked as [`policy.example.toml`](policy.example.toml) in the built docs).

## Sections

### `[permissions]`

Toggles operations on/off:

- `read`, `glob`, `grep`, `write`, `patch`, `delete`
- `allow_full_scan`: allow `path_prefix=""` for `glob`/`grep`

### `[auth]` / `[[auth.tokens]]`

The HTTP service requires:

```
Authorization: Bearer <token>
```

Each token is restricted to a workspace allowlist (`allowed_workspaces`):

- exact: `"ws1"`
- prefix: `"team1-*"`
- all: `"*"`

Tokens can be provided as:

- `token = "sha256:<64 hex chars>"` (recommended for committed policies)
- `token_env_var = "DB_VFS_TOKEN"` (load plaintext token at runtime)

### `[limits]`

Budgets to control CPU/memory/DB load, including:

- request sizes: `max_read_bytes`, `max_write_bytes`, `max_patch_bytes`
- scan budgets: `max_walk_entries`, `max_walk_files`, `max_walk_ms`, `max_results`
- service: `max_io_ms`, `max_concurrency_io`, `max_concurrency_scan`, `max_db_connections`
- rate limiting: `max_requests_per_ip_per_sec`, `max_requests_burst_per_ip`, `max_rate_limit_ips`

### `[secrets]`

Controls deny rules and text redaction:

- `deny_globs`: deny direct access to matching paths
- `redact_regexes`: applied to returned text
- `replacement`: string used to replace redacted matches

### `[traversal]`

Scan-only skipping rules:

- `skip_globs`: skipped during `glob`/`grep` traversal (performance only; does not deny direct reads)

### `[audit]`

Service-only observability:

- `jsonl_path`: optional JSONL log path; when set, `db-vfs-service` appends one JSON object per request.
- `required`: whether audit initialization failures should fail service startup (default: `true`).
