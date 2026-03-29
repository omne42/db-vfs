# Policy

Service policy is loaded as `db_vfs_core::policy::VfsPolicy` (`.toml` or `.json`).

Start from [`policy.example.toml`](policy.example.toml).

## Default highlights

| Section | Key | Default |
| --- | --- | --- |
| `permissions` | `read/glob/grep` | `false` |
| `permissions` | `write/patch/delete` | `false` |
| `permissions` | `allow_full_scan` | `false` |
| `audit` | `required` | `true` |
| `limits` | `max_walk_ms` | `Some(2000)` |

`policy.example.toml` is an opt-in example for a real service deployment, not a dump of literal
`VfsPolicy::default()` values.

## `allowed_workspaces` matching

Supported patterns:

- `*`: allow all workspaces.
- exact match, e.g. `ws-prod`.
- trailing wildcard prefix, e.g. `team-a-*`.

`workspace_id` values themselves are always literal identifiers. They cannot contain `*`, so the
wildcard syntax stays reserved for auth policy matching and never collides with a real namespace.

Not supported:

- multiple `*` (`foo*bar*`)
- middle wildcard (`a*b`)
- malformed patterns rejected by policy validation.

## Token hash generation

Input is raw token bytes exactly as sent by client; no extra trimming beyond your shell quoting.
Use `auth.tokens[*].token` for pre-hashed `sha256:<64 hex>` values. `auth.tokens[*].token_env_var`
always loads the raw bearer token from the environment and hashes that plaintext at startup.
A literal `sha256:<64 hex>` value in `token_env_var` is rejected as invalid plaintext bearer
syntax instead of being treated as a pre-hashed token.
Plaintext env-backed tokens must also be valid HTTP Bearer tokens (`token68` syntax), so values
with whitespace or disallowed punctuation are rejected at startup instead of becoming impossible
runtime credentials.

```bash
printf '%s' 'dev-token-change-me' | sha256sum
# then use: token = "sha256:<hex>"
```

## Limits reference

Critical bounded fields include:

- request bytes: `max_read_bytes`, `max_write_bytes`, `max_patch_bytes`
- scan bounds: `max_results`, `max_walk_files`, `max_walk_entries`, `max_walk_ms`, `max_line_bytes`
- service runtime: `max_io_ms`, concurrency and DB pool limits
- rate limit: `max_requests_per_ip_per_sec`, `max_requests_burst_per_ip`, `max_rate_limit_ips`

Budget semantics:

- `max_io_ms` applies to non-scan requests (`read`/`write`/`patch`/`delete`) and bounded pool wait/connect time.
- Service startup migrations also reuse `max_io_ms` for their connect/lock budget.
- Omitting `limits.max_walk_ms` in JSON/TOML policy config deserializes to the default `Some(2000)`.
- `glob` and `grep` use `max_walk_ms` as their runtime budget.
- `max_walk_ms = None` keeps scan execution unbounded; DB pool wait/connect stays bounded by `max_io_ms`.
- When `audit.required = true`, the same request runtime budget also caps the remaining append+flush wait after VFS execution begins.
- Required audit append+flush keeps the originating `max_concurrency_io` / `max_concurrency_scan` permit until the request can actually return.
- SQLite `busy_timeout` and Postgres `statement_timeout` / `lock_timeout` are reset to the active request or startup migration budget.
- When `secrets.redact_regexes` is non-empty, size budgeting must account for both the original
  scan input and a bounded redacted copy. Treat one in-flight redacted scan as up to
  `2 * max_read_bytes` of content memory.

Secrets semantics:

- `secrets.replacement` must not contain control characters.
- Multi-line `secrets.redact_regexes` matches are redacted with original line-break structure preserved so ranged `read` and `grep` stay line-oriented.
- Ranged `read` with redaction enabled rejects files whose original content already exceeds
  `max_read_bytes`, even if the requested line slice would be smaller after redaction.

## Audit behavior matrix

| `audit.jsonl_path` | `audit.required` | Startup behavior |
| --- | --- | --- |
| unset | `true/false` | audit disabled |
| set + writable | `true/false` | audit enabled |
| set + open fails | `true` | startup fails |
| set + open fails | `false` | startup continues, audit disabled |

`flush_every_events` and `flush_max_interval_ms` are valid only when `jsonl_path` is set.

When audit is enabled and `audit.required = true`, runtime behavior is fail-closed: each request
waits for its audit record to append+flush successfully, the originating concurrency permit stays
held until that wait finishes, and the same request runtime budget continues to cover the required
audit wait. Losing the audit worker, write/flush failures, or exhausting the remaining request
budget turns into a visible `503 audit_unavailable` failure instead of silent event loss or a
panic-driven connection abort. That error means the request outcome may already be committed, so
callers should verify state before retrying non-idempotent writes.
