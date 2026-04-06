# Policy

Service policy is loaded as `db_vfs_service::policy::ServicePolicy` (`.toml` or `.json`).

Its core VFS subset projects to `db_vfs_core::policy::VfsPolicy`; auth/audit/runtime-only fields
stay in the service layer instead of leaking into `db-vfs-core`.

The service binary backend is feature-gated independently from policy loading:

- default build enables SQLite via `sqlite-bundled`
- Postgres-only build uses `--no-default-features --features postgres`
- plain SQLite build without bundled libsqlite uses `--no-default-features --features sqlite`

Start from [`policy.example.toml`](policy.example.toml).

Policy files must be direct regular files. The loader rejects symlinks, directories, FIFOs,
device nodes, and other non-regular paths before opening them, so startup cannot block
indefinitely on a special file or silently follow an unexpected link target.

When `trust_mode=trusted`, env interpolation is applied only inside parsed JSON/TOML string
values. Comments and non-string fields are not treated as template input. When
`trust_mode=untrusted`, those same string-value placeholders are rejected instead of being
expanded.

## Default highlights

| Section | Key | Default |
| --- | --- | --- |
| `permissions` | `read/glob/grep` | `false` |
| `permissions` | `write/patch/delete` | `false` |
| `permissions` | `allow_full_scan` | `false` |
| `audit` | `required` | `true` |
| `limits` | `max_walk_ms` | `Some(2000)` |

`policy.example.toml` is an opt-in example for a real service deployment, not a dump of literal
`ServicePolicy::default()` values.

## `allowed_workspaces` matching

Supported patterns:

- `*`: allow all workspaces.
- exact match, e.g. `ws-prod`.
- trailing wildcard prefix, e.g. `team-a-*`.
  This requires at least one additional character after the prefix, so `team-a-*` matches
  `team-a-123` but not the bare `team-a-`.

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
- JSON body buffering and decode also consume the frontdoor `max_io_ms` budget, including `glob` /
  `grep` requests before scan execution starts.
- Once the body is buffered, the service does a lightweight `workspace_id` auth preflight before
  it constructs the final typed request body, so token-valid but workspace-disallowed `write` /
  `patch` requests fail before allocating their full request strings.
- Service startup migrations also reuse `max_io_ms` for their connect/lock budget.
- Omitting `limits.max_walk_ms` in JSON/TOML policy config deserializes to the default `Some(2000)`.
- `glob` and `grep` use `max_walk_ms` as their runtime budget.
- `max_walk_ms = None` keeps scan execution unbounded; DB pool wait/connect stays bounded by `max_io_ms`.
- When `audit.required = true`, the same request runtime budget also caps the remaining append+flush wait after VFS execution begins.
- Required audit append+flush keeps the originating `max_concurrency_io` / `max_concurrency_scan` permit until the request can actually return.
- The same permit retention applies to early rejects that already acquired a request slot, including invalid content type / JSON / schema, invalid `workspace_id`, and token-authorized requests whose workspace is still denied by `allowed_workspaces`.
- Required audit permit retention also applies to VFS-path `401 unauthorized` and `429 rate_limited`
  responses once the service can classify the path as IO vs scan work.
- SQLite `busy_timeout` and Postgres `statement_timeout` / `lock_timeout` are reset to the active request or startup migration budget.
- Capacity planning for scan workloads should budget up to `2 * max_read_bytes` per in-flight scan when `secrets.redact_regexes` is enabled, because the service may need to hold both the original content and a bounded redacted copy at once.

Secrets semantics:

- `secrets.replacement` must not contain control characters.
- `DbVfs::new_validated()` rebuilds policy-derived matchers from the validated policy.
- `DbVfs::new_with_supplied_matchers_validated()` and
  `DbVfs::try_new_with_supplied_matchers_validated()` are the canonical strict validated
  constructors for caller-supplied matchers and fail fast on mismatch.
- Deprecated compatibility aliases `DbVfs::new_with_matchers_validated()` and
  `DbVfs::try_new_with_matchers_validated()` preserve that same fail-fast behavior; they no longer
  imply or permit silent matcher rebuild fallback.
- `patch` is intentionally unavailable while `secrets.redact_regexes` is active; diff application
  against raw stored text would otherwise let callers probe masked content through context-match
  success or failure.
- Multi-line `secrets.redact_regexes` matches are redacted with original line-break structure preserved so ranged `read` and `grep` stay line-oriented.
- Redaction-enabled ranged `read` rejects raw files larger than `max_read_bytes` before full-content load, and also rejects redacted whole-file intermediates that would overflow the same budget.

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
panic-driven connection abort. Required-audit queue saturation also fails closed immediately with
the same error instead of blocking forever on the enqueue path. That error means the request
outcome may already be committed, so callers should verify state before retrying non-idempotent
writes.

When `audit.required = false`, sink failures still fail open, but the optional logger now rotates
the possibly corrupted JSONL file and respawns a fresh worker on the next event instead of
remaining permanently disconnected for the rest of the process lifetime.
