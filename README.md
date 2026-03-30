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

`workspace_id` is a literal namespace, not a glob. It must be non-empty and must not contain
whitespace, path separators, `:`, `..`, or `*`. The `*` character is reserved for auth
`allowed_workspaces` pattern syntax.

`ignore_missing = true` makes `/v1/delete` idempotent for absent targets by returning
`200 {"deleted":false,...}`.

Line-range `read` still enforces `max_read_bytes` on the returned slice. Without secret redaction
rules, the store can stop after the requested range instead of materializing the whole file. When
secret redaction rules are active, both the raw backing file and the redacted whole-file
intermediate must fit within the same budget; otherwise the request fails with `file_too_large`
before slice extraction. Line-oriented reads treat `\n`, `\r\n`, and lone `\r` as line
boundaries.

`grep` is line-oriented for both literal and regex queries. `regex = true` patterns that can
consume `\n` or `\r` are rejected instead of silently behaving like whole-file regex search, and
literal queries containing `\n` or `\r` short-circuit to no matches without forcing content loads.
Line numbering and `matches[].text` follow the same `\n` / `\r\n` / lone `\r` line-boundary
semantics.

`expected_version` is monotonic per `(workspace_id, path)` even across delete/recreate. Recreating
a deleted file does not reset its version back to `1`, so stale CAS tokens cannot hit a new file
lifetime by accident.

## Security Baseline

- Keep auth enabled; avoid `--unsafe-no-auth` outside local isolated dev.
- Prefer `sha256:<64 hex>` tokens or env-backed runtime tokens.
- `auth.tokens[*].token_env_var` always carries the raw bearer token; only
  `auth.tokens[*].token` accepts a pre-hashed `sha256:<64 hex>` value.
- A literal `sha256:<64 hex>` string in `token_env_var` is rejected at startup because it is not a
  valid Bearer token value.
- If you use plaintext env-backed tokens, keep them valid HTTP Bearer tokens (`token68` syntax; no whitespace or disallowed punctuation).
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
- Omitting `limits.max_walk_ms` in policy config deserializes to the default `Some(2000)` scan budget.
- `max_walk_ms` bounds scan execution (`glob`/`grep`); `max_walk_ms = None` keeps scan runtime unbounded.
- `max_concurrency_io` / `max_concurrency_scan` are acquired before request body buffering and JSON schema decode, so malformed or oversized bodies cannot bypass service saturation gates.
- When `audit.required = true`, the originating request keeps its concurrency permit until append+flush completes.
- The same request runtime budget also caps any remaining required-audit append+flush wait after VFS execution begins.
- Service startup DB migrations also reuse `max_io_ms` for connect/lock budgeting, so startup cannot hang indefinitely under backend contention.
- SQLite `busy_timeout` and Postgres `statement_timeout`/`lock_timeout` follow the active request or startup migration budget.
- Scan requests still keep DB pool wait/connect bounded by `max_io_ms` even when `max_walk_ms = None`.
- When secret redaction rules are active, size scan concurrency for up to `2 * max_read_bytes` per in-flight scan because the service may hold both the original file content and a bounded redacted copy at once.

Secrets semantics:

- `secrets.replacement` must not contain control characters, so `read` line ranges and `grep.matches[].text` stay line-oriented.
- `db_vfs_core::redaction::SecretRedactor::from_rules()` enforces the same replacement size/control-character bounds as `VfsPolicy::validate()`, so direct crate callers cannot bypass them.
- `ValidatedVfsPolicy::new()` also proves that policy-derived secret/traversal matchers compile, so validated-policy constructor families do not defer matcher failures to runtime.
- `DbVfs::try_new_with_matchers_validated()` is the strict validated-matcher constructor; the older compatibility constructor still rebuilds policy-derived matchers on mismatch, but now emits a one-time warning instead of failing silently.
- Multi-line secret regexes are redacted with line structure preserved before ranged `read` slices or `grep` result lines are returned.
- When redaction rules are active, `grep` evaluates literal/regex matches against that redacted line view instead of the hidden raw secret text, so masked content cannot still act as a match oracle.
- `grep` and redaction-backed ranged `read` also budget redaction-expanded intermediates against `max_read_bytes`; over-budget redacted content is rejected or skipped as `file_too_large`.

## Observability / Audit

- `x-request-id` is accepted/echoed; invalid/missing IDs are replaced by service-generated IDs.
- Optional JSONL audit via `audit.jsonl_path`.
- Audit records include `auth_subject="sha256:<64 hex>"` whenever the service can derive a stable
  bearer-token fingerprint from the request, so successful requests, post-auth rejects, and
  syntactically valid unauthorized attempts can still be tied back to the same caller identity
  without writing raw tokens to disk.
- With `audit.required = true`, audit runs fail-closed after startup: each request waits for its
  audit record to append+flush successfully, keeps its originating concurrency slot until that
  wait finishes, and uses the same request runtime budget for the required audit wait; worker loss
  or audit-budget exhaustion turns audited traffic into a visible availability failure instead of
  silently dropping events.
- The same fail-closed permit retention also applies to early rejects that already consumed a
  request slot (for example invalid content type / JSON / schema, invalid `workspace_id`, or a
  disallowed workspace), so audited rejection paths cannot free concurrency before append+flush
  finishes.
- If required audit append/flush fails after startup, the service returns `503 audit_unavailable`;
  the operation may already have completed, so clients should verify state before retrying writes.
  The same error is used when required audit cannot finish within the request's remaining runtime budget.
- Audit path/glob redaction is conservative for malformed or pattern-based secret-ish inputs too;
  values such as `.env/../visible.txt`, `".[en]nv"`, or control-character variants are masked as
  `<secret>` instead of being written through to JSONL.
- Early rejects (unauthorized/invalid JSON/rate-limited) are audited with `workspace_id="<unknown>"`.
- Service logs use `tracing`; configure via `RUST_LOG`.

## Troubleshooting matrix

| HTTP | Common causes | First checks |
| --- | --- | --- |
| `401` | missing/invalid token | `Authorization`, token hash/env var |
| `403` | workspace/policy denied | `allowed_workspaces`, `permissions.*`, `secrets.deny_globs` |
| `409` | stale CAS version | re-read latest version before retry |
| `408` | timeout budget exceeded (operation status may be unknown) | `limits.max_io_ms`, `limits.max_walk_ms`, DB latency, pool/lock wait |
| `503` | concurrency saturation or required audit unavailable | `max_concurrency_*`, `max_db_connections`, audit worker / `audit.jsonl_path` health |

## More docs

- Docs entrypoints: `docs/README.md` and `docs/docs-system-map.md`
- Human docs (`mdBook`): `docs/` (`./scripts/docs.sh`)
- LLM bundle: `llms.txt` and `docs/llms.txt` (`./scripts/llms.sh`)
