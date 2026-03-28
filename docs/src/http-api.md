# HTTP API

All endpoints are `POST` JSON.

## Request prerequisites

- Header `content-type: application/json`
- Header `authorization: Bearer <token>` (unless service runs with `--unsafe-no-auth`)
  - `<token>` must satisfy HTTP Bearer `token68` syntax; whitespace-bearing or malformed tokens are rejected before auth matching.

## Endpoint contracts

### `/v1/read`

Request fields:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `workspace_id` | string | yes | literal namespace; no whitespace, path separators, `:`, `..`, or `*` |
| `path` | string | yes | root-relative path |
| `start_line` | u64|null | no | must pair with `end_line`; `max_read_bytes` applies to the returned slice after redaction |
| `end_line` | u64|null | no | must pair with `start_line`; multi-line redaction preserves line numbering before the slice is selected |

Response fields: `requested_path`, `path`, `bytes_read`, `content`, `truncated`, `start_line`, `end_line`, `version`.

### `/v1/write`

Request fields: `workspace_id`, `path`, `content`, `expected_version` (`u64|null`).

`expected_version` is scoped to a monotonically increasing per-path version stream. Deleting and
recreating the same `(workspace_id, path)` does not reset the version counter.

Response fields: `requested_path`, `path`, `bytes_written`, `created`, `version`.

### `/v1/patch`

Request fields: `workspace_id`, `path`, `patch`, `expected_version` (`u64`, required).

Response fields: `requested_path`, `path`, `bytes_written`, `version`.

### `/v1/delete`

Request fields: `workspace_id`, `path`, `expected_version` (`u64|null`), `ignore_missing`
(`bool`, optional, default `false`).

When `ignore_missing = true`, deleting a missing target returns `200` with `deleted = false`
instead of `404 not_found`.

With `expected_version`, stale delete tokens from an earlier file lifetime return `409 conflict`
after recreate; they do not silently match a new file that reused the same path.

Response fields: `requested_path`, `path`, `deleted`.

### `/v1/glob`

Request fields: `workspace_id`, `pattern`, `path_prefix` (`string|null`).

Response fields: `matches`, `truncated`, `scanned_files`, `scanned_entries`,
`scan_limit_reached`, `scan_limit_reason`, `elapsed_ms`, and public skip counters.

`scanned_entries` excludes paths denied by `secrets.deny_globs`; detailed secret-denied counts are
kept internal/audit-only and are not serialized in the public response.

### `/v1/grep`

Request fields: `workspace_id`, `query`, `regex` (`bool`), `glob` (`string|null`), `path_prefix` (`string|null`).

When `regex = true`, the pattern is evaluated against each logical line independently. Patterns
that can consume `\n` or `\r` are rejected with `invalid_regex`; multi-line whole-file regex
matching is not part of this endpoint contract.

Response fields: `matches[] { path, line, text, line_truncated }`, plus scan diagnostics (same
shape as `glob`).

`matches[].text` remains single-line. `secrets.replacement` cannot contain control characters, and
multi-line secret redaction preserves original line boundaries before per-line results are emitted.

## Path normalization rules

- `workspace_id` must be a literal identifier; `*` is reserved for auth allowlist patterns and is
  rejected in requests;
- must be root-relative;
- no leading `/`, no `..`, no control chars, no leading/trailing whitespace;
- normalized path is echoed in response fields.

## Errors

Error body:

```json
{ "code": "<stable_code>", "message": "<human readable>" }
```

Common codes:

- `invalid_json_syntax`, `invalid_json_schema`, `invalid_json`, `unsupported_media_type`, `payload_too_large`
- `unauthorized`, `not_permitted`, `secret_path_denied`
- `not_found`, `conflict`, `timeout`, `busy`, `rate_limited`, `audit_unavailable`

`patch` means “unified diff apply/parse failure” (not the endpoint name).

`audit_unavailable` means required audit append/flush failed after request handling started. The
operation may already have completed, so callers should verify state before replaying writes.

## Retry guidance

- `408 timeout` (operation may still complete; typically pool/lock wait or in-flight execution), `429 rate_limited`, `503 busy`: exponential backoff (e.g., 100ms, 250ms, 500ms, max 3-5 retries).
- `503 audit_unavailable`: restore audit backend health first; for writes, check current file state before deciding whether to retry.
- `409 conflict`: fetch latest version and retry with fresh `expected_version`.
- `400/401/403/415`: fix request/policy first; do not blind-retry.
