# HTTP API

All endpoints are `POST` JSON.

## Request prerequisites

- Header `content-type: application/json`
- Header `authorization: Bearer <token>` (unless service runs with `--unsafe-no-auth`)
  - `<token>` must satisfy HTTP Bearer `token68` syntax; whitespace-bearing or malformed tokens are rejected before auth matching.
- The service acquires the relevant concurrency permit before buffering/decoding JSON, and that body
  parse work is budgeted under `max_io_ms` even for scan endpoints. Slow request bodies can
  therefore fail with `408 timeout` before VFS execution starts.

## Endpoint contracts

### `/v1/read`

Request fields:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `workspace_id` | string | yes | literal namespace; no whitespace, path separators, `:`, `..`, or `*` |
| `path` | string | yes | root-relative path |
| `start_line` | u64|null | no | must pair with `end_line`; `max_read_bytes` applies to the returned slice. Without secret redaction rules, the store may stop once the requested range is collected instead of materializing the whole file |
| `end_line` | u64|null | no | must pair with `start_line`; multi-line redaction preserves line numbering before the slice is selected, and redaction-enabled ranged reads require both the raw file and any redacted whole-file intermediate to stay within `max_read_bytes`. Line boundaries treat `\n`, `\r\n`, and lone `\r` equivalently, including mixed-ending files |

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

`grep` is line-oriented for both literal and regex queries. When `regex = true`, patterns that can
consume `\n` or `\r` are rejected with `invalid_regex`; multi-line whole-file regex matching is
not part of this endpoint contract. Literal queries containing `\n` or `\r` are treated as
impossible line-spanning literals and return no matches without loading file contents.
Line numbering and emitted `matches[].text` use the same `\n` / `\r\n` / lone `\r` boundary rules,
including mixed-ending files.

Response fields: `matches[] { path, line, text, line_truncated }`, plus scan diagnostics (same
shape as `glob`).

`matches[].text` remains single-line. `secrets.replacement` cannot contain control characters, and
multi-line secret redaction preserves original line boundaries before per-line results are emitted.
When redaction rules are active, `grep` also evaluates literal/regex matches against that
redacted line view, so hidden secrets do not remain discoverable through match/no-match behavior.
If redaction would expand a scanned file beyond `limits.max_read_bytes`, `grep` skips that file and
counts it under `skipped_too_large_files` instead of allocating an unbounded redacted intermediate.

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
operation may already have completed, so callers should verify state before replaying writes. This
also covers required-audit waits that overrun the originating request's remaining runtime budget.
Required-audit queue saturation uses the same error instead of indefinitely blocking behind a full
audit channel.
Early rejects that already acquired a concurrency permit, such as invalid JSON/schema/content-type
or post-auth `workspace_id` rejection, also keep that permit until required audit append+flush
finishes.

The same required-audit fail-closed rule applies to VFS-path `401 unauthorized` and
`429 rate_limited` responses: once the service can classify the request as IO vs scan work, it
holds the matching `max_concurrency_*` slot until the audit append+flush succeeds or fails.

`busy` can be returned before JSON validation runs: the service acquires the relevant concurrency
permit before buffering and decoding the body, so saturated servers fail fast instead of spending
CPU on request bodies they cannot execute. Successful/erroring VFS requests keep that same permit
until any required audit append+flush completes.

When JSONL audit is enabled, the side-channel audit record also carries `auth_subject` whenever the
service can derive a stable bearer-token fingerprint (`sha256:<64 hex>`) for the caller. This
applies to successful requests, post-auth request rejections, and syntactically valid unauthorized
token attempts without persisting the raw credential.

## Retry guidance

- `408 timeout` (operation may still complete; typically pool/lock wait or in-flight execution), `429 rate_limited`, `503 busy`: exponential backoff (e.g., 100ms, 250ms, 500ms, max 3-5 retries).
- `503 audit_unavailable`: restore audit backend health first; for writes, check current file state before deciding whether to retry.
- `409 conflict`: fetch latest version and retry with fresh `expected_version`.
- `400/401/403/415`: fix request/policy first; do not blind-retry.
