# HTTP API

All endpoints are `POST` JSON.

## Request prerequisites

- Header `content-type: application/json`
- Header `authorization: Bearer <token>` (unless service runs with `--unsafe-no-auth`)

## Endpoint contracts

### `/v1/read`

Request fields:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `workspace_id` | string | yes | namespace |
| `path` | string | yes | root-relative path |
| `start_line` | u64|null | no | must pair with `end_line` |
| `end_line` | u64|null | no | must pair with `start_line` |

Response fields: `requested_path`, `path`, `bytes_read`, `content`, `truncated`, `start_line`, `end_line`, `version`.

### `/v1/write`

Request fields: `workspace_id`, `path`, `content`, `expected_version` (`u64|null`).

Response fields: `requested_path`, `path`, `bytes_written`, `created`, `version`.

### `/v1/patch`

Request fields: `workspace_id`, `path`, `patch`, `expected_version` (`u64`, required).

Response fields: `requested_path`, `path`, `bytes_written`, `version`.

### `/v1/delete`

Request fields: `workspace_id`, `path`, `expected_version` (`u64|null`).

Response fields: `requested_path`, `path`, `deleted`.

### `/v1/glob`

Request fields: `workspace_id`, `pattern`, `path_prefix` (`string|null`).

Response fields: `matches`, `truncated`, `scanned_files`, `scanned_entries`, `scan_limit_reached`, `scan_limit_reason`, `elapsed_ms`, and skip counters.

### `/v1/grep`

Request fields: `workspace_id`, `query`, `regex` (`bool`), `glob` (`string|null`), `path_prefix` (`string|null`).

Response fields: `matches[] { path, line, text, line_truncated }`, plus scan diagnostics (same shape as `glob`).

## Path normalization rules

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
- `not_found`, `conflict`, `timeout`, `busy`, `rate_limited`

`patch` means “unified diff apply/parse failure” (not the endpoint name).

## Retry guidance

- `408 timeout`, `429 rate_limited`, `503 busy`: exponential backoff (e.g., 100ms, 250ms, 500ms, max 3-5 retries).
- `409 conflict`: fetch latest version and retry with fresh `expected_version`.
- `400/401/403/415`: fix request/policy first; do not blind-retry.
