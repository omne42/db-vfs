# HTTP API

The service exposes JSON POST endpoints:

- `/v1/read`
- `/v1/write`
- `/v1/patch`
- `/v1/delete`
- `/v1/glob`
- `/v1/grep`

All requests require:

- `content-type: application/json`
- `authorization: Bearer <token>` (unless started with `--unsafe-no-auth`)

Notes on success responses:

- `read`/`write`/`patch`/`delete` include `requested_path` (normalized input) and `path` (normalized stored path).
- `glob`/`grep` include scan counters and `skipped_*` diagnostics to make partial results explainable.

## Errors

Errors are returned as JSON with an HTTP status code:

```json
{ "code": "invalid_path", "message": "..." }
```

5xx errors use a non-leaky `"internal error"` message.

### Status codes

- `400`: `invalid_path`, `invalid_regex`, `invalid_json`, `patch`
- `401`: `unauthorized` (missing/invalid `Authorization`)
- `403`: `forbidden`, `not_permitted`, `secret_path_denied`
- `404`: `not_found`
- `408`: `timeout`
- `409`: `conflict`
- `413`: `payload_too_large`, `input_too_large`, `file_too_large`, `quota_exceeded`
- `415`: `unsupported_media_type` (missing/invalid `content-type`)
- `429`: `rate_limited`
- `503`: `busy`

## Tracing

- The service accepts and returns `x-request-id`.
- If missing, it generates one and includes it on the response.
