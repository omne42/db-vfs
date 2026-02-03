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

## Errors

Errors are returned as JSON with an HTTP status code:

```json
{ "code": "invalid_path", "message": "..." }
```

5xx errors use a non-leaky `"internal error"` message.

## Tracing

- The service accepts and returns `x-request-id`.
- If missing, it generates one and includes it on the response.
