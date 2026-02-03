# Troubleshooting

## `401 unauthorized`

- Missing or invalid `Authorization` header.
- Token does not match any configured auth rule.

## `403 forbidden`

- Workspace is not allowed for the current token.
- Operation is disabled by policy.

## `408 timeout`

- Request exceeded the configured wall-clock timeout budget.
- For SQLite, the service attempts to interrupt in-flight queries (best-effort).

## `413 payload too large`

- Request exceeded `limits.max_read_bytes` / `max_write_bytes` / `max_patch_bytes`.

## `415 unsupported media type`

- Missing or invalid `content-type`; the API expects `application/json`.

## `429 too many requests`

- Per-IP rate limit exceeded (`limits.max_requests_per_ip_per_sec` / `max_requests_burst_per_ip`).

## `503 busy`

- The service is at its configured concurrency limit.
