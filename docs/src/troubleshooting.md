# Troubleshooting

Use this template for each failure:

`Symptom -> Likely cause -> Immediate checks -> Fix -> Retry? -> Success criteria`

## `401 unauthorized`

- Symptom: response `401` + `code=unauthorized`.
- Likely cause: missing/invalid bearer token.
- Immediate checks: `Authorization: Bearer <token>`, token hash in policy.
- Fix: align runtime token and policy token hash/env var.
- Retry: yes, after fixing auth.
- Success criteria: request returns expected 2xx/4xx business result.

## `403 forbidden`

- Symptom: `403` with `not_permitted` / `secret_path_denied`.
- Likely cause: policy blocks operation or workspace/path.
- Immediate checks: `permissions.*`, `allowed_workspaces`, `secrets.deny_globs`.
- Fix: adjust policy for intended scope.
- Retry: only after policy fix.
- Success criteria: operation succeeds on allowed workspace/path.

## `409 conflict`

- Symptom: CAS mismatch.
- Likely cause: stale `expected_version`.
- Immediate checks: read latest file/version first.
- Fix: retry with latest version and idempotent write/patch logic.
- Retry: yes.
- Success criteria: update/delete accepted with current version.

## `408 timeout`

- Symptom: `timeout` under load or large requests.
- Likely cause: `limits.max_io_ms` too low or backend contention.
- Immediate checks: server logs with `request_id`, DB health, pool saturation.
- Fix: tune limits and query scope; reduce request payload/scan scope.
- Retry: yes, exponential backoff (3-5 attempts max).
- Success criteria: sustained requests complete within budget.

## `429 rate_limited`

- Symptom: `rate_limited`.
- Likely cause: per-IP burst exhausted.
- Immediate checks: caller request rate, gateway throttling.
- Fix: throttle caller and tune rate-limit policy.
- Retry: yes, with backoff and jitter.
- Success criteria: no repeated immediate 429 for steady traffic.

## `503 busy`

- Symptom: `busy` at peak concurrency.
- Likely cause: semaphore/pool saturation.
- Immediate checks: `limits.max_concurrency_io`, `max_concurrency_scan`, `max_db_connections`.
- Fix: tune concurrency, reduce expensive operations.
- Retry: yes, with bounded retries.
- Success criteria: queue drains and requests recover to normal latencies.

## `415 unsupported_media_type`

- Symptom: `code=unsupported_media_type`.
- Likely cause: missing/invalid JSON content type.
- Immediate checks: `content-type: application/json`.
- Fix: send proper JSON headers/body.
- Retry: yes after fixing request format.
- Success criteria: parser reaches business handler.
