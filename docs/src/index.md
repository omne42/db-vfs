# db-vfs

`db-vfs` is a DB-backed virtual filesystem for service workloads.

It provides six operations:

- `read`: read a file (optionally by line range).
- `write`: create or CAS-update a file.
- `patch`: CAS-apply unified diff to a file.
- `delete`: delete with optional CAS version.
- `glob`: list paths by glob pattern.
- `grep`: search text under scoped traversal.

## Safety model

`db-vfs` enforces a policy-first model:

- **Permissions** decide which operations are allowed.
- **Limits** bound CPU/memory/DB work.
- **Secrets** deny sensitive paths and redact output.
- **Traversal** skips noisy paths for scan performance.
- **Auth** binds tokens to workspace allowlists.

Scan operations are **scoped and budgeted**: callers must provide `path_prefix` (or a safe literal
prefix must be derivable from `glob`), and traversal is constrained by `limits.*` budgets.

## High-concurrency expectations

High concurrency assumes all of the following are configured correctly:

- `limits.max_concurrency_io`, `limits.max_concurrency_scan`
- `limits.max_db_connections`, `limits.max_io_ms`
- per-IP rate limiting (`limits.max_requests_per_ip_per_sec`, `max_requests_burst_per_ip`, `max_rate_limit_ips`)

## Start here

- First deployment: read [`Policy`](policy.md) → [`Security`](security.md) → [`Storage Backends`](storage.md)
- API integration: read [`Concepts`](concepts.md) → [`HTTP API`](http-api.md)
- Production operations: read [`Observability`](observability.md) → [`Troubleshooting`](troubleshooting.md)
