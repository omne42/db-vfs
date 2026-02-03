# Security

## Threat model

`db-vfs` is a library + HTTP service for performing virtual filesystem operations against a
database-backed store with an explicit, caller-provided policy (`VfsPolicy`).

It enforces policy checks in-process. It is designed for *trusted* deployments (e.g. internal
services) where you still want strong, explicit guardrails.

## Not an OS sandbox

This project does **not** provide OS-level isolation. If you need strong isolation, run the service
inside an OS sandbox / container / VM and apply network controls.

## Auth & secrets

- The service requires `Authorization: Bearer <token>` by default.
- Prefer storing only `sha256:<64 hex>` token hashes in committed policy files.
- For plaintext tokens, use `auth.tokens[].token_env_var` so secrets live in the process environment.
- `--unsafe-no-auth` is restricted to loopback binds by default; using it on a public interface is
  dangerous.
- For production deployments, enforce “no-unsafe-flags” in your service manager / startup scripts
  (e.g. refuse `--unsafe-no-auth-allow-non-loopback`).

Secrets are mitigated via:

- Path deny rules (`policy.secrets.deny_globs`) to block direct access.
- Regex redaction (`policy.secrets.redact_regexes`) applied to `read`/`grep` output.

## Resource limits & DoS

Policy limits bound work and memory:

- Request sizes: `max_read_bytes`, `max_write_bytes`, `max_patch_bytes`.
- Scan bounds: `max_walk_entries`, `max_walk_files`, `max_walk_ms`, `max_results`.
- Service concurrency: `max_concurrency_io`, `max_concurrency_scan`, `max_db_connections`.
- Service timeouts: `max_io_ms` (plus Postgres `statement_timeout` when enabled).
- Per-IP rate limiting: `max_requests_per_ip_per_sec`, `max_requests_burst_per_ip`,
  `max_rate_limit_ips`.

These are best-effort safeguards, not a replacement for OS-level limits and network-level
mitigations (load balancers, WAF, reverse proxy rate limits, etc.).

SQLite note: database file permissions depend on the process `umask`; set a restrictive `umask`
in your service manager / startup script on multi-user systems.

## Timeout semantics

Service-layer timeouts return early to the client, but the underlying blocking DB operation may
continue briefly in the background. For SQLite, the service attempts to interrupt in-flight queries
on timeout; for Postgres, `statement_timeout` is configured. Treat timeouts as a *budgeting* and
*backpressure* mechanism, not a hard cancel.

## Path probing side-channels

If untrusted callers can control `path` inputs and observe detailed errors/timing, they may be able
to infer information about stored paths (existence, deny rules, etc.).

If this matters, reduce observable error detail, enforce rate limits, and run behind an API gateway.

## Reporting

If you discover a security issue, please open an issue with:

- Minimal reproduction
- Expected vs actual behavior
- Environment details (OS, Rust toolchain, DB backend)
