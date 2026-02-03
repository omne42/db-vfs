# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `db-vfs-service`: optional Postgres backend via `--postgres` (build with `--features postgres`).
- Policy: `auth` section with bearer tokens + per-token workspace allowlist.
- Policy: `auth.tokens[].token_env_var` to load a plaintext token from an environment variable at runtime.
- Policy: `auth.tokens[].token = "sha256:<64 hex>"` for storing hashed tokens.
- Policy: `permissions.allow_full_scan` to gate `path_prefix = ""` scans for `glob`/`grep`.
- `db-vfs-service`: `--unsafe-no-auth` for local development.
- Policy: `limits.max_concurrency_io`, `limits.max_concurrency_scan`, and `limits.max_db_connections`.
- Policy: `limits.max_io_ms` for service IO timeouts.
- Policy: `limits.max_requests_per_ip_per_sec` and `limits.max_requests_burst_per_ip` for per-IP rate limiting.
- Policy: `limits.max_rate_limit_ips` to cap tracked IPs for rate limiting.
- Policy: `traversal.skip_globs` to skip paths during scan traversal (performance only).
- `db-vfs-service`: `x-request-id` header (propagated or generated) for request tracing.
- `db-vfs-core`: `glob_utils` helpers for glob normalization/validation.
- Docs: add `SECURITY.md` threat model and guidance.
- Dev: add `rust-toolchain.toml`, `rustfmt.toml`, `scripts/gate.sh`, and `githooks/` (Conventional Commits + changelog gate).
- Dev: pre-commit guard to block oversized Rust files (`DB_VFS_MAX_RS_LINES`).
- Docs: add mdBook docs under `docs/` and an LLM-friendly bundle (`llms.txt`, `docs/llms.txt`).

### Changed

- Docs: clarify `path_prefix` scoping and `expected_version` CAS semantics.
- Docs: generate `llms.txt` bundles from `docs/src/SUMMARY.md` (stable ordering).
- Docs: `llms.txt` now includes `CHANGELOG.md` and starts with YAML front matter metadata.
- Dev: `./scripts/gate.sh` checks that `llms.txt` outputs are up to date.
- `db-vfs-service`: require `Authorization: Bearer <token>` by default (configured via policy).
- `db-vfs-service`: remove global VFS mutex; use per-request store with concurrency limiting.
- `db-vfs-service`: validate bearer token before parsing JSON request bodies.
- `db-vfs-service`: use r2d2 connection pooling for SQLite/Postgres stores.
- `db-vfs-service`: apply request timeouts for IO endpoints and set Postgres `statement_timeout`.
- `db-vfs-service`: apply a small service timeout headroom over `limits.max_io_ms` (to allow DB timeouts to fire first).
- `db-vfs-service`: add per-IP token-bucket rate limiting middleware.
- `db-vfs-service`: restrict `--unsafe-no-auth` to loopback binds by default.
- `db-vfs-service`: refactor server module into submodules to keep Rust files small.
- Policy: `auth.tokens[].token` now requires `sha256:<64 hex chars>` (use `token_env_var` for plaintext tokens).
- `db-vfs-core`: expand default `secrets.deny_globs` (e.g. `.omne_agent_data/**`, `.ssh/**`, `.aws/**`, `.kube/**`).
- `db-vfs-service`: bound the in-memory rate limiter map to avoid unbounded growth.
- Policy parsing: deny unknown fields (`serde(deny_unknown_fields)`).
- `policy.example.toml`: safer defaults (no write/patch/delete; auth enabled; full scan disabled).
- Store API: split file reads into `get_meta` + `get_content`.

### Fixed

- Dev: remove unused variable warning when `db-vfs-service` is built without `postgres`.
- `db-vfs-service`: avoid panic on invalid/missing DB backend args.
- `db-vfs-service`: attempt to interrupt in-flight SQLite queries on timeout to reduce lingering background work.
- `db-vfs-service`: avoid blocking the async runtime when attempting SQLite timeout interrupts.
- `db-vfs-service`: include semaphore queueing time in request timeouts (avoid unbounded waits under load).
- `db-vfs-service`: ensure SQLite interrupts are still requested even if timeout races cancel-handle installation.
- Enforce size limits before fetching DB content to avoid memory DoS from oversized stored files.
- `glob`/`grep`: report `scan_limit_reason=Entries/Files` when truncated by DB prefix list limit.
- `db-vfs-service`: request body size limit and non-leaky 5xx error messages.
- `db-vfs-service`: hash bearer tokens once and compare in constant time; avoid retaining plaintext tokens.
- `db-vfs-core`: cap `path`/`path_prefix`, glob patterns, and grep queries to avoid oversized input allocations.
- Policy: validate `limits.max_io_ms` and cap request size limits to 256MB.
- `db-vfs-service`: map `input_too_large`, `file_too_large`, `secret_path_denied`, and `patch` errors to 4xx status codes.
- `db-vfs`: validate `workspace_id` and ensure `read` respects `limits.max_read_bytes` for line ranges.
- `db-vfs`: cap `read` retries when content cannot be loaded to avoid infinite loops.
- `glob`: report `scanned_files` separately from `scanned_entries` and respect `traversal.skip_globs`.
- `patch`: fetch existing content using `limits.max_read_bytes` (consistent with read limits).
- Lint: fix `clippy::large_enum_variant`.
- Docs: fix `Getting started` instructions to enable `permissions.write` when using `policy.example.toml`.
- `db-vfs-core`: validate `secrets.deny_globs`, `traversal.skip_globs`, and `secrets.replacement` sizes to avoid pathological policies.
- `db-vfs-service`: align SQLite `busy_timeout` with `limits.max_io_ms` (capped).
- Docs: document HTTP status codes and `429 rate_limited`.
- `db-vfs-service`: return JSON error bodies for invalid JSON / missing `content-type` (new codes: `invalid_json`, `unsupported_media_type`, `payload_too_large`).
- `glob`/`grep`: derive a safer `path_prefix` from glob patterns that end with `/` (avoid overscanning sibling prefixes).

## [0.1.0] - 2026-01-31

### Added

- `db-vfs-core`: Policy + Secrets + Limits, error codes, path normalization, deny+redaction helpers.
- `db-vfs`: SQLite (default) + Postgres (feature) stores and VFS ops: `read/write/patch/delete/glob/grep`.
- `db-vfs-service`: HTTP JSON API for the VFS (SQLite).
- Schema migrations for SQLite/Postgres (`files` table with `(workspace_id, path)` primary key + `updated_at_ms` index).
- Tests:
  - SQLite VFS semantic tests (CAS conflicts, deny globs, grep/glob scoping).
  - HTTP smoke test for `write` + `read`.
