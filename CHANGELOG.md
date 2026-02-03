# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- CI: add GitHub Actions workflows for gates/tests and docs deploy (mdBook → GitHub Pages).
- Dev: add `./scripts/setup-githooks.sh` helper to enable repo git hooks.
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
- Policy: `audit.jsonl_path` for an optional JSONL audit log (service-only).
- Policy: `audit.required` to control whether audit init failures should fail service startup (default: fail).
- Policy: `audit.flush_every_events` and `audit.flush_max_interval_ms` to tune JSONL audit flush batching (default: 32 events or 250ms).
- `db-vfs-service`: `--trust-mode trusted|untrusted` to restrict policy loading in untrusted environments.
- `db-vfs-service`: optional JSONL audit log when `audit.jsonl_path` is set.
- `db-vfs-service`: `${VAR}` env interpolation in policy files (trusted mode only).
- `db-vfs-core`: `glob_utils` helpers for glob normalization/validation.
- Docs: add `SECURITY.md` threat model and guidance.
- Dev: add `rust-toolchain.toml`, `rustfmt.toml`, `scripts/gate.sh`, and `githooks/` (Conventional Commits + changelog gate).
- Dev: pre-commit guard to block oversized Rust files (`DB_VFS_MAX_RS_LINES`).
- Docs: add mdBook docs under `docs/` and an LLM-friendly bundle (`llms.txt`, `docs/llms.txt`).
- Tests: add VFS regression coverage for grep/read redaction + limit semantics.
- Tests: add auth parsing/allowlist unit tests in `db-vfs-service`.
- Tests: add optional Postgres store integration test (requires `DB_VFS_TEST_POSTGRES_URL`).

### Changed

- Docs: include `llms.txt` in the built mdBook output (`docs/book/llms.txt`) for easy download when hosted.
- `db-vfs-service`: build with bundled SQLite (`rusqlite` feature `bundled`) for portability.
- `db-vfs-service`: run SQLite migrations with `busy_timeout` aligned to `limits.max_io_ms` (capped).
- Docs: recommend `./scripts/setup-githooks.sh` in development docs/README.
- Docs: clarify `path_prefix` scoping and `expected_version` CAS semantics.
- Docs: clarify that deny/skip globs like `dir/*` also apply to descendants under `dir/**`.
- Docs: generate `llms.txt` bundles from `docs/src/SUMMARY.md` (stable ordering).
- Docs: `llms.txt` now includes `CHANGELOG.md` and starts with YAML front matter metadata.
- Docs: clarify that GitHub Pages deploy requires enabling Pages (workflow skips deploy otherwise).
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
- `db-vfs-core`: `path`/`path_prefix` now reject leading/trailing whitespace (no implicit trimming).
- `db-vfs-service`: log an auth configuration summary (counts) at startup without retaining tokens.

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
- Docs: fix mdBook build (mdbook v0.5 config + SUMMARY nesting) and make `policy.example.toml` link work when building via `./scripts/docs.sh`.
- `db-vfs-service`: ensure request timeouts release the concurrency semaphore permit (avoid stuck permits under lingering blocking work).
- `db-vfs-service`: reduce per-request handler boilerplate (shared validation/permit/audit path).
- `db-vfs-service`: batch JSONL audit log flushes to reduce per-request IO overhead.
- `db-vfs-service`: audit log now includes early rejections (unauthorized, invalid JSON, rate limited) with `workspace_id="<unknown>"`.
- `db-vfs-service`: redact scan audit fields (`path_prefix`, `glob_pattern`) when they match secret deny rules.
- `db-vfs-service`: warn once if the audit log worker thread stops (audit events will be dropped).
- Policy: reject `audit.flush_*` when `audit.jsonl_path` is not set (service-only; avoids ignored settings).
- `grep`: reject empty queries and enforce `max_line_bytes` after redaction.
- `read`: enforce `max_read_bytes` after redaction and count `bytes_read` on returned content.
- `read`: return `conflict` (not `db`) when a file changes during retry-based content loading.
- `db-vfs`: `read`/`write`/`patch`/`delete` responses now include `requested_path` (normalized input).
- `glob`/`grep`: report additional skip counters (e.g. secret denies, traversal skips) to make partial results explainable.
- `db-vfs-service`: policy loader rejects non-regular files and avoids unbounded policy reads.
- `db-vfs-service`: `secret_path_denied` HTTP errors no longer include the denied path in the message.
- `db-vfs-service`: derive a lock path from `audit.jsonl_path` for cross-process audit locking (avoid `.lock.lock` naming edge cases).
- Policy: reject `audit.jsonl_path` values with leading/trailing whitespace or control characters.
- `db-vfs-service`: reject oversized bearer tokens in the `Authorization` header.
- CI: docs workflow no longer fails when GitHub Pages is not enabled (skips deploy).
- SQLite store: treat only UNIQUE/PRIMARYKEY constraint violations as `conflict` on create.
- `db-vfs-core`: `path`/`path_prefix` now reject control characters.

## [0.1.0] - 2026-01-31

### Added

- `db-vfs-core`: Policy + Secrets + Limits, error codes, path normalization, deny+redaction helpers.
- `db-vfs`: SQLite (default) + Postgres (feature) stores and VFS ops: `read/write/patch/delete/glob/grep`.
- `db-vfs-service`: HTTP JSON API for the VFS (SQLite).
- Schema migrations for SQLite/Postgres (`files` table with `(workspace_id, path)` primary key + `updated_at_ms` index).
- Tests:
  - SQLite VFS semantic tests (CAS conflicts, deny globs, grep/glob scoping).
  - HTTP smoke test for `write` + `read`.
