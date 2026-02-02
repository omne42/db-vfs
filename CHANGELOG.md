# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `db-vfs-service`: optional Postgres backend via `--postgres` (build with `--features postgres`).
- Policy: `auth` section with bearer tokens + per-token workspace allowlist.
- Policy: `auth.tokens[].token = "sha256:<64 hex>"` for storing hashed tokens.
- Policy: `permissions.allow_full_scan` to gate `path_prefix = ""` scans for `glob`/`grep`.
- `db-vfs-service`: `--unsafe-no-auth` for local development.
- Policy: `limits.max_concurrency_io`, `limits.max_concurrency_scan`, and `limits.max_db_connections`.
- `db-vfs-service`: `x-request-id` header (propagated or generated) for request tracing.

### Changed

- Docs: clarify `path_prefix` scoping and `expected_version` CAS semantics.
- `db-vfs-service`: require `Authorization: Bearer <token>` by default (configured via policy).
- `db-vfs-service`: remove global VFS mutex; use per-request store with concurrency limiting.
- `db-vfs-service`: validate bearer token before parsing JSON request bodies.
- `db-vfs-service`: use r2d2 connection pooling for SQLite/Postgres stores.
- Policy parsing: deny unknown fields (`serde(deny_unknown_fields)`).
- `policy.example.toml`: safer defaults (no write/patch/delete; auth enabled; full scan disabled).
- Store API: split file reads into `get_meta` + `get_content`.

### Fixed

- Dev: remove unused variable warning when `db-vfs-service` is built without `postgres`.
- Enforce size limits before fetching DB content to avoid memory DoS from oversized stored files.
- `glob`/`grep`: report `scan_limit_reason=Entries/Files` when truncated by DB prefix list limit.
- `db-vfs-service`: request body size limit and non-leaky 5xx error messages.
- Lint: fix `clippy::large_enum_variant`.

## [0.1.0] - 2026-01-31

### Added

- `db-vfs-core`: Policy + Secrets + Limits, error codes, path normalization, deny+redaction helpers.
- `db-vfs`: SQLite (default) + Postgres (feature) stores and VFS ops: `read/write/patch/delete/glob/grep`.
- `db-vfs-service`: HTTP JSON API for the VFS (SQLite).
- Schema migrations for SQLite/Postgres (`files` table with `(workspace_id, path)` primary key + `updated_at_ms` index).
- Tests:
  - SQLite VFS semantic tests (CAS conflicts, deny globs, grep/glob scoping).
  - HTTP smoke test for `write` + `read`.
