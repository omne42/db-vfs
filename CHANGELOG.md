# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- service/auth: enable bearer auth by default, tighten workspace allowlist matching, and compare token hashes in constant time.
- service/headers: cap oversized `Authorization` headers and strictly validate/sanitize incoming `x-request-id`.
- service/policy: harden untrusted policy loading by rejecting env-token interpolation and non-regular policy files.
- core/path-policy: tighten workspace/path validation (control chars, wildcard constraints, oversized inputs).
- migrations: add DB-level integrity checks for version/timestamp/path/content-size consistency.

### Changed

- service/runtime: move to per-request stores with pooled SQLite/Postgres connections, bounded concurrency, and timeout headroom.
- service/api: split JSON parse/schema rejections into stable error codes and standardize 4xx mappings for client-visible validation failures.
- vfs/api: `read`/`write`/`patch`/`delete` responses now include `requested_path` for normalized input traceability.
- docs/policy example: align defaults and guidance with safer production posture and explicit scope/limit semantics.
- docs/api: expand HTTP contract, observability, troubleshooting, and deployment guidance for operations and integration.

### Fixed

- store/vfs: reject version overflow and enforce record/meta invariants to avoid silent persistence inconsistencies.
- read/grep/glob/patch: tighten limit enforcement (size, redaction, scan truncation) and improve conflict/diagnostic behavior.
- audit: improve lock-path derivation, batch flush behavior, and failure handling for early rejection paths.
- service/middleware: avoid creating rate-limit buckets for missing peer IP and ensure fallback request IDs for middleware-generated audit events.

### Internal

- ci/scripts/hooks: pin actions, align multi-platform gates, add workflow timeouts, and strengthen local commit policy checks.
- tooling/docs: enforce llms bundle freshness and mdBook workflow consistency in local/CI gates.
- tests: add regression coverage for request-id sanitization, auth-before-json parsing, no-IP rate-limit semantics, store invariants, and migration constraints.

## [0.1.0] - 2026-01-31

### Added

- `db-vfs-core`: Policy + Secrets + Limits, error codes, path normalization, deny+redaction helpers.
- `db-vfs`: SQLite (default) + Postgres (feature) stores and VFS ops: `read/write/patch/delete/glob/grep`.
- `db-vfs-service`: HTTP JSON API for the VFS (SQLite).
- Schema migrations for SQLite/Postgres (`files` table with `(workspace_id, path)` primary key + `updated_at_ms` index).
- Tests:
  - SQLite VFS semantic tests (CAS conflicts, deny globs, grep/glob scoping).
  - HTTP smoke test for `write` + `read`.
