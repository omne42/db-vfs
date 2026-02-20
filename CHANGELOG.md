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
- service/runtime: store validated policy/redaction/traversal matchers behind `Arc` so per-request runner setup uses pointer clones instead of implicit matcher deep copies.
- service/api: split JSON parse/schema rejections into stable error codes and standardize 4xx mappings for client-visible validation failures.
- vfs/api: `read`/`write`/`patch`/`delete` responses now include `requested_path` for normalized input traceability.
- core/path-match: reduce transient allocations in runtime path normalization for redaction/traversal matching.
- docs/policy example: align defaults and guidance with safer production posture and explicit scope/limit semantics.
- docs/api: expand HTTP contract, observability, troubleshooting, and deployment guidance for operations and integration.

### Fixed

- store/vfs: reject version overflow and enforce record/meta invariants to avoid silent persistence inconsistencies.
- service/audit: preserve request-time `ts_ms` in async audit worker instead of overwriting it with worker flush time.
- read/grep/glob/patch: tighten limit enforcement (size, redaction, scan truncation) and improve conflict/diagnostic behavior.
- core/redaction+traversal+glob-match: reject control/NUL and parent-segment runtime paths during matcher normalization to close invalid-path bypass edges.
- vfs/scan counters: avoid lossy `usize -> u64` casts in scan/read/patch accounting paths on wide-pointer targets.
- service/scan-timeout: restore `max_walk_ms = None` semantics to keep scan operations unbounded instead of implicitly falling back to `max_io_ms`.
- vfs/glob-match: tighten fast-path canonical-path checks so non-canonical runtime paths continue through normalization and preserve match behavior.
- store/pagination: restore compatibility for legacy `Store` implementations by adding default cursor-page fallback when only prefix listing is implemented.
- store/pagination: optimize legacy fallback cursor scanning by avoiding redundant filtering work and adapting growth strategy based on cursor position.
- audit: improve lock-path derivation, batch flush behavior, and failure handling for early rejection paths.
- service/auth: enforce constant-time full-scan token matching path while still rejecting duplicate configured token hashes.
- core/vfs: centralize scan-response byte cap constant so policy validation and `glob`/`grep` runtime truncation stay aligned.
- service/middleware: apply a shared fallback rate-limit bucket for missing peer IP and ensure fallback request IDs for middleware-generated audit events.
- vfs/scan: speed up literal `grep` matching and JSON escaped-byte accounting on ASCII-heavy content paths to reduce scan CPU overhead.
- store/pagination: make legacy cursor-pagination fallback robust against unsorted `list_metas_by_prefix` implementations by sorting before cursor partitioning.
- service/rate-limiter: avoid preallocating large shard/capacity structures when rate limiting is disabled.
- service/rate-limiter: reduce mutex hold times on hot allow/prune paths, avoid hash-index truncation on 32-bit targets, and use fused token refill math in bucket updates.
- vfs/scan pagination: fail fast on non-monotonic store cursors in `glob`/`grep` to prevent retry loops on broken page implementations.
- vfs/scan sorting: switch final result ordering to `sort_unstable*` in `glob`/`grep` to reduce sort overhead without changing output semantics.
- store/prefix-bounds: reduce pagination bound-calculation allocations by removing intermediate `Vec<char>` creation in prefix successor derivation.
- vfs/read+grep+patch: enforce actual loaded content size against `limits.max_read_bytes` even when persisted metadata is stale/inconsistent, preventing oversized processing and tightening policy correctness.

### Internal

- ci/scripts/hooks: pin actions, align multi-platform gates, add workflow timeouts, and strengthen local commit policy checks.
- ci/scripts/hooks: add strict pre-commit clippy profile to block `unwrap/expect`, ignored must-use results, redundant clones, and common low-level iteration/IO pitfalls in non-test code.
- tooling/docs: enforce llms bundle freshness and mdBook workflow consistency in local/CI gates.
- tests: add regression coverage for request-id sanitization, auth-before-json parsing, no-IP rate-limit semantics, store invariants, and migration constraints.
- tests: add regression coverage to ensure audit worker keeps provided event timestamps unchanged.
- tests: add regression coverage for legacy unsorted prefix-pagination fallback correctness and disabled rate-limiter minimal allocation behavior.

## [0.1.0] - 2026-01-31

### Added

- `db-vfs-core`: Policy + Secrets + Limits, error codes, path normalization, deny+redaction helpers.
- `db-vfs`: SQLite (default) + Postgres (feature) stores and VFS ops: `read/write/patch/delete/glob/grep`.
- `db-vfs-service`: HTTP JSON API for the VFS (SQLite).
- Schema migrations for SQLite/Postgres (`files` table with `(workspace_id, path)` primary key + `updated_at_ms` index).
- Tests:
  - SQLite VFS semantic tests (CAS conflicts, deny globs, grep/glob scoping).
  - HTTP smoke test for `write` + `read`.
