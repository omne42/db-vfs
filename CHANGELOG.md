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

- release: bump crate versions (`db-vfs`, `db-vfs-core`, `db-vfs-service`) to `1.0.0`.
- service/runtime: move to per-request stores with pooled SQLite/Postgres connections, bounded concurrency, and timeout headroom.
- service/runtime: store validated policy/redaction/traversal matchers behind `Arc` so per-request runner setup uses pointer clones instead of implicit matcher deep copies.
- service/api: split JSON parse/schema rejections into stable error codes and standardize 4xx mappings for client-visible validation failures.
- service/api: reject unknown request fields with `invalid_json_schema`, clarify `delete.ignore_missing`, and keep workspace allowlist denials on the documented `not_permitted` contract.
- vfs/api: `read`/`write`/`patch`/`delete` responses now include `requested_path` for normalized input traceability.
- core/path-match: reduce transient allocations in runtime path normalization for redaction/traversal matching.
- docs/policy example: align defaults and guidance with safer production posture and explicit scope/limit semantics.
- docs/api: expand HTTP contract, observability, troubleshooting, and deployment guidance for operations and integration, including strict request schemas and scan-budget semantics.

### Fixed

- service/postgres: apply `statement_timeout` per request budget so scan operations honor `max_walk_ms` / `None` instead of a fixed `max_io_ms` cap.
- service/handlers: return `408 timeout` when queue wait exhausts the request budget before execution starts.
- service/audit-handlers: switch path/glob audit redaction helpers to borrowed-string inputs and avoid eager response-path cloning in read/write/patch/delete audit hooks, reducing per-request transient allocations without changing redaction behavior.
- core/path+redaction+traversal+vfs/glob-match: centralize runtime canonical-path checks into a shared single-pass helper, removing duplicated multi-scan validators and preventing matcher-behavior drift across modules.
- service/auth: validate workspace wildcard syntax during auth-rule compilation and reject invalid trailing `*` patterns early, avoiding silent runtime no-match configs while removing redundant per-request wildcard-shape checks.
- core/path: add an ASCII fast path for `workspace_id` validation to reduce per-request character-class overhead on common hot-path inputs.
- service/auth: precompile `allowed_workspaces` patterns at startup and decode `sha256:` token hashes directly into fixed-size buffers, reducing per-request auth matching overhead and startup-time transient allocations.
- core/redaction: make `redact_text_owned_bounded` enforce `max_output_bytes` even when no regex rules/matches apply, closing a bounds-check bypass and skipping unnecessary regex traversal for oversized inputs.
- core/redaction+vfs/grep: add borrowed bounded-redaction path and use it in grep so matched lines avoid eager string allocation before response-byte budgeting when redaction rules are enabled.
- service/postgres-cancel: reuse cancel tokens from queue fallback errors and move fallback in-flight guards into spawned task captures so slot accounting is released even if execution is canceled before task start.
- service/audit-handlers: de-duplicate secret-path redaction when `requested_path` and `path` are identical, reducing redundant matcher checks and transient allocations on read/write/patch/delete audit paths.
- vfs/grep: short-circuit newline-containing literal queries before file-size gating so impossible line matches no longer inflate `skipped_too_large_files`, while also skipping unnecessary hot-path checks.
- vfs/read: simplify newline-scan index arithmetic in line-range extraction (bounds-proven `+` instead of saturating math) to trim per-line CPU overhead.
- vfs/grep: short-circuit literal queries containing `\n` before content fetch so line-based impossible matches no longer trigger unnecessary `get_content` I/O on scanned files.
- service/audit: make `audit_preview` enforce the configured byte budget even when adding the truncation marker, avoiding oversize preview fields on truncated inputs.
- vfs/grep: skip impossible per-line scan work when a literal query contains `\n` (line-based grep cannot match newline-delimited literals), and trim per-match hot-path overhead by using a saturating line counter plus deferred text allocation until response-byte budget passes.
- vfs/read: replace lossy `usize -> u64` cast in redaction overflow reporting with a checked conversion to avoid size truncation on wide-pointer targets.
- vfs/grep: add a literal-query fast reject on loaded file content so non-matching files skip per-line scan work without changing match semantics.
- vfs/glob+grep pagination: advance the cursor only when another page is expected, trimming redundant cursor string writes on terminal pages.
- service/request-id: saturate UNIX-millis narrowing when generating `x-request-id` to avoid lossy timestamp wrap on extreme clock values.
- service/handlers timeout budgeting: when queue wait consumes the full request budget, fail fast before spawning blocking VFS work, avoiding guaranteed-timeout worker churn under saturation.
- service/handlers timeout budgeting: guard `tokio::Instant` deadline construction with `checked_add` so extremely large budgets no longer panic on overflow, and fast-fail zero-budget requests before semaphore wait.
- vfs/grep + core/redaction: build regex error previews lazily only on compile failure, removing avoidable per-request/per-rule string allocations on successful paths.
- vfs/read: when initial metadata reports an oversized file, re-check metadata before failing so concurrent newer/smaller versions do not return a false `file_too_large`.
- vfs/patch: when initial metadata reports an oversized file, re-check metadata before failing so stale metadata does not return a false `file_too_large`, and return correct conflict/success outcomes after refresh.
- store/sqlite+postgres: avoid redundant existence lookup on unconditional delete misses, removing an unnecessary DB round-trip on a common no-op path.
- vfs/glob+grep time budget: re-check `max_walk_ms` immediately after each page fetch so slow store calls that return empty pages still report `truncated=true` with `scan_limit_reason=time`.
- service/runner timeout race: bias timeout `select!` to prefer completed worker results over simultaneous timeout wakeups, avoiding false timeout responses at boundary conditions.
- core/glob-validation: avoid re-normalizing already-normalized glob patterns in redaction/traversal/runtime glob compilation, reducing per-rule/per-request allocation and scan overhead without changing validation behavior.
- vfs/glob+grep pagination: enforce that each fetched page starts strictly after the previous cursor, preventing duplicate/backtracking rows from misbehaving stores and removing now-redundant defensive result re-sorting work on scan hot paths.
- store/sqlite+postgres: short-circuit `list_metas_by_prefix_page` when `limit=0` to avoid unnecessary database round-trips.
- vfs/read: remove per-line byte-limit recount in line-range extraction by enforcing a single upfront content-size guard, reducing hot-loop overhead without changing limit behavior.
- vfs/glob+grep pagination: reject non-monotonic path ordering within a single store page to avoid silent row skips on misordered paginated backends.
- service/audit-redaction: treat denied directory-prefix roots (for example `.git` / `.git/`) as secret in audit field redaction to avoid leaking protected scan roots.
- vfs/glob+grep: compile single-pattern scan globs into `GlobMatcher` (instead of a one-entry `GlobSet`) to trim matcher overhead on scan hot paths.
- store/sqlite+postgres+core: replace lossy `usize -> u64` casts in persisted size/pagination conversions with checked conversions to avoid silent truncation on wide-pointer targets.
- vfs/grep: cache per-file escaped-path byte length while budgeting JSON response size, removing repeated per-match path escaping work on hot scan paths.
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
- service/rate-limiter: reduce per-request shard-index overhead by replacing generic hasher-based indexing with lightweight IP-key mapping.
- service/rate-limiter: reclaim empty/low-utilization shard `HashMap` capacity at the configured prune threshold to reduce long-lived memory retention after bursty traffic.
- service/rate-limiter: re-check per-IP buckets after prune/retry capacity paths before denying, avoiding false rejections under concurrent bucket churn at max tracked-IP limits.
- service/rate-limiter: when a shard is fully pruned to empty, shrink its bucket map even below the high-capacity threshold to reclaim long-lived memory after bursty traffic.
- vfs/scan pagination: fail fast on non-monotonic store cursors in `glob`/`grep` to prevent retry loops on broken page implementations.
- vfs/scan sorting: switch final result ordering to `sort_unstable*` in `glob`/`grep` to reduce sort overhead without changing output semantics.
- store/prefix-bounds: reduce pagination bound-calculation allocations by removing intermediate `Vec<char>` creation in prefix successor derivation.
- vfs/read+grep+patch: enforce actual loaded content size against `limits.max_read_bytes` even when persisted metadata is stale/inconsistent, preventing oversized processing and tightening policy correctness.
- vfs/grep: reuse prebuilt literal searcher state during line scans to cut repeated per-line matcher setup overhead.
- vfs/glob+grep pagination: reuse cursor string buffers across page advances to avoid per-page `String` allocations on long scans.
- service/auth: reject oversized plaintext env-backed tokens at startup so impossible-to-authenticate configurations fail fast.
- core/path-match+glob: replace repeated `String::drain` prefix normalization loops with linear slice-based stripping in path/glob/runtime matcher hot paths, reducing worst-case normalization CPU under long `./` prefixes without changing matching semantics.
- core/path+vfs/glob-prefix: remove `Vec + join` intermediates in non-canonical path normalization and safe-glob-prefix derivation to reduce transient allocations on request hot paths.
- service/audit-redaction: apply descendant-aware secret masking to audited `glob_pattern` values so protected roots (for example `.git`) are redacted consistently.
- vfs/grep: defer escaped-path JSON-size accounting until a file produces a match, avoiding unnecessary per-file escape work for non-matching content.
- vfs/grep+patch: replace remaining lossy `usize -> u64` casts in input-size error accounting with checked/saturating conversions to avoid theoretical truncation on wide-pointer targets.

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
