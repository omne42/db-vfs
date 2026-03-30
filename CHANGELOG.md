# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- service/auth: enable bearer auth by default, tighten workspace allowlist matching, and compare token hashes in constant time.
- service/headers: cap oversized `Authorization` headers and strictly validate/sanitize incoming `x-request-id`.
- service/policy: harden untrusted policy loading by rejecting env-token interpolation and non-regular policy files.
- core/policy: make omitted `limits.max_walk_ms` deserialize to the default `Some(2000)` scan budget.
- core/path-policy: tighten workspace/path validation (control chars, wildcard constraints, oversized inputs).
- migrations: add DB-level integrity checks for version/timestamp/path/content-size consistency.
- service/audit-runtime: keep required-audit waits under the originating request's concurrency slot and remaining runtime budget so slow audit sinks cannot free execution capacity before the response can legally return.
- service/audit-runtime+core/redaction: make early-reject paths keep their original concurrency permit through required audit append+flush, and match audited glob/pattern redaction against real secret deny semantics so values like `".[en]nv"` are masked instead of leaking to JSONL.
- service/auth+audit: add stable hashed `auth_subject` audit identities for matched and syntactically valid presented bearer tokens, and route handler-built audit events through a shared event builder so success/error/post-auth rejection paths stay consistent.

### Changed

- release: bump crate versions (`db-vfs`, `db-vfs-core`, `db-vfs-service`) to `1.0.0`.
- service/runtime: move to per-request stores with pooled SQLite/Postgres connections and bounded concurrency.
- service/runtime: store validated policy/redaction/traversal matchers behind `Arc` so per-request runner setup uses pointer clones instead of implicit matcher deep copies.
- vfs/api: add a strict validated-matcher constructor for callers that need policy/matcher mismatches to fail hard instead of silently rebuilding policy-derived matchers.
- service/api: split JSON parse/schema rejections into stable error codes and standardize 4xx mappings for client-visible validation failures.
- service/api: reject unknown request fields with `invalid_json_schema` instead of silently accepting undeclared JSON members.
- vfs/api: `read`/`write`/`patch`/`delete` responses now include `requested_path` for normalized input traceability.
- core/path-match: reduce transient allocations in runtime path normalization for redaction/traversal matching.
- docs/policy example: align defaults and guidance with safer production posture and explicit scope/limit semantics.
- docs/api: expand HTTP contract, observability, troubleshooting, and deployment guidance for operations and integration, including strict request schemas and `delete.ignore_missing`.

### Fixed

- vfs/api: make `DbVfs::new_with_matchers_validated` fail on policy/matcher mismatches instead of silently rebuilding policy-derived matchers, so validated constructors no longer hide integration errors.
- vfs/read+service/store+docs: make redaction-enabled ranged reads fail before loading oversized raw files, account for redaction copy amplification in scan memory planning, and surface legacy cursor-pagination fallback usage with an explicit warning instead of silent scan-contract degradation.
- service/startup: bind startup SQLite/Postgres migrations to `limits.max_io_ms` so lock contention fails fast instead of hanging startup behind nearly unbounded DB waits.
- vfs/glob+grep: derive safe prefixes from exact-file literals too, so root-level patterns like `README.md` remain allowed under `allow_full_scan=false` instead of being rejected as full scans.
- vfs/grep+service/handlers+docs: treat literal `\r` queries the same as `\n` for line-oriented grep short-circuiting so CRLF inputs no longer do useless content work or return silent false negatives, and rename the internal permit helper to reflect its immediate `503 busy` semantics.
- vfs/grep+docs: evaluate grep matches against the redacted line view whenever secret redaction is active, so masked secrets no longer remain discoverable via match/no-match behavior.
- store/vfs/read+grep+docs: treat lone `\r` as a real line boundary alongside `\n`/`\r\n`, fixing CR-only ranged reads, grep line numbering, and legacy store line-range fallback semantics.
- store/vfs/read+grep+docs: keep mixed `\r`, `\n`, and `\r\n` files on the same shared line splitter so ranged `read` slices, grep line numbers, and emitted line text stay aligned across APIs.
- core/redaction+vfs/read+grep: make `SecretRedactor::from_rules()` enforce replacement size/control-character invariants itself, and budget redaction-expanded intermediates against `max_read_bytes` so ranged `read` / `grep` fail or skip with `file_too_large` instead of allocating unbounded whole-file redacted buffers.
- vfs/grep+docs: make `regex=true` explicitly line-oriented and reject patterns that can consume `\n`/`\r`, so multi-line regex requests fail clearly instead of silently returning misleading no-match results.
- vfs/core: reject or neutralize caller-supplied `SecretRedactor` / `TraversalSkipper` values that diverge from the active policy so public constructors cannot bypass `secrets.deny_globs` or `traversal.skip_globs`.
- store/sqlite+postgres: persist per-path version generations across delete/recreate so stale `expected_version` values cannot match a newly recreated file, and add regression coverage for SQLite, Postgres store integration, and Postgres HTTP smoke paths.
- vfs/scan+docs: stop serializing secret-denied scan counters, exclude denied paths from public `scanned_entries`, and correct `delete.ignore_missing` plus policy-default documentation.
- service/auth+audit+sqlite: reject plaintext env-backed tokens that violate HTTP Bearer token syntax, reject literal `sha256:<hex>` values in `token_env_var` instead of treating them as pre-hashed secrets, return stable `503 audit_unavailable` errors when required audit append/flush fails, fail fast on held audit locks, and force `--sqlite :memory:` through a single migrated pooled connection.
- service/policy: stat policy paths before open so non-regular files fail fast, and scope env interpolation to parsed JSON/TOML string values so comments and non-string fields are not treated as template input.
- service/policy: reject symlink policy paths up front so loader input stays on a direct regular-file boundary instead of silently following link targets.
- service/audit-handlers+core/redaction: keep the original concurrency permit held through required-audit waits for JSON/workspace early rejects too, and drive audit glob redaction from real deny-glob matching so secret patterns like `.[en]nv` no longer leak into JSONL.
- core/policy+vfs: make `ValidatedVfsPolicy::new()` prove policy-derived matcher construction up front, so validated-policy constructor families no longer carry a reachable matcher fallback panic path.
- service/audit-redaction: conservatively mask malformed secret-ish request paths in audit fields, so inputs like `.env/../visible.txt` or control-character variants do not leak denied roots into JSONL.
- store/vfs/read: finish the chunked no-redaction ranged-read path across the `Store` trait plus SQLite/Postgres backends, so narrow line-range reads no longer require whole-file materialization.
- store/sqlite+postgres: make versioned delete distinguish `conflict` from `not_found` without a post-delete race window, and add regression coverage for the three-way outcome.
- service/postgres: set `statement_timeout` per checked-out request budget so scan operations honor `max_walk_ms` semantics instead of inheriting `max_io_ms`.
- store/sqlite+postgres: make CAS update failure classification use the row snapshot being updated, and clamp `updated_at_ms` to a monotonic floor so wall-clock rollback cannot violate persisted timestamp invariants.
- core/policy+redaction+vfs/read+grep: default `max_walk_ms` to `Some(2000)`, reject control characters in `secrets.replacement`, and preserve line structure when redacting multi-line secret matches before ranged reads or grep responses are emitted.
- service/runner+backend: remove undocumented `250ms` timeout headroom and keep scan DB pool wait/connect bounded by `max_io_ms` even when `max_walk_ms = None`.
- service/frontdoor+runner+audit: budget JSON body buffering/decode under `max_io_ms`, keep required-audit `401 unauthorized` / `429 rate_limited` / timeout rejection paths on the matching request-class permit, and return timed-out execution permits to the rejection/audit path while backend lock/query waits stay bounded by `max_io_ms` even when scan runtime is unbounded.
- service/handlers: stop spending request budgets on semaphore queueing; saturated concurrency now returns `503 busy`, while `408 timeout` stays reserved for pool/lock wait and in-flight execution budgets.
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
- service/handlers timeout budgeting: stop queueing behind saturated semaphores so request budgets are not spent before execution starts.
- service/handlers+audit: allow embedded routers to run without `ConnectInfo`, omitting `peer_ip` instead of failing requests, and make `audit.required=true` wait for per-request write/flush acknowledgement so write failures surface to the triggering request.
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
- service/sqlite+postgres: bind startup migrations to the existing `max_io_ms` budget so SQLite no longer starts with an effectively unbounded `busy_timeout`, and Postgres startup runs under bounded `statement_timeout` plus `lock_timeout` instead of waiting indefinitely on migration-time contention.
- vfs/read: remove per-line byte-limit recount in line-range extraction by enforcing a single upfront content-size guard, reducing hot-loop overhead without changing limit behavior.
- vfs/glob+grep pagination: reject non-monotonic path ordering within a single store page to avoid silent row skips on misordered paginated backends.
- service/audit-redaction: treat denied directory-prefix roots (for example `.git` / `.git/`) as secret in audit field redaction to avoid leaking protected scan roots.
- service/audit-redaction: expand brace-alternation probes before masking audited scan patterns so values like `.{envrc,netrc}` redact instead of leaking secret filenames.
- service/handlers: acquire `max_concurrency_*` permits before buffering and decoding JSON bodies so saturated servers return `busy` without letting malformed or oversized requests bypass execution gates.
- vfs/glob+grep: compile single-pattern scan globs into `GlobMatcher` (instead of a one-entry `GlobSet`) to trim matcher overhead on scan hot paths.
- store/sqlite+postgres+core: replace lossy `usize -> u64` casts in persisted size/pagination conversions with checked conversions to avoid silent truncation on wide-pointer targets.
- vfs/grep: cache per-file escaped-path byte length while budgeting JSON response size, removing repeated per-match path escaping work on hot scan paths.
- store/vfs: reject version overflow and enforce record/meta invariants to avoid silent persistence inconsistencies.
- service/audit: preserve request-time `ts_ms` in async audit worker instead of overwriting it with worker flush time.
- read/grep/glob/patch: tighten limit enforcement (size, redaction, scan truncation) and improve conflict/diagnostic behavior.
- core/redaction+traversal+glob-match: reject control/NUL and parent-segment runtime paths during matcher normalization to close invalid-path bypass edges.
- vfs/scan counters: avoid lossy `usize -> u64` casts in scan/read/patch accounting paths on wide-pointer targets.
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
- core/redaction+service/handlers: move audit path/glob masking behind `SecretRedactor` helper APIs so handlers no longer duplicate deny-glob probe semantics outside the core matcher boundary.
- vfs/grep: defer escaped-path JSON-size accounting until a file produces a match, avoiding unnecessary per-file escape work for non-matching content.
- vfs/grep+patch: replace remaining lossy `usize -> u64` casts in input-size error accounting with checked/saturating conversions to avoid theoretical truncation on wide-pointer targets.
- vfs/store/docs: keep validated-matcher and ranged-read compatibility paths backward-compatible but no longer silent by emitting one-time warnings when policy/matcher rebuild fallback or whole-file ranged-read fallback is used.

### Internal

- ci/scripts/hooks: pin actions, align multi-platform gates, add workflow timeouts, and strengthen local commit policy checks.
- ci/scripts/hooks: add strict pre-commit clippy profile to block `unwrap/expect`, ignored must-use results, redundant clones, and common low-level iteration/IO pitfalls in non-test code.
- tooling/docs: enforce llms bundle freshness and mdBook workflow consistency in local/CI gates.
- tests: add regression coverage for request-id sanitization, auth-before-json parsing, no-IP rate-limit semantics, store invariants, and migration constraints.
- tests/service-policy: add an explicit FIFO regression test so policy loading keeps rejecting special files before `open`, instead of only covering generic non-regular paths.
- tests: add regression coverage to ensure audit worker keeps provided event timestamps unchanged.
- tests: add regression coverage for legacy unsorted prefix-pagination fallback correctness and disabled rate-limiter minimal allocation behavior.
- tests: add Postgres rollback regression coverage proving missing-path update/delete attempts do not persist `file_generations` rows.
- tests: add regression coverage for required-audit worker loss returning stable `503 audit_unavailable` errors.

## [0.1.0] - 2026-01-31

### Added

- `db-vfs-core`: Policy + Secrets + Limits, error codes, path normalization, deny+redaction helpers.
- `db-vfs`: SQLite (default) + Postgres (feature) stores and VFS ops: `read/write/patch/delete/glob/grep`.
- `db-vfs-service`: HTTP JSON API for the VFS (SQLite).
- Schema migrations for SQLite/Postgres (`files` table with `(workspace_id, path)` primary key + `updated_at_ms` index).
- Tests:
  - SQLite VFS semantic tests (CAS conflicts, deny globs, grep/glob scoping).
  - HTTP smoke test for `write` + `read`.
