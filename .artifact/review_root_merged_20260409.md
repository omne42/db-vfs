# review_root merged status (2026-04-09)

Base checked:

- `origin/main` @ `37107745788bbcbf525e222dece8ae71c214bf00`

Reviewed inputs:

- `review_root_1.md`
- `review_root_2.md`
- `review_root_3.md`
- `review_root_4.md`
- `review_root_5.md`
- `review_root_6.md`
- `review_root_7.md`
- `review_root_8.md`

## Deduplicated findings

The eight review files collapsed into these concrete themes:

1. `service` audit redaction duplicated core secret/path semantics.
2. `audit.required = true` early rejects did not consistently stay inside request budget or keep the originating concurrency slot.
3. Request-body buffering / JSON decode could hold permits without a frontdoor timeout.
4. Scan runtime budget and DB pool wait/connect budget were inconsistent.
5. `db-vfs-service` backend feature boundaries were too wide and still dragged SQLite into Postgres-only builds.
6. Postgres integration tests were outside the default regression matrix.
7. `DbVfs::new_with_matchers_validated` had a silent matcher-rebuild fallback.
8. `Store` legacy fallback paths were too implicit for third-party backends.

## Current mainline status

As of `origin/main` checked on 2026-04-09, items 1-7 are already fixed in source, and item 8 is no longer silent.

### 1. Audit redaction is now delegated to core-derived redactors

- `service/src/server/handlers.rs`
  - `audit_err_hide_secret_path()` uses `SecretRedactor::redact_audit_path_pair()` / `redact_audit_path()`.
  - `audit_redact_scan_fields()` uses `SecretRedactor::redact_audit_path()` / `redact_audit_glob_pattern()`.

This means transport-layer audit masking no longer hand-rolls its own path/glob heuristics.

### 2. Required-audit early rejects now keep permit + budget

- `service/src/server/mod.rs`
  - `try_acquire_required_audit_gate_for_path()` acquires the same request-class semaphore before required-audit early-reject logging.
- `service/src/server/auth.rs`
  - unauthorized requests go through that gate before required audit ack.
- `service/src/server/layers.rs`
  - rate-limited requests do the same.
- `service/src/server/handlers.rs`
  - JSON/schema/workspace rejects log through `log_request_rejection_audit(..., Some(permit), remaining)`.

The old "early reject escapes saturation / audit wait semantics" claim is stale against current main.

### 3. Frontdoor body buffering / JSON decode is budgeted

- `service/src/server/handlers.rs`
  - `try_acquire_permit_then_buffer_json()` acquires the request semaphore before buffering.
  - buffering is wrapped in `tokio::time::timeout(...)`.
  - `run_json_decode_stage()` bounds decode time and returns remaining budget.
  - timed-out decode workers retain the permit until they actually finish via `retain_permit_until_completion()`.

This closes the slow-client / malformed-body permit-holding gap described in the older review.

### 4. Scan DB wait/connect stays on `max_io_ms`

- `service/src/server/runner.rs`
  - `db_pool_timeout()` is always `io_timeout(policy)`.
  - `backend_operation_timeout()` falls back to that DB budget when scan runtime is unbounded.
- `service/src/server/backend.rs`
  - SQLite busy timeout and Postgres session timeouts are set from the active backend operation timeout.

This matches the current contract in `README.md` and `docs/architecture/system-boundaries.md`.

### 5. Service backend feature split is already fixed

- `service/Cargo.toml`
  - `db-vfs = { path = "..", default-features = false }`
  - SQLite and Postgres are now opt-in feature edges.

The older report about unconditional `sqlite-bundled` in `db-vfs-service` no longer applies on main.

### 6. Postgres tests are no longer `#[ignore]` and CI includes them

- `tests/postgres_store.rs`
  - tests runtime-skip when `DB_VFS_TEST_POSTGRES_URL` is unset; they are no longer ignored.
- `service/tests/http_smoke.rs`
  - Postgres smoke coverage also runtime-skips instead of `#[ignore]`.
- `.github/workflows/ci-linux.yml`
  - includes a `postgres-integration` job with a live Postgres service.
- `.github/workflows/ci-macos.yml`
  - exercises `--features postgres`.
- `.github/workflows/ci-windows.yml`
  - exercises `--features postgres`.

So the "Postgres path is outside the regression matrix" finding is stale for current main.

### 7. Validated matcher constructors are now strict

- `src/vfs/mod.rs`
  - `try_new_with_supplied_matchers_validated()` is the strict constructor.
  - deprecated aliases `try_new_with_matchers_validated()` and `new_with_matchers_validated()` now remain strict aliases and return `Result<Self>`.

The previous silent matcher rebuild path is gone on main.

### 8. Store legacy fallbacks are still present, but no longer silent

- `src/store/mod.rs`
  - backends must explicitly declare `range_read_mode()` and `prefix_pagination_mode()`.
  - default compatibility fallbacks now require `LegacyCompatibilityFallback` to be declared and emit one-time warnings.
  - native-mode backends that forget to implement the corresponding method now fail with explicit `db` errors instead of silently degrading.

This is not the "remove all compatibility fallback" option suggested by one review, but it does fix the contract-lie part of that finding.

## Net conclusion

No additional correctness, compatibility, or maintainability fix remains required on `origin/main` for the substantive issues raised by these eight review files.

The review set is valuable as historical evidence, but it is no longer an accurate "todo list" for current mainline code.

## Verification run on the checked mainline worktree

Executed in `/root/autodl-tmp/zjj/p/git_worktree/db-vfs-review-root-20260409-mainline-ours`:

- `cargo fmt --all --check`
- `cargo test --workspace --locked`
- `cargo test --workspace --all-features --locked`
- `cargo test --workspace --no-default-features --locked`
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`

## Remote branch-protection spot check

Checked with `/root/.local/bin/gh-shiertier` on 2026-04-09:

- `omne42/omne_foundation`
- `omne42/omne-runtime`
- `omne42/toolchain-installer`

All three already have `main` branch protection with:

- `enforce_admins.enabled = true`
- `required_status_checks.strict = true`
- non-empty required check sets

So the requested "must wait for required CI/CD checks before merge" rule is already in place on those three repos.
