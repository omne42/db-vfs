# Concepts

## Namespace: `workspace_id`

`workspace_id` is the namespace boundary. All operations are scoped to:

- `workspace_id`
- a root-relative `path` or `path_prefix`

## Root-relative paths

All `path` / `path_prefix` values are root-relative:

- Must not start with `/`
- Must not contain `..`
- Must not have leading/trailing whitespace
- Must not contain control characters

`path_prefix` may be empty (`""`) to mean “the whole workspace” **only if**
`policy.permissions.allow_full_scan = true`.

## Safety policy

The policy is validated on load and governs:

- Which operations are permitted (`permissions`)
- How much work each request can do (`limits`)
- Which paths are denied or redacted (`secrets`)
- Which paths are skipped during scans only (`traversal`)
- Service auth tokens and workspace allowlists (`auth`)

## Concurrency and CAS

Writes are guarded by optimistic concurrency using a monotonically increasing `version`:

- `read` returns the current `version`
- `write(expected_version = null)` is **create-only**
- `write(expected_version = v)` updates iff the current version is `v`
- `patch` requires `expected_version`
- `delete(expected_version = v)` enforces CAS; `delete(expected_version = null)` is unconditional

## Scan scoping

To avoid unbounded traversal, scan operations are scoped:

- `grep` requires an explicit `path_prefix` unless a safe literal prefix can be derived from `glob`
- `glob` similarly requires `path_prefix` for broad patterns without a safe literal prefix

## Error codes

Library errors carry stable `code`s (e.g. `invalid_path`, `not_permitted`, `conflict`, `timeout`).
The HTTP service maps these to HTTP status codes and returns a JSON error body.
