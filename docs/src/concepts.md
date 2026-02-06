# Concepts

## Core rules

- `workspace_id` **MUST** be valid and non-empty.
- `path` and `path_prefix` **MUST** be root-relative (no leading `/`, no `..`, no control chars).
- `path_prefix = ""` **MUST NOT** be used unless `permissions.allow_full_scan = true`.
- `read/write/patch/delete` **MUST** pass secret deny checks for target path.
- `glob/grep` **MUST** be scoped by `path_prefix` unless a safe literal prefix is derivable.

## Safe literal prefix

A safe literal prefix is a non-wildcard, root-relative directory prefix extracted from `glob`.

Examples:

- `docs/**/*.md` -> safe prefix `docs/`.
- `docs/*` -> safe prefix `docs/`.
- `**/*.md` -> no safe prefix (caller must provide `path_prefix`).
- `*/foo/*.md` -> no safe prefix.

## Operation semantics matrix

| Operation | Target exists | expected_version | Result |
| --- | --- | --- | --- |
| `write` | no | `null` | create (version=1) |
| `write` | yes | `null` | `conflict` |
| `write` | yes | `v` matches | update (version+1) |
| `write` | yes | `v` mismatches | `conflict` |
| `patch` | yes | `v` matches | patched (version+1) |
| `patch` | yes/no | `v` mismatches or missing | `conflict` / `not_found` |
| `delete` | yes | `null` | deleted |
| `delete` | yes | `v` matches | deleted |
| `delete` | yes | `v` mismatches | `conflict` |
| `delete` | no | any | `not_found` |

## Path normalization

Canonicalization is deterministic:

1. validate root-relative constraints;
2. normalize separators;
3. reject invalid forms (`..`, control chars, invalid workspace id);
4. return canonical `requested_path` and normalized stored `path`.

## Error contract

| `code` | Typical HTTP | Retry? | Client action |
| --- | --- | --- | --- |
| `unauthorized` | 401 | no | fix token/header |
| `not_permitted` / `secret_path_denied` | 403 | no | fix policy/path |
| `conflict` | 409 | conditional | re-read latest version and retry |
| `timeout` | 408 | yes | backoff + retry |
| `busy` / `rate_limited` | 503 / 429 | yes | backoff + retry with limits |
| `invalid_*` / `patch` | 400 | no | fix request payload |
