# Policy

Service policy is loaded as `db_vfs_core::policy::VfsPolicy` (`.toml` or `.json`).

Start from [`policy.example.toml`](policy.example.toml).

## Default highlights

| Section | Key | Default |
| --- | --- | --- |
| `permissions` | `read/glob/grep` | `true` |
| `permissions` | `write/patch/delete` | `false` |
| `permissions` | `allow_full_scan` | `false` |
| `audit` | `required` | `true` |
| `limits` | `max_walk_ms` | `Some(2000)` |

## `allowed_workspaces` matching

Supported patterns:

- `*`: allow all workspaces.
- exact match, e.g. `ws-prod`.
- trailing wildcard prefix, e.g. `team-a-*`.

Not supported:

- multiple `*` (`foo*bar*`)
- middle wildcard (`a*b`)
- malformed patterns rejected by policy validation.

## Token hash generation

Input is raw token bytes exactly as sent by client; no extra trimming beyond your shell quoting.

```bash
printf '%s' 'dev-token-change-me' | sha256sum
# then use: token = "sha256:<hex>"
```

## Limits reference

Critical bounded fields include:

- request bytes: `max_read_bytes`, `max_write_bytes`, `max_patch_bytes`
- scan bounds: `max_results`, `max_walk_files`, `max_walk_entries`, `max_walk_ms`, `max_line_bytes`
- service runtime: `max_io_ms`, concurrency and DB pool limits
- rate limit: `max_requests_per_ip_per_sec`, `max_requests_burst_per_ip`, `max_rate_limit_ips`

## Audit behavior matrix

| `audit.jsonl_path` | `audit.required` | Startup behavior |
| --- | --- | --- |
| unset | `true/false` | audit disabled |
| set + writable | `true/false` | audit enabled |
| set + open fails | `true` | startup fails |
| set + open fails | `false` | startup continues, audit disabled |

`flush_every_events` and `flush_max_interval_ms` are valid only when `jsonl_path` is set.
