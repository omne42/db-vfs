# db-vfs

DB-backed “virtual filesystem” (DB-VFS) intended for server / high-concurrency workloads.

Goals:

- Preserve the explicit safety model shape: **Policy + Secrets + Limits**.
- Provide tool-like operations: `read`, `glob`, `grep`, `write`, `patch`, `delete`.
- Support SQLite (dev/test) and Postgres (production).

This is intentionally *not* part of `safe-fs-tools` to keep that crate focused on local OS
filesystem semantics and a small dependency graph.

## HTTP service (SQLite)

Run:

```bash
cd db-vfs
cargo run -p db-vfs-service -- \
  --sqlite ./db-vfs.sqlite \
  --policy ./policy.example.toml \
  --listen 127.0.0.1:8080
```

Endpoints (JSON POST):

- `/v1/read`
- `/v1/write`
- `/v1/patch`
- `/v1/delete`
- `/v1/glob`
- `/v1/grep`

