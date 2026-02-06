# Getting Started

## Prerequisites

Run from repository root (`db-vfs/`).

```bash
rustc --version
cargo --version
```

Expected: Rust/Cargo are installed and versions are available.

## 5-minute local run (SQLite)

1. Copy a local policy file (do not edit the example in place):

```bash
cp policy.example.toml policy.local.toml
```

2. Set a development token:

```bash
export DB_VFS_TOKEN='dev-token-change-me'
```

3. Enable local writes in `policy.local.toml`:

```toml
[permissions]
write = true
```

4. Start service:

```bash
cargo run -p db-vfs-service -- \
  --sqlite ./db-vfs.sqlite \
  --policy ./policy.local.toml \
  --listen 127.0.0.1:8080
```

## Smoke test

Write:

```bash
curl -sS http://127.0.0.1:8080/v1/write \
  -H 'content-type: application/json' \
  -H "authorization: Bearer ${DB_VFS_TOKEN}" \
  -d '{"workspace_id":"w1","path":"docs/a.txt","content":"hello","expected_version":null}'
```

Expected response fragment:

```json
{"path":"docs/a.txt","created":true,"version":1}
```

Read:

```bash
curl -sS http://127.0.0.1:8080/v1/read \
  -H 'content-type: application/json' \
  -H "authorization: Bearer ${DB_VFS_TOKEN}" \
  -d '{"workspace_id":"w1","path":"docs/a.txt","start_line":null,"end_line":null}'
```

Expected response fragment:

```json
{"path":"docs/a.txt","content":"hello","version":1}
```

## Common startup mistakes

- `401 unauthorized`: token missing/wrong; check `Authorization` and `DB_VFS_TOKEN`.
- `403 not_permitted`: `permissions.write = false`; enable write in policy.
- `415 unsupported_media_type`: missing `content-type: application/json`.
