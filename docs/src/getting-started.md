# Getting started

## Prerequisites

- Rust toolchain (see `rust-toolchain.toml`)

## Run the service (SQLite)

Create a policy file (start from `policy.example.toml`) and set a bearer token at runtime:

```bash
export DB_VFS_TOKEN='dev-token-change-me'
```

Run:

```bash
cargo run -p db-vfs-service -- \
  --sqlite ./db-vfs.sqlite \
  --policy ./policy.example.toml \
  --listen 127.0.0.1:8080
```

## Smoke test

Write a file:

```bash
curl -sS http://127.0.0.1:8080/v1/write \
  -H 'content-type: application/json' \
  -H "authorization: Bearer ${DB_VFS_TOKEN}" \
  -d '{"workspace_id":"w1","path":"docs/a.txt","content":"hello","expected_version":null}'
```

Read it back:

```bash
curl -sS http://127.0.0.1:8080/v1/read \
  -H 'content-type: application/json' \
  -H "authorization: Bearer ${DB_VFS_TOKEN}" \
  -d '{"workspace_id":"w1","path":"docs/a.txt","start_line":null,"end_line":null}'
```
