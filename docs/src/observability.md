# Observability

## `x-request-id`

The service:

- Echoes `x-request-id` if provided by the client.
- Otherwise generates one and adds it to the response headers.

## Logging

The service uses `tracing`; configure via `RUST_LOG`, for example:

```bash
RUST_LOG=db_vfs_service=info cargo run -p db-vfs-service -- --sqlite ./db.sqlite --policy ./policy.example.toml
```

## JSONL audit log (optional)

If `policy.audit.jsonl_path` is set, the service appends one JSON object per request (JSONL / ndjson).

Notes:

- Records include `request_id`, `peer_ip`, `op`, `workspace_id`, `status`, and scan diagnostics.
- Records do not include file content or grep query text (grep logs only query length + regex flag).
- `policy.audit.required` controls startup behavior if the audit log cannot be initialized (default: fail startup).
