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
