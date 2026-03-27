# Observability

## Request ID contract

`x-request-id` behavior:

- client-provided value is accepted if it matches `[A-Za-z0-9_-]{1,128}`;
- invalid/missing value is replaced by service-generated ID;
- response always returns `x-request-id`.

## Audit JSONL schema

Sample line:

```json
{"ts_ms":1738828800000,"request_id":"...","op":"write","status":200,"workspace_id":"w1","peer_ip":"127.0.0.1"}
```

Core fields:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `ts_ms` | u64 | yes | event timestamp |
| `request_id` | string | yes | request correlation ID |
| `op` | string | yes | `read/write/patch/delete/glob/grep` |
| `status` | u16 | yes | HTTP status |
| `workspace_id` | string | yes | `<unknown>` for early rejects |
| `peer_ip` | string|null | no | TCP peer IP when available |
| `error_code` | string|null | no | stable error code |

## `peer_ip` handling

- source: TCP peer address (`ConnectInfo<SocketAddr>`);
- no forwarded-header parsing;
- apply local retention policy according to compliance requirements.

## Logging levels

Recommended `RUST_LOG`:

- dev: `RUST_LOG=db_vfs_service=debug`
- test/staging: `RUST_LOG=db_vfs_service=info`
- prod: `RUST_LOG=db_vfs_service=warn`

## Audit operations

- keep audit file permissions restrictive (`600` or equivalent owner-only access);
- configure external log rotation;
- monitor disk usage;
- understand startup behavior difference between `audit.required=true/false`.
