# db-vfs

`db-vfs` is a DB-backed “virtual filesystem” (VFS) intended for server / high-concurrency workloads.

It provides tool-like operations with explicit safety policy enforcement:

- `read` (optional line ranges)
- `glob`
- `grep`
- `write`
- `patch` (unified diff)
- `delete`

This repo contains:

- `db-vfs` (crate): core VFS operations backed by a `Store` trait.
- `db-vfs-service` (crate): an HTTP JSON service (Axum) with auth, request limits, and concurrency control.

Non-goals:

- Full git-repo tooling (checkout/build, etc).
- Large binary file storage.
- Unbounded traversal/search (scans are scoped and budgeted).

## Where to start

- New users: [`Getting started`](getting-started.md)
- Understanding semantics: [`Concepts`](concepts.md)
- Configuration: [`Policy`](policy.md) and [`policy.example.toml`](policy.example.toml)
- Integrating over HTTP: [`HTTP API`](http-api.md)
- LLM/RAG ingestion: [`llms.txt`](llms.md)
