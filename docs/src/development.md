# Development

## Gates

Run format/check/clippy/test:

```bash
./scripts/gate.sh
```

## Git hooks

Enable local hooks:

```bash
git config core.hooksPath githooks
```

The hooks enforce:

- Conventional Commits messages
- `CHANGELOG.md` updates in every commit
- a max Rust file size guard (`DB_VFS_MAX_RS_LINES`, default 1000)

## Docs

Build the mdBook (requires `mdbook`):

```bash
./scripts/docs.sh
```

Regenerate `llms.txt`:

```bash
./scripts/llms.sh
```
