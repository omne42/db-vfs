# Development

## Gates

Run format/check/clippy/test:

```bash
./scripts/gate.sh
```

## Git hooks

Enable local hooks:

```bash
./scripts/setup-githooks.sh
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

GitHub Actions also builds docs on pushes; deploying to GitHub Pages requires enabling Pages for the repo
(Settings → Pages → Source: GitHub Actions). If Pages is not enabled, the workflow still builds but
skips deploy.

Regenerate `llms.txt`:

```bash
./scripts/llms.sh
```

Verify `llms.txt` is up to date:

```bash
./scripts/llms.sh --check
```
