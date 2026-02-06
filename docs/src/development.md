# Development

## Prerequisites

Run all commands from repository root.

Required tools:

- Rust toolchain (`rustc`, `cargo`)
- `mdbook` (for docs build)

## Validation gates

### `./scripts/gate.sh`

Purpose: format/check/clippy/tests/docs/LLMS checks.

Pass criteria:

- exit code `0`
- no `error:` lines in output

Common failures:

- stale lockfile/features -> run targeted `cargo check` locally first
- stale llms bundle -> run `./scripts/llms.sh`

### `./scripts/docs.sh`

Purpose: build mdBook docs.

Pass criteria: exit code `0` and generated `docs/book/` output.

### `./scripts/llms.sh --check`

Purpose: ensure `llms.txt` and `docs/llms.txt` are up to date.

Pass criteria: reports `llms: up to date`.

## Git hooks

Enable local hooks:

```bash
./scripts/setup-githooks.sh
```

Hooks are local fast-fail checks; CI remains the merge authority.

Policy for `CHANGELOG.md` updates:

- user-visible/security behavior changes: required
- internal-only refactors/chore: may be grouped into one entry

## Docs and Pages troubleshooting

If docs deploy does not happen, check:

1. workflow trigger branch/path filters;
2. GitHub Pages settings (GitHub Actions source);
3. workflow permissions for pages/id-token.
