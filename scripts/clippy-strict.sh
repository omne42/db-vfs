#!/usr/bin/env bash
set -euo pipefail

if ! repo_root="$(git rev-parse --show-toplevel 2>/dev/null)"; then
  echo "clippy-strict: must run inside a git repository." >&2
  exit 1
fi

if [[ ! -f "$repo_root/Cargo.toml" ]]; then
  echo "clippy-strict: no Cargo.toml found; skipping." >&2
  exit 0
fi

if [[ "${DB_VFS_SKIP_STRICT_CLIPPY:-}" == "1" ]]; then
  echo "clippy-strict: skipped (DB_VFS_SKIP_STRICT_CLIPPY=1)" >&2
  exit 0
fi

echo "clippy-strict: rust ownership/error-performance lint profile" >&2
(
  cd "$repo_root"
  # Keep this target set intentionally scoped to non-test code so the gate
  # enforces production quality without being dominated by test helper patterns.
  cargo clippy --workspace --all-features --locked -- \
    -D warnings \
    -D clippy::unwrap_used \
    -D clippy::expect_used \
    -D clippy::let_underscore_must_use \
    -D clippy::needless_range_loop \
    -D clippy::redundant_clone \
    -D clippy::unbuffered_bytes
)
