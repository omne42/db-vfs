#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
docs_dir="$repo_root/docs"

if ! command -v mdbook >/dev/null 2>&1; then
  cat >&2 <<'EOF'
docs: missing dependency: mdbook

Install:
  cargo install mdbook
EOF
  exit 1
fi

mdbook build "$docs_dir"

# Copy a few helpful repo files into the built book output so in-book links work when hosting
# `docs/book/` as a standalone static directory.
cp "$repo_root/policy.example.toml" "$docs_dir/book/policy.example.toml"

echo "docs: built $docs_dir/book" >&2
