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
echo "docs: built $docs_dir/book" >&2
