#!/usr/bin/env bash
set -euo pipefail

if ! repo_root="$(git rev-parse --show-toplevel 2>/dev/null)"; then
  echo "docs: must run inside a git repository" >&2
  exit 1
fi
docs_dir="$repo_root/docs"
book_out="$docs_dir/book"

if [[ ! -d "$docs_dir" ]]; then
  echo "docs: missing docs directory: $docs_dir" >&2
  exit 1
fi

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
for path in "$repo_root/policy.example.toml" "$repo_root/llms.txt"; do
  if [[ ! -f "$path" ]]; then
    echo "docs: missing file to copy into book output: $path" >&2
    exit 1
  fi
done

cp "$repo_root/policy.example.toml" "$book_out/policy.example.toml"
cp "$repo_root/llms.txt" "$book_out/llms.txt"

echo "docs: built $book_out" >&2
