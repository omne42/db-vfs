#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage:
  ./scripts/llms.sh        # regenerate llms.txt
  ./scripts/llms.sh --check  # verify llms.txt is up to date
EOF
}

mode="write"
case "${1:-}" in
  "" ) ;;
  --check )
    mode="check"
    shift
    ;;
  -h|--help )
    usage
    exit 0
    ;;
  * )
    usage
    exit 2
    ;;
esac

if [[ "$#" -ne 0 ]]; then
  usage
  exit 2
fi

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
out="$repo_root/llms.txt"
tmp="$(mktemp "${out}.tmp.XXXXXX")"

cleanup() {
  rm -f "$tmp"
}
trap cleanup EXIT

emit_file() {
  local path="$1"
  if [[ ! -f "$repo_root/$path" ]]; then
    echo "llms: missing file: $path" >&2
    exit 1
  fi
  printf '\n' >>"$tmp"
  printf -- '---\nfile: %s\n---\n\n' "$path" >>"$tmp"
  cat "$repo_root/$path" >>"$tmp"
  printf '\n' >>"$tmp"
}

cat >"$tmp" <<'EOF'
# db-vfs — LLM documentation bundle

This file is generated from the repo sources to make RAG/LLM ingestion easier.

Update it by running:

  ./scripts/llms.sh
EOF

emit_file "README.md"
emit_file "policy.example.toml"
emit_file "SECURITY.md"
emit_file "docs/src/SUMMARY.md"
emit_file "docs/src/index.md"
emit_file "docs/src/getting-started.md"
emit_file "docs/src/concepts.md"
emit_file "docs/src/policy.md"
emit_file "docs/src/http-api.md"
emit_file "docs/src/storage.md"
emit_file "docs/src/security.md"
emit_file "docs/src/observability.md"
emit_file "docs/src/troubleshooting.md"
emit_file "docs/src/development.md"
emit_file "docs/src/llms.md"

if [[ "$mode" == "check" ]]; then
  if [[ ! -f "$out" ]]; then
    echo "llms: missing $out; run ./scripts/llms.sh" >&2
    exit 1
  fi
  if cmp -s "$tmp" "$out"; then
    echo "llms: up to date" >&2
    exit 0
  fi
  echo "llms: llms.txt is out of date; run ./scripts/llms.sh" >&2
  exit 1
fi

mv "$tmp" "$out"
trap - EXIT
echo "llms: wrote $out" >&2
