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
docs_src="$repo_root/docs/src"
summary="$docs_src/SUMMARY.md"
out_root="$repo_root/llms.txt"
out_docs="$repo_root/docs/llms.txt"
tmp="$(mktemp)"

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
It follows `docs/src/SUMMARY.md` for the docs ordering.

Update it by running:

  ./scripts/llms.sh
EOF

emit_file "README.md"
emit_file "policy.example.toml"
emit_file "SECURITY.md"
emit_file "docs/src/SUMMARY.md"

if [[ ! -f "$summary" ]]; then
  echo "llms: missing docs summary: $summary" >&2
  exit 1
fi

sed -n 's/.*\[\(.*\)\](\(.*\.md\)).*/\1\t\2/p' "$summary" |
  while IFS=$'\t' read -r title file; do
    [[ -z "${file}" ]] && continue

    path="docs/src/${file}"
    if [[ ! -f "$repo_root/$path" ]]; then
      echo "llms: missing doc file referenced from SUMMARY.md: ${file}" >&2
      exit 1
    fi

    printf '\n' >>"$tmp"
    printf -- '---\nfile: %s\ntitle: %s\n---\n\n' "$path" "$title" >>"$tmp"
    cat "$repo_root/$path" >>"$tmp"
    printf '\n' >>"$tmp"
  done

if [[ "$mode" == "check" ]]; then
  if [[ ! -f "$out_root" || ! -f "$out_docs" ]]; then
    echo "llms: missing llms.txt outputs; run ./scripts/llms.sh" >&2
    exit 1
  fi
  if ! cmp -s "$tmp" "$out_root"; then
    echo "llms: llms.txt is out of date; run ./scripts/llms.sh" >&2
    exit 1
  fi
  if ! cmp -s "$tmp" "$out_docs"; then
    echo "llms: docs/llms.txt is out of date; run ./scripts/llms.sh" >&2
    exit 1
  fi
  echo "llms: up to date" >&2
  exit 0
fi

cp "$tmp" "$out_root"
cp "$tmp" "$out_docs"
echo "llms: wrote $out_root" >&2
echo "llms: wrote $out_docs" >&2
