#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
Usage:
  ./scripts/llms.sh          # regenerate llms.txt
  ./scripts/llms.sh --check  # verify llms.txt is up to date

Env:
  DB_VFS_LLMS_CHANGELOG_MODE=summary|full   # default: summary
USAGE
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

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/.." && pwd)"
if [[ ! -f "$repo_root/Cargo.toml" ]]; then
  echo "llms: failed to locate repository root from script path: $script_dir" >&2
  exit 1
fi

docs_src="$repo_root/docs/src"
summary="$docs_src/SUMMARY.md"
out_root="$repo_root/llms.txt"
out_docs="$repo_root/docs/llms.txt"
tmp="$(mktemp)"

cleanup() {
  rm -f "$tmp"
}
trap cleanup EXIT

changelog_mode="${DB_VFS_LLMS_CHANGELOG_MODE:-summary}"
case "$changelog_mode" in
  summary|full) ;;
  *)
    echo "llms: invalid DB_VFS_LLMS_CHANGELOG_MODE=$changelog_mode (expected summary|full)" >&2
    exit 2
    ;;
esac

source_commit="workspace"
generated_at_utc="stable"
generator_version="scripts/llms.sh@v3"

escape_yaml_double_quoted() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/ }"
  printf '%s' "$value"
}

make_section_id() {
  local raw="$1"
  printf '%s' "$raw" \
    | tr '[:upper:]' '[:lower:]' \
    | sed -E 's/[^a-z0-9]+/-/g; s/^-+//; s/-+$//'
}

validate_summary_entry_path() {
  local file="$1"
  if [[ -z "$file" ]]; then
    echo "llms: empty markdown path in SUMMARY.md" >&2
    return 1
  fi
  if [[ "$file" = /* ]]; then
    echo "llms: absolute paths are not allowed in SUMMARY.md: $file" >&2
    return 1
  fi
  if [[ "$file" == *".."* ]]; then
    echo "llms: parent directory segments are not allowed in SUMMARY.md: $file" >&2
    return 1
  fi
  if [[ "$file" == *"\\"* ]]; then
    echo "llms: backslash separators are not allowed in SUMMARY.md: $file" >&2
    return 1
  fi
  return 0
}

emit_file() {
  local path="$1"
  local title="${2:-$path}"

  if [[ ! -f "$repo_root/$path" ]]; then
    echo "llms: missing file: $path" >&2
    exit 1
  fi

  local escaped_title
  escaped_title="$(escape_yaml_double_quoted "$title")"
  local section_id
  section_id="$(make_section_id "$path")"

  printf '\n' >>"$tmp"
  printf -- '---\nfile: %s\ntitle: "%s"\nsection_id: "%s"\n---\n\n' \
    "$path" "$escaped_title" "$section_id" >>"$tmp"
  cat "$repo_root/$path" >>"$tmp"
  printf '\n' >>"$tmp"
}

emit_changelog_summary() {
  local path="CHANGELOG.md"
  if [[ ! -f "$repo_root/$path" ]]; then
    echo "llms: missing file: $path" >&2
    exit 1
  fi

  local section_id
  section_id="$(make_section_id "${path}-summary")"
  printf '\n' >>"$tmp"
  printf -- '---\nfile: %s\ntitle: "%s"\nsection_id: "%s"\n---\n\n' \
    "$path" "Changelog (recent summary)" "$section_id" >>"$tmp"

  printf '> Note: this is a recent summary only; full history remains in `CHANGELOG.md`.\n\n' >>"$tmp"
  head -n 160 "$repo_root/$path" >>"$tmp"
  printf '\n' >>"$tmp"
}

check_bundle_consistency() {
  local required_terms=(
    "Normative priority for behavior conflicts"
    "invalid_json_syntax"
    "secret_path_denied"
    "rate_limited"
    "max_walk_ms"
  )

  for term in "${required_terms[@]}"; do
    if ! grep -q "$term" "$tmp"; then
      echo "llms: consistency check failed; missing required term: $term" >&2
      exit 1
    fi
  done
}

cat >"$tmp" <<__BUNDLE_HEADER__
---
title: db-vfs docs bundle
description: DB-backed virtual filesystem with explicit Policy + Secrets + Limits, plus an HTTP service.
tags: [rust, sqlite, postgres, vfs, security, policy, http]
generated_at_utc: ${generated_at_utc}
source_commit: ${source_commit}
generator_version: ${generator_version}
bundle_type: stable-with-recent-history
---

# db-vfs — LLM documentation bundle

This bundle is generated from repository docs for RAG/LLM ingestion.

Normative priority for behavior conflicts:

1. Policy
2. HTTP API
3. Concepts
4. Security
5. Other guides
6. Changelog (history reference only)

Unreleased changelog items do not necessarily represent current released behavior.

Update with:

  ./scripts/llms.sh
__BUNDLE_HEADER__

emit_file "README.md" "Project README"
emit_file "policy.example.toml" "Policy Example"
emit_file "SECURITY.md" "Security Policy"
if [[ "$changelog_mode" == "full" ]]; then
  emit_file "CHANGELOG.md" "Changelog"
else
  emit_changelog_summary
fi
emit_file "docs/src/SUMMARY.md" "Docs Summary"

awk '
  {
    if (match($0, /\[[^][]+\]\([^()]+\.md\)/)) {
      seg = substr($0, RSTART, RLENGTH)
      title = seg
      sub(/^\[/, "", title)
      sub(/\]\([^()]+\.md\)$/, "", title)
      file = seg
      sub(/^\[[^][]+\]\(/, "", file)
      sub(/\)$/, "", file)
      printf("%s\t%s\n", title, file)
    }
  }
' "$summary" |
  while IFS=$'\t' read -r title file; do
    [[ -z "${file}" ]] && continue
    validate_summary_entry_path "$file"

    path="docs/src/${file}"
    if [[ ! -f "$repo_root/$path" ]]; then
      echo "llms: missing doc file referenced from SUMMARY.md: ${file}" >&2
      exit 1
    fi

    escaped_title="$(escape_yaml_double_quoted "$title")"
    section_id="$(make_section_id "$path")"

    printf '\n' >>"$tmp"
    printf -- '---\nfile: %s\ntitle: "%s"\nsection_id: "%s"\n---\n\n' \
      "$path" "$escaped_title" "$section_id" >>"$tmp"
    cat "$repo_root/$path" >>"$tmp"
    printf '\n' >>"$tmp"
  done

check_bundle_consistency

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
