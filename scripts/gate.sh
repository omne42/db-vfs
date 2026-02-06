#!/usr/bin/env bash
set -euo pipefail

if ! repo_root="$(git rev-parse --show-toplevel 2>/dev/null)"; then
  echo "gate: must run inside a git repository." >&2
  exit 1
fi

if [[ ! -f "$repo_root/Cargo.toml" ]]; then
  echo "gate: no Cargo.toml found; skipping." >&2
  exit 0
fi

llms_script="$repo_root/scripts/llms.sh"
if [[ -f "$llms_script" && ! -x "$llms_script" ]]; then
  echo "gate: llms script exists but is not executable: $llms_script" >&2
  exit 1
fi
if [[ -x "$llms_script" ]]; then
  echo "gate: llms (--check)" >&2
  "$llms_script" --check
fi

echo "gate: rust (fmt/check/clippy/test)" >&2
(
  cd "$repo_root"
  cargo fmt --all -- --check
  cargo check --workspace --all-targets --locked
  cargo check --workspace --all-targets --no-default-features --locked
  cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
  cargo test --workspace --locked
  cargo test --workspace --no-default-features --locked
  cargo test --workspace --all-features --locked
  cargo tree -d --workspace --locked
  if command -v cargo-audit >/dev/null 2>&1; then
    cargo audit
  else
    echo "gate: cargo-audit not installed; skipping advisory scan" >&2
  fi
)
