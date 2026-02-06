#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [[ -z "$repo_root" ]]; then
  echo "setup-githooks: not a git repository; run: git init" >&2
  exit 1
fi

hooks_dir="$repo_root/githooks"
if [[ ! -d "$hooks_dir" ]]; then
  echo "setup-githooks: missing githooks directory: $hooks_dir" >&2
  exit 1
fi

for hook in pre-commit commit-msg; do
  if [[ ! -f "$hooks_dir/$hook" ]]; then
    echo "setup-githooks: missing required hook file: $hooks_dir/$hook" >&2
    exit 1
  fi
done

git -C "$repo_root" config core.hooksPath githooks
chmod +x "$hooks_dir/pre-commit" "$hooks_dir/commit-msg"

current_hooks_path="$(git -C "$repo_root" config --get core.hooksPath || true)"
if [[ "$current_hooks_path" != "githooks" ]]; then
  echo "setup-githooks: failed to set core.hooksPath to githooks (got: $current_hooks_path)" >&2
  exit 1
fi

echo "Configured git hooks: core.hooksPath=githooks" >&2
echo "Hooks enabled: pre-commit, commit-msg" >&2
