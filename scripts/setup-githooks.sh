#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [[ -z "$repo_root" ]]; then
  echo "setup-githooks: not a git repository; run: git init" >&2
  exit 1
fi

git -C "$repo_root" config core.hooksPath githooks
chmod +x "$repo_root/githooks/"* || true

echo "Configured git hooks: core.hooksPath=githooks" >&2
echo "Hooks enabled: pre-commit, commit-msg" >&2
