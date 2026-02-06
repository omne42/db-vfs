# LLM Context (`llms.txt`)

This repository maintains two synchronized bundle files:

- `llms.txt` (root, canonical generated output)
- `docs/llms.txt` (copy for docs distribution)

## Maintenance rules

- Source of truth for content is normal docs/README/SECURITY files.
- `llms.txt` and `docs/llms.txt` are generated artifacts.
- Do not hand-edit generated bundle files.

## Regenerate

```bash
./scripts/llms.sh
```

Expected result:

- root and docs copies are rewritten with identical content
- metadata header includes generation timestamp and source commit

Verify in CI/local:

```bash
./scripts/llms.sh --check
```

If check fails, regenerate then commit updated bundles.

## Front matter template

```yaml
---
title: db-vfs docs bundle
generated_at_utc: 2026-02-06T00:00:00Z
source_commit: <git-sha>
generator_version: scripts/llms.sh@v2
---
```

## Safe usage note

Before pasting bundle content into any LLM tool, remove sensitive values (tokens, credentials,
internal-only secrets, private URLs).
