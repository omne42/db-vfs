# `llms.txt`

Inspired by the AI SDK docs’ `llms.txt`, this repo includes a single-file documentation bundle for
LLM/RAG ingestion:

- `llms.txt` (repo root)
- `docs/llms.txt` (same content, colocated with docs)

Both are Markdown stored in a `.txt` file so they can be copied/pasted into LLM tools easily.

## Regenerate

After documentation changes:

```bash
./scripts/llms.sh
```

Verify it is up to date:

```bash
./scripts/llms.sh --check
```

## Suggested prompt

Paste `llms.txt` into your LLM tool as context, then ask questions like:

> Use the provided `llms.txt` documentation to answer my questions about `db-vfs`.
> If the answer is not in the docs, say so explicitly.
