# Security

See `SECURITY.md` for the threat model and guidance.

Key points:

- Root-relative path normalization rejects `/`-absolute paths and `..` segments.
- Secret deny rules apply to direct access; redaction applies to returned text.
- `glob`/`grep` require scoping (`path_prefix`) unless explicitly allowed.
- Auth is required by default; `--unsafe-no-auth` is intended for local development only.
- The rate limiter uses the TCP peer IP and does not parse `x-forwarded-for`.
