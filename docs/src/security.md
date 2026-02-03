# Security

See `SECURITY.md` for the threat model and guidance.

Key points:

- Root-relative path normalization rejects `/`-absolute paths and `..` segments.
- Secret deny rules apply to direct access; redaction applies to returned text.
  - Note: deny/skip globs like `dir/*` also apply to descendants under `dir/**` (directory-probe semantics).
- `glob`/`grep` require scoping (`path_prefix`) unless explicitly allowed.
- Auth is required by default; `--unsafe-no-auth` is intended for local development only.
- If the policy/config is not fully trusted, run the service with `--trust-mode untrusted` to disable risky features (env interpolation, env-backed tokens, writes, full scans, audit paths, and `--unsafe-no-auth`).
- The rate limiter uses the TCP peer IP and does not parse `x-forwarded-for`.
