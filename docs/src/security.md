# Security

## Minimum security baseline

Use this checklist for production:

- [ ] run behind HTTPS/TLS end-to-end;
- [ ] keep auth enabled (do **not** use `--unsafe-no-auth`);
- [ ] scope tokens with `allowed_workspaces` (avoid `*`);
- [ ] set rate limiting (`limits.max_requests_per_ip_per_sec` and burst);
- [ ] enable audit log with `audit.jsonl_path` and keep `audit.required = true`;
- [ ] run with restrictive file permissions/umask for SQLite.

## Terms

- **Direct access deny**: `secrets.deny_globs` blocks path operations.
- **Redaction**: `secrets.redact_regexes` rewrites output text.
- **Directory-probe semantics**: `dir/*` also applies to `dir/**` descendants.

## Untrusted mode checklist

When policy source is not trusted, run with `--trust-mode untrusted`:

- [ ] no env interpolation in policy;
- [ ] no env-backed auth tokens;
- [ ] no writes/patch/delete;
- [ ] no full scan;
- [ ] no audit path configuration;
- [ ] no `--unsafe-no-auth`.

## Reverse proxy note

Rate limiting uses TCP peer IP (not `x-forwarded-for`).

Recommended deployment pattern:

- enforce edge/gateway rate limits first;
- keep service rate limit as a second guardrail;
- avoid trusting spoofable forwarded headers unless handled by a trusted edge.
