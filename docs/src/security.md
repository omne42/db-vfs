# Security

## Minimum security baseline

Use this checklist for production:

- [ ] run behind HTTPS/TLS end-to-end;
- [ ] keep auth enabled (do **not** use `--unsafe-no-auth`);
- [ ] if you embed the Router from Rust, stay on `BuilderAuthMode::Enforced` by default; only use
  the explicit unauthenticated builder modes when that risk is intentional and reviewed;
- [ ] scope tokens with `allowed_workspaces` (avoid `*`);
- [ ] keep `workspace_id` values literal; do not treat `*` as a valid namespace character;
- [ ] set rate limiting (`limits.max_requests_per_ip_per_sec` and burst);
- [ ] enable audit log with `audit.jsonl_path` and keep `audit.required = true`;
- [ ] run with restrictive file permissions/umask for SQLite.

## Terms

- **Direct access deny**: `secrets.deny_globs` blocks path operations.
- **Redaction**: `secrets.redact_regexes` rewrites output text.
- **Directory-probe semantics**: `dir/*` also applies to `dir/**` descendants.
- **Matcher consistency**: library callers若显式传入 `SecretRedactor` / `TraversalSkipper`，它们必须来自同一份已验证 policy；严格构造器会直接拒绝不一致，compatibility 构造器会回退成 policy 编译结果并发出一次显式告警。

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
