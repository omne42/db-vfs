# Security Policy

## Private vulnerability reporting

Do **not** disclose unpatched vulnerabilities in public issues.

Preferred channel:

- GitHub Private Vulnerability Reporting / Security Advisory (if enabled for this repository).

If private advisory is unavailable, contact maintainers privately first and avoid posting exploit
details publicly.

## Response process (target SLA)

- Acknowledge report: within **72 hours**.
- Initial triage + severity assignment: within **7 days**.
- Fix + coordinated disclosure target:
  - critical/high: as soon as possible (typically <= 30 days)
  - medium/low: next scheduled patch cycle.

Actual timelines depend on exploitability and patch validation.

## Supported versions

| Version line | Status | Security fixes |
| --- | --- | --- |
| `Unreleased` / `main` | active | yes |
| latest stable (`0.1.x`) | active | yes |
| older than latest stable | EOL | no guarantee |

## Security baseline requirements

- Use HTTPS/TLS for all bearer-token transport.
- Keep auth enabled in production; avoid `--unsafe-no-auth`.
- Use high-entropy tokens (random, >= 32 bytes recommended) and rotate regularly.
- Scope tokens by `allowed_workspaces` (avoid global wildcard in production).
- Enable per-IP rate limiting and audit logging.

## Threat model notes

`db-vfs` is an application-layer guardrail system, not an OS sandbox.

- It validates paths/policies and enforces operation budgets.
- It mitigates secrets exposure via deny-globs and redaction.
- It does **not** replace container sandboxing, host hardening, or network controls.

For stronger isolation, deploy inside hardened containers/VMs and enforce edge gateway controls.
