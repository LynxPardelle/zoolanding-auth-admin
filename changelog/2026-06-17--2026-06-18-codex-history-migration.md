# 2026-06-17 through 2026-06-18 CT — Codex history migration

This entry preserves dated evidence removed from `Codex.md` during the knowledge-architecture pilot. Current behavior is defined by README, code, tests, `template.yaml`, and workflows.

## Baseline before migration

- `AGENTS.md` did not exist.
- `README.md` was 9,523 bytes and 156 lines.
- `Codex.md` was 7,168 bytes and 29 lines, including 11 dated references.
- README plus Codex totaled 16,691 bytes; one dedicated changelog entry existed.

## Pilot result

- `Codex.md` is 1,144 bytes, an 84.0% reduction.
- The default `AGENTS.md` plus README path is 11,230 bytes, 32.7% smaller than the previous README plus Codex path.
- The 3,839-byte profile example moved to one task-specific document and stays outside the default read path.

## Migrated chronology

- 2026-06-17 CT: the Lambda timeout baseline moved from 15 to 30 seconds after a cold Cognito-backed production sign-in reached the old limit.
- 2026-06-17 CT: native protection for this private repository was unavailable on the account plan, so CI and deploy workflow merge guards remained the enforceable promotion boundary.
- 2026-06-18 00:21 CT: profile-driven Cognito MFA challenges gained server-side challenge records, short-lived challenge/CSRF cookies, scoped Cognito permissions, and controlled authentication errors.
- 2026-06-18 01:20 CT: signed-in users gained voluntary TOTP enrollment with reauthentication and a server-side temporary access-token record.
- 2026-06-18 03:42 CT: TOTP display labels became profile-configurable and self-service disablement required password plus current TOTP; lost-device recovery remained admin-only.
- 2026-06-18 12:51 CT: `/auth/session/me` began returning sanitized public MFA state from a fresh server-side Cognito read.
- 2026-06-18 15:52 CT: admin MFA reset added CSRF, self-reset prevention, session-version revocation, and a sanitized immutable audit event.
- 2026-06-18 17:43 CT: stable public auth error codes were added for verified environment mismatch and expired challenge state while generic credential failures stayed non-specific.
- 2026-06-18 18:01 CT: `environmentClaimMode` kept strict `single` as default and added explicit server-only `list` opt-in.
- 2026-06-18 23:00 CT: audit keys gained a random per-write suffix and the read-only readiness check was added. See [the dedicated audit-readiness entry](2026-06-18-auth-admin-audit-readiness.md).

No secrets, raw configuration values, tokens, cookies, or user PII were migrated.
