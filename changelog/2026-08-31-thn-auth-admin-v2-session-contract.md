# 2026-08-31 — THN Auth Admin v2 session contract

## Scope

- Added the dormant, additive Auth Admin v2 session handler for the dedicated
  TEST-only The Hair Narrative admin origin. The existing v1 handler and its
  full byte fingerprint remain unchanged; the v2 SAM function points directly
  to `auth_admin_session_v2.lambda_handler`.
- Required the exact active THN service-binding registry row before every v2
  route can use Cognito or session storage. Unknown methods, paths, origins,
  purposes, versions, scopes, and disabled users fail closed.
- Added host-only session, CSRF, challenge, and enrollment cookies with a
  30-minute idle session, 12-hour absolute session, and five-minute single-use
  challenge/enrollment state. Session rotation preserves the validated subject,
  immutable `accountPurpose`, and current `sessionVersion`.
- Enforced password plus Cognito TOTP challenge behavior, strict ID-token
  validation, generic browser errors, exact account/IP rolling failure windows,
  and separate current-user authorization checks.
- Added DynamoDB transaction contracts that consume a claimed challenge and
  persist its successor atomically. Conditional races remain authentication
  conflicts; throttling, transaction conflicts, provider outages, and malformed
  storage responses are classified as sanitized service unavailability.

## Isolation and safety

- The implementation is build-only. It adds no route, event, stack resource,
  Cognito account, DNS/TLS record, deployment, or AWS mutation.
- No v2 session or challenge table is shared with Zoosite v1. TASK-016 must add
  the isolated retained/PITR resources and least-privilege permissions,
  including the exact transaction access across challenge, session, and
  current-user tables, before this handler can be wired to an API.
- A specification conflict remains a deployment blocker: TASK-018 requires QR
  and manual-key TOTP enrollment, while trust-boundary SEC-007 literally forbids
  TOTP secrets in every browser payload. The enrollment exception and its
  no-store/no-log/no-evidence constraints must be approved explicitly, or TOTP
  must be provisioned out of band, before activation.

## Verification

- TDD regression tests reproduced transient DynamoDB transaction cancellation
  being misclassified as invalid MFA and a malformed non-null claim response
  being misclassified as invalid credentials. Both now fail closed as service
  unavailability, while condition-only races remain authentication conflicts.
- Full offline suite: 138 tests passed.
- Python compilation and whitespace validation passed on the frozen tree.
- The v1 `lambda_function.py` matches its normalized Git baseline: 77,378
  UTF-8 bytes at SHA-256
  `bef7b3b31ef6643adcbadef4dd1d7d2e7e1f82ed0dbfc3c728d910c8db2de67f`.
- Local `sam validate --lint` passed. `pip-audit` is unavailable on this
  workstation and is not counted as a passing check.

No commit, push, deployment, route activation, or AWS change was performed.
