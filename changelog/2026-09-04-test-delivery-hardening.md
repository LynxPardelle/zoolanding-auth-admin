# 2026-09-04 — TEST delivery and immutable rollback hardening

- Replaced the broad TEST deployment path with exact `dev`-to-`test` promotion, unprivileged validation/build, commit-pinned actions, and OIDC only in the protected `test` environment job.
- Added full-SHA, full-inventory artifact verification, runtime-configuration validation before credentials, and a live-state guard that keeps ordinary Auth Admin v2 provisioning and activation disabled.
- Added fail-closed change-set review, stack/Lambda readiness smoke checks, immutable rollback coordinates, and manual rollback from one successful recorded TEST artifact.
- Verification passed with 256 tests, Actionlint, Python and Bash syntax checks, scoped CloudFormation lint, dependency audit, and diff validation. No workflow was dispatched and no AWS, Cognito, production, draft, or Zoosite state changed.
