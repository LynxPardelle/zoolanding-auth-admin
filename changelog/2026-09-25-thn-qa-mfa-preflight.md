# THN TEST QA MFA preflight repair

Date: 2026-09-25 (Central Time). Implementation and local validation only;
publication and AWS deployment require separate approval.

- An authorized QA create rehearsal failed before Cognito creation. Live read-only
  checks confirmed required TOTP through `GetUserPoolMfaConfig`; the operator
  incorrectly expected `EnabledMfas` in `DescribeUserPool`, where it was absent.
  The failed request left one intent and failure audit entry and no QA identity
  or reservation.
- The operator now checks the dedicated pool's required, TOTP-only configuration
  through the correct API. Its exact pool-scoped role gains only the matching
  read action. Negative tests keep optional, disabled, SMS and email MFA closed.
- `operator-patch` prepares a separate active TEST release. It preserves every
  live parameter, route, retained resource and other function package. The
  source-delta and change-set gates permit only the reviewed mediator package,
  MFA read permission, alias and retained Lambda versions.
- Local unit tests and template contracts are the pre-deployment evidence. Live
  QA creation, enablement, sign-in and TOTP enrollment remain unverified until
  the reviewed TEST release is approved and applied.
