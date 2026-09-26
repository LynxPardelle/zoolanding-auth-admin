# THN TEST QA MFA preflight repair

Date: 2026-09-25 (Central Time). The TEST promotion and first deployment
attempt were explicitly approved; the blocked change set was not executed.

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
- The approved first TEST rollout passed CI and source-only validation, then
  stopped before `ExecuteChangeSet`: CloudFormation reported conditional
  replacement on the mediator URL and alias resource policy through the
  function ARN dependency. The stack remained `UPDATE_COMPLETE` with
  termination protection; both diagnostic change sets were removed without
  execution.
- The change-set review now recognizes only those exact indirect fixed-ARN
  dependencies, including their target properties, causes and dynamic
  evaluations. It still rejects direct replacement, unrelated resources and
  changes outside the reviewed mediator package and MFA read action.
- A second, unexecuted preview replaced the dynamic mediator ARN references
  with a static ARN. CloudFormation then reported definite replacement of the
  owner mediator URL and alias resource policy. That preview was deleted. The
  narrower conditional path remains a possible endpoint interruption and is
  awaiting explicit acceptance of that changed risk before deployment.
- Live QA creation, enablement, sign-in and TOTP enrollment remain unverified
  until the repaired TEST release succeeds.
