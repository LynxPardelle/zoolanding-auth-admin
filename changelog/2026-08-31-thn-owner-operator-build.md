# 2026-08-31 — THN owner operator build

## Scope

- Added the local-only `tools/provision_thn_owner.py` operator for the one The
  Hair Narrative client-owner account.
- Formalized the dedicated Cognito group as `journal-owner`; this is a new
  TASK-017 contract selected to match the existing THN auth-profile naming.
- Anchored the pool, client, and `journal-owner` group to the exact TEST
  CloudFormation stack logical resources. The reviewed account, `aws`
  partition, and `us-east-1` are fixed trust inputs rather than caller-selected
  destinations.
- Added a transactional `OWNER#client-owner` singleton reservation and exact
  one-member Cognito checks. Repeated partial create, enable, and disable runs
  reconcile safely without creating another owner or bumping a version twice.
  If a new Cognito user cannot pass identity or singleton-group validation, the
  create path now compensates by disabling that unequivocally new user before
  returning the failure. An ambiguous `AdminCreateUser` failure never claims
  ownership from a later read and therefore never disables a potentially
  concurrent user; a later create run can reconcile the ungrouped account.
- Added closed create, enable, disable, password/TOTP reset, and monotonic
  session-version repair operations. Reset fails closed: it disables state and
  Cognito, revokes sessions, replaces the temporary password, deletes the
  registered software token with `AdminDeleteSoftwareToken`, and requires a
  separate later enable. Purpose, scope, group, and resource selectors remain
  code-owned.
- Replaced direct human Cognito/DynamoDB/CloudFormation permissions with one
  exact `lambda:InvokeFunction` permission on a versioned `:test` alias. The
  direct-invoke-only mediator has no HTTP route, Function URL, asynchronous
  destination, production selector, or shared user-lifecycle permission.
- Added sanitized, conditional create-only intent/completed/failed audit events
  with one operation ID in the reviewed CLI. The intent must be written before
  any mutation. Owner PII, temporary
  passwords, TOTP material, Cognito identifiers, and provider errors do not
  enter results or audit items.
- Removed owner email, temporary password, account, and region selectors from
  argv and sanitized parser failures so rejected values are not echoed. The CLI
  prompts locally for email/password and validates STS against an inert-until-
  reviewed code-owned account digest; its SDK is pinned in
  `requirements-tools.txt`.
- Added live `AdminGetUser` and paginated `AdminListGroupsForUser` checks before
  issuing or accepting a client-owner session. Disabled users, subject drift,
  or missing/extra groups now fail closed without extending the session.
- Restored the v1 Python source to its exact baseline and gave v1, v2 session,
  origin-authorizer, and owner-mediator functions separate makefile source
  allowlists. Repository tests, tools, and another function's modules cannot
  cross those artifact boundaries. The builder now keys dependency installation
  before copying files, so the mediator packages the pinned boto3 service model
  required by `AdminDeleteSoftwareToken`.

## Verification

- Auth Admin unit/contract suite: 246 tests passed after the mediator and
  lifecycle closure.
- CI now audits both runtime dependencies and the pinned owner-operator SDK
  requirements.
- Basic SAM validation passed. The bundled lint catalog's only error is its
  stale schema for `AWS::Lambda::ResourcePolicy`; CloudFormation's sanitized
  read-only type lookup confirms that resource is available in `us-east-1`.
- A clean no-cache SAM build completed successfully.
- All four artifact allowlists passed. The mediator imported from its isolated
  built artifact with only its handler, current-user contract, and reviewed
  owner core. The local Windows dependency build is
  validation-only; the reviewed deploy build must run on Linux or in a Lambda
  build container.
- The shared `zoolanding-cognito-user-lifecycle` checkout remained clean at
  `6b440d982c2b5e64eae1ec4cc800f104c65f587f`; its 18 tests passed and no
  workflow was executed.

TASK-017 remains build-only. No account was created, enabled, disabled, or
reset; no AWS, DNS, GitHub, Cognito, DynamoDB, or deployment state changed.

Activation remains blocked because raw `lambda:InvokeFunction` permission also
allows asynchronous enqueue even though the approved operator contract is
synchronous-only. The alias now has an explicit resource-policy deny for every
non-named principal, and sanitized runtime failures increment a dedicated
native Lambda error alarm.

The audit table now denies human/direct `PutItem` and all mutation/deletion
paths except create-only mediator appends guarded by
`attribute_not_exists(pk/sk)`. This is append-only against the human operator,
not WORM against an authorized deployer able to change the trusted mediator.
