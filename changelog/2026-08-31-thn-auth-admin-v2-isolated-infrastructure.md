# 2026-08-31 — THN Auth Admin v2 isolated infrastructure

## Scope

- Added a dormant TEST-only Auth Admin v2 stack slice behind the explicit
  `EnableThnAuthAdminV2=false` default and reviewed descriptor/policy gates.
- Added five isolated DynamoDB tables for sessions, current-user state,
  challenges, throttles, and reserved audit storage. Every table is encrypted,
  protected from deletion, retained on replacement/deletion, and uses PITR;
  ephemeral tables also use TTL.
- Added a dedicated retained Cognito user pool/client with admin-created users,
  no public signup, mandatory software-token MFA, and a secretless client whose
  password flow is usable only through IAM-authorized admin operations.
- Changed password/challenge calls to the IAM-authorized
  `AdminInitiateAuth`/`AdminRespondToAuthChallenge` flow on the exact dedicated
  pool. The Client ID alone can no longer bypass the BFF failure windows through
  Cognito's unauthenticated `InitiateAuth` API.
- Added a dedicated execution role, Lambda, HTTP API, six exact session routes,
  six route-specific invoke permissions, retained access/function logs, and
  Lambda/API alarms. No wildcard route, function URL, managed CORS preflight,
  v1 route, or public output was added.
- Limited the role to the exact registry row and exact session/challenge/
  throttle/current-user operations required by the implementation. The audit
  table has no session-runtime writer. The build-only owner path now uses an
  invoke-only human role plus a non-HTTP mediator whose audit appends are
  conditional and whose role is the only principal exempted from the table's
  `PutItem` deny.
- Decoupled retained TEST state from executable route activation behind the
  separate default-false `ProvisionThnAuthAdminV2State` lifecycle. The five
  tables, dedicated pool/client/group, and four fixed-name log groups remain
  stack-managed when routes are disabled, preventing retained-orphan collisions
  on reactivation; production still receives none of these resources.
- Added a minimized ordinary-deploy guard that blocks on active v2 parameters,
  legacy `ThnAuthAdminV2*` resources, unstable stack state, or unverifiable AWS
  responses. It projects only status/counts and never prints AWS response data.

## Ownership and isolation

- Removed the non-routable `/auth-v2/runtime-config` fallback from Auth Admin.
  API Proxy is the sole owner of that route; Auth Admin owns only the six
  session routes.
- Added the Auth Admin v2 role to the Content-Hub-owned registry resource policy
  for one consistent `GetItem` on one service-binding key. It receives no
  registry write, `ConditionCheckItem`, reservation, scan, query, or v1 access.
- Existing v1 resources remain outside the v2 condition and retain their prior
  route and role boundaries.

## Verification

- Auth Admin unit/contract suite: 246 tests passed, including the normalized
  source fingerprint for the unchanged v1 handler.
- Basic `sam validate` and a clean `sam build --no-cached` passed. The local
  bundled lint catalog predates `AWS::Lambda::ResourcePolicy` and reports only
  that type as unknown; a sanitized read-only CloudFormation `describe-type`
  query confirmed the type exists in `us-east-1`. The compiled template
  contains exactly six Auth Admin v2 route keys and no runtime-config route or
  session-runtime audit write permission.
- Content Hub registry-focused suite: 35 tests passed. Its source template also
  passed `sam validate --lint`.
- The Content Hub full-suite timezone failures reproduce against `HEAD` on this
  Windows Python 3.13 environment because IANA timezone data is unavailable;
  scheduler/runtime files are byte-unchanged by this task.

## Activation blockers

- No stack, route, user, DNS/TLS record, or AWS resource was activated.
- Stack termination protection must be verified through the deployment
  workflow before enabling the v2 condition; the template gate alone cannot
  prove the stack setting.
- API Proxy still needs its dedicated `/auth-v2/runtime-config` implementation
  before cutover.
- V1, v2 session, origin-authorizer, and owner-mediator functions now use exact
  makefile source allowlists; repository-only tests/tools cannot enter another
  function's deployment artifact. Runtime dependencies are installed per
  artifact instead of relying on the Lambda runtime SDK.
- The approved manual TOTP enrollment UX conflicts with the literal SEC-007
  ban on returning a TOTP secret to a browser. A narrow enrollment exception or
  out-of-band provisioning decision remains required before activation.
- The exact mediator invoke permission also permits asynchronous Lambda
  invocation, which conflicts with the synchronous-only owner-operator contract
  and remains an activation gate. Alias exclusivity and failure observability
  are now closed by a full resource policy and dedicated Lambda error alarm.

No commit, push, deployment, or AWS mutation was performed.
