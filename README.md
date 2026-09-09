# Zoolanding Auth Admin

<!-- zoolanding-hub-routing:start -->
## Zoolanding Knowledge Router

Shared procedures are routed through the Zoolandingpage hub. Start with [AGENTS.md](AGENTS.md) and open only the document needed for the current task.

| Task | Read |
| --- | --- |
| Auth profile contract | [docs/api-driven-config/17-auth-profile-registry.md](https://github.com/LynxPardelle/zoolandingpage/blob/main/docs/api-driven-config/17-auth-profile-registry.md) |
| Protected feature contract | [docs/api-driven-config/19-protected-feature-contract.md](https://github.com/LynxPardelle/zoolandingpage/blob/main/docs/api-driven-config/19-protected-feature-contract.md) |
| Draft auth audit | [docs/api-driven-config/18-draft-auth-audit-matrix.md](https://github.com/LynxPardelle/zoolandingpage/blob/main/docs/api-driven-config/18-draft-auth-audit-matrix.md) |
| Fleet ownership | [docs/repository-map.md](https://github.com/LynxPardelle/zoolandingpage/blob/main/docs/repository-map.md) |

Critical repository-specific safety, deployment, and rollback rules remain local.
<!-- zoolanding-hub-routing:end -->

Generic serverless auth-admin BFF for Zoolanding drafts.

It adds private session, account, and user-management workflows on top of Cognito-backed draft auth. It is intended for features such as `/mi-cuenta`, `/admin/*`, future blogs, per-draft analytics dashboards, and client-side configuration surfaces that need server-side authorization.

## Start here

| Task | Source |
| --- | --- |
| Agent safety and read order | [AGENTS.md](AGENTS.md) |
| Current security and session contract | [Security Model](#security-model) |
| Exact HTTP surface | [Endpoints](#endpoints), [lambda_function.py](lambda_function.py), and [template.yaml](template.yaml) |
| Server-only profile shape | [Profile configuration](docs/profile-configuration.md) |
| Tests and readiness | [Local Verification](#local-verification) and [tests/](tests/) |
| Promotion and deployment | [Deployment Shape](#deployment-shape) and [.github/workflows/](.github/workflows/) |
| Historical implementation evidence | [changelog/README.md](changelog/README.md) |

Shared browser-safe contracts live in the Zoolandingpage hub:

- [Auth profile registry](https://github.com/LynxPardelle/zoolandingpage/blob/main/docs/api-driven-config/17-auth-profile-registry.md)
- [Protected feature contract](https://github.com/LynxPardelle/zoolandingpage/blob/main/docs/api-driven-config/19-protected-feature-contract.md)
- [Fleet ownership](https://github.com/LynxPardelle/zoolandingpage/blob/main/docs/repository-map.md)

The hub owns cross-repository browser contracts. This repository owns the BFF implementation, server-side trust boundaries, storage, deployment, and rollback. Keep dated evidence in `changelog/`; keep current behavior here, in code, tests, template, and workflows.

## Security Model

- Browser auth forms send only public context: `domain`, `authProfileId`, email, password, code, and language.
- Tenant, environment, Cognito user pool, app client, group policy, approval policy, and manageable groups come from `AUTH_ADMIN_CONFIG_JSON_BASE64`.
- No JWT, ID token, access token, or refresh token is returned to the browser; raw Cognito challenge sessions are also server-only.
- Sign-in creates a server-side session and returns only sanitized metadata.
- Cognito `SOFTWARE_TOKEN_MFA` and `MFA_SETUP` challenges store raw Cognito `Session` values server-side behind a short-lived challenge cookie.
- The THN v2 `POST /auth-v2/session/mfa/setup` response is the only narrow
  browser exception for TOTP setup material. It returns the manual setup key
  only after exact-origin and CSRF checks, lasts five minutes through a
  single-use enrollment state, uses no-store/no-referrer headers, and never
  puts setup material in URLs, logs, analytics, screenshots, or durable state.
- Voluntary TOTP enrollment for an already signed-in user stores the temporary Cognito access token server-side only behind a short-lived enrollment cookie while the setup code is verified.
- Voluntary TOTP disablement requires an active BFF session, normal CSRF, the current password, and the current authenticator code before Cognito MFA preference is changed.
- Admin/support MFA reset is separate from self-service disablement. It requires an approved admin session and CSRF, blocks self-reset, disables the target user's Cognito software-token MFA preference, bumps the target session version, and writes an audit event.
- This BFF currently creates sessions through custom sign-in. Cognito Managed Login / Hosted UI can remain enabled for drafts that prefer it, but Hosted UI sessions do not become BFF HttpOnly sessions unless a future server-side callback/token-exchange endpoint is added.
- Requests after sign-in must carry `X-ZLP-Domain` and `X-ZLP-Auth-Profile-Id`; the Lambda compares them with the private session before returning account/admin data.
- The session cookie is `__Host-zlp_session` with `HttpOnly`, `Secure`, `SameSite=Lax`, and `Path=/`.
- Mutating requests require `X-ZLP-CSRF` to match the `zlp_csrf` cookie and the server-side CSRF hash.
- Challenge mutations require the same CSRF header to match the readable challenge CSRF cookie, normally `zlp_challenge_csrf`, and the server-side challenge CSRF hash.
- Failure responses may include stable public `errorCode` values so drafts can localize copy; for example `auth_environment_mismatch` after valid credentials prove a user belongs to another configured environment, or `auth_challenge_expired` when the short-lived challenge is gone.
- `/mi-cuenta` should call `GET /auth/session/me` and is valid for any authenticated user.
- `GET /auth/session/me` may include public MFA metadata from Cognito `AdminGetUser` under `account.mfa`; it must not return TOTP secrets, Cognito sessions, tokens, or recovery material.
- `/admin/*` calls require an approved account with a configured admin group.
- Admin requests re-check current user state/session version so suspensions and group changes do not rely on stale session roles.
- Every admin mutation writes an audit event.

## Endpoints

Shared v1 surface:

- `POST /auth/session/signin`
- `POST /auth/session/challenge/respond`
- `POST /auth/session/mfa/setup`
- `POST /auth/session/mfa/verify`
- `POST /auth/session/mfa/enroll/start`
- `POST /auth/session/mfa/enroll/verify`
- `POST /auth/session/mfa/disable`
- `GET /auth/session/me`
- `POST /auth/session/logout`
- `GET /auth/admin/users`
- `POST /auth/admin/users/{subject}/approve`
- `POST /auth/admin/users/{subject}/groups`
- `POST /auth/admin/users/{subject}/suspend`
- `POST /auth/admin/users/{subject}/reactivate`
- `POST /auth/admin/users/{subject}/mfa/reset`

Dormant The Hair Narrative TEST-only v2 surface (disabled by default):

- `POST /auth-v2/session/signin`
- `POST /auth-v2/session/challenge/respond`
- `POST /auth-v2/session/mfa/setup`
- `POST /auth-v2/session/mfa/verify`
- `GET /auth-v2/session/me`
- `POST /auth-v2/session/logout`

The v2 surface uses isolated tables, a dedicated retained Cognito pool/client,
namespaced cookies, an exact service-binding registry row, IAM-authorized
server-side Cognito authentication, mandatory TOTP, and the exact dedicated
origin `https://admin-test.thehairnarrative.com`. API Proxy—not this service—owns
`GET|POST /auth-v2/runtime-config`. No v2 route is active while
`EnableThnAuthAdminV2=false`. Retained tables, Cognito resources, and fixed-name
log groups require the separate default-false
`ProvisionThnAuthAdminV2State=true` TEST-only lifecycle. Once provisioned, they
stay under stack ownership when routes are disabled; no THN v2 state resource
exists in the production stack. The ordinary TEST workflow explicitly keeps
both toggles false and fails closed if it detects active v2 parameters or any
pre-parameter `ThnAuthAdminV2*` resource. Only a future dedicated workflow may
own the complete v2 parameter set.

The build-only owner operator is [tools/provision_thn_owner.py](tools/provision_thn_owner.py).
It accepts only the named TEST operator role whose account matches the reviewed,
code-owned SHA-256 account anchor, and only in `us-east-1`. The anchor is never
an environment or argv account selector. The CLI is a
thin synchronous SigV4 client of the exact versioned
`zoolanding-auth-admin-test-ThnOwnerOperatorV2:test` alias's buffered
`AWS_IAM` function URL. It discovers that exact URL through
`GetFunctionUrlConfig`; the human role receives `InvokeFunctionUrl` and the
post-October-2025 `InvokeFunction` permission only when
`lambda:InvokedViaFunctionUrl=true`. Identity and resource policies deny direct
or asynchronous invocation, including from the named operator. The mediator has
no API route, browser CORS, custom domain, DLQ, or destination and owns the
Cognito, current-state, and conditional audit permissions. The mediator
anchors pool, client, and group IDs to the exact
`zoolanding-auth-admin-test` CloudFormation logical resources, and requires
the newly formalized `journal-owner` group in that pool. Its closed
operations are `create`, `enable`, `disable`, `reset`, and
`repair-session-version`; `accountPurpose=client-owner` is code-owned and
immutable. Creation starts disabled at session version 1, and enablement is a
separate versioned operation before first login. A singleton DynamoDB
reservation and exact Cognito membership prevent a second owner. Every run
must successfully write a conditional create-only intent before mutation. The
reviewed tool then attempts a completed or failed terminal event; if a terminal
write fails, the durable intent remains the reconciliation anchor.
Reset disables the account, revokes sessions, sets a temporary password,
deletes the registered TOTP, and requires an explicit later `enable`. The CLI
prompts for owner email and temporary passwords instead of accepting either in
argv. Install its pinned SDK with `python -m pip install -r requirements-tools.txt`.
The isolated Lambda artifacts also install their exact pinned runtime
requirements: PyJWT for v1/v2 session handlers and boto3 for the owner mediator.
The CLI and mediator never call or edit
the shared Cognito user-lifecycle service and never returns provider IDs,
owner PII, temporary passwords, or TOTP material.

The audit table denies `PutItem` to every principal except the deterministic
mediator execution role and denies update/delete/batch/PartiQL mutation to all
principals. The mediator still requires
`attribute_not_exists(pk/sk)` on every append. This is append-only against the
human operator; it is not WORM against an authorized deployer able to replace
the mediator or stack policy.

### Isolated TEST QA rehearsal

[tools/provision_thn_qa.py](tools/provision_thn_qa.py) is a separate signed client
of that same IAM-only buffered alias. The existing mediator (reserved concurrency
one) dispatches four closed operations with server-fixed `accountPurpose=qa`;
neither client nor browser can choose a subject, scope, purpose, pool or group.
The owner CLI, fixed `client-owner` purpose and transactional owner singleton
remain unchanged. QA has its own transactional reservation, immutable purpose
and exact provider-subject binding. A durable owner binding denies QA creation,
enablement and reset, including malformed owner-binding records.

| QA operation | Authority after success | Meaning |
| --- | --- | --- |
| `qa-create` | Disabled, version 1 | Reserve the sole QA identity before owner onboarding; join only the exact QA rehearsal group |
| `qa-enable` | Enabled, new version | Allowed only before owner binding, with completed reset and no terminal retirement |
| `qa-reset` | Disabled, new version | Revoke old sessions/challenges first; reset password and remove TOTP for another human enrollment |
| `qa-disable` | Disabled, terminal retirement | Revoke first, disable provider sign-in, globally sign out and remove only QA membership; repeat to finish cleanup |

Reset is not retirement: a partial reset keeps a pending marker and cannot be
enabled until an explicit reset retry completes. Terminal disable can never be
undone with create, reset or enable. Both operations revoke the exact reserved
subject's state/version before provider discovery or identity reads, so provider
failure cannot leave old BFF authority active. Provider cleanup failures still
report failure and require retry; success is not inferred from a sleep or timeout.
An ambiguous enable or missing completion audit quarantines QA as retired.

QA challenges, TOTP enrollment and session finalization carry a server-only
reservation/subject/purpose/version fence captured before authentication. Each
continuation rechecks current authority. Atomic successor writes also check the
exact QA state, reservation and absence of an owner binding, closing reset,
reenablement and finalization races. Aliases cannot enter the unfenced owner
path; historical QA challenges without a fence cannot finalize a session.
The browser sees no fence, reservation, provider identifier or new capability.

The client prompts for email and temporary password without echoing them. Never
put these values, cookies or TOTP material in command arguments or evidence.
Final rehearsal closure requires successful terminal `qa-disable`, rejected old
session/challenge access and QA membership absent before owner onboarding.
Retain the QA account, state, content and append-only audit: this procedure does
not delete data or add cleanup permissions. It declares no new infrastructure
resource or service, and does not change existing IAM policies, pool, routes,
domain, function, human role or the shared Cognito user-lifecycle service.
Publishing code may create new immutable versions of the existing functions;
keep reviewed rollback versions. Local tests do not prove live cleanup or MFA.

## Server-only profile configuration

Deployments pass a base64-encoded JSON profile allowlist through `AuthAdminConfigJsonBase64`. The exact example, field rules, MFA policy, and sensitive setup-material boundary live in [docs/profile-configuration.md](docs/profile-configuration.md). Browser requests cannot choose tenant, environment, group, approval, Cognito, or storage policy.

## Local Verification

```powershell
python -m unittest discover -s tests -p "test_*.py"
sam validate
pip-audit -r requirements.txt
pip-audit -r requirements-tools.txt
python tools\check_auth_admin_readiness.py --region us-east-1
python tools\provision_thn_owner.py --help
python tools\provision_thn_qa.py --help
```

The readiness check is read-only by default. It discovers the configured test and production auth-admin stack table outputs, verifies the session, user-state, and audit tables have PITR enabled, and confirms an audit table is present. Use `--enable-pitr` only when the discovered table names are confirmed auth-admin stack tables.

## Deployment Shape

Branches:

- `dev` runs CI only; the former cloud development environment is retired.
- `test` deploys to GitHub Environment `test` and SAM config `test`.
- `main` deploys to GitHub Environment `production` and SAM config `prod`.

Required GitHub Environment variables:

- `AWS_ROLE_ARN`
- `AWS_REGION`, normally `us-east-1`
- `AUTH_ADMIN_CONFIG_READY`, set to `true` after the matching secret exists
- `COGNITO_USER_POOL_ARNS`, comma-delimited allowlist for IAM-scoped Cognito admin actions

Required GitHub Environment secret:

- `AUTH_ADMIN_CONFIG_JSON_BASE64`

Deploy jobs fail closed before AWS credential setup unless `AWS_ROLE_ARN`, `AUTH_ADMIN_CONFIG_READY=true`, `COGNITO_USER_POOL_ARNS`, and `AUTH_ADMIN_CONFIG_JSON_BASE64` are present in the target GitHub Environment. CI still runs without those values.

Front-door routing should expose these endpoints as same-origin `/auth/session/*` and `/auth/admin/*`. Do not expose wildcard `/auth/*` in a way that steals draft-rendered pages such as `/auth/callback`.

The THN v2 slice must not be activated through the ordinary workflow. Use the
[dedicated THN TEST release](docs/thn-test-release.md) for explicit provisioning,
enablement and route-only disablement. Before activation, the workflow must preserve
the enabled parameter set on every later deployment, verify real stack
termination protection, deploy the reviewed origin-proof parameter pair, and
verify the CloudFront-overwritten viewer IP used by the account/IP failure
windows. V1, v2 session, origin-authorizer, and owner-mediator artifacts now
have separate source allowlists. The API Proxy v2 runtime route must also be
complete. These gates keep shared v1 drafts operationally zero-touch.

The former asynchronous-invoke and TOTP-ceremony activation blockers are
closed in the build-only contract. The owner mediator is reachable only through
its signed, buffered function URL and still increments the dedicated native
Lambda `Errors` alarm for sanitized runtime failures. TOTP setup has the narrow
five-minute, single-use browser exception described above. The default-off
template and ordinary-deploy guard still prevent either contract from becoming
active before the dedicated TEST activation workflow and remaining front-door
gates are complete.

Lambda artifact dependency installation explicitly targets Linux x86_64 /
Python 3.13 to match `template.yaml`, even when the Makefile runs on Windows.
Native dependencies must have compatible binary wheels; the build does not
silently compile them for the host. Source allowlists and runtime behavior are
explicit. QA dispatch and both operator clients belong only to the existing
owner-mediator artifact; the read-only QA fence module additionally belongs to
the existing v2 session artifact. V1 and origin-authorizer payloads admit no QA
source. Existing CI discovers the QA tests and builds these same four target
allowlists; no new job, permission, deployment environment or artifact target is
introduced. Build-only CFFI console launchers are omitted, and artifact checks
reject Windows binaries and compiled host bytecode.
