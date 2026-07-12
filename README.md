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

## Server-only profile configuration

Deployments pass a base64-encoded JSON profile allowlist through `AuthAdminConfigJsonBase64`. The exact example, field rules, MFA policy, and sensitive setup-material boundary live in [docs/profile-configuration.md](docs/profile-configuration.md). Browser requests cannot choose tenant, environment, group, approval, Cognito, or storage policy.

## Local Verification

```powershell
python -m unittest discover -s tests -p "test_*.py"
sam validate
pip-audit -r requirements.txt
python tools\check_auth_admin_readiness.py --region us-east-1
```

The readiness check is read-only by default. It discovers the configured test and production auth-admin stack table outputs, verifies the session, user-state, and audit tables have PITR enabled, and confirms an audit table is present. Use `--enable-pitr` only when the discovered table names are confirmed auth-admin stack tables.

## Deployment Shape

Branches:

- `dev` deploys to GitHub Environment `dev` and SAM config `dev`.
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
