# Zoolanding Auth Admin

Generic serverless auth-admin BFF for Zoolanding drafts.

It adds private session, account, and user-management workflows on top of Cognito-backed draft auth. It is intended for features such as `/mi-cuenta`, `/admin/*`, future blogs, per-draft analytics dashboards, and client-side configuration surfaces that need server-side authorization.

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

## Config

Deployments pass a base64-encoded JSON config through `AuthAdminConfigJsonBase64`.

```json
{
  "version": 1,
  "profiles": [
    {
      "enabled": true,
      "environment": "test",
      "domain": "zoositioweb.com.mx",
      "authProfileId": "staff",
      "provider": "cognito",
      "issuer": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_EXAMPLE",
      "userPoolId": "us-east-1_EXAMPLE",
      "clientId": "public-client-id",
      "audiences": ["public-client-id"],
      "tenantId": "zoosite",
      "tenantClaim": "custom:tenant_id",
      "environmentClaim": "custom:zoolanding_env",
      "groupClaim": "cognito:groups",
      "allowedGroups": ["zoosite-client", "zoosite-admin"],
      "adminGroups": ["zoosite-admin"],
      "manageableGroups": ["zoosite-client", "zoosite-admin"],
      "defaultUserStatus": "pending",
      "adminGroupsAutoApproved": true,
      "customAuth": {
        "signin": { "enabled": true }
      },
      "mfa": {
        "mode": "optional",
        "totp": {
          "enabled": true,
          "issuer": "zoositioweb",
          "accountLabelTemplate": "{email}",
          "friendlyDeviceName": "zoositioweb acceso"
        }
      },
      "session": {
        "challengeRespondPath": "/auth/session/challenge/respond",
        "mfaSetupPath": "/auth/session/mfa/setup",
        "mfaVerifyPath": "/auth/session/mfa/verify",
        "mfaEnrollStartPath": "/auth/session/mfa/enroll/start",
        "mfaEnrollVerifyPath": "/auth/session/mfa/enroll/verify",
        "mfaDisablePath": "/auth/session/mfa/disable",
        "challengeCsrfCookieName": "zlp_challenge_csrf",
        "mfaEnrollCsrfCookieName": "zlp_mfa_enroll_csrf"
      },
      "admin": {
        "usersPath": "/auth/admin/users",
        "approveUserPathTemplate": "/auth/admin/users/{subject}/approve",
        "groupsPathTemplate": "/auth/admin/users/{subject}/groups",
        "suspendUserPathTemplate": "/auth/admin/users/{subject}/suspend",
        "reactivateUserPathTemplate": "/auth/admin/users/{subject}/reactivate",
        "resetUserMfaPathTemplate": "/auth/admin/users/{subject}/mfa/reset"
      }
    }
  ]
}
```

Rules:

- `adminGroups` and `manageableGroups` must be subsets of `allowedGroups`.
- `environmentClaim`, when present, must be a Cognito custom claim such as `custom:zoolanding_env`.
- Config rejects secret-like keys and common secret-looking values.
- The deployed stack environment must match the selected profile `environment`.
- Stack-created DynamoDB tables are default storage. A future per-profile `tables` block can point a profile to draft-specific tables.
- `mfa.mode` may be `off`, `optional`, or `required`; `optional` and `required` require TOTP to be enabled in profile policy and Cognito.
- `mfa.totp.issuer`, `accountLabelTemplate`, and `friendlyDeviceName` are optional profile fields for authenticator-app display names. Template placeholders are limited to safe profile/user fields such as `{domain}`, `{authProfileId}`, `{tenantId}`, `{username}`, and `{email}`.
- TOTP setup material is sensitive enrollment material. Pages may display a setup secret only for explicit enrollment and must not put it in URLs, logs, analytics payloads, or durable notes.
- `/auth/session/mfa/disable` is self-service only for users who can reauthenticate with password plus current TOTP code. Lost-device recovery still belongs to an admin/support path.
- `/auth/admin/users/{subject}/mfa/reset` is the admin/support lost-device path. Cognito `AdminSetUserMFAPreference` disables the target user's software-token MFA preference; the user configures a replacement authenticator on a later sign-in/enrollment flow. It does not expose or delete a TOTP secret in browser responses.

## Local Verification

```powershell
python -m unittest discover -s tests -p "test_*.py"
sam validate
pip-audit -r requirements.txt
```

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
