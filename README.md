# Zoolanding Auth Admin

Generic serverless auth-admin BFF for Zoolanding drafts.

It adds private session, account, and user-management workflows on top of Cognito-backed draft auth. It is intended for features such as `/mi-cuenta`, `/admin/*`, future blogs, per-draft analytics dashboards, and client-side configuration surfaces that need server-side authorization.

## Security Model

- Browser auth forms send only public context: `domain`, `authProfileId`, email, password, code, and language.
- Tenant, environment, Cognito user pool, app client, group policy, approval policy, and manageable groups come from `AUTH_ADMIN_CONFIG_JSON_BASE64`.
- No JWT, ID token, access token, or refresh token is returned to the browser.
- Sign-in creates a server-side session and returns only sanitized metadata.
- This BFF currently creates sessions through custom sign-in. Cognito Managed Login / Hosted UI can remain enabled for drafts that prefer it, but Hosted UI sessions do not become BFF HttpOnly sessions unless a future server-side callback/token-exchange endpoint is added.
- Requests after sign-in must carry `X-ZLP-Domain` and `X-ZLP-Auth-Profile-Id`; the Lambda compares them with the private session before returning account/admin data.
- The session cookie is `__Host-zlp_session` with `HttpOnly`, `Secure`, `SameSite=Lax`, and `Path=/`.
- Mutating requests require `X-ZLP-CSRF` to match the `zlp_csrf` cookie and the server-side CSRF hash.
- `/mi-cuenta` should call `GET /auth/session/me` and is valid for any authenticated user.
- `/admin/*` calls require an approved account with a configured admin group.
- Admin requests re-check current user state/session version so suspensions and group changes do not rely on stale session roles.
- Every admin mutation writes an audit event.

## Endpoints

- `POST /auth/session/signin`
- `GET /auth/session/me`
- `POST /auth/session/logout`
- `GET /auth/admin/users`
- `POST /auth/admin/users/{subject}/approve`
- `POST /auth/admin/users/{subject}/groups`
- `POST /auth/admin/users/{subject}/suspend`
- `POST /auth/admin/users/{subject}/reactivate`

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
- `AUTH_ADMIN_CONFIG_JSON_BASE64`
- `COGNITO_USER_POOL_ARNS`, comma-delimited allowlist for IAM-scoped Cognito admin actions

Front-door routing should expose these endpoints as same-origin `/auth/session/*` and `/auth/admin/*`. Do not expose wildcard `/auth/*` in a way that steals draft-rendered pages such as `/auth/callback`.
